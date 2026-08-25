#include "lattice_protocol.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/pem.h>
#include <openssl/rand.h>

#define DEFAULT_MAX_CLIENTS 256U
#define HARD_MAX_CLIENTS 4096U
#define MAX_CLIENT_OUTBOUND (2U * LATTICE_MAX_FRAME_BYTES)
#define DEFAULT_MAX_BUFFERED_BYTES (128U * 1024U * 1024U)
#define HARD_MAX_BUFFERED_BYTES (1024ULL * 1024ULL * 1024ULL)
#ifndef LATTICE_VERSION
#define LATTICE_VERSION "0.1.0"
#endif
/* Fairness budgets per poll iteration. A busy peer cannot retain the single
 * event loop by continuously keeping its socket readable or writable. */
#define MAX_RECEIVE_BYTES_PER_TICK (64U * 1024U)
#define MAX_SEND_BYTES_PER_TICK (64U * 1024U)
#define MAX_FRAMES_PER_TICK 64U

struct client {
  int fd;
  unsigned char *in;
  size_t in_len;
  size_t in_cap;
  unsigned char *out;
  size_t out_offset;
  size_t out_len;
  size_t out_cap;
  size_t frames_this_tick;
  bool authenticated;
  unsigned char challenge[32];
};

struct signer {
  bool enabled;
  EVP_PKEY *key;
  unsigned char *session_token;
  size_t session_token_len;
};

struct daemon_state {
  struct client *clients;
  size_t max_clients;
  size_t max_buffered_bytes;
  size_t buffered_bytes;
  uint64_t accepted;
  uint64_t rejected;
  uint64_t frames;
  struct signer signer;
};

struct daemon_options {
  const char *socket_path;
  const char *key_file;
  const char *session_token_file;
  size_t max_clients;
  size_t max_buffered_bytes;
  char *config_socket_path;
  char *config_key_file;
  char *config_session_token_file;
  bool config_has_max_clients;
  bool config_has_max_buffered_bytes;
};

static volatile sig_atomic_t stop_requested = 0;

static void on_signal(int signal_number) {
  (void)signal_number;
  stop_requested = 1;
}

static uint32_t read_u32(const unsigned char *p) {
  return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
         ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static uint64_t read_u64(const unsigned char *p) {
  uint64_t value = 0;
  for (size_t i = 0; i < 8; ++i) value = (value << 8) | p[i];
  return value;
}

static void write_u32(unsigned char *p, uint32_t value) {
  p[0] = (unsigned char)(value >> 24);
  p[1] = (unsigned char)(value >> 16);
  p[2] = (unsigned char)(value >> 8);
  p[3] = (unsigned char)value;
}

static void write_u64(unsigned char *p, uint64_t value) {
  for (size_t i = 0; i < 8; ++i) p[7 - i] = (unsigned char)(value >> (i * 8));
}

static int set_nonblocking(int fd) {
  const int flags = fcntl(fd, F_GETFL, 0);
  if (flags < 0) return -1;
  return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static void close_client(struct daemon_state *state, struct client *client) {
  if (client->fd >= 0) close(client->fd);
  if (state->buffered_bytes >= client->in_cap + client->out_cap) {
    state->buffered_bytes -= client->in_cap + client->out_cap;
  } else {
    state->buffered_bytes = 0;
  }
  free(client->in);
  free(client->out);
  *client = (struct client){ .fd = -1 };
}

static int reserve(struct daemon_state *state, unsigned char **buffer, size_t *capacity, size_t required, size_t limit) {
  if (required > limit) return -1;
  if (*capacity >= required) return 0;
  size_t next = *capacity ? *capacity : 4096;
  while (next < required) {
    if (next > limit / 2) { next = limit; break; }
    next *= 2;
  }
  const size_t additional = next - *capacity;
  if (additional > state->max_buffered_bytes - state->buffered_bytes) return -1;
  unsigned char *replacement = realloc(*buffer, next);
  if (!replacement) return -1;
  *buffer = replacement;
  *capacity = next;
  state->buffered_bytes += additional;
  return 0;
}

static int queue_frame(
  struct daemon_state *state,
  struct client *client,
  unsigned char kind,
  uint64_t request_id,
  const unsigned char *payload,
  size_t payload_len
) {
  if (payload_len > LATTICE_MAX_FRAME_BYTES) return -1;
  const size_t pending = client->out_len - client->out_offset;
  const size_t frame_len = LATTICE_FRAME_HEADER_BYTES + payload_len;
  if (pending + frame_len > MAX_CLIENT_OUTBOUND) return -1;

  if (client->out_offset && pending) memmove(client->out, client->out + client->out_offset, pending);
  client->out_offset = 0;
  client->out_len = pending;
  if (reserve(state, &client->out, &client->out_cap, pending + frame_len, MAX_CLIENT_OUTBOUND) != 0) return -1;

  unsigned char *frame = client->out + client->out_len;
  memcpy(frame, LATTICE_PROTOCOL_MAGIC, 4);
  frame[4] = LATTICE_PROTOCOL_VERSION;
  frame[5] = kind;
  frame[6] = 0;
  frame[7] = 0;
  write_u64(frame + 8, request_id);
  write_u32(frame + 16, (uint32_t)payload_len);
  if (payload_len) memcpy(frame + LATTICE_FRAME_HEADER_BYTES, payload, payload_len);
  client->out_len += frame_len;
  return 0;
}

static int queue_error(struct daemon_state *state, struct client *client, uint64_t request_id, const char *message) {
  return queue_frame(state, client, LATTICE_FRAME_ERROR, request_id, (const unsigned char *)message, strlen(message));
}

static size_t active_client_count(const struct daemon_state *state) {
  size_t active = 0;
  for (size_t i = 0; i < state->max_clients; ++i) {
    if (state->clients[i].fd >= 0) active++;
  }
  return active;
}

static int authenticate_client(
  struct daemon_state *state,
  struct client *client,
  uint64_t request_id,
  const unsigned char *proof,
  size_t proof_len
) {
  unsigned char expected[EVP_MAX_MD_SIZE];
  unsigned int expected_len = 0;
  if (proof_len != 32 || !HMAC(
        EVP_sha256(), state->signer.session_token, (int)state->signer.session_token_len,
        client->challenge, sizeof(client->challenge), expected, &expected_len
      ) || expected_len != 32 || CRYPTO_memcmp(expected, proof, 32) != 0) {
    return queue_error(state, client, request_id, "invalid authentication proof");
  }
  client->authenticated = true;
  return queue_frame(state, client, LATTICE_FRAME_AUTHENTICATED, request_id, NULL, 0);
}

static int sign_payload(
  struct daemon_state *state,
  struct client *client,
  uint64_t request_id,
  const unsigned char *payload,
  size_t payload_len
) {
  EVP_MD_CTX *context = EVP_MD_CTX_new();
  if (!context) return queue_error(state, client, request_id, "signature context unavailable");
  size_t signature_len = 0;
  int ok = EVP_DigestSignInit(context, NULL, NULL, NULL, state->signer.key) == 1 &&
           EVP_DigestSign(context, NULL, &signature_len, payload, payload_len) == 1;
  unsigned char *signature = ok ? malloc(signature_len) : NULL;
  if (!signature) ok = 0;
  if (ok) ok = EVP_DigestSign(context, signature, &signature_len, payload, payload_len) == 1;
  EVP_MD_CTX_free(context);
  if (!ok) { free(signature); return queue_error(state, client, request_id, "signing failed"); }
  const int queued = queue_frame(state, client, LATTICE_FRAME_SIGNATURE, request_id, signature, signature_len);
  OPENSSL_cleanse(signature, signature_len);
  free(signature);
  return queued;
}

static int process_frame(
  struct daemon_state *state,
  struct client *client,
  unsigned char kind,
  uint64_t request_id,
  const unsigned char *payload,
  size_t payload_len
) {
  state->frames++;
  if (state->signer.enabled && !client->authenticated) {
    if (kind == LATTICE_FRAME_AUTH) return authenticate_client(state, client, request_id, payload, payload_len);
    return queue_error(state, client, request_id, "authenticate first");
  }
  if (kind == LATTICE_FRAME_PING) {
    return queue_frame(state, client, LATTICE_FRAME_PONG, request_id, payload, payload_len);
  }
  if (kind == LATTICE_FRAME_STATS) {
    char stats[256];
    const int written = snprintf(
      stats, sizeof(stats),
      "{\"protocol\":\"ltp/1\",\"accepted\":%llu,\"rejected\":%llu,\"active\":%zu,\"max_clients\":%zu,\"frames\":%llu,\"buffered_bytes\":%zu,\"max_buffered_bytes\":%zu}",
      (unsigned long long)state->accepted,
      (unsigned long long)state->rejected,
      active_client_count(state),
      state->max_clients,
      (unsigned long long)state->frames,
      state->buffered_bytes,
      state->max_buffered_bytes
    );
    if (written < 0 || (size_t)written >= sizeof(stats)) return -1;
    return queue_frame(state, client, LATTICE_FRAME_STATS_RESPONSE, request_id, (const unsigned char *)stats, (size_t)written);
  }
  if (kind == LATTICE_FRAME_SIGN) {
    if (!state->signer.enabled) return queue_error(state, client, request_id, "signing not configured");
    return sign_payload(state, client, request_id, payload, payload_len);
  }
  return queue_error(state, client, request_id, "unsupported frame kind");
}

static int consume_frames(struct daemon_state *state, struct client *client) {
  while (client->frames_this_tick < MAX_FRAMES_PER_TICK && client->in_len >= LATTICE_FRAME_HEADER_BYTES) {
    const unsigned char *header = client->in;
    if (memcmp(header, LATTICE_PROTOCOL_MAGIC, 4) != 0 || header[4] != LATTICE_PROTOCOL_VERSION) return -1;
    const uint32_t payload_len = read_u32(header + 16);
    if (payload_len > LATTICE_MAX_FRAME_BYTES) return -1;
    const size_t frame_len = LATTICE_FRAME_HEADER_BYTES + (size_t)payload_len;
    if (client->in_len < frame_len) return 0;
    if (process_frame(state, client, header[5], read_u64(header + 8), header + LATTICE_FRAME_HEADER_BYTES, payload_len) != 0) return -1;
    const size_t remaining = client->in_len - frame_len;
    if (remaining) memmove(client->in, client->in + frame_len, remaining);
    client->in_len = remaining;
    client->frames_this_tick++;
  }
  return 0;
}

static bool has_complete_buffered_frame(const struct client *client) {
  if (client->in_len < LATTICE_FRAME_HEADER_BYTES) return false;
  const uint32_t payload_len = read_u32(client->in + 16);
  return payload_len <= LATTICE_MAX_FRAME_BYTES &&
         client->in_len >= LATTICE_FRAME_HEADER_BYTES + (size_t)payload_len;
}

static int receive_client(struct daemon_state *state, struct client *client) {
  size_t received_this_tick = 0;
  for (;;) {
    if (received_this_tick >= MAX_RECEIVE_BYTES_PER_TICK || client->frames_this_tick >= MAX_FRAMES_PER_TICK) return 0;
    const size_t limit = LATTICE_FRAME_HEADER_BYTES + LATTICE_MAX_FRAME_BYTES;
    const size_t desired = client->in_len > limit - 4096 ? limit : client->in_len + 4096;
    if (reserve(state, &client->in, &client->in_cap, desired, limit) != 0) return -1;
    const size_t available = client->in_cap - client->in_len;
    const size_t budget = MAX_RECEIVE_BYTES_PER_TICK - received_this_tick;
    const size_t read_size = available < budget ? available : budget;
    const ssize_t received = recv(client->fd, client->in + client->in_len, read_size, 0);
    if (received > 0) {
      client->in_len += (size_t)received;
      received_this_tick += (size_t)received;
      if (consume_frames(state, client) != 0) return -1;
      continue;
    }
    if (received == 0) return -1;
    if (errno == EAGAIN || errno == EWOULDBLOCK) return 0;
    if (errno == EINTR) continue;
    return -1;
  }
}

static int flush_client(struct client *client) {
  size_t sent_this_tick = 0;
  while (client->out_offset < client->out_len) {
    if (sent_this_tick >= MAX_SEND_BYTES_PER_TICK) return 0;
    const size_t pending = client->out_len - client->out_offset;
    const size_t budget = MAX_SEND_BYTES_PER_TICK - sent_this_tick;
    const size_t write_size = pending < budget ? pending : budget;
    const ssize_t sent = send(client->fd, client->out + client->out_offset, write_size, 0);
    if (sent > 0) {
      client->out_offset += (size_t)sent;
      sent_this_tick += (size_t)sent;
      continue;
    }
    if (sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return 0;
    if (sent < 0 && errno == EINTR) continue;
    return -1;
  }
  client->out_offset = 0;
  client->out_len = 0;
  return 0;
}

static int open_listener(const char *socket_path) {
  if (strlen(socket_path) >= sizeof(((struct sockaddr_un *)0)->sun_path)) {
    fprintf(stderr, "socket path is too long\n");
    return -1;
  }
  struct stat existing;
  if (lstat(socket_path, &existing) == 0) {
    fprintf(stderr, "refusing to replace existing socket path: %s\n", socket_path);
    return -1;
  }
  if (errno != ENOENT) { perror("lstat socket"); return -1; }

  const int listener = socket(AF_UNIX, SOCK_STREAM, 0);
  if (listener < 0) { perror("socket"); return -1; }
  struct sockaddr_un address;
  memset(&address, 0, sizeof(address));
  address.sun_family = AF_UNIX;
  strncpy(address.sun_path, socket_path, sizeof(address.sun_path) - 1);
  const mode_t old_mask = umask(0077);
  const int bound = bind(listener, (const struct sockaddr *)&address, sizeof(address));
  umask(old_mask);
  if (bound != 0) { perror("bind"); close(listener); return -1; }
  if (chmod(socket_path, 0600) != 0) { perror("chmod socket"); close(listener); unlink(socket_path); return -1; }
  if (listen(listener, 256) != 0 || set_nonblocking(listener) != 0) {
    perror("listen/nonblocking"); close(listener); unlink(socket_path); return -1;
  }
  return listener;
}

static void accept_clients(int listener, struct daemon_state *state) {
  for (;;) {
    const int fd = accept(listener, NULL, NULL);
    if (fd < 0) {
      if (errno == EAGAIN || errno == EWOULDBLOCK) return;
      if (errno == EINTR) continue;
      perror("accept"); return;
    }
    if (set_nonblocking(fd) != 0) { close(fd); continue; }
    size_t slot = state->max_clients;
    for (size_t i = 0; i < state->max_clients; ++i) {
      if (state->clients[i].fd < 0) { slot = i; break; }
    }
    if (slot == state->max_clients) {
      state->rejected++;
      close(fd);
      continue;
    }
    struct client *client = &state->clients[slot];
    *client = (struct client){ .fd = fd };
    if (state->signer.enabled) {
      if (RAND_bytes(client->challenge, sizeof(client->challenge)) != 1 ||
          queue_frame(state, client, LATTICE_FRAME_CHALLENGE, 0, client->challenge, sizeof(client->challenge)) != 0) {
        close_client(state, client);
        continue;
      }
    }
    state->accepted++;
  }
}

static int open_private_regular_file(const char *path) {
  const int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (fd < 0) { perror(path); return -1; }
  struct stat file;
  if (fstat(fd, &file) != 0) { perror(path); close(fd); return -1; }
  if (!S_ISREG(file.st_mode) || file.st_uid != geteuid() || (file.st_mode & 0077) != 0) {
    fprintf(stderr, "refusing non-private file: %s\n", path);
    close(fd);
    return -1;
  }
  return fd;
}

static int load_signer(struct signer *signer, const char *key_file, const char *session_token_file) {
  if (!key_file && !session_token_file) return 0;
  if (!key_file || !session_token_file) return -1;
  const int token_fd = open_private_regular_file(session_token_file);
  const int key_fd = open_private_regular_file(key_file);
  if (token_fd < 0 || key_fd < 0) { if (token_fd >= 0) close(token_fd); if (key_fd >= 0) close(key_fd); return -1; }
  FILE *token_file = fdopen(token_fd, "rb");
  FILE *key_stream = fdopen(key_fd, "r");
  if (!token_file || !key_stream) {
    perror("fdopen private material");
    if (token_file) fclose(token_file); else close(token_fd);
    if (key_stream) fclose(key_stream); else close(key_fd);
    return -1;
  }
  unsigned char token[4096];
  const size_t read_len = fread(token, 1, sizeof(token), token_file);
  const int read_error = ferror(token_file);
  fclose(token_file);
  size_t token_len = read_len;
  while (token_len && (token[token_len - 1] == '\n' || token[token_len - 1] == '\r')) token_len--;
  if (read_error || token_len == 0 || read_len == sizeof(token)) {
    fprintf(stderr, "invalid session token file\n");
    fclose(key_stream);
    return -1;
  }
  BIO *key_bio = BIO_new_fp(key_stream, BIO_NOCLOSE);
  EVP_PKEY *key = key_bio ? PEM_read_bio_PrivateKey(key_bio, NULL, NULL, NULL) : NULL;
  BIO_free(key_bio);
  fclose(key_stream);
  if (!key || EVP_PKEY_get_base_id(key) != EVP_PKEY_ED25519) {
    fprintf(stderr, "key file must contain an Ed25519 private key\n");
    EVP_PKEY_free(key);
    return -1;
  }
  signer->session_token = malloc(token_len);
  if (!signer->session_token) { EVP_PKEY_free(key); return -1; }
  memcpy(signer->session_token, token, token_len);
  OPENSSL_cleanse(token, sizeof(token));
  signer->session_token_len = token_len;
  signer->key = key;
  signer->enabled = true;
  return 0;
}

static void free_signer(struct signer *signer) {
  if (signer->session_token) {
    OPENSSL_cleanse(signer->session_token, signer->session_token_len);
    free(signer->session_token);
  }
  EVP_PKEY_free(signer->key);
  *signer = (struct signer){0};
}

static void usage(const char *program) {
  fprintf(stderr,
    "Usage: %s --socket <path> [options]\n"
    "       %s --config <latticed.conf> [--verify-config]\n\n"
    "Options:\n"
    "  -f, --config <path>                 Read Socket, MaxClients, MaxBufferedBytes,\n"
    "                                      KeyFile and SessionTokenFile directives\n"
    "  --socket <path>                     LTP/1 Unix socket (required without config)\n"
    "  --max-clients <1-4096>              Concurrent local-client ceiling\n"
    "  --max-buffered-bytes <4MiB-1GiB>    Aggregate memory ceiling\n"
    "  --key-file <ed25519-pem>            Enable signing (requires --session-token-file)\n"
    "  --session-token-file <private-file> Session token for signing clients\n"
    "  --verify-config                     Validate configuration without starting\n"
    "  --version                           Print version\n"
    "  -h, --help                          Print this help\n",
    program, program);
}

static void free_options(struct daemon_options *options) {
  free(options->config_socket_path);
  free(options->config_key_file);
  free(options->config_session_token_file);
  *options = (struct daemon_options){0};
}

static char *trim(char *value) {
  while (*value == ' ' || *value == '\t' || *value == '\r' || *value == '\n') value++;
  size_t len = strlen(value);
  while (len && (value[len - 1] == ' ' || value[len - 1] == '\t' || value[len - 1] == '\r' || value[len - 1] == '\n')) value[--len] = '\0';
  return value;
}

static int parse_size_option(const char *value, unsigned long long minimum, unsigned long long maximum, size_t *out) {
  if (!value || !*value) return -1;
  errno = 0;
  char *end = NULL;
  const unsigned long long parsed = strtoull(value, &end, 10);
  if (errno || !end || *end || parsed < minimum || parsed > maximum || parsed > SIZE_MAX) return -1;
  *out = (size_t)parsed;
  return 0;
}

static int set_config_string(char **owned, const char **target, const char *value, const char *directive, const char *path, unsigned line) {
  if (*owned) {
    fprintf(stderr, "%s:%u: duplicate %s directive\n", path, line, directive);
    return -1;
  }
  *owned = strdup(value);
  if (!*owned) { perror("strdup config value"); return -1; }
  *target = *owned;
  return 0;
}

static int open_config_file(const char *path) {
  const int fd = open(path, O_RDONLY | O_NOFOLLOW);
  if (fd < 0) { perror("open config"); return -1; }
  struct stat metadata;
  if (fstat(fd, &metadata) != 0) { perror("stat config"); close(fd); return -1; }
  if (!S_ISREG(metadata.st_mode) || (metadata.st_mode & 0022) != 0 ||
      (metadata.st_uid != geteuid() && metadata.st_uid != 0)) {
    fprintf(stderr, "configuration must be a regular file owned by this user or root and not group/world writable\n");
    close(fd);
    return -1;
  }
  return fd;
}

static int read_config(const char *path, struct daemon_options *options) {
  const int fd = open_config_file(path);
  if (fd < 0) return -1;
  FILE *file = fdopen(fd, "r");
  if (!file) { perror("fdopen config"); close(fd); return -1; }
  char line[4098];
  unsigned line_number = 0;
  int result = 0;
  while (fgets(line, sizeof(line), file)) {
    line_number++;
    const size_t line_len = strlen(line);
    if (line_len == sizeof(line) - 1 && line[line_len - 1] != '\n') {
      fprintf(stderr, "%s:%u: configuration line exceeds 4096 bytes\n", path, line_number);
      result = -1;
      break;
    }
    char *text = trim(line);
    if (!*text || *text == '#') continue;
    char *separator = text;
    while (*separator && *separator != ' ' && *separator != '\t') separator++;
    if (!*separator) {
      fprintf(stderr, "%s:%u: expected a directive and value\n", path, line_number);
      result = -1;
      break;
    }
    *separator++ = '\0';
    char *value = trim(separator);
    if (!*value) {
      fprintf(stderr, "%s:%u: empty value for %s\n", path, line_number, text);
      result = -1;
      break;
    }
    if (strcmp(text, "Socket") == 0) {
      result = set_config_string(&options->config_socket_path, &options->socket_path, value, text, path, line_number);
    } else if (strcmp(text, "KeyFile") == 0) {
      result = set_config_string(&options->config_key_file, &options->key_file, value, text, path, line_number);
    } else if (strcmp(text, "SessionTokenFile") == 0) {
      result = set_config_string(&options->config_session_token_file, &options->session_token_file, value, text, path, line_number);
    } else if (strcmp(text, "MaxClients") == 0) {
      if (options->config_has_max_clients || parse_size_option(value, 1, HARD_MAX_CLIENTS, &options->max_clients) != 0) result = -1;
      else options->config_has_max_clients = true;
    } else if (strcmp(text, "MaxBufferedBytes") == 0) {
      if (options->config_has_max_buffered_bytes || parse_size_option(value, 4ULL * 1024ULL * 1024ULL, HARD_MAX_BUFFERED_BYTES, &options->max_buffered_bytes) != 0) result = -1;
      else options->config_has_max_buffered_bytes = true;
    } else {
      fprintf(stderr, "%s:%u: unknown directive %s\n", path, line_number, text);
      result = -1;
    }
    if (result != 0) {
      if (result == -1 && (strcmp(text, "MaxClients") == 0 || strcmp(text, "MaxBufferedBytes") == 0)) {
        fprintf(stderr, "%s:%u: invalid or duplicate value for %s\n", path, line_number, text);
      }
      break;
    }
  }
  if (ferror(file)) { perror("read config"); result = -1; }
  fclose(file);
  return result;
}

static int apply_cli_options(int argc, char **argv, struct daemon_options *options) {
  for (int i = 1; i < argc; ++i) {
    if ((strcmp(argv[i], "-f") == 0 || strcmp(argv[i], "--config") == 0) && i + 1 < argc) i++;
    else if (strcmp(argv[i], "--verify-config") == 0 || strcmp(argv[i], "--version") == 0 || strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) continue;
    else if (strcmp(argv[i], "--socket") == 0 && i + 1 < argc) options->socket_path = argv[++i];
    else if (strcmp(argv[i], "--key-file") == 0 && i + 1 < argc) options->key_file = argv[++i];
    else if (strcmp(argv[i], "--session-token-file") == 0 && i + 1 < argc) options->session_token_file = argv[++i];
    else if (strcmp(argv[i], "--max-clients") == 0 && i + 1 < argc) {
      if (parse_size_option(argv[++i], 1, HARD_MAX_CLIENTS, &options->max_clients) != 0) return -1;
    } else if (strcmp(argv[i], "--max-buffered-bytes") == 0 && i + 1 < argc) {
      if (parse_size_option(argv[++i], 4ULL * 1024ULL * 1024ULL, HARD_MAX_BUFFERED_BYTES, &options->max_buffered_bytes) != 0) return -1;
    } else return -1;
  }
  return 0;
}

int main(int argc, char **argv) {
  const char *config_path = NULL;
  bool verify_config = false;
  for (int i = 1; i < argc; ++i) {
    if ((strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0)) { usage(argv[0]); return 0; }
    if (strcmp(argv[i], "--version") == 0) { printf("latticed %s\n", LATTICE_VERSION); return 0; }
    if ((strcmp(argv[i], "-f") == 0 || strcmp(argv[i], "--config") == 0) && i + 1 < argc) config_path = argv[++i];
    else if (strcmp(argv[i], "--verify-config") == 0) verify_config = true;
  }
  struct daemon_options options = {
    .max_clients = DEFAULT_MAX_CLIENTS,
    .max_buffered_bytes = DEFAULT_MAX_BUFFERED_BYTES,
  };
  if (config_path && read_config(config_path, &options) != 0) { free_options(&options); return 1; }
  if (apply_cli_options(argc, argv, &options) != 0) { usage(argv[0]); free_options(&options); return 2; }
  if (verify_config) {
    if (!config_path) { fprintf(stderr, "--verify-config requires --config\n"); free_options(&options); return 2; }
    if (!options.socket_path || (!!options.key_file != !!options.session_token_file)) {
      fprintf(stderr, "configuration requires Socket and paired KeyFile/SessionTokenFile directives\n");
      free_options(&options);
      return 1;
    }
    printf("latticed configuration is valid\n");
    free_options(&options);
    return 0;
  }
  if (!options.socket_path || (!!options.key_file != !!options.session_token_file)) { usage(argv[0]); free_options(&options); return 2; }

  const int listener = open_listener(options.socket_path);
  if (listener < 0) { free_options(&options); return 1; }
  struct daemon_state state = { .max_clients = options.max_clients, .max_buffered_bytes = options.max_buffered_bytes };
  if (load_signer(&state.signer, options.key_file, options.session_token_file) != 0) { close(listener); unlink(options.socket_path); free_options(&options); return 1; }
  state.clients = calloc(options.max_clients, sizeof(*state.clients));
  struct pollfd *pollfds = calloc(options.max_clients + 1, sizeof(*pollfds));
  if (!state.clients || !pollfds) { perror("calloc"); close(listener); unlink(options.socket_path); free(state.clients); free(pollfds); free_signer(&state.signer); free_options(&options); return 1; }
  for (size_t i = 0; i < options.max_clients; ++i) state.clients[i].fd = -1;
  signal(SIGINT, on_signal);
  signal(SIGTERM, on_signal);
  /* A peer can disappear between poll() and send(). Treat EPIPE as a
   * per-client failure in flush_client(), never as a daemon-wide crash. */
  signal(SIGPIPE, SIG_IGN);

  fprintf(stderr, "latticed listening on %s (ltp/1, max clients %zu, max buffered bytes %zu)\n", options.socket_path, options.max_clients, options.max_buffered_bytes);
  while (!stop_requested) {
    /* Drain at most a fixed number of complete frames from each peer before
     * polling. This covers frames left over from the prior tick even when the
     * kernel has no new readability event for that socket. */
    bool buffered_work = false;
    for (size_t i = 0; i < options.max_clients; ++i) {
      struct client *client = &state.clients[i];
      client->frames_this_tick = 0;
      if (client->fd < 0 || client->in_len == 0) continue;
      if (consume_frames(&state, client) != 0) {
        close_client(&state, client);
        continue;
      }
      if (has_complete_buffered_frame(client)) buffered_work = true;
    }
    pollfds[0] = (struct pollfd){ .fd = listener, .events = POLLIN };
    for (size_t i = 0; i < options.max_clients; ++i) {
      pollfds[i + 1] = (struct pollfd){ .fd = state.clients[i].fd, .events = state.clients[i].fd >= 0 ? POLLIN : 0 };
      if (state.clients[i].out_len > state.clients[i].out_offset) pollfds[i + 1].events |= POLLOUT;
    }
    /* Do not sleep for a second when a peer already has complete frames in
     * memory. The next pass gives every client another bounded turn. */
    const int ready = poll(pollfds, options.max_clients + 1, buffered_work ? 0 : 1000);
    if (ready < 0) { if (errno == EINTR) continue; perror("poll"); break; }
    if (pollfds[0].revents & POLLIN) accept_clients(listener, &state);
    for (size_t i = 0; i < options.max_clients; ++i) {
      struct client *client = &state.clients[i];
      const short events = pollfds[i + 1].revents;
      if (client->fd < 0 || !events) continue;
      if (events & (POLLERR | POLLHUP | POLLNVAL) || (events & POLLIN && receive_client(&state, client) != 0) || (events & POLLOUT && flush_client(client) != 0)) {
        close_client(&state, client);
      }
    }
  }
  for (size_t i = 0; i < options.max_clients; ++i) close_client(&state, &state.clients[i]);
  close(listener);
  unlink(options.socket_path);
  free(state.clients);
  free(pollfds);
  free_signer(&state.signer);
  free_options(&options);
  return 0;
}
