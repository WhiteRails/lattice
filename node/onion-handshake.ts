import * as crypto from 'crypto';

const PROTOID = Buffer.from('ntor3-curve25519-sha3_256-1', 'ascii');
const VER = Buffer.from('LatticeCircuit/1', 'ascii');
const T_MSGKDF = Buffer.concat([PROTOID, Buffer.from(':kdf_phase1')]);
const T_MSGMAC = Buffer.concat([PROTOID, Buffer.from(':msg_mac')]);
const T_KEY_SEED = Buffer.concat([PROTOID, Buffer.from(':key_seed')]);
const T_VERIFY = Buffer.concat([PROTOID, Buffer.from(':verify')]);
const T_FINAL = Buffer.concat([PROTOID, Buffer.from(':kdf_final')]);
const T_AUTH = Buffer.concat([PROTOID, Buffer.from(':auth_final')]);
const SERVER = Buffer.from('Server', 'ascii');
const KEY_STREAM_BYTES = 72;
const RAW_KEY_RE = /^[A-Za-z0-9_-]{43}$/;
const HEX_32_RE = /^[a-f0-9]{64}$/;
const X25519_SPKI_PREFIX = Buffer.from('302a300506032b656e032100', 'hex');
const X25519_PKCS8_PREFIX = Buffer.from('302e020100300506032b656e04220420', 'hex');

export interface RawX25519KeyPair {
  publicKey: string;
  privateKey: string;
}

export interface NtorCreate {
  version: 1;
  node_id: string;
  onion_key_id: string;
  client_public_key: string;
  encrypted_extensions: string;
  extensions_mac: string;
}

export interface NtorCreated {
  version: 1;
  server_public_key: string;
  auth: string;
  encrypted_extensions: string;
}

export interface OnionHopKeys {
  forwardKey: Buffer;
  backwardKey: Buffer;
  forwardNonceSalt: Buffer;
  backwardNonceSalt: Buffer;
}

export interface NtorClientState {
  create: NtorCreate;
  privateKey: string;
  onionPublicKey: string;
}

export function generateRawX25519KeyPair(): RawX25519KeyPair {
  const pair = crypto.generateKeyPairSync('x25519', {
    publicKeyEncoding: { format: 'der', type: 'spki' },
    privateKeyEncoding: { format: 'der', type: 'pkcs8' },
  });
  return {
    publicKey: Buffer.from(pair.publicKey).subarray(-32).toString('base64url'),
    privateKey: Buffer.from(pair.privateKey).subarray(-32).toString('base64url'),
  };
}

export function ntorNodeId(identityPublicKeyDerB64: string): string {
  const identity = Buffer.from(identityPublicKeyDerB64, 'base64');
  if (identity.length < 32 || identity.length > 128) throw new Error('Invalid node identity public key');
  return crypto.createHash('sha3-256').update(identity).digest('hex');
}

export function ntorOnionKeyId(onionPublicKey: string): string {
  return decodeRawKey(onionPublicKey, 'onion public key').toString('hex');
}

export function createNtorV3Client(
  nodeId: string,
  onionPublicKey: string,
  ephemeral: RawX25519KeyPair = generateRawX25519KeyPair(),
): NtorClientState {
  if (!HEX_32_RE.test(nodeId)) throw new Error('Invalid ntor node id');
  const id = Buffer.from(nodeId, 'hex');
  const b = decodeRawKey(onionPublicKey, 'onion public key');
  const xPublic = decodeRawKey(ephemeral.publicKey, 'client public key');
  const bx = deriveRawX25519(ephemeral.privateKey, onionPublicKey);
  const secretInput = Buffer.concat([bx, id, xPublic, b, PROTOID, encap(VER)]);
  const phase1 = kdf(secretInput, T_MSGKDF, 64);
  const macKey = phase1.subarray(32, 64);
  const encryptedExtensions = Buffer.alloc(0);
  const extensionsMac = mac(macKey, Buffer.concat([id, b, xPublic, encryptedExtensions]), T_MSGMAC);
  return {
    privateKey: ephemeral.privateKey,
    onionPublicKey,
    create: {
      version: 1,
      node_id: nodeId,
      onion_key_id: b.toString('hex'),
      client_public_key: ephemeral.publicKey,
      encrypted_extensions: '',
      extensions_mac: extensionsMac.toString('base64url'),
    },
  };
}

export function answerNtorV3(
  create: NtorCreate,
  expectedNodeId: string,
  onionKeyPair: RawX25519KeyPair,
  ephemeral: RawX25519KeyPair = generateRawX25519KeyPair(),
): { created: NtorCreated; keys: OnionHopKeys } {
  validateCreate(create, expectedNodeId, onionKeyPair.publicKey);
  const id = Buffer.from(expectedNodeId, 'hex');
  const b = decodeRawKey(onionKeyPair.publicKey, 'onion public key');
  const xPublic = decodeRawKey(create.client_public_key, 'client public key');
  const xb = deriveRawX25519(onionKeyPair.privateKey, create.client_public_key);
  const phase1Secret = Buffer.concat([xb, id, xPublic, b, PROTOID, encap(VER)]);
  const phase1 = kdf(phase1Secret, T_MSGKDF, 64);
  const expectedMac = mac(phase1.subarray(32, 64), Buffer.concat([id, b, xPublic]), T_MSGMAC);
  const providedMac = Buffer.from(create.extensions_mac, 'base64url');
  if (!safeEqual(providedMac, expectedMac)) throw new Error('Invalid ntor client extensions MAC');

  const yPublic = decodeRawKey(ephemeral.publicKey, 'server public key');
  const xy = deriveRawX25519(ephemeral.privateKey, create.client_public_key);
  const secretInput = Buffer.concat([xy, xb, id, b, xPublic, yPublic, PROTOID, encap(VER)]);
  const keySeed = hash(secretInput, T_KEY_SEED);
  const verify = hash(secretInput, T_VERIFY);
  const serverMessage = Buffer.alloc(0);
  const authInput = Buffer.concat([
    verify, id, b, yPublic, xPublic, providedMac, encap(serverMessage), PROTOID, SERVER,
  ]);
  return {
    created: {
      version: 1,
      server_public_key: ephemeral.publicKey,
      auth: hash(authInput, T_AUTH).toString('base64url'),
      encrypted_extensions: '',
    },
    keys: splitKeyStream(kdf(keySeed, T_FINAL, KEY_STREAM_BYTES)),
  };
}

/** ntor-v3 server path for HSM/plugin-backed onion keys. */
export async function answerNtorV3WithDerive(
  create: NtorCreate,
  expectedNodeId: string,
  onionPublicKey: string,
  deriveStatic: (clientPublicKey: string) => Promise<Buffer>,
  ephemeral: RawX25519KeyPair = generateRawX25519KeyPair(),
): Promise<{ created: NtorCreated; keys: OnionHopKeys }> {
  validateCreate(create, expectedNodeId, onionPublicKey);
  const id = Buffer.from(expectedNodeId, 'hex');
  const b = decodeRawKey(onionPublicKey, 'onion public key');
  const xPublic = decodeRawKey(create.client_public_key, 'client public key');
  const xb = await deriveStatic(create.client_public_key);
  if (xb.length !== 32 || xb.every(byte => byte === 0)) throw new Error('Invalid ntor backend shared secret');
  const phase1Secret = Buffer.concat([xb, id, xPublic, b, PROTOID, encap(VER)]);
  const phase1 = kdf(phase1Secret, T_MSGKDF, 64);
  const expectedMac = mac(phase1.subarray(32, 64), Buffer.concat([id, b, xPublic]), T_MSGMAC);
  const providedMac = Buffer.from(create.extensions_mac, 'base64url');
  if (!safeEqual(providedMac, expectedMac)) throw new Error('Invalid ntor client extensions MAC');

  const yPublic = decodeRawKey(ephemeral.publicKey, 'server public key');
  const xy = deriveRawX25519(ephemeral.privateKey, create.client_public_key);
  const secretInput = Buffer.concat([xy, xb, id, b, xPublic, yPublic, PROTOID, encap(VER)]);
  const keySeed = hash(secretInput, T_KEY_SEED);
  const verify = hash(secretInput, T_VERIFY);
  const authInput = Buffer.concat([
    verify, id, b, yPublic, xPublic, providedMac, encap(Buffer.alloc(0)), PROTOID, SERVER,
  ]);
  return {
    created: {
      version: 1,
      server_public_key: ephemeral.publicKey,
      auth: hash(authInput, T_AUTH).toString('base64url'),
      encrypted_extensions: '',
    },
    keys: splitKeyStream(kdf(keySeed, T_FINAL, KEY_STREAM_BYTES)),
  };
}

export function finishNtorV3(client: NtorClientState, created: NtorCreated): OnionHopKeys {
  if (created.version !== 1) throw new Error('Unsupported ntor created version');
  const create = client.create;
  const id = Buffer.from(create.node_id, 'hex');
  const b = decodeRawKey(client.onionPublicKey, 'onion public key');
  const xPublic = decodeRawKey(create.client_public_key, 'client public key');
  const yPublic = decodeRawKey(created.server_public_key, 'server public key');
  const yx = deriveRawX25519(client.privateKey, created.server_public_key);
  const bx = deriveRawX25519(client.privateKey, client.onionPublicKey);
  const secretInput = Buffer.concat([yx, bx, id, b, xPublic, yPublic, PROTOID, encap(VER)]);
  const keySeed = hash(secretInput, T_KEY_SEED);
  const verify = hash(secretInput, T_VERIFY);
  const clientMac = Buffer.from(create.extensions_mac, 'base64url');
  const serverMessage = Buffer.from(created.encrypted_extensions, 'base64url');
  const authInput = Buffer.concat([
    verify, id, b, yPublic, xPublic, clientMac, encap(serverMessage), PROTOID, SERVER,
  ]);
  const expected = hash(authInput, T_AUTH);
  if (!safeEqual(Buffer.from(created.auth, 'base64url'), expected)) throw new Error('Invalid ntor server authentication');
  return splitKeyStream(kdf(keySeed, T_FINAL, KEY_STREAM_BYTES));
}

function validateCreate(create: NtorCreate, nodeId: string, onionPublicKey: string): void {
  if (create.version !== 1) throw new Error('Unsupported ntor create version');
  if (!HEX_32_RE.test(nodeId) || create.node_id !== nodeId) throw new Error('ntor node identity mismatch');
  const expectedKeyId = ntorOnionKeyId(onionPublicKey);
  if (create.onion_key_id !== expectedKeyId) throw new Error('ntor onion key mismatch');
  decodeRawKey(create.client_public_key, 'client public key');
  if (create.encrypted_extensions !== '') throw new Error('Unsupported ntor client extensions');
  const clientMac = Buffer.from(create.extensions_mac, 'base64url');
  if (clientMac.length !== 32) throw new Error('Invalid ntor client MAC');
}

function splitKeyStream(stream: Buffer): OnionHopKeys {
  if (stream.length !== KEY_STREAM_BYTES) throw new Error('Invalid ntor key stream');
  return {
    forwardKey: Buffer.from(stream.subarray(0, 32)),
    backwardKey: Buffer.from(stream.subarray(32, 64)),
    forwardNonceSalt: Buffer.from(stream.subarray(64, 68)),
    backwardNonceSalt: Buffer.from(stream.subarray(68, 72)),
  };
}

export function deriveRawX25519(privateKey: string, publicKey: string): Buffer {
  const privateRaw = decodeRawKey(privateKey, 'X25519 private key');
  const publicRaw = decodeRawKey(publicKey, 'X25519 public key');
  const privateObject = crypto.createPrivateKey({
    key: Buffer.concat([X25519_PKCS8_PREFIX, privateRaw]), format: 'der', type: 'pkcs8',
  });
  const publicObject = crypto.createPublicKey({
    key: Buffer.concat([X25519_SPKI_PREFIX, publicRaw]), format: 'der', type: 'spki',
  });
  const shared = crypto.diffieHellman({ privateKey: privateObject, publicKey: publicObject });
  if (shared.length !== 32 || shared.every(byte => byte === 0)) throw new Error('Invalid X25519 shared secret');
  return shared;
}

function hash(input: Buffer, tag: Buffer): Buffer {
  return crypto.createHash('sha3-256').update(encap(tag)).update(input).digest();
}

function mac(key: Buffer, input: Buffer, tag: Buffer): Buffer {
  return crypto.createHash('sha3-256').update(encap(tag)).update(encap(key)).update(input).digest();
}

function kdf(input: Buffer, tag: Buffer, length: number): Buffer {
  return crypto.createHash('shake256', { outputLength: length }).update(encap(tag)).update(input).digest();
}

function encap(input: Buffer): Buffer {
  const length = Buffer.alloc(8);
  length.writeBigUInt64BE(BigInt(input.length));
  return Buffer.concat([length, input]);
}

function decodeRawKey(value: string, label: string): Buffer {
  if (!RAW_KEY_RE.test(value)) throw new Error(`Invalid ${label} encoding`);
  const key = Buffer.from(value, 'base64url');
  if (key.length !== 32) throw new Error(`Invalid ${label} length`);
  return key;
}

function safeEqual(left: Buffer, right: Buffer): boolean {
  return left.length === right.length && crypto.timingSafeEqual(left, right);
}
