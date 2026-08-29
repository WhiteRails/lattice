#!/usr/bin/env sh
set -eu

release_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
release_version=${LATTICE_VERSION:-$(node -p "require('$release_root/package.json').version")}
release_os=$(uname -s | tr '[:upper:]' '[:lower:]')
release_arch=$(uname -m)
release_name="lattice-${release_version}-${release_os}-${release_arch}"
release_dir="$release_root/artifacts/$release_name"
release_archive="$release_root/artifacts/$release_name.tar.gz"
model_name="lt-smollm2-135m-instruct-q4_k_m.gguf"
model_sha256="2e8040ceae7815abe0dcb3540b9995eaa1fa0d2ca9e797d0a635ae4433c68c2d"
model_cache="$release_root/build/$model_name"
llama_revision="c1d0e7a004015f23bc0233470b747b596f29b264"

# LNP/1's only installable distribution in this release is Linux. macOS and
# Windows ship source adapters until their platform credentials exist; creating
# a generic archive there would incorrectly suggest a usable VPN installer.
if [ "$release_os" != "linux" ]; then
  echo "public Lattice network bundles are currently built only on Linux" >&2
  exit 1
fi

if [ -e "$release_dir" ] || [ -e "$release_archive" ]; then
  echo "release destination already exists: $release_dir" >&2
  echo "choose another LATTICE_VERSION or move the existing artifact" >&2
  exit 1
fi

cmake -S "$release_root/daemon" -B "$release_root/build/release-daemon" -DCMAKE_BUILD_TYPE=Release
cmake --build "$release_root/build/release-daemon" --config Release
cargo build --manifest-path "$release_root/clients/rust/Cargo.toml" --release
cargo build --manifest-path "$release_root/network/Cargo.toml" --workspace --release

llama_root="$release_root/build/llama.cpp"
if [ ! -d "$llama_root/.git" ]; then
  git init "$llama_root"
  git -C "$llama_root" remote add origin https://github.com/ggml-org/llama.cpp.git
  git -C "$llama_root" fetch --depth 1 origin "$llama_revision"
  git -C "$llama_root" checkout --detach FETCH_HEAD
fi
if [ "$(git -C "$llama_root" rev-parse HEAD)" != "$llama_revision" ]; then
  echo "llama.cpp checkout does not match the pinned revision" >&2
  exit 1
fi
cmake -S "$llama_root" -B "$release_root/build/llama.cpp-release" \
  -DCMAKE_BUILD_TYPE=Release \
  -DGGML_NATIVE=OFF \
  -DBUILD_SHARED_LIBS=OFF \
  -DLLAMA_OPENSSL=OFF \
  -DLLAMA_BUILD_EXAMPLES=OFF \
  -DLLAMA_BUILD_SERVER=OFF \
  -DLLAMA_BUILD_TESTS=OFF \
  -DLLAMA_BUILD_UI=OFF \
  -DLLAMA_USE_PREBUILT_UI=OFF
cmake --build "$release_root/build/llama.cpp-release" --config Release --target llama-completion

if [ ! -f "$model_cache" ]; then
  curl --fail --location --retry 3 --output "$model_cache" \
    "https://huggingface.co/bartowski/SmolLM2-135M-Instruct-GGUF/resolve/main/SmolLM2-135M-Instruct-Q4_K_M.gguf?download=true"
fi
model_actual_sha256=$(openssl dgst -sha256 "$model_cache" | awk '{print $NF}')
if [ "$model_actual_sha256" != "$model_sha256" ]; then
  echo "unexpected checksum for $model_cache" >&2
  exit 1
fi

mkdir -p "$release_dir/bin" "$release_dir/models" "$release_dir/etc/lattice" "$release_dir/lib/systemd/system" "$release_dir/lib/sysctl.d" "$release_dir/share/applications" "$release_dir/THIRD_PARTY_LICENSES"
install -m 0755 "$release_root/build/release-daemon/latticed" "$release_dir/bin/latticed"
install -m 0755 "$release_root/clients/rust/target/release/lattice" "$release_dir/bin/lattice"
install -m 0755 "$release_root/clients/rust/target/release/lt" "$release_dir/bin/lt"
install -m 0755 "$release_root/network/target/release/lattice-netd" "$release_dir/bin/lattice-netd"
install -m 0755 "$release_root/network/target/release/lattice-gatewayd" "$release_dir/bin/lattice-gatewayd"
install -m 0755 "$release_root/network/target/release/lattice-resolver" "$release_dir/bin/lattice-resolver"
install -m 0755 "$release_root/network/target/release/lattice-netctl" "$release_dir/bin/lattice-netctl"
install -m 0755 "$release_root/build/llama.cpp-release/bin/llama-completion" "$release_dir/bin/lt-llm"
install -m 0644 "$model_cache" "$release_dir/models/$model_name"
install -m 0644 "$release_root/daemon/latticed.conf.example" "$release_dir/etc/lattice/latticed.conf.example"
install -m 0644 "$release_root/daemon/systemd/latticed.service" "$release_dir/lib/systemd/system/latticed.service"
install -m 0644 "$release_root/network/platform/linux/systemd/lattice-netd@.service" "$release_dir/lib/systemd/system/lattice-netd@.service"
install -m 0644 "$release_root/network/platform/linux/systemd/lattice-resolver.service" "$release_dir/lib/systemd/system/lattice-resolver.service"
install -m 0644 "$release_root/network/platform/linux/systemd/lattice-gatewayd.service" "$release_dir/lib/systemd/system/lattice-gatewayd.service"
install -m 0644 "$release_root/network/platform/linux/lattice-uri.desktop" "$release_dir/share/applications/lattice-uri.desktop"
install -m 0644 "$release_root/network/platform/linux/sysctl/90-lattice.conf" "$release_dir/lib/sysctl.d/90-lattice.conf"
install -m 0755 "$release_root/network/platform/linux/install.sh" "$release_dir/install-network.sh"
install -m 0644 "$release_root/README.md" "$release_dir/README.md"
install -m 0644 "$llama_root/LICENSE" "$release_dir/THIRD_PARTY_LICENSES/llama.cpp-MIT.txt"
install -m 0644 "$release_root/docs/third-party-notices.md" "$release_dir/THIRD_PARTY_NOTICES.md"

tar -C "$release_root/artifacts" -czf "$release_archive" "$release_name"
shasum -a 256 "$release_archive" > "$release_archive.sha256"
printf '%s\n' "created $release_archive" "created $release_archive.sha256"
