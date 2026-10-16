# Mobile proving harness

Runs SPARROW proofs in a browser on desktop or a physical device: artifact
download and Cache API storage, SIGNET authentication, the SAGE cache, one-pass
zkey authentication, portable or threaded WASM, and Groth16 self-verification.
It reports the configuration and timings as JSON. Device emulation on a desktop
does not measure mobile performance; use a physical device.

## Build

```bash
scripts/build.sh wasm-web --sparrow
scripts/build.sh wasm-web-threads --sparrow
```

The threaded build needs a secure, cross-origin-isolated page.

## Configure

Copy `tools/mobile-harness/config.example.json` and add one profile per circuit.
Paths are absolute or relative to the configuration file. Each profile pins the
SHA-256 of its graph, zkey, manifest and input, and may set `sageProgramSha256`
(see [SAGE cache](#sage-cache)). Generate the configuration from deployment
metadata.

Check paths, digests and settings without opening a port:

```bash
node tools/mobile-harness/server.mjs path/to/config.json --check
```

## Run

### Android over USB

Android treats `http://localhost` as a secure origin. With USB debugging on:

```bash
node tools/mobile-harness/server.mjs path/to/config.json 8766
adb reverse tcp:8766 tcp:8766
```

Open the tokenized URL the server prints. A threaded run needs the diagnostics to
show a secure context, cross-origin isolation and `SharedArrayBuffer`.

### iOS, iPadOS and Wi-Fi devices

A LAN address over plain HTTP is not a secure context, so serve over HTTPS with a
certificate the device trusts, for example with `mkcert`:

```bash
mkcert -install
mkdir -p target/mobile-tls
mkcert -cert-file target/mobile-tls/cert.pem -key-file target/mobile-tls/key.pem \
  "$(scutil --get LocalHostName).local" 192.168.x.x localhost 127.0.0.1 ::1

CURVY_TLS_CERT=target/mobile-tls/cert.pem \
CURVY_TLS_KEY=target/mobile-tls/key.pem \
CURVY_MOBILE_HOST=0.0.0.0 \
node tools/mobile-harness/server.mjs path/to/config.json 8766
```

Trust the development CA on the device, use a hostname the certificate covers,
and remove the CA after testing.

### Server

- Binds to localhost unless `CURVY_MOBILE_HOST` is set.
- Serves only the harness files, the prover packages and the configured
  artifacts.
- Every request needs the random access token; the first page load turns it into
  an HttpOnly same-site cookie. The token does not encrypt traffic, so use HTTPS
  on a shared network.
- `CURVY_MOBILE_PKG_WEB` and `CURVY_MOBILE_PKG_WEB_THREADS` serve prover packages
  from other directories; `CURVY_MOBILE_BUILD_LABEL` names the build in reports.

## Artifact reads

Manifest, input and graph are read from Cache API under fixed limits: 4 MiB for a
manifest, 16 MiB for input JSON, and 64 MiB (client) or 96 MiB (batch) for a
SIGNET graph. The manifest and input are checked against their pins and the graph
is authenticated by SIGNET; a cached copy that fails is evicted and fetched once.
The zkey is streamed, and every chunk is authenticated against the manifest
before Rust parses it.

## SAGE cache

The derived SAGE program is cached only for a profile with a trusted
`sageProgramSha256`; without one, every run compiles from the authenticated
graph and reports `sageCacheStored: false` and `sageProgramPinned: false`. Take
the pin from the artifact pipeline, not from the device:

```bash
cargo run -p curvy-prover --features sage --example derive_sage_cache -- \
  path/to/circuit.signet SOURCE_SIGNET_SHA256 target/circuit.sage batch
```

It prints `program_sha256`. The value depends on the source graph and the SAGE
compiler version (`sageCacheVersion()`). A wrong pin fails the run. A cached
program that fails validation is evicted and recompiled.

## Reports

Each report records the versions, artifact digests, browser and device, runtime
mode, worker count, window bits, MSM chunk points, manifest chunk bytes, SAGE pin
and cache status, phase timings and the self-verification result.
`proofAndVerifyMs` includes the streamed zkey read in manifest mode.

Reload before changing the worker count: a WebAssembly Rayon pool cannot be
resized. If the browser kills a worker or reloads the page, lower the MSM chunk
size and worker count.
