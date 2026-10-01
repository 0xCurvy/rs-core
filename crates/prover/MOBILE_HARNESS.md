# Browser and mobile proving harness

The SPARROW harness validates a production-shaped browser proving integration
on desktop and physical mobile devices. It exercises artifact download and
storage, SIGNET authentication, the origin-local SAGE cache, one-pass zkey
authentication, portable or threaded WASM, and Groth16 self-verification.

## What the harness verifies

A successful run establishes that the selected browser and device can:

- authenticate the configured SIGNET graph and zkey manifest;
- derive or reload a validated `SAGEPC01` cache entry;
- read a zkey sequentially from Cache API without materializing it in a single
  JavaScript buffer;
- authenticate every complete zkey chunk before Rust parses it;
- initialize the selected portable or shared-memory WASM module;
- generate and self-verify a Groth16 proof; and
- export the effective configuration and timings as JSON.

It does not establish mobile performance when run with desktop device emulation.
Use a physical device to measure process limits, thermal throttling, browser
eviction behavior, and worker startup.

## Build the WASM modules

Build both variants when one harness session must compare the portable fallback
with browser threads:

```bash
scripts/build-wasm.sh web --sparrow
scripts/build-wasm.sh web --threads --sparrow
```

The portable build works without shared memory. The threaded build requires a
secure, cross-origin-isolated page and top-level Web Workers.

## Configure artifact profiles

Copy `crates/prover/js/mobile-harness.config.example.json` and add one profile
per circuit. Paths may be absolute or relative to the configuration file. Each
profile must provide pinned SHA-256 values for its graph, zkey, manifest, and
input. A profile may also set `sageProgramSha256`, the trusted digest of the
SAGE program derived from its graph; leave it `null` to recompile on every run
(see [SAGE cache behavior](#sage-cache-behavior)).

Keep the initial matrix small. A medium circuit and the largest supported client
circuit are usually enough to reveal initialization overhead, peak-memory risk,
thread scaling, and thermal degradation. Add a circuit when it has a materially
different witness size, proving-key layout, or host limits profile.

Validate paths, digests, profile identifiers, and tuning ranges without opening
a network port:

```bash
node crates/prover/js/mobile-harness-server.mjs \
  path/to/mobile-harness.config.json --check
```

The configuration should be generated from deployment metadata rather than
maintained as a second source of artifact URLs and hashes.

## Android over USB

Android browsers treat `http://localhost` as a potentially trustworthy origin.
With ADB and USB debugging enabled:

```bash
node crates/prover/js/mobile-harness-server.mjs \
  path/to/mobile-harness.config.json 8766
adb reverse tcp:8766 tcp:8766
```

Open the tokenized URL printed by the server. The diagnostics must report a
secure context, cross-origin isolation, and `SharedArrayBuffer` before a threaded
run can start.

## iOS, iPadOS, and Wi-Fi devices

A device that opens a LAN address over plain HTTP does not have the secure
context required by Cache API and WASM threads. Serve the harness over HTTPS
with a certificate trusted by the device. One development setup uses `mkcert`:

```bash
brew install mkcert
mkcert -install
mkdir -p target/mobile-tls
mkcert \
  -cert-file target/mobile-tls/cert.pem \
  -key-file target/mobile-tls/key.pem \
  "$(scutil --get LocalHostName).local" 192.168.x.x localhost 127.0.0.1 ::1

CURVY_TLS_CERT=target/mobile-tls/cert.pem \
CURVY_TLS_KEY=target/mobile-tls/key.pem \
CURVY_MOBILE_HOST=0.0.0.0 \
node crates/prover/js/mobile-harness-server.mjs \
  path/to/mobile-harness.config.json 8766
```

Install and trust the development CA on the device, use a hostname covered by
the certificate, and remove the CA after testing. Replace `192.168.x.x` with the
host's LAN address.

The server binds to localhost unless `CURVY_MOBILE_HOST` explicitly exposes it.
It serves only allowlisted harness and artifact paths. Every request requires a
random access token; the first page load exchanges the query token for an
HttpOnly same-site cookie and removes it from browser history. HTTPS is still
required on a shared network because the token does not encrypt artifact or
witness traffic.

## Run a device matrix

For each representative profile:

1. Confirm the secure-context and isolation diagnostics.
2. Cache the source artifacts and record origin quota and persistence status.
3. Run the portable single-thread build.
4. Run the threaded build with half the exposed logical CPUs.
5. Run the threaded build with the selected production worker policy.
6. Repeat the production setting three to five times without reloading to expose
   thermal degradation.
7. Download the JSON report.

Keep one logical CPU available for browser, wallet, and network work unless
measurements support a different policy. Reload before changing the worker count
because a WebAssembly Rayon global pool cannot be resized.

If the browser terminates a worker or reloads the page, reduce the MSM chunk
size and worker count. Record the failure as a process-limit result rather than
discarding it. Browser JavaScript does not expose a reliable cross-platform peak
process-memory counter.

## Artifact reads

The runner reads the manifest, input, and source graph from Cache API under
fixed size ceilings that mirror the Rust limits: 4 MiB for a manifest, 16 MiB
for input JSON, and 64 MiB (client) or 96 MiB (batch) for a SIGNET graph. A
declared or streamed length above the ceiling is rejected before it is
buffered. The manifest and input are checked against their pinned digests, and
the graph is authenticated by SIGNET. A cached copy that fails its check is
evicted and fetched once from the harness server; a network copy is stored only
after it passes. The zkey is never buffered: every chunk is authenticated
against the pinned manifest before Rust parses it.

## SAGE cache behavior

The derived SAGE cache is used only for profiles with a trusted
`sageProgramSha256`. Hashing a cache entry and using that hash as its own pin
does not authenticate it, so without a pin the harness compiles the
authenticated SIGNET graph on every run and neither reads nor writes the derived
entry. Such runs report `sageCacheStored: false` and `sageProgramPinned: false`.

Obtain the pin from the trusted artifact pipeline, not from the device being
measured. `derive_sage_cache` prints it as `program_sha256`:

```bash
cargo run -p curvy-prover --features sage --example derive_sage_cache -- \
  path/to/circuit.signet SOURCE_SIGNET_SHA256 target/circuit.sage batch
```

The digest is specific to the source graph and the SAGE compiler version
(`sageCacheVersion()`); regenerate it when either changes. A wrong pin fails
the run rather than falling back.

On a cold pinned run, the harness authenticates the source SIGNET graph,
compiles it, serializes the SAGE program, checks it against the pin, releases
the compiler instance, reloads the bytes through the validated decoder, and
stores them in Cache API.

On a warm pinned run, it hashes the cached program and Rust validates the
program digest, embedded source digest, format, dimensions, indices, and exact
length. Any failure evicts the entry and recompiles from the authenticated
source graph. The cache digest detects local storage corruption; the pinned
SIGNET and program digests remain the deployment trust anchors.

First use has a higher transient memory requirement because compilation and
serialization overlap briefly. Test one profile at a time when device quota or
process memory is constrained.

## Interpret the report

Retain these fields with each result:

- SDK, Rust crate, and WASM package versions;
- graph, zkey, manifest, and input digests;
- browser, OS, device, and architecture;
- portable or threaded runtime;
- worker count, window bits, MSM chunk points, and manifest chunk bytes;
- SAGE program pin status and cache hit or miss;
- module import, WASM initialization, Rayon initialization, SAGE startup, and
  proof timings; and
- proof self-verification status.

`proofAndVerifyMs` includes the sequential Cache API zkey read in manifest mode
because authentication and proving consume the same stream. Do not compare a
cold download with a warm proof, or a first threaded initialization with a
reused pool.

Window width and MSM chunk size affect performance and memory, not proof
semantics or artifact digests. Pin them only after repeated self-verifying runs
on the intended devices. Native measurements provide a starting point, not a
mobile policy. See [docs/benchmarks.md](../../docs/benchmarks.md) for the
benchmark method and representative reference values.
