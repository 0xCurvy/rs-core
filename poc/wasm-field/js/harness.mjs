// Shared by Node and the Chromium page: instantiate the bare WASM module and
// run text commands (see run_command in src/lib.rs). No wasm-bindgen.
export async function createRunner(bytes, log = console.error) {
  let memory;
  const decoder = new TextDecoder();
  const read = (ptr, len) => decoder.decode(new Uint8Array(memory.buffer, ptr, len));
  const {instance} = await WebAssembly.instantiate(bytes, {
    env: {
      now_ms: () => performance.now(),
      log: (ptr, len) => log(read(ptr, len)),
    },
  });
  memory = instance.exports.memory;
  return {
    run(command) {
      const encoded = new TextEncoder().encode(command);
      const ptr = instance.exports.cmd_alloc(encoded.length);
      new Uint8Array(memory.buffer, ptr, encoded.length).set(encoded);
      const len = instance.exports.cmd_run();
      return JSON.parse(read(instance.exports.out_ptr(), len));
    },
    memoryBytes: () => memory.buffer.byteLength,
  };
}
