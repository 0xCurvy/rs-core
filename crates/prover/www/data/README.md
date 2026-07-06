# Harness circuit artifacts

The **scan** harness (`../scan-bench.html`) is self-contained — it generates its
own announcements via the wasm core and needs nothing here.

The **prover** harness (`../index.html`) proves real circuits and needs, per
circuit `<name>` (`agg`, `pending`):

| file | tracked? | what it is |
|---|---|---|
| `<name>-input.json` | yes | flat circuit input signals |
| `<name>-vkey.json`  | yes | verification key (for in-page verify) |
| `<name>.wtns`       | no (gitignored) | precomputed witness — generate with snarkjs `wtns.calculate(input, circuit.wasm)` |
| `<name>.zkey`       | no (gitignored) | Groth16 proving key — supply from your circuit's trusted setup |

Drop the `.wtns` and `.zkey` files here before running the prover harness. The
`.json` fixtures are small and committed so the harness wiring is exercisable
without the large binaries.
