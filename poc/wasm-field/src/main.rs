//! Native runner: `poc COMMAND...` (see `wasm_field_poc::run_command`).

fn main() {
    let command = std::env::args().skip(1).collect::<Vec<_>>().join(" ");
    println!("{}", wasm_field_poc::run_command(&command));
}
