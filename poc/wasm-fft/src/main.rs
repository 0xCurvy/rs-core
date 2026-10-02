fn main() {
    let command = std::env::args().skip(1).collect::<Vec<_>>().join(" ");
    println!("{}", wasm_fft_poc::run_command(&command));
}
