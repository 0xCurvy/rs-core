fn main() {
    napi_build::setup();

    // On macOS the addon's install name would otherwise be the path it was linked at, in the
    // build machine's target directory. Node.js loads it by its own path.
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
        println!("cargo:rustc-cdylib-link-arg=-Wl,-install_name,@rpath/curvy_rs_core_node.node");
    }
}
