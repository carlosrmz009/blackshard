fn main() {
    // rustc generates the cdylib export .def file. MSVC's LNK4104 requests
    // PRIVATE annotations that affect import-library emission but not the
    // COM exports themselves; Rust does not expose a way to annotate those
    // generated lines. Keep this exception local to the AMSI DLL.
    println!("cargo:rustc-link-arg=/IGNORE:4104");
}
