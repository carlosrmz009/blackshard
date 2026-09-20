//! Compiles a YARA rule file using blackshard's exact yara-x configuration.
//!
//! Useful before importing a public ruleset: blackshard enables only a subset of yara-x's modules,
//! so a rule that compiles under upstream YARA may still be rejected here.
//!
//! ```text
//! cargo run --release --example compile_ruleset -- yara-rules-core.yar
//! ```

fn main() {
    let Some(path) = std::env::args().nth(1) else {
        eprintln!("usage: compile_ruleset <rules.yar>");
        std::process::exit(2);
    };
    let source = match std::fs::read_to_string(&path) {
        Ok(source) => source,
        Err(error) => {
            eprintln!("could not read {path}: {error}");
            std::process::exit(2);
        }
    };

    let mut compiler = yara_x::Compiler::new();
    compiler.new_namespace("probe");
    match compiler.add_source(source.as_str()) {
        Ok(_) => println!("compiled {} rules", compiler.build().iter().count()),
        Err(error) => {
            eprintln!("compilation failed: {error}");
            std::process::exit(1);
        }
    }
}
