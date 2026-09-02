//! `charter-emit` — read a charter on stdin, write its canonical form (§1.2) to stdout.
//!
//! The counterpart of `charter-parse`. Together they are how `roundtrip/` fixtures are
//! produced and how the TypeScript emitter is held to the same bytes.

use std::io::Read;

fn main() {
    let mut src = String::new();
    if std::io::stdin().read_to_string(&mut src).is_err() {
        eprintln!("could not read stdin");
        std::process::exit(2);
    }
    match pays_charter::parse(&src) {
        Ok(ast) => print!("{}", pays_charter::emit(&ast)),
        Err(diags) => {
            for d in &diags {
                eprintln!("{}", d.render(&src));
            }
            std::process::exit(1);
        }
    }
}
