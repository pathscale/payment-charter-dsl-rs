//! `charter-parse` — read a charter on stdin, report diagnostics, exit non-zero on error.
//!
//! Exists so the TypeScript emitter can be verified by the Rust parser: emit from TS, parse
//! here, and compare. That check is most of why the emitter needs no conformance suite of its
//! own, and it is the only thing standing between two implementations and quiet divergence.

use std::io::Read;

fn main() {
    let mut src = String::new();
    if std::io::stdin().read_to_string(&mut src).is_err() {
        eprintln!("could not read stdin");
        std::process::exit(2);
    }
    match pays_charter::check(&src) {
        Ok((_, warnings)) => {
            for w in &warnings {
                eprintln!("{}", w.render(&src));
            }
            println!("ok");
        }
        Err(diags) => {
            for d in &diags {
                eprintln!("{}", d.render(&src));
            }
            std::process::exit(1);
        }
    }
}
