//! `charter-compile` — read a charter on stdin, write its canonical compiled form to stdout.
//!
//! What §12's `compiled_digest` is taken over, and what `canonical/` fixtures store.

use std::io::Read;

fn main() {
    let mut src = String::new();
    if std::io::stdin().read_to_string(&mut src).is_err() {
        std::process::exit(2);
    }
    let ast = match pays_charter::parse(&src) {
        Ok(a) => a,
        Err(d) => {
            for x in &d {
                eprintln!("{}", x.render(&src));
            }
            std::process::exit(1);
        }
    };
    // A uniform two-decimal resolver: the fixtures are about the encoding, not the scale, and
    // the scale is stated here rather than assumed silently.
    match pays_charter::compile(&ast, &pays_charter::Resolver::uniform(2)) {
        Ok(c) => {
            use std::io::Write;
            std::io::stdout().write_all(&pays_policy::compiled::encode(&c)).unwrap();
        }
        Err(d) => {
            for x in &d {
                eprintln!("{}", x.render(&src));
            }
            std::process::exit(1);
        }
    }
}
