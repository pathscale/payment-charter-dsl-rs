//! A minimal JSON reader.
//!
//! `pays-charter` may take dependencies, and will take `serde` for the wire form. This exists
//! so the resolver tier and the conformance harnesses can be read with no network and no
//! lockfile, which is what keeps `cargo test` runnable from a clean checkout.

#![allow(dead_code)]

use std::collections::BTreeMap;

#[derive(Clone, Debug, PartialEq)]
pub enum Json {
    Null,
    Bool(bool),
    Num(f64),
    Str(String),
    Arr(Vec<Json>),
    Obj(BTreeMap<String, Json>),
}

impl Json {
    pub fn get(&self, k: &str) -> Option<&Json> {
        match self {
            Json::Obj(m) => m.get(k),
            _ => None,
        }
    }
    pub fn str(&self, k: &str) -> Option<&str> {
        match self.get(k) {
            Some(Json::Str(s)) => Some(s),
            _ => None,
        }
    }
    pub fn num(&self, k: &str) -> Option<f64> {
        match self.get(k) {
            Some(Json::Num(n)) => Some(*n),
            _ => None,
        }
    }
    pub fn arr(&self, k: &str) -> Option<&[Json]> {
        match self.get(k) {
            Some(Json::Arr(v)) => Some(v),
            _ => None,
        }
    }
}

pub fn parse(s: &str) -> Json {
    let b: Vec<char> = s.chars().collect();
    let mut i = 0;
    let v = value(&b, &mut i);
    v
}

fn skip_ws(b: &[char], i: &mut usize) {
    while *i < b.len() && b[*i].is_whitespace() {
        *i += 1;
    }
}

fn value(b: &[char], i: &mut usize) -> Json {
    skip_ws(b, i);
    match b.get(*i) {
        Some('{') => {
            *i += 1;
            let mut m = BTreeMap::new();
            loop {
                skip_ws(b, i);
                if b.get(*i) == Some(&'}') {
                    *i += 1;
                    break;
                }
                let Json::Str(k) = value(b, i) else { panic!("object key") };
                skip_ws(b, i);
                assert_eq!(b.get(*i), Some(&':'), "expected ':'");
                *i += 1;
                m.insert(k, value(b, i));
                skip_ws(b, i);
                if b.get(*i) == Some(&',') {
                    *i += 1;
                }
            }
            Json::Obj(m)
        }
        Some('[') => {
            *i += 1;
            let mut v = Vec::new();
            loop {
                skip_ws(b, i);
                if b.get(*i) == Some(&']') {
                    *i += 1;
                    break;
                }
                v.push(value(b, i));
                skip_ws(b, i);
                if b.get(*i) == Some(&',') {
                    *i += 1;
                }
            }
            Json::Arr(v)
        }
        Some('"') => {
            *i += 1;
            let mut s = String::new();
            while let Some(&c) = b.get(*i) {
                *i += 1;
                match c {
                    '"' => break,
                    '\\' => {
                        let e = b[*i];
                        *i += 1;
                        s.push(match e {
                            'n' => '\n',
                            't' => '\t',
                            other => other,
                        });
                    }
                    _ => s.push(c),
                }
            }
            Json::Str(s)
        }
        Some('t') => {
            *i += 4;
            Json::Bool(true)
        }
        Some('f') => {
            *i += 5;
            Json::Bool(false)
        }
        Some('n') => {
            *i += 4;
            Json::Null
        }
        _ => {
            let start = *i;
            while matches!(b.get(*i), Some(c) if c.is_ascii_digit() || *c == '-' || *c == '+' || *c == '.' || *c == 'e' || *c == 'E')
            {
                *i += 1;
            }
            let text: String = b[start..*i].iter().collect();
            Json::Num(text.parse().unwrap_or_else(|_| panic!("number: {text:?}")))
        }
    }
}

