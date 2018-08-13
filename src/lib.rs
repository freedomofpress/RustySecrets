//! `RustySecrets` implements Shamir's secret sharing in Rust. It provides the possibility to sign shares.

#![deny(
    missing_docs,
    missing_debug_implementations,
    missing_copy_implementations,
    trivial_casts,
    trivial_numeric_casts,
    unsafe_code,
    unstable_features,
    unused_import_braces,
    unused_qualifications
)]
#![cfg_attr(feature = "cargo-clippy", allow(doc_markdown))]
// `error_chain!` can recurse deeply
#![recursion_limit = "1024"]

#[macro_use]
extern crate error_chain;

extern crate base64;
extern crate merkle_sigs;
extern crate protobuf;
extern crate rand;
extern crate ring;

#[macro_use]
mod gf256;
mod lagrange;
mod share;

pub mod errors;
pub mod proto;
pub mod sss;
pub mod wrapped_secrets;

#[cfg(test)]
extern crate itertools;

#[cfg(test)]
extern crate flate2;

#[cfg(test)]
#[macro_use]
extern crate quickcheck;
