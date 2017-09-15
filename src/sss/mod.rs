
//! SSS provides Shamir's secret sharing with raw data.

use errors::*;

mod share;
pub(crate) use self::share::*;

mod format;
// pub use self::format::*;

mod scheme;
pub(crate) use self::scheme::*;

mod encode;

use ring::digest::{Algorithm, SHA512};
static HASH_ALGO: &'static Algorithm = &SHA512;

/// Performs threshold k-out-of-n Shamir's secret sharing.
///
/// # Examples
///
/// ```
/// use rusty_secrets::sss::generate_shares;
///
/// let secret = "These programs were never about terrorism: they’re about economic spying, \
///               social control, and diplomatic manipulation. They’re about power.";
///
/// match generate_shares(7, 10, &secret.as_bytes(), true) {
///     Ok(shares) => {
///         // Do something with the shares
///     },
///     Err(_) => {
///         // Deal with error
///     }
/// }
/// ```
pub fn generate_shares(k: u8, n: u8, secret: &[u8], sign_shares: bool) -> Result<Vec<String>> {
    SSS::default()
        .generate_shares(k, n, secret, sign_shares)
        .map(|shares| {
            shares.into_iter().map(Share::into_string).collect()
        })
}

/// Recovers the secret from a k-out-of-n Shamir's secret sharing scheme.
///
/// At least `k` distinct shares need to be provided to recover the secret.
///
/// # Examples
///
/// ```
/// use rusty_secrets::sss::recover_secret;
///
/// let share1 = "2-1-Cha7s14Q/mSwWko0ittr+/Uf79RHQMIP".to_string();
/// let share2 = "2-4-ChaydsUJDypD9ZWxwvIICh/cmZvzusOF".to_string();
/// let shares = vec![share1, share2];
///
/// match recover_secret(&shares, false) {
///     Ok(secret) => {
///         // Do something with the secret
///     },
///     Err(e) => {
///         // Deal with the error
///     }
/// }
/// ```
pub fn recover_secret(shares: &[String], verify_signatures: bool) -> Result<Vec<u8>> {
    let shares = Share::parse_all(shares, verify_signatures)?;
    SSS::recover_secret(shares, verify_signatures)
}
