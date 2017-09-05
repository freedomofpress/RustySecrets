//! (Beta) `wrapped_secrets` provides Shamir's secret sharing with a wrapped secret. It currently offers versioning and MIME information about the data.

use errors::*;
use protobuf;
use protobuf::Message;
use proto::{RustySecret, RustySecretsVersions};

use sss::SSS;
pub(crate) use sss::Share;

/// Performs threshold k-out-of-n Shamir's secret sharing.
///
/// # Examples
///
/// ```
/// use rusty_secrets::wrapped_secrets::generate_shares;
///
/// let secret = "These programs were never about terrorism: they’re about economic spying, \
///               social control, and diplomatic manipulation. They’re about power.";
///
/// let result = generate_shares(
///     7,
///     10,
///     &secret.as_bytes(),
///     Some("text/html".to_string()),
///     true,
/// );
///
/// match result {
///     Ok(shares) => {
///         // Do something with the shares
///     },
///     Err(_) => {
///         // Deal with error
///     }
/// }
/// ```
pub fn generate_shares(
    k: u8,
    n: u8,
    secret: &[u8],
    mime_type: Option<String>,
    sign_shares: bool,
) -> Result<Vec<String>> {
    WrappedSecrets::default()
        .generate_shares(k, n, secret, mime_type, sign_shares)
        .map(|shares| {
            shares.into_iter().map(Share::into_string).collect()
        })
}

/// Recovers the secret from a k-out-of-n Shamir's secret sharing.
///
/// At least `k` distinct shares need to be provided to recover the share.
///
/// # Examples
///
/// ```rust
/// use rusty_secrets::wrapped_secrets::recover_secret;
///
/// let share1 = "2-1-Cha7s14Q/mSwWko0ittr+/Uf79RHQMIP".to_string();
/// let share2 = "2-4-ChaydsUJDypD9ZWxwvIICh/cmZvzusOF".to_string();
/// let shares = vec![share1, share2];
///
/// match recover_secret(shares, false) {
///     Ok(secret) => {
///         // Do something with the secret
///     },
///     Err(e) => {
///         // Deal with the error
///     }
/// }
/// ```
pub fn recover_secret(shares: Vec<String>, verify_signatures: bool) -> Result<RustySecret> {
    let shares = Share::parse_all(&shares, verify_signatures)?;
    WrappedSecrets::recover_secret(shares, verify_signatures)
}


/// TODO
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct WrappedSecrets;

impl WrappedSecrets {
    /// Performs threshold k-out-of-n Shamir's secret sharing.
    pub fn generate_shares(
        &self,
        k: u8,
        n: u8,
        secret: &[u8],
        mime_type: Option<String>,
        sign_shares: bool,
    ) -> Result<Vec<Share>> {
        let mut rusty_secret = RustySecret::new();
        rusty_secret.set_version(RustySecretsVersions::INITIAL_RELEASE);
        rusty_secret.set_secret(secret.to_owned());

        if let Some(mt) = mime_type {
            rusty_secret.set_mime_type(mt);
        }

        let data = rusty_secret.write_to_bytes().unwrap();

        SSS::default().generate_shares(k, n, data.as_slice(), sign_shares)
    }

    /// Recovers the secret from a k-out-of-n Shamir's secret sharing.
    ///
    /// At least `k` distinct shares need to be provided to recover the share.
    pub fn recover_secret(shares: Vec<Share>, verify_signatures: bool) -> Result<RustySecret> {
        let secret = SSS::recover_secret(shares, verify_signatures)?;

        protobuf::parse_from_bytes::<RustySecret>(secret.as_slice())
            .chain_err(|| ErrorKind::SecretDeserializationError)
    }
}