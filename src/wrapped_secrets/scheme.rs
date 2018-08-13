use errors::*;
use proto::wrapped::SecretProto;
use proto::VersionProto;
use protobuf;
use protobuf::Message;
use rand::Rng;

pub(crate) use sss::Share;
use sss::SSS;

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct WrappedSecrets;

impl WrappedSecrets {
    /// Performs threshold k-out-of-n Shamir's secret sharing.
    pub fn split_secret<R: Rng>(
        self,
        rng: &mut R,
        k: u8,
        n: u8,
        secret: &[u8],
        mime_type: Option<String>,
        sign_shares: bool,
    ) -> Result<Vec<Share>> {
        let mut rusty_secret = SecretProto::new();
        rusty_secret.set_version(VersionProto::INITIAL_RELEASE);
        rusty_secret.set_secret(secret.to_owned());

        if let Some(mt) = mime_type {
            rusty_secret.set_mime_type(mt);
        }

        let data = rusty_secret.write_to_bytes().unwrap();

        SSS::default().split_secret(rng, k, n, data.as_slice(), sign_shares)
    }

    /// Recovers the secret from a k-out-of-n Shamir's secret sharing.
    ///
    /// At least `k` distinct shares need to be provided to recover the share.
    pub fn recover_secret(shares: &[Share], verify_signatures: bool) -> Result<SecretProto> {
        let secret = SSS::recover_secret(shares, verify_signatures)?;

        protobuf::parse_from_bytes::<SecretProto>(secret.as_slice())
            .chain_err(|| ErrorKind::SecretDeserializationError)
    }
}
