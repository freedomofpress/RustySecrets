
use std::error::Error;
use std::collections::{HashMap, HashSet};

use merkle_sigs::{MerklePublicKey, Proof};
use merkle_sigs::verify_data_vec_signature;

use errors::*;
use share::IsShare;
use sss::format::{format_share_for_signing, share_string_from, share_from_string};

/// A share identified by an `id`, a threshold `k`, a number of total shares `n`,
/// the `data` held in the share, and the share's `metadata`.
// #[derive(Clone, Debug, Hash, PartialEq, Eq)]
// TODO: Write manual instances which ignore the signature
#[derive(Clone, Debug)]
pub(crate) struct Share {
    /// The identifier of the share (varies between 1 and n where n is the total number of generated shares)
    pub id: u8,
    /// The number of shares necessary to recover the secret, aka a threshold
    pub k: u8,
    /// The total number of shares that have been dealt
    pub n: u8,
    /// The share data itself
    pub data: Vec<u8>,
    /// If the share is signed, this fields holds the signature
    /// along with the proof of inclusion into the underlying MerkleTree.
    pub signature_pair: Option<SignaturePair>,
}

impl Share {
    /// TODO: Doc
    pub(crate) fn from_string(raw: &str, id: u8, is_signed: bool) -> Result<Self> {
        share_from_string(raw, id, is_signed)
    }

    /// TODO: Doc
    pub(crate) fn parse_all(raws: &[String], is_signed: bool) -> Result<Vec<Share>> {
        raws.into_iter()
            .enumerate()
            .map(|(id, raw)| Self::from_string(raw, id as u8, is_signed))
            .collect()
    }

    /// Format the share as a string suitable for being stored in a file.
    /// The format is the following:
    ///
    /// ```text
    /// 2-1-LiTyeXwEP71IUA
    /// ^ ^ ^^^^^^^^^^^^^^
    /// K N        D
    ///
    /// It is built out of three parts separated with a dash: K-N-D.
    ///
    /// - K specifies the number of shares necessary to recover the secret.
    /// - N is the identifier of the share and varies between 1 and n where
    ///   n is the total number of generated shares.
    /// - D is a Base64 encoding of a ShareData protobuf containing
    ///   information about the share, and if signed, the signature.
    /// ```
    pub fn into_string(self) -> String {
        share_string_from(
            self.data,
            self.k,
            self.id,
            self.signature_pair.map(Into::into),
        )
    }
}

impl IsShare for Share {
    type Signature = Option<SignaturePair>;

    fn verify_signatures(shares: &[Self]) -> Result<()> {
        let mut rh_compatibility_sets = HashMap::new();

        for share in shares {
            if !share.is_signed() {
                bail!(ErrorKind::MissingSignature(share.id()));
            }

            let sig_pair = share.signature_pair.as_ref().unwrap();
            let signature = &sig_pair.signature;
            let proof = &sig_pair.proof;
            let root_hash = &proof.root_hash;

            verify_data_vec_signature(
                format_share_for_signing(share.k, share.n, share.data.as_slice()),
                &(signature.to_vec(), proof.clone()),
                &root_hash,
            ).map_err(|e| {
                ErrorKind::InvalidSignature(share.id, String::from(e.description()))
            })?;

            rh_compatibility_sets.entry(root_hash).or_insert_with(
                HashSet::new,
            );

            let rh_set = rh_compatibility_sets.get_mut(&root_hash).unwrap();
            rh_set.insert(share.id);
        }

        let rh_sets = rh_compatibility_sets.keys().count();

        match rh_sets {
            0 => bail!(ErrorKind::EmptyShares),
            1 => {} // All shares have the same roothash.
            _ => {
                bail! {
                    ErrorKind::IncompatibleSets(
                        rh_compatibility_sets
                            .values()
                            .map(|x| x.to_owned())
                            .collect(),
                    )
                }
            }
        }

        Ok(())
    }

    fn id(&self) -> u8 {
        self.id
    }

    fn data(&self) -> &[u8] {
        &self.data
    }

    fn k(&self) -> u8 {
        self.k
    }

    fn n(&self) -> u8 {
        self.n
    }

    fn is_signed(&self) -> bool {
        self.signature_pair.is_some()
    }

    fn signature(&self) -> &Self::Signature {
        &self.signature_pair
    }
}

#[derive(Clone, Debug)]
/// Holds the signature along with the proof of inclusion
/// in the underlying Merkle tree used in the Lamport signature scheme.
pub struct SignaturePair {
    /// The signature
    pub signature: Vec<Vec<u8>>,
    /// The proof of inclusion
    pub proof: Proof<MerklePublicKey>,
}

impl From<SignaturePair> for (Vec<Vec<u8>>, Proof<MerklePublicKey>) {
    fn from(pair: SignaturePair) -> Self {
        (pair.signature, pair.proof)
    }
}

impl From<(Vec<Vec<u8>>, Proof<MerklePublicKey>)> for SignaturePair {
    fn from(pair: (Vec<Vec<u8>>, Proof<MerklePublicKey>)) -> Self {
        Self {
            signature: pair.0,
            proof: pair.1,
        }
    }
}

// impl Hash for SignaturePair {
//     fn hash<H: Hasher>(&self, state: &mut H) {
//         self.signature.hash(state);
//         self.proof.root_hash.hash(state);
//     }
// }
