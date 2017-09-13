use std::collections::{HashMap, HashSet};

use errors::*;
use share::{IsShare, IsSignedShare};

// The order of validation that we think makes the most sense is the following:
// 1) Validate shares individually
// 2) Validate duplicate shares share num && data
// 2) Validate group consistency
// 3) Validate other properties, in no specific order

/// TODO: Doc
pub(crate) fn validate_signed_shares<S: IsSignedShare>(
    shares: Vec<S>,
    verify_signatures: bool,
) -> Result<(u8, Vec<S>)> {
    let (threshold, shares) = validate_shares(shares)?;

    if verify_signatures {
        S::verify_signatures(&shares)?;
    }

    Ok((threshold, shares))
}

/// TODO: Doc
pub(crate) fn validate_shares<S: IsShare>(shares: Vec<S>) -> Result<(u8, Vec<S>)> {
    if shares.is_empty() {
        bail!(ErrorKind::EmptyShares);
    }

    let shares_count = shares.len();
    let mut result: Vec<S> = Vec::with_capacity(shares_count);

    let mut k_compatibility_sets = HashMap::new();

    for share in shares {
        let (id, threshold) = (share.get_id(), share.get_threshold());

        // TODO: Check that ID < shares_count

        k_compatibility_sets.entry(threshold).or_insert_with(
            HashSet::new,
        );
        let k_set = k_compatibility_sets.get_mut(&threshold).unwrap();
        k_set.insert(id);

        if result.iter().any(|s| s.get_id() == id) {
            bail!(ErrorKind::DuplicateShareId(id));
        }

        if result.iter().any(|s| s.get_data() == share.get_data()) && share.get_threshold() != 1 {
            // When threshold = 1, shares data can be the same
            bail!(ErrorKind::DuplicateShareData(id));
        }

        result.push(share);
    }

    // Validate threshold

    let k_sets = k_compatibility_sets.keys().count();

    if k_sets == 0 {
        bail!(ErrorKind::EmptyShares);
    }

    if k_sets > 1 {
        bail! {
            ErrorKind::IncompatibleSets(
                k_compatibility_sets
                    .values()
                    .map(|x| x.to_owned())
                    .collect(),
            )
        }
    }

    // It is safe to unwrap because k_sets == 1
    let threshold = k_compatibility_sets.keys().last().unwrap().to_owned();

    if shares_count < threshold as usize {
        bail!(ErrorKind::MissingShares(threshold as usize, shares_count));
    }

    Ok((threshold, result))
}
