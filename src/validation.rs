use errors::*;
use merkle_sigs::verify_data_vec_signature;
use share_format;
use share_format::format_share_for_signing;
use std::collections::HashMap;
use std::error::Error;

type ProcessedShares = Result<(u8, Vec<(u8, Vec<u8>)>)>;

// The order of validation that we think makes the most sense is the following:
// 1) Validate shares individually
// 2) Validate duplicate shares share num && data
// 2) Validate group consistency
// 3) Validate other properties, in no specific order

pub fn process_and_validate_shares(
    shares_strings: Vec<String>,
    verify_signatures: bool,
) -> ProcessedShares {
    let mut shares: Vec<(u8, Vec<u8>)> = Vec::new();

    let mut k_compatibility_sets = HashMap::new();
    let mut rh_compatibility_sets = HashMap::new();

    for (counter, line) in shares_strings.iter().enumerate() {
        let share_index = counter as u8;
        let (share_data, k, n, sig_pair) =
            share_format::share_from_string(line, counter as u8, verify_signatures)?;

        if verify_signatures {
            if sig_pair.is_none() {
                bail!(ErrorKind::MissingSignature(share_index));
            }

            let (signature, p) = sig_pair.unwrap();
            let root_hash = p.root_hash.clone();

            verify_data_vec_signature(
                format_share_for_signing(k, n, &share_data.as_slice()),
                &(signature.to_vec(), p),
                &root_hash,
            ).map_err(|e| {
                ErrorKind::InvalidSignature(share_index, String::from(e.description()))
            })?;

            rh_compatibility_sets
                .entry(root_hash.clone())
                .or_insert_with(Vec::new);
            let vec = rh_compatibility_sets.get_mut(&root_hash).unwrap();
            vec.push(share_index);
        }

        k_compatibility_sets.entry(k).or_insert_with(Vec::new);
        let vec = k_compatibility_sets.get_mut(&k).unwrap();
        vec.push(share_index);

        if shares.iter().any(|s| s.0 == n) {
            bail!(ErrorKind::DuplicateShareId(share_index));
        }

        if shares.iter().any(|s| s.1 == share_data) && k != 1 {
            // When k = 1, shares data can be the same
            bail!(ErrorKind::DuplicateShareData(share_index));
        }

        shares.push((n, share_data));
    }

    // Validate k

    let k_sets = k_compatibility_sets.keys().count();
    let rh_sets = rh_compatibility_sets.keys().count();

    if verify_signatures {
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
    }

    match k_sets {
        0 => bail!(ErrorKind::EmptyShares),
        1 => {} // All shares have the same roothash.
        _ => {
            bail! {
                ErrorKind::IncompatibleSets(
                    k_compatibility_sets
                        .values()
                        .map(|x| x.to_owned())
                        .collect(),
                )
            }
        }
    }

    // It is safe to unwrap because k_sets == 1
    let k = *k_compatibility_sets.keys().last().unwrap();
    let shares_num = shares.len();

    if shares_num < k as usize {
        bail!(ErrorKind::MissingShares(k as usize, shares_num));
    }

    shares.truncate(k as usize);
    Ok((k, shares))
}
