extern crate rusty_secrets;

use rusty_secrets::sss::{recover_secret, split_secret};

#[test]
#[should_panic(expected = "EmptyShares")]
fn test_recover_no_shares() {
    for signed in &[true, false] {
        let shares = vec![];
        recover_secret(&shares, *signed).unwrap();
    }
}

#[test]
#[should_panic(expected = "ShareParsingErrorEmptyShare")]
fn test_share_parsing_error_empty_share() {
    let shares = vec!["2-1-".to_string()];
    recover_secret(&shares, false).unwrap();
}

#[test]
#[should_panic(expected = "ShareParsingError")]
fn test_recover_2_parts_share() {
    let share1 = "2-1-CgmKQZHMO+5n5pU".to_string();
    let share2 = "2-2".to_string();

    let shares = vec![share1, share2];

    recover_secret(&shares, false).unwrap();
}

#[test]
#[should_panic(expected = "IntegerParsingError")]
fn test_recover_incorrect_share_num() {
    let share1 = "2-1-CgnlCxRNtnkzENE".to_string();
    let share2 = "2-DEFINITLY_NAN-CgkAnUgP3lfwjyM".to_string();

    let shares = vec![share1, share2];

    recover_secret(&shares, false).unwrap();
}

#[test]
#[should_panic(expected = "ShareParsingInvalidShareId")]
fn test_recover_0_share_num() {
    let shares = vec!["2-0-1YAYwmOHqZ69jA".to_string()];
    recover_secret(&shares, false).unwrap();
}

#[test]
#[should_panic(expected = "ShareParsingError")]
fn test_recover_invalid_b64() {
    let share1 = "2-1-CgnlCxRNtnkzENE".to_string();
    let share2 = "2-2-YJZQDG((((m22Y)))77Gw".to_string();

    let shares = vec![share1, share2];

    recover_secret(&shares, false).unwrap();
}

#[test]
#[should_panic(expected = "DuplicateShareId")]
fn test_recover_duplicate_shares_number() {
    let share1 = "2-1-CgnlCxRNtnkzENE".to_string();
    let share2 = "2-1-CgkAnUgP3lfwjyM".to_string();

    let shares = vec![share1, share2];

    recover_secret(&shares, false).unwrap();
}

#[test]
#[should_panic(expected = "InconsistentSecretLengths")]
fn test_recover_inconsistent_secret_lengths() {
    let share1 = "2-1-CgnlCxRNtnkzENE".to_string();
    let share2 = "2-2-ChbG46L1zRszs0PPn63XnnupmZTcgYJ3".to_string();

    let shares = vec![share1, share2];

    recover_secret(&shares, false).unwrap();
}

#[test]
#[should_panic(expected = "InconsistentThresholds")]
fn test_inconsistent_thresholds() {
    let share1 = "2-1-CgnlCxRNtnkzENE".to_string();
    let share2 = "3-2-CgkAnUgP3lfwjyM".to_string();

    let shares = vec![share1, share2];

    recover_secret(&shares, false).unwrap();
}

#[test]
#[should_panic(expected = "MissingShares")]
fn test_recover_too_few_shares() {
    let share1 = "3-1-ChbcCdSZOaMn6DM1jFca2P6/0WRlP7AK".to_string();
    let share2 = "3-2-ChbG46L1zRszs0PPn63XnnupmZTcgYJ3".to_string();

    let shares = vec![share1, share2];

    recover_secret(&shares, false).unwrap();
}

#[test]
#[should_panic(expected = "ShareParsingInvalidShareThreshold")]
fn test_recover_invalid_share_threshold() {
    let share1 = "1-1-CgnlCxRNtnkzENE".to_string();
    let share2 = "1-1-CgkAnUgP3lfwjyM".to_string();

    let shares = vec![share1, share2];

    recover_secret(&shares, false).unwrap();
}

// See https://github.com/SpinResearch/RustySecrets/issues/43
#[test]
fn test_recover_too_few_shares_bug() {
    let original = b"Test for issue #43".to_vec();
    let shares = split_secret(4, 5, &original, false).unwrap();
    let mut share_1 = shares[0].clone().into_bytes();
    let mut share_2 = shares[3].clone().into_bytes();

    share_1[0] = b'2';
    share_2[0] = b'2';

    let sub_shares = vec![
        String::from_utf8_lossy(&share_1).into_owned(),
        String::from_utf8_lossy(&share_2).into_owned(),
    ];

    match recover_secret(&sub_shares, false) {
        Err(_) => assert!(true),
        Ok(recovered) => assert_ne!(original, recovered),
    }
}
