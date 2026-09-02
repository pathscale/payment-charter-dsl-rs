//! §2.9: UTC offsets only. No zone names, no database, no daylight saving.

fn charter(tz: &str) -> String {
    format!(
        "charter t version 1\nresolver common@41\ntimezone {tz}\n\n  \
         asset USDC_solana = mint://USDC/Circle/EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v/solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp\n\n  \
         limit spend\n    amount 100.00 USDC_solana\n    per fixed day\n"
    )
}

#[test]
fn offsets_are_accepted() {
    for tz in ["UTC", "UTC+00:00", "UTC+14:00", "UTC-12:00", "UTC+05:45", "UTC+09:30"] {
        let r = pays_charter::check(&charter(tz));
        assert!(r.is_ok(), "{tz} should compile: {:?}", r.err());
    }
}

#[test]
fn a_zone_name_names_the_replacement() {
    // The mistake worth diagnosing well: it is what every other system takes.
    let errs = pays_charter::check(&charter("Europe/London")).unwrap_err();
    assert!(errs.iter().any(|e| e.code == "E206"), "{errs:?}");
    let msg = errs.iter().find(|e| e.code == "E206").unwrap().message.clone();
    assert!(msg.contains("UTC+01:00"), "the error should name the replacement: {msg}");
}

#[test]
fn out_of_range_and_odd_minutes_are_rejected() {
    for bad in ["UTC+15:00", "UTC-13:00", "UTC+01:07", "UTC+00:20"] {
        let r = pays_charter::check(&charter(bad));
        assert!(r.is_err(), "{bad} should be rejected");
        assert!(r.unwrap_err().iter().any(|e| e.code == "E206"));
    }
}

#[test]
fn a_window_may_override_the_charter_offset() {
    let src = format!(
        "charter t version 1\nresolver common@41\ntimezone UTC\n\n  \
         asset USDC_solana = mint://USDC/Circle/EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v/solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp\n\n  \
         limit spend\n    amount 100.00 USDC_solana\n    per fixed day in UTC+10:00\n"
    );
    assert!(pays_charter::check(&src).is_ok());
}
