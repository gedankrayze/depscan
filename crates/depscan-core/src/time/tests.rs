use super::*;

#[test]
fn timestamps_retain_legacy_report_and_cache_wire_precision() {
    for (fraction, canonical) in [
        ("", ""),
        (".1", ".100"),
        (".12", ".120"),
        (".123", ".123"),
        (".1234", ".123400"),
        (".12345", ".123450"),
        (".123456", ".123456"),
        (".1234567", ".123456700"),
        (".12345678", ".123456780"),
        (".123456789", ".123456789"),
        (".000000000", ""),
    ] {
        let raw = format!("2026-08-20T12:00:00{fraction}Z");
        let timestamp: Timestamp = serde_json::from_value(serde_json::json!(raw)).unwrap();
        let z = format!("2026-08-20T12:00:00{canonical}Z");
        assert_eq!(timestamp.to_rfc3339_z(), z);
        assert_eq!(serde_json::to_value(timestamp).unwrap(), z);
        assert_eq!(
            timestamp.to_rfc3339(),
            format!("2026-08-20T12:00:00{canonical}+00:00")
        );
        assert_eq!(Timestamp::parse(&z).unwrap(), timestamp);
    }
}

#[test]
fn offsets_normalize_to_the_same_utc_revision_and_calendar_date() {
    let timestamp = Timestamp::parse("2026-08-21T01:00:00.1+02:00").unwrap();
    assert_eq!(timestamp.to_rfc3339_z(), "2026-08-20T23:00:00.100Z");
    assert_eq!(timestamp.date(), Date::new(2026, 8, 20).unwrap());
    assert_eq!(
        timestamp,
        Timestamp::parse("2026-08-20T23:00:00.100000000Z").unwrap()
    );
    assert_eq!(
        Timestamp::parse("2026-08-20T12:00:00-00:00")
            .unwrap()
            .to_string(),
        "2026-08-20T12:00:00Z"
    );
}

#[test]
fn unix_timestamps_keep_pre_epoch_nanosecond_arithmetic() {
    let before = Timestamp::from_timestamp(-1, 999_999_999).unwrap();
    let epoch = Timestamp::from_timestamp(0, 0).unwrap();
    assert_eq!(before.to_rfc3339_z(), "1969-12-31T23:59:59.999999999Z");
    assert_eq!(before.as_second(), -1);
    assert_eq!(epoch - before, Duration::new(0, 1));
    assert_eq!(before + Duration::new(0, 1), epoch);
    assert!(Timestamp::from_timestamp(0, 1_000_000_000).is_none());
    assert!(Timestamp::from_timestamp(i64::MAX, 0).is_none());
    assert!(Timestamp::from_timestamp(i64::MIN, 0).is_none());
}

#[test]
fn unsupported_or_ambiguous_timestamps_fail_instead_of_normalizing() {
    for raw in [
        "2016-12-31T23:59:60Z",
        "2016-12-31T23:59:60.5+00:00",
        "2026-08-20T12:00Z",
        "2026-08-20T12:00:00",
        "2026-08-20T12:00:00Z[UTC]",
        "2026-08-20T12:00:00+00",
        "2026-02-30T12:00:00Z",
        "2026-08-20T12:00:00.Z",
        "2026-08-20T12:00:00.1234567891Z",
        "2026-08-20T12:00:00+25:00",
        "+10000-01-01T00:00:00Z",
        "",
        "2026-08-20T💥",
    ] {
        assert!(Timestamp::parse(raw).is_err(), "accepted {raw}");
        assert!(serde_json::from_value::<Timestamp>(serde_json::json!(raw)).is_err());
    }
}

#[test]
fn supported_year_boundaries_round_trip_and_expiry_dates_remain_date_only() {
    for timestamp in [
        Timestamp(jiff::Timestamp::MIN),
        Timestamp::parse("0000-01-01T00:00:00Z").unwrap(),
        Timestamp(jiff::Timestamp::MAX),
    ] {
        assert_eq!(
            Timestamp::parse(&timestamp.to_rfc3339_z()).unwrap(),
            timestamp
        );
    }
    let date: Date = serde_json::from_str("\"2030-01-01\"").unwrap();
    assert_eq!(date.yesterday().unwrap().to_string(), "2029-12-31");
    assert_eq!(date.tomorrow().unwrap().to_string(), "2030-01-02");
    assert_eq!(serde_json::to_string(&date).unwrap(), "\"2030-01-01\"");
    assert!(serde_json::from_str::<Date>("\"2030-01-01T00:00:00Z\"").is_err());
}
