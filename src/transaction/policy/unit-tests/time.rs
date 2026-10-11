//! Signing-policy dates, windows, parsers and decisions at every boundary.

use super::{
    parse_utc_yyyymmddhhmm, parse_weekly_windows, PolicyError, SigningDecision, SigningPolicy,
    SigningWindow, UtcDateTime, MAX_WEEKLY_WINDOWS,
};

const MIN_UNIX: u64 = 946_684_800; // 2000-01-01T00:00:00Z
const MAX_UNIX: u64 = 4_102_444_799; // 2099-12-31T23:59:59Z
/// 2024-02-05T00:00:00Z, a Monday.
const MONDAY: u64 = 1_707_091_200;
const DAY: u64 = 86_400;

fn date(year: u16, month: u8, day: u8, hour: u8, minute: u8, second: u8) -> UtcDateTime {
    UtcDateTime::new(year, month, day, hour, minute, second)
}

fn window(weekday: u8, start_minute: u16, end_minute: u16) -> SigningWindow {
    SigningWindow {
        weekday,
        start_minute,
        end_minute,
    }
}

fn weekly(windows: &[SigningWindow]) -> SigningPolicy {
    let mut policy = SigningPolicy::disabled();
    policy.weekly_enabled = true;
    policy.weekly_count = windows.len() as u8;
    policy.windows[..windows.len()].copy_from_slice(windows);
    policy
}

#[test]
fn dates_convert_to_and_from_unix_seconds_exactly() {
    let vectors = [
        (date(2000, 1, 1, 0, 0, 0), MIN_UNIX, 5),
        (date(2000, 2, 29, 23, 59, 59), 951_868_799, 1),
        (date(2001, 3, 1, 0, 0, 0), 983_404_800, 3),
        (date(2023, 12, 31, 23, 59, 59), 1_704_067_199, 6),
        (date(2024, 2, 29, 13, 47, 29), 1_709_214_449, 3),
        (date(2024, 3, 1, 0, 0, 0), 1_709_251_200, 4),
        (date(2061, 7, 15, 8, 5, 9), 2_888_640_309, 4),
        (date(2099, 12, 31, 23, 59, 59), MAX_UNIX, 3),
    ];
    for (value, unix, weekday) in vectors {
        assert_eq!(value.to_unix_seconds(), Ok(unix), "{value:?}");
        assert_eq!(UtcDateTime::from_unix_seconds(unix), Ok(value));
        assert_eq!(value.weekday_monday0(), Ok(weekday), "{value:?}");
    }
    // The day after a non-leap and a leap year end.
    assert_eq!(
        UtcDateTime::from_unix_seconds(1_704_067_200),
        Ok(date(2024, 1, 1, 0, 0, 0))
    );
    assert_eq!(
        UtcDateTime::from_unix_seconds(951_868_800),
        Ok(date(2000, 3, 1, 0, 0, 0))
    );
    for offset in 0..7u8 {
        let day = date(2024, 2, 5 + offset, 12, 0, 0);
        assert_eq!(day.weekday_monday0(), Ok(offset));
    }
}

#[test]
fn unix_seconds_outside_the_supported_years_are_rejected() {
    assert_eq!(
        UtcDateTime::from_unix_seconds(MIN_UNIX - 1),
        Err(PolicyError::DateOutOfRange)
    );
    assert_eq!(
        UtcDateTime::from_unix_seconds(MAX_UNIX + 1),
        Err(PolicyError::DateOutOfRange)
    );
    assert!(date(1999, 12, 31, 0, 0, 0).weekday_monday0().is_err());
}

#[test]
fn date_validation_checks_every_field_boundary() {
    for valid in [
        date(2000, 1, 1, 0, 0, 0),
        date(2099, 12, 31, 23, 59, 59),
        date(2024, 2, 29, 0, 0, 0),
        date(2000, 2, 29, 0, 0, 0),
        date(2023, 4, 30, 0, 0, 0),
        date(2023, 1, 31, 0, 0, 0),
    ] {
        assert_eq!(valid.validate(), Ok(()), "{valid:?}");
    }
    for out_of_range in [date(1999, 12, 31, 0, 0, 0), date(2100, 1, 1, 0, 0, 0)] {
        assert_eq!(out_of_range.validate(), Err(PolicyError::DateOutOfRange));
    }
    for invalid in [
        date(2024, 0, 1, 0, 0, 0),
        date(2024, 13, 1, 0, 0, 0),
        date(2024, 1, 0, 0, 0, 0),
        date(2023, 2, 29, 0, 0, 0),
        date(2024, 2, 30, 0, 0, 0),
        date(2023, 4, 31, 0, 0, 0),
        date(2023, 1, 32, 0, 0, 0),
        date(2024, 1, 1, 24, 0, 0),
        date(2024, 1, 1, 0, 60, 0),
        date(2024, 1, 1, 0, 0, 60),
    ] {
        assert_eq!(
            invalid.validate(),
            Err(PolicyError::InvalidDate),
            "{invalid:?}"
        );
        assert!(invalid.to_unix_seconds().is_err());
    }
}

#[test]
fn utc_timestamps_parse_only_twelve_valid_digits() {
    assert_eq!(
        parse_utc_yyyymmddhhmm(b"202402291347"),
        Ok(date(2024, 2, 29, 13, 47, 0))
    );
    assert_eq!(
        parse_utc_yyyymmddhhmm(b"209912312359"),
        Ok(date(2099, 12, 31, 23, 59, 0))
    );
    for malformed in [
        &b"20240229134"[..],
        b"2024022913470",
        b"2024-2291347",
        b"20240229134x",
    ] {
        assert_eq!(
            parse_utc_yyyymmddhhmm(malformed),
            Err(PolicyError::InvalidFormat)
        );
    }
    assert_eq!(
        parse_utc_yyyymmddhhmm(b"202302291347"),
        Err(PolicyError::InvalidDate)
    );
    assert_eq!(
        parse_utc_yyyymmddhhmm(b"210001010000"),
        Err(PolicyError::DateOutOfRange)
    );
}

#[test]
fn windows_validate_and_contain_half_open_minute_ranges() {
    assert_eq!(window(6, 0, 1_440).validate(), Ok(()));
    for invalid in [
        window(7, 0, 10),
        window(0, 10, 10),
        window(0, 11, 10),
        window(0, 0, 1_441),
    ] {
        assert_eq!(invalid.validate(), Err(PolicyError::InvalidWindow));
    }
    let morning = window(2, 490, 505);
    assert!(morning.contains(2, 490));
    assert!(morning.contains(2, 504));
    assert!(!morning.contains(2, 489));
    assert!(!morning.contains(2, 505));
    assert!(!morning.contains(3, 495));
}

#[test]
fn weekly_windows_parse_sort_and_reject_overlaps() {
    let (windows, count) =
        parse_weekly_windows(b" tue 01:00-01:30 ;MON 10:00-10:30;mon 09:00-09:30;Sun 23:00-23:59")
            .unwrap();
    assert_eq!(count, 4);
    assert_eq!(
        windows,
        [
            window(0, 540, 570),
            window(0, 600, 630),
            window(1, 60, 90),
            window(6, 1_380, 1_439),
        ]
    );
    // Touching windows do not overlap.
    let (windows, count) = parse_weekly_windows(b"WED 08:10-08:25;WED 08:25-08:30").unwrap();
    assert_eq!(count, 2);
    assert_eq!(windows[..2], [window(2, 490, 505), window(2, 505, 510)]);
    for (name, weekday) in [(b"THU", 3u8), (b"FRI", 4), (b"SAT", 5), (b"wed", 2)] {
        let mut input = name.to_vec();
        input.extend_from_slice(b"   00:00-23:59");
        assert_eq!(parse_weekly_windows(&input).unwrap().0[0].weekday, weekday);
    }

    assert_eq!(
        parse_weekly_windows(b"MON 09:00-09:31;MON 09:30-10:00"),
        Err(PolicyError::OverlappingWindow)
    );
    assert_eq!(
        parse_weekly_windows(
            b"MON 01:00-01:30;MON 02:00-02:30;MON 03:00-03:30;MON 04:00-04:30;MON 05:00-05:30"
        ),
        Err(PolicyError::TooManyWindows)
    );
    for malformed in [
        &b""[..],
        b";",
        b"MON 08:10-08:25;",
        b"MON",
        b"MO",
        b"MON08:10-08:25",
        b"XYZ 08:10-08:25",
        b"MON 08-10-08:25",
        b"MON 08:10:08:25",
        b"MON 08:10-08-25",
        b"MON 8:10-08:25",
        b"MON 08:1x-08:25",
    ] {
        assert_eq!(
            parse_weekly_windows(malformed),
            Err(PolicyError::InvalidFormat),
            "{}",
            String::from_utf8_lossy(malformed)
        );
    }
    for invalid in [
        &b"MON 24:00-24:10"[..],
        b"MON 08:60-09:00",
        b"MON 09:00-08:00",
    ] {
        assert_eq!(
            parse_weekly_windows(invalid),
            Err(PolicyError::InvalidWindow)
        );
    }
    // Out-of-range hours and minutes fail even when the minute span would fit.
    for out_of_range in [&b"MON 08:60-09:30"[..], b"MON 23:00-24:00"] {
        assert_eq!(
            parse_weekly_windows(out_of_range),
            Err(PolicyError::InvalidWindow)
        );
    }
    assert_eq!(
        parse_weekly_windows(b"MON 23:59-23:59"),
        Err(PolicyError::InvalidWindow)
    );
    assert_eq!(
        parse_weekly_windows(b"MON 23:00-23:59").unwrap().0[0],
        window(0, 1_380, 1_439)
    );
}

#[test]
fn policy_flags_report_which_clock_inputs_are_needed() {
    let disabled = SigningPolicy::default();
    assert_eq!(disabled, SigningPolicy::disabled());
    assert!(!disabled.has_not_before());
    assert!(!disabled.has_time_policy());
    assert!(!disabled.requires_clock());

    let mut lock = SigningPolicy::disabled();
    lock.not_before_unix = MONDAY;
    assert!(lock.has_not_before());
    assert!(lock.has_time_policy());
    lock.rtc_floor_unix = MONDAY - 1;
    assert!(lock.requires_clock());
    lock.rtc_floor_unix = MONDAY;
    assert!(!lock.requires_clock());

    let mut weekly = weekly(&[window(0, 0, 60)]);
    weekly.rtc_floor_unix = MONDAY;
    assert!(!weekly.has_not_before());
    assert!(weekly.has_time_policy());
    assert!(weekly.requires_clock());
}

#[test]
fn policy_validation_rejects_malformed_window_sets_and_times() {
    assert_eq!(SigningPolicy::disabled().validate(), Ok(()));
    assert_eq!(
        weekly(&[
            window(1, 600, 630),
            window(0, 540, 570),
            window(0, 600, 660)
        ])
        .validate(),
        Ok(())
    );

    assert_eq!(
        weekly(&[
            window(0, 0, 60),
            window(1, 0, 60),
            window(2, 0, 60),
            window(3, 0, 60)
        ])
        .validate(),
        Ok(())
    );
    let mut too_many = weekly(&[]);
    too_many.weekly_count = MAX_WEEKLY_WINDOWS as u8 + 1;
    assert_eq!(too_many.validate(), Err(PolicyError::TooManyWindows));
    assert_eq!(weekly(&[]).validate(), Err(PolicyError::InvalidWindow));
    let mut count_without_flag = weekly(&[window(0, 0, 60)]);
    count_without_flag.weekly_enabled = false;
    assert_eq!(
        count_without_flag.validate(),
        Err(PolicyError::InvalidWindow)
    );
    let mut stale_trailing = weekly(&[window(0, 0, 60)]);
    stale_trailing.windows[3] = window(1, 0, 60);
    assert_eq!(stale_trailing.validate(), Err(PolicyError::InvalidWindow));
    assert_eq!(
        weekly(&[window(0, 0, 60), window(0, 120, 120)]).validate(),
        Err(PolicyError::InvalidWindow)
    );
    // Overlap is detected between non-adjacent, unsorted windows too.
    assert_eq!(
        weekly(&[window(0, 0, 60), window(1, 0, 60), window(0, 59, 90)]).validate(),
        Err(PolicyError::OverlappingWindow)
    );
    // Touching windows in either order do not overlap.
    assert_eq!(
        weekly(&[window(0, 60, 120), window(0, 0, 60)]).validate(),
        Ok(())
    );
    assert_eq!(
        weekly(&[window(0, 59, 90), window(0, 0, 60)]).validate(),
        Err(PolicyError::OverlappingWindow)
    );

    for (not_before, floor) in [(1, 0), (0, 1), (MAX_UNIX + 1, 0)] {
        let mut policy = SigningPolicy::disabled();
        policy.not_before_unix = not_before;
        policy.rtc_floor_unix = floor;
        assert_eq!(policy.validate(), Err(PolicyError::DateOutOfRange));
    }
    let mut in_range = SigningPolicy::disabled();
    in_range.not_before_unix = MAX_UNIX;
    in_range.rtc_floor_unix = MIN_UNIX;
    assert_eq!(in_range.validate(), Ok(()));
}

#[test]
fn evaluation_enforces_floor_lock_and_weekly_windows_in_order() {
    assert_eq!(
        SigningPolicy::disabled().evaluate(0),
        SigningDecision::Allowed
    );
    assert_eq!(weekly(&[]).evaluate(MONDAY), SigningDecision::PolicyInvalid);

    let mut lock = SigningPolicy::disabled();
    lock.not_before_unix = MONDAY;
    lock.rtc_floor_unix = MONDAY - DAY;
    assert_eq!(
        lock.evaluate(MONDAY - DAY - 1),
        SigningDecision::ClockRollback
    );
    assert_eq!(
        lock.evaluate(MONDAY - DAY),
        SigningDecision::BeforeNotBefore
    );
    assert_eq!(lock.evaluate(MONDAY - 1), SigningDecision::BeforeNotBefore);
    assert_eq!(lock.evaluate(MONDAY), SigningDecision::Allowed);

    // Tuesday 08:10-08:25 and Thursday 21:33-21:43.
    let policy = weekly(&[window(1, 490, 505), window(3, 1_293, 1_303)]);
    let tuesday = MONDAY + DAY;
    let thursday = MONDAY + 3 * DAY;
    assert_eq!(
        policy.evaluate(tuesday + 490 * 60),
        SigningDecision::Allowed
    );
    assert_eq!(
        policy.evaluate(tuesday + 504 * 60 + 59),
        SigningDecision::Allowed
    );
    assert_eq!(
        policy.evaluate(tuesday + 490 * 60 - 1),
        SigningDecision::OutsideWeeklyWindow
    );
    assert_eq!(
        policy.evaluate(tuesday + 505 * 60),
        SigningDecision::OutsideWeeklyWindow
    );
    assert_eq!(
        policy.evaluate(thursday + 1_300 * 60),
        SigningDecision::Allowed
    );
    assert_eq!(
        policy.evaluate(MONDAY + 490 * 60),
        SigningDecision::OutsideWeeklyWindow
    );
    assert_eq!(policy.evaluate(MAX_UNIX + 1), SigningDecision::ClockInvalid);
}
