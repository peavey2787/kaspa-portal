//! Immutable advanced transaction-signing policy primitives.
//!
//! The firmware persists these values in an authenticated device-bound record.
//! This module deliberately contains only pure policy/date parsing and
//! evaluation so hardware adapters and UI code cannot drift on enforcement.

pub const MAX_WEEKLY_WINDOWS: usize = 4;
pub const MIN_YEAR: u16 = 2000;
pub const MAX_YEAR: u16 = 2099;
const SECONDS_PER_DAY: u64 = 86_400;
const MINUTES_PER_DAY: u16 = 1_440;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UtcDateTime {
    pub year: u16,
    pub month: u8,
    pub day: u8,
    pub hour: u8,
    pub minute: u8,
    pub second: u8,
}

impl UtcDateTime {
    pub const fn new(year: u16, month: u8, day: u8, hour: u8, minute: u8, second: u8) -> Self {
        Self {
            year,
            month,
            day,
            hour,
            minute,
            second,
        }
    }

    pub fn validate(self) -> Result<(), PolicyError> {
        if self.year < MIN_YEAR || self.year > MAX_YEAR {
            return Err(PolicyError::DateOutOfRange);
        }
        if self.month == 0 || self.month > 12 {
            return Err(PolicyError::InvalidDate);
        }
        let max_day = days_in_month(self.year, self.month);
        if self.day == 0
            || self.day > max_day
            || self.hour > 23
            || self.minute > 59
            || self.second > 59
        {
            return Err(PolicyError::InvalidDate);
        }
        Ok(())
    }

    pub fn to_unix_seconds(self) -> Result<u64, PolicyError> {
        self.validate()?;
        let days = days_before_year(self.year)
            + days_before_month(self.year, self.month)
            + u64::from(self.day - 1);
        Ok(days * SECONDS_PER_DAY
            + u64::from(self.hour) * 3_600
            + u64::from(self.minute) * 60
            + u64::from(self.second))
    }

    pub fn from_unix_seconds(unix: u64) -> Result<Self, PolicyError> {
        let max = UtcDateTime::new(MAX_YEAR, 12, 31, 23, 59, 59).to_unix_seconds()?;
        let min = UtcDateTime::new(MIN_YEAR, 1, 1, 0, 0, 0).to_unix_seconds()?;
        if unix < min || unix > max {
            return Err(PolicyError::DateOutOfRange);
        }
        let mut days = unix / SECONDS_PER_DAY;
        let seconds = unix % SECONDS_PER_DAY;
        let mut year = 1970u16;
        loop {
            let year_days = if is_leap_year(year) { 366 } else { 365 };
            if days < year_days {
                break;
            }
            days -= year_days;
            year += 1;
        }
        let mut month = 1u8;
        loop {
            let month_days = u64::from(days_in_month(year, month));
            if days < month_days {
                break;
            }
            days -= month_days;
            month += 1;
        }
        Ok(Self {
            year,
            month,
            day: days as u8 + 1,
            hour: (seconds / 3_600) as u8,
            minute: ((seconds % 3_600) / 60) as u8,
            second: (seconds % 60) as u8,
        })
    }

    /// Monday=0 through Sunday=6.
    pub fn weekday_monday0(self) -> Result<u8, PolicyError> {
        let days = self.to_unix_seconds()? / SECONDS_PER_DAY;
        // 1970-01-01 was Thursday; Monday-indexed Thursday is 3.
        Ok(((days + 3) % 7) as u8)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SigningWindow {
    pub weekday: u8,
    pub start_minute: u16,
    pub end_minute: u16,
}

impl SigningWindow {
    pub const EMPTY: Self = Self {
        weekday: 0,
        start_minute: 0,
        end_minute: 0,
    };

    pub fn validate(self) -> Result<(), PolicyError> {
        if self.weekday > 6
            || self.start_minute >= self.end_minute
            || self.end_minute > MINUTES_PER_DAY
        {
            return Err(PolicyError::InvalidWindow);
        }
        Ok(())
    }

    pub const fn contains(self, weekday: u8, minute: u16) -> bool {
        self.weekday == weekday && minute >= self.start_minute && minute < self.end_minute
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SigningPolicy {
    pub not_before_unix: u64,
    pub weekly_enabled: bool,
    pub weekly_count: u8,
    pub windows: [SigningWindow; MAX_WEEKLY_WINDOWS],
    /// Authenticated monotonic floor used to detect RTC rollback.
    pub rtc_floor_unix: u64,
}

impl SigningPolicy {
    pub const fn disabled() -> Self {
        Self {
            not_before_unix: 0,
            weekly_enabled: false,
            weekly_count: 0,
            windows: [SigningWindow::EMPTY; MAX_WEEKLY_WINDOWS],
            rtc_floor_unix: 0,
        }
    }

    pub const fn has_not_before(self) -> bool {
        self.not_before_unix != 0
    }
    pub const fn has_time_policy(self) -> bool {
        self.not_before_unix != 0 || self.weekly_enabled
    }

    /// Whether transaction authorization still needs a live RTC reading.
    /// A standalone no-sign-before lock is permanently matured once the
    /// authenticated monotonic floor proves the target was reached. Weekly
    /// windows always need current wall-clock time.
    pub const fn requires_clock(self) -> bool {
        self.weekly_enabled
            || (self.not_before_unix != 0 && self.rtc_floor_unix < self.not_before_unix)
    }

    pub fn validate(self) -> Result<(), PolicyError> {
        validate_window_shape(self)?;
        validate_windows(self)?;
        validate_policy_times(self)
    }

    pub fn evaluate(self, now_unix: u64) -> SigningDecision {
        if self.validate().is_err() {
            return SigningDecision::PolicyInvalid;
        }
        if self.rtc_floor_unix != 0 && now_unix < self.rtc_floor_unix {
            return SigningDecision::ClockRollback;
        }
        if self.not_before_unix != 0 && now_unix < self.not_before_unix {
            return SigningDecision::BeforeNotBefore;
        }
        if self.weekly_enabled {
            let Ok(now) = UtcDateTime::from_unix_seconds(now_unix) else {
                return SigningDecision::ClockInvalid;
            };
            let Ok(weekday) = now.weekday_monday0() else {
                return SigningDecision::ClockInvalid;
            };
            let minute = u16::from(now.hour) * 60 + u16::from(now.minute);
            let allowed = self.windows[..self.weekly_count as usize]
                .iter()
                .any(|window| window.contains(weekday, minute));
            if !allowed {
                return SigningDecision::OutsideWeeklyWindow;
            }
        }
        SigningDecision::Allowed
    }
}

fn validate_window_shape(policy: SigningPolicy) -> Result<(), PolicyError> {
    let count = usize::from(policy.weekly_count);
    if count > MAX_WEEKLY_WINDOWS {
        return Err(PolicyError::TooManyWindows);
    }
    if policy.weekly_enabled != (count != 0) {
        return Err(PolicyError::InvalidWindow);
    }
    if policy.windows[count..]
        .iter()
        .any(|window| *window != SigningWindow::EMPTY)
    {
        return Err(PolicyError::InvalidWindow);
    }
    Ok(())
}

fn validate_windows(policy: SigningPolicy) -> Result<(), PolicyError> {
    let count = usize::from(policy.weekly_count);
    for index in 0..count {
        policy.windows[index].validate()?;
        if policy.windows[index + 1..count]
            .iter()
            .any(|other| windows_overlap(policy.windows[index], *other))
        {
            return Err(PolicyError::OverlappingWindow);
        }
    }
    Ok(())
}

fn validate_policy_times(policy: SigningPolicy) -> Result<(), PolicyError> {
    if policy.not_before_unix != 0 {
        UtcDateTime::from_unix_seconds(policy.not_before_unix)?;
    }
    if policy.rtc_floor_unix != 0 {
        UtcDateTime::from_unix_seconds(policy.rtc_floor_unix)?;
    }
    Ok(())
}

impl Default for SigningPolicy {
    fn default() -> Self {
        Self::disabled()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SigningDecision {
    Allowed,
    ClockInvalid,
    ClockRollback,
    BeforeNotBefore,
    OutsideWeeklyWindow,
    PolicyInvalid,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PolicyError {
    InvalidDate,
    DateOutOfRange,
    InvalidWindow,
    TooManyWindows,
    OverlappingWindow,
    InvalidFormat,
    NotFuture,
}

pub fn parse_utc_yyyymmddhhmm(input: &[u8]) -> Result<UtcDateTime, PolicyError> {
    if input.len() != 12 || input.iter().any(|byte| !byte.is_ascii_digit()) {
        return Err(PolicyError::InvalidFormat);
    }
    let year = decimal4(&input[0..4])?;
    let month = decimal2(&input[4..6])? as u8;
    let day = decimal2(&input[6..8])? as u8;
    let hour = decimal2(&input[8..10])? as u8;
    let minute = decimal2(&input[10..12])? as u8;
    let value = UtcDateTime::new(year, month, day, hour, minute, 0);
    value.validate()?;
    Ok(value)
}

/// Parses `MON 08:10-08:25;MON 21:33-21:43` (up to four windows).
/// Windows are sorted into canonical weekday/start order and overlaps fail.
pub fn parse_weekly_windows(
    input: &[u8],
) -> Result<([SigningWindow; MAX_WEEKLY_WINDOWS], u8), PolicyError> {
    let (mut windows, count) = parse_window_list(input)?;
    sort_windows(&mut windows, count);
    reject_adjacent_overlaps(&windows, count)?;
    Ok((windows, count as u8))
}

fn parse_window_list(
    input: &[u8],
) -> Result<([SigningWindow; MAX_WEEKLY_WINDOWS], usize), PolicyError> {
    let mut windows = [SigningWindow::EMPTY; MAX_WEEKLY_WINDOWS];
    let mut count = 0usize;
    for raw in input.split(|byte| *byte == b';') {
        let part = trim_ascii(raw);
        if part.is_empty() {
            return Err(PolicyError::InvalidFormat);
        }
        if count >= MAX_WEEKLY_WINDOWS {
            return Err(PolicyError::TooManyWindows);
        }
        windows[count] = parse_window(part)?;
        count += 1;
    }
    if count == 0 {
        Err(PolicyError::InvalidFormat)
    } else {
        Ok((windows, count))
    }
}

fn sort_windows(windows: &mut [SigningWindow; MAX_WEEKLY_WINDOWS], count: usize) {
    for index in 1..count {
        let current = windows[index];
        let mut cursor = index;
        while cursor > 0 && window_key(current) < window_key(windows[cursor - 1]) {
            windows[cursor] = windows[cursor - 1];
            cursor -= 1;
        }
        windows[cursor] = current;
    }
}

fn reject_adjacent_overlaps(
    windows: &[SigningWindow; MAX_WEEKLY_WINDOWS],
    count: usize,
) -> Result<(), PolicyError> {
    if windows[..count]
        .windows(2)
        .any(|pair| windows_overlap(pair[0], pair[1]))
    {
        Err(PolicyError::OverlappingWindow)
    } else {
        Ok(())
    }
}

fn parse_window(input: &[u8]) -> Result<SigningWindow, PolicyError> {
    if input.len() < 14 || !input[3].is_ascii_whitespace() {
        return Err(PolicyError::InvalidFormat);
    }
    let weekday = parse_weekday(&input[..3])?;
    let (start_minute, end_minute) = parse_time_range(trim_ascii(&input[3..]))?;
    let value = SigningWindow {
        weekday,
        start_minute,
        end_minute,
    };
    value.validate()?;
    Ok(value)
}

fn parse_time_range(input: &[u8]) -> Result<(u16, u16), PolicyError> {
    if input.len() != 11 || input[2] != b':' || input[5] != b'-' || input[8] != b':' {
        return Err(PolicyError::InvalidFormat);
    }
    let start = parse_hhmm(&input[0..2], &input[3..5])?;
    let end = parse_hhmm(&input[6..8], &input[9..11])?;
    Ok((start, end))
}

fn parse_hhmm(hour: &[u8], minute: &[u8]) -> Result<u16, PolicyError> {
    let hour = decimal2(hour)?;
    let minute = decimal2(minute)?;
    if hour > 23 || minute > 59 {
        return Err(PolicyError::InvalidWindow);
    }
    Ok(hour * 60 + minute)
}

fn parse_weekday(input: &[u8]) -> Result<u8, PolicyError> {
    if eq_ascii_case(input, b"MON") {
        Ok(0)
    } else if eq_ascii_case(input, b"TUE") {
        Ok(1)
    } else if eq_ascii_case(input, b"WED") {
        Ok(2)
    } else if eq_ascii_case(input, b"THU") {
        Ok(3)
    } else if eq_ascii_case(input, b"FRI") {
        Ok(4)
    } else if eq_ascii_case(input, b"SAT") {
        Ok(5)
    } else if eq_ascii_case(input, b"SUN") {
        Ok(6)
    } else {
        Err(PolicyError::InvalidFormat)
    }
}

fn windows_overlap(left: SigningWindow, right: SigningWindow) -> bool {
    left.weekday == right.weekday
        && left.start_minute < right.end_minute
        && right.start_minute < left.end_minute
}

const fn window_key(value: SigningWindow) -> u32 {
    value.weekday as u32 * 2_000 + value.start_minute as u32
}

fn decimal2(input: &[u8]) -> Result<u16, PolicyError> {
    if input.len() != 2 || input.iter().any(|byte| !byte.is_ascii_digit()) {
        return Err(PolicyError::InvalidFormat);
    }
    Ok(u16::from(input[0] - b'0') * 10 + u16::from(input[1] - b'0'))
}

fn decimal4(input: &[u8]) -> Result<u16, PolicyError> {
    if input.len() != 4 || input.iter().any(|byte| !byte.is_ascii_digit()) {
        return Err(PolicyError::InvalidFormat);
    }
    Ok(u16::from(input[0] - b'0') * 1000
        + u16::from(input[1] - b'0') * 100
        + u16::from(input[2] - b'0') * 10
        + u16::from(input[3] - b'0'))
}

fn trim_ascii(mut input: &[u8]) -> &[u8] {
    while input.first().is_some_and(|byte| byte.is_ascii_whitespace()) {
        input = &input[1..];
    }
    while input.last().is_some_and(|byte| byte.is_ascii_whitespace()) {
        input = &input[..input.len() - 1];
    }
    input
}

fn eq_ascii_case(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .all(|(a, b)| a.eq_ignore_ascii_case(b))
}

const fn is_leap_year(year: u16) -> bool {
    year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400))
}

const fn days_in_month(year: u16, month: u8) -> u8 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => 0,
    }
}

fn days_before_year(year: u16) -> u64 {
    let y = u64::from(year - 1);
    let before = y * 365 + y / 4 - y / 100 + y / 400;
    let base_y = 1969u64;
    let base = base_y * 365 + base_y / 4 - base_y / 100 + base_y / 400;
    before - base
}

fn days_before_month(year: u16, month: u8) -> u64 {
    let mut total = 0u64;
    let mut current = 1u8;
    while current < month {
        total += days_in_month(year, current) as u64;
        current += 1;
    }
    total
}
