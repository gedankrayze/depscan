//! UTC instants shared by reports, caches, and advisory revision identities.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::{fmt, ops, str::FromStr};

pub use jiff::{SignedDuration as Duration, civil::Date};

/// A UTC instant with stable RFC 3339 wire formatting (0/3/6/9 fractional digits).
///
/// Jiff supports years -9999 through 9999. Leap-second inputs are rejected rather
/// than silently normalized to a different advisory revision or cache timestamp.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Timestamp(jiff::Timestamp);

#[derive(Debug, Clone, Copy, thiserror::Error)]
#[error("invalid RFC 3339 timestamp or unsupported leap second/year")]
pub struct TimestampError;

impl Timestamp {
    pub fn now() -> Self {
        Self(jiff::Timestamp::now())
    }

    pub fn from_timestamp(seconds: i64, nanoseconds: u32) -> Option<Self> {
        if nanoseconds >= 1_000_000_000 {
            return None;
        }
        jiff::Timestamp::new(seconds, nanoseconds as i32)
            .ok()
            .map(Self)
    }

    pub fn parse(value: &str) -> Result<Self, TimestampError> {
        // Require seconds and an explicit offset. Temporal annotations, optional
        // seconds, basic ISO forms, and normalized leap seconds are not RFC 3339.
        let (_, time) = value.split_once(['T', 't', ' ']).ok_or(TimestampError)?;
        let bytes = time.as_bytes();
        if bytes.len() < 9
            || bytes.get(2) != Some(&b':')
            || bytes.get(5) != Some(&b':')
            || bytes.get(6..8) == Some(b"60")
        {
            return Err(TimestampError);
        }
        let mut suffix = &bytes[8..];
        if suffix.first() == Some(&b'.') {
            let digits = suffix[1..]
                .iter()
                .take_while(|byte| byte.is_ascii_digit())
                .count();
            if digits == 0 || digits > 9 {
                return Err(TimestampError);
            }
            suffix = &suffix[digits + 1..];
        }
        if suffix != b"Z"
            && suffix != b"z"
            && !(suffix.len() == 6
                && matches!(suffix[0], b'+' | b'-')
                && suffix[3] == b':'
                && suffix[1..3]
                    .iter()
                    .chain(&suffix[4..])
                    .all(u8::is_ascii_digit))
        {
            return Err(TimestampError);
        }
        if suffix.len() == 6 && (&suffix[1..3] > b"23" || &suffix[4..] > b"59") {
            return Err(TimestampError);
        }
        value.parse().map(Self).map_err(|_| TimestampError)
    }

    pub fn as_second(self) -> i64 {
        // Jiff truncates toward zero; Unix seconds use the floor for pre-epoch instants.
        self.0.as_second() - i64::from(self.0.subsec_nanosecond() < 0)
    }

    pub fn date(self) -> Date {
        self.0.to_zoned_datetime(jiff::tz::TimeZone::UTC).date()
    }

    pub fn to_rfc3339(self) -> String {
        self.format("+00:00")
    }

    pub fn to_rfc3339_z(self) -> String {
        self.format("Z")
    }

    fn format(self, offset: &str) -> String {
        let mut text = self.0.to_string();
        debug_assert!(text.ends_with('Z'));
        text.pop();
        if let Some(dot) = text.find('.') {
            let digits = text.len() - dot - 1;
            let width = digits.div_ceil(3) * 3;
            text.extend(std::iter::repeat_n('0', width - digits));
        }
        text.push_str(offset);
        text
    }
}

impl FromStr for Timestamp {
    type Err = TimestampError;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

impl fmt::Display for Timestamp {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.to_rfc3339_z())
    }
}

impl Serialize for Timestamp {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_rfc3339_z())
    }
}

impl<'de> Deserialize<'de> for Timestamp {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Self::parse(&raw).map_err(serde::de::Error::custom)
    }
}

impl ops::Add<Duration> for Timestamp {
    type Output = Self;
    fn add(self, duration: Duration) -> Self {
        Self(self.0 + duration)
    }
}

impl ops::Sub<Duration> for Timestamp {
    type Output = Self;
    fn sub(self, duration: Duration) -> Self {
        Self(self.0 - duration)
    }
}

impl ops::Sub for Timestamp {
    type Output = Duration;
    fn sub(self, other: Self) -> Duration {
        self.0.duration_since(other.0)
    }
}

#[cfg(test)]
mod tests;
