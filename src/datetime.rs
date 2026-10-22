//! Minimal civil-time helpers standing in for the parts of Python's `datetime`
//! and `time` modules the ported scanner uses: unix-epoch conversions,
//! ISO-8601 rendering and calendar-day arithmetic. It ports no single upstream
//! file; every conversion here replaces a `datetime.*` call in zero-breach.
//!
//! Everything is computed in UTC. The Python original rendered timestamps in
//! the machine's local zone; a Rust build with no external time-library
//! dependency cannot do that portably, so dates here may differ from the
//! Python tool by a timezone offset (never by logic).

/// Seconds between 1601-01-01 (the Windows/NTFS epoch) and 1970-01-01.
pub const WINDOWS_EPOCH_OFFSET_SECS: i64 = 11_644_473_600;

/// A civil date, used for calendar arithmetic and the campaign window.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct CivilDate {
    pub year: i64,
    pub month: i64,
    pub day: i64,
}

/// A civil date and time, second resolution — what the reports print.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CivilDateTime {
    pub date: CivilDate,
    pub hour: i64,
    pub min: i64,
    pub sec: i64,
}

/// Days since 1970-01-01 for a proleptic-Gregorian civil date
/// (Howard Hinnant's `days_from_civil` algorithm).
pub fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400; // [0, 399]
    let mp = (m + 9) % 12; // [0, 11]
    let doy = (153 * mp + 2) / 5 + d - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    era * 146_097 + doe - 719_468
}

/// Inverse of [`days_from_civil`].
pub fn civil_from_days(z: i64) -> CivilDate {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    CivilDate {
        year: if m <= 2 { y + 1 } else { y },
        month: m,
        day: d,
    }
}

pub fn civil_from_unix_secs(secs: i64) -> CivilDateTime {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    CivilDateTime {
        date: civil_from_days(days),
        hour: rem / 3600,
        min: (rem % 3600) / 60,
        sec: rem % 60,
    }
}

/// Wall-clock seconds since the Unix epoch, UTC.
pub fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Days since the Unix epoch, UTC — the unit `age_days` works in.
pub fn now_days() -> i64 {
    now_unix().div_euclid(86_400)
}

/// Render unix seconds as `YYYY-MM-DDTHH:MM:SS` (Python's
/// `isoformat(timespec="seconds")`).
pub fn iso_from_unix(secs: i64) -> String {
    let t = civil_from_unix_secs(secs);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}",
        t.date.year, t.date.month, t.date.day, t.hour, t.min, t.sec
    )
}

/// `YYYY-MM-DD` for a unix timestamp.
pub fn date_str_from_unix(secs: i64) -> String {
    let d = civil_from_unix_secs(secs).date;
    format!("{:04}-{:02}-{:02}", d.year, d.month, d.day)
}

/// Parse `YYYY-MM-DD` (Python's `strptime("%Y-%m-%d")`).
pub fn parse_date(s: &str) -> Option<CivilDate> {
    let b = s.as_bytes();
    if b.len() != 10 || b[4] != b'-' || b[7] != b'-' {
        return None;
    }
    if !b.iter().enumerate().all(|(i, c)| {
        if i == 4 || i == 7 {
            *c == b'-'
        } else {
            c.is_ascii_digit()
        }
    }) {
        return None;
    }
    let year: i64 = s[0..4].parse().ok()?;
    let month: i64 = s[5..7].parse().ok()?;
    let day: i64 = s[8..10].parse().ok()?;
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    Some(CivilDate { year, month, day })
}

/// Parse the leading `YYYY-MM-DD` of an ISO timestamp (Python's
/// `datetime.date.fromisoformat(earliest[:10])`).
pub fn parse_iso_date_prefix(s: &str) -> Option<CivilDate> {
    let head: String = s.chars().take(10).collect();
    parse_date(&head)
}

impl CivilDate {
    pub fn to_days(self) -> i64 {
        days_from_civil(self.year, self.month, self.day)
    }
    pub fn iso(self) -> String {
        format!("{:04}-{:02}-{:02}", self.year, self.month, self.day)
    }
}

/// Chromium timestamps: microseconds since 1601-01-01 (the `chrome_time`
/// helper in modules/browser.py). Returns unix seconds.
pub fn chrome_time_to_unix(us: i64) -> i64 {
    us.div_euclid(1_000_000) - WINDOWS_EPOCH_OFFSET_SECS
}

/// Firefox timestamps: microseconds since 1970-01-01 (`unix_us_time`).
pub fn unix_us_to_unix(us: i64) -> i64 {
    us.div_euclid(1_000_000)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn civil_round_trip() {
        for z in [-25567i64, 0, 1, 19_000, 20_663, 100_000] {
            let d = civil_from_days(z);
            assert_eq!(d.to_days(), z);
        }
    }

    #[test]
    fn known_dates() {
        assert_eq!(civil_from_days(0).iso(), "1970-01-01");
        assert_eq!(parse_date("2024-01-01").unwrap().to_days(), 19_723);
        assert_eq!(iso_from_unix(0), "1970-01-01T00:00:00");
        assert_eq!(iso_from_unix(1_740_000_000), "2025-02-19T21:20:00");
    }

    #[test]
    fn chrome_epoch() {
        // 2024-01-01T00:00:00Z in Windows-epoch microseconds.
        let us = (19_723 * 86_400 + WINDOWS_EPOCH_OFFSET_SECS) * 1_000_000;
        assert_eq!(chrome_time_to_unix(us), 19_723 * 86_400);
    }
}
