//! Window boundaries, as arithmetic.
//!
//! §2.9 removed IANA zone names and daylight saving, so this file needs no database, no tzdata
//! version, and no ambiguous or nonexistent local times. A `day` boundary is where
//! `utc_seconds + offset_seconds` crosses a multiple of 86400 (§8.1.7); `week`, `month` and
//! `year` are the calendar boundaries of the date so computed.
//!
//! The civil-date conversions are Howard Hinnant's `days_from_civil` / `civil_from_days`:
//! integer only, proleptic Gregorian, valid across the whole range this language can express.

/// Days since 1970-01-01 for a proleptic Gregorian date.
pub fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

/// The inverse: `(year, month, day)` from days since the epoch.
pub fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// A calendar unit for a fixed window.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CalUnit {
    Day,
    Week,
    Month,
    Year,
}

impl CalUnit {
    pub fn parse(s: &str) -> Option<CalUnit> {
        Some(match s {
            "day" => CalUnit::Day,
            "week" => CalUnit::Week,
            "month" => CalUnit::Month,
            "year" => CalUnit::Year,
            _ => return None,
        })
    }
}

/// The instance identifier of the fixed window containing `at`, for an offset in seconds.
///
/// Two payments share a window iff this returns the same value, which is the whole of §8.1.6:
/// a payment belongs to the window in which it was **reserved**, not the one in which it
/// settled, because this is computed once at decision time.
pub fn fixed_window(at: i64, offset_seconds: i32, unit: CalUnit) -> i64 {
    let local = at + offset_seconds as i64;
    // Floor division: a negative local time is before the epoch, not after it.
    let day = local.div_euclid(86400);
    match unit {
        CalUnit::Day => day,
        // 1970-01-01 was a Thursday; shift so weeks start on Monday.
        CalUnit::Week => (day + 3).div_euclid(7),
        CalUnit::Month => {
            let (y, m, _) = civil_from_days(day);
            y * 12 + (m - 1)
        }
        CalUnit::Year => civil_from_days(day).0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn civil_round_trips() {
        for &(y, m, d) in &[
            (1970, 1, 1),
            (2026, 9, 3),
            (2000, 2, 29),
            (1969, 12, 31),
            (2400, 2, 29),
        ] {
            let days = days_from_civil(y, m, d);
            assert_eq!(civil_from_days(days), (y, m, d), "{y}-{m}-{d}");
        }
    }

    #[test]
    fn the_epoch_is_day_zero() {
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(fixed_window(0, 0, CalUnit::Day), 0);
    }

    #[test]
    fn an_offset_moves_the_boundary_not_the_length() {
        // 2026-09-01T00:00:00Z
        let midnight_utc = days_from_civil(2026, 9, 1) * 86400;
        // At UTC-05:00 the local day rolls five hours later in UTC terms, so an instant one
        // hour before UTC midnight is still the previous local day.
        let before = midnight_utc - 3600;
        assert_ne!(
            fixed_window(before, 0, CalUnit::Day),
            fixed_window(midnight_utc, 0, CalUnit::Day)
        );
        assert_eq!(
            fixed_window(before, -5 * 3600, CalUnit::Day),
            fixed_window(midnight_utc, -5 * 3600, CalUnit::Day),
            "both fall in the same local day at UTC-05:00"
        );
    }

    #[test]
    fn every_day_is_the_same_length() {
        // The DST cases §2.9 deleted: no 23-hour day, no 25-hour day, no ambiguity.
        let start = days_from_civil(2026, 3, 1) * 86400;
        let mut seen = alloc::vec::Vec::new();
        for d in 0..40 {
            seen.push(fixed_window(start + d * 86400, -5 * 3600, CalUnit::Day));
        }
        for w in seen.windows(2) {
            assert_eq!(w[1] - w[0], 1, "consecutive days are consecutive instances");
        }
    }

    #[test]
    fn quarter_hour_offsets_work() {
        let t = days_from_civil(2026, 9, 1) * 86400;
        // UTC+05:45 is a real offset, and the boundary lands 5h45m earlier in UTC terms.
        let a = fixed_window(t - (5 * 3600 + 45 * 60) - 1, 5 * 3600 + 45 * 60, CalUnit::Day);
        let b = fixed_window(t - (5 * 3600 + 45 * 60), 5 * 3600 + 45 * 60, CalUnit::Day);
        assert_eq!(b - a, 1);
    }

    #[test]
    fn months_and_years_are_calendar_boundaries() {
        let jan = days_from_civil(2026, 1, 31) * 86400;
        let feb = days_from_civil(2026, 2, 1) * 86400;
        assert_ne!(fixed_window(jan, 0, CalUnit::Month), fixed_window(feb, 0, CalUnit::Month));
        assert_eq!(
            fixed_window(feb, 0, CalUnit::Month),
            fixed_window(days_from_civil(2026, 2, 28) * 86400, 0, CalUnit::Month)
        );
        assert_ne!(
            fixed_window(days_from_civil(2026, 12, 31) * 86400, 0, CalUnit::Year),
            fixed_window(days_from_civil(2027, 1, 1) * 86400, 0, CalUnit::Year)
        );
    }

    #[test]
    fn weeks_start_on_monday() {
        // 2026-09-03 is a Thursday; the Monday before is 2026-08-31.
        let thu = days_from_civil(2026, 9, 3) * 86400;
        let mon = days_from_civil(2026, 8, 31) * 86400;
        let sun = days_from_civil(2026, 8, 30) * 86400;
        assert_eq!(fixed_window(thu, 0, CalUnit::Week), fixed_window(mon, 0, CalUnit::Week));
        assert_ne!(fixed_window(sun, 0, CalUnit::Week), fixed_window(mon, 0, CalUnit::Week));
    }
}
