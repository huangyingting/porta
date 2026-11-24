//! Human-readable durations for command-line options and log messages:
//! `250ms`, `30s`, `5m`, `1h30m`, `2d` or `1h 30m`.

use std::time::Duration;

use thiserror::Error;

#[derive(Debug, Error, Eq, PartialEq)]
pub enum DurationError {
    #[error("empty duration")]
    Empty,
    #[error("invalid duration {0:?}: use a number and a unit such as 500ms, 30s, 5m, 2h or 1d")]
    Invalid(String),
    #[error("duration {0:?} is too long")]
    Overflow(String),
}

/// Parses one or more `<number><unit>` components, optionally separated by
/// spaces. Units: `ms`, `s`, `m`, `h`, `d` and their spelled-out forms.
pub fn parse_duration(value: &str) -> Result<Duration, DurationError> {
    let text = value.trim();
    if text.is_empty() {
        return Err(DurationError::Empty);
    }
    let invalid = || DurationError::Invalid(value.to_owned());
    let overflow = || DurationError::Overflow(value.to_owned());
    let mut total = Duration::ZERO;
    let mut rest = text;
    while !rest.is_empty() {
        let digits = rest
            .find(|character: char| !character.is_ascii_digit())
            .unwrap_or(rest.len());
        if digits == 0 {
            return Err(invalid());
        }
        let number: u64 = rest[..digits].parse().map_err(|_| overflow())?;
        rest = rest[digits..].trim_start();
        let unit_length = rest
            .find(|character: char| !character.is_ascii_alphabetic())
            .unwrap_or(rest.len());
        let unit = &rest[..unit_length];
        rest = rest[unit_length..].trim_start();
        let component = match unit {
            "ms" | "msec" | "msecs" | "millis" | "millisecond" | "milliseconds" => {
                Duration::from_millis(number)
            }
            "s" | "sec" | "secs" | "second" | "seconds" => Duration::from_secs(number),
            "m" | "min" | "mins" | "minute" | "minutes" => {
                Duration::from_secs(number.checked_mul(60).ok_or_else(overflow)?)
            }
            "h" | "hr" | "hrs" | "hour" | "hours" => {
                Duration::from_secs(number.checked_mul(3_600).ok_or_else(overflow)?)
            }
            "d" | "day" | "days" => {
                Duration::from_secs(number.checked_mul(86_400).ok_or_else(overflow)?)
            }
            _ => return Err(invalid()),
        };
        total = total.checked_add(component).ok_or_else(overflow)?;
    }
    Ok(total)
}

/// Formats a duration as its non-zero components, `1h 30m 5s 250ms`,
/// dropping anything below a millisecond; zero is `0s`.
pub fn format_duration(duration: Duration) -> String {
    let mut seconds = duration.as_secs();
    let milliseconds = duration.subsec_millis();
    let mut parts = Vec::new();
    for (unit, size) in [("d", 86_400), ("h", 3_600), ("m", 60)] {
        if seconds >= size {
            parts.push(format!("{}{unit}", seconds / size));
            seconds %= size;
        }
    }
    if seconds > 0 {
        parts.push(format!("{seconds}s"));
    }
    if milliseconds > 0 {
        parts.push(format!("{milliseconds}ms"));
    }
    if parts.is_empty() {
        return "0s".to_owned();
    }
    parts.join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_units_and_combinations() {
        for (text, expected) in [
            ("250ms", Duration::from_millis(250)),
            ("30s", Duration::from_secs(30)),
            ("5m", Duration::from_secs(300)),
            ("2h", Duration::from_secs(7_200)),
            ("1d", Duration::from_secs(86_400)),
            ("1h30m", Duration::from_secs(5_400)),
            (" 1h 30m 5s ", Duration::from_secs(5_405)),
            ("10 seconds", Duration::from_secs(10)),
            ("3days", Duration::from_secs(259_200)),
            ("0s", Duration::ZERO),
        ] {
            assert_eq!(parse_duration(text), Ok(expected), "{text}");
        }
        assert_eq!(parse_duration(" "), Err(DurationError::Empty));
        for invalid in ["10", "s", "5x", "-5s", "1.5s", "5m-", "1h,30m"] {
            assert!(
                matches!(parse_duration(invalid), Err(DurationError::Invalid(_))),
                "{invalid}"
            );
        }
        assert!(matches!(
            parse_duration("99999999999999999999s"),
            Err(DurationError::Overflow(_))
        ));
        assert!(matches!(
            parse_duration(&format!("{}d", u64::MAX / 10)),
            Err(DurationError::Overflow(_))
        ));
    }

    #[test]
    fn formats_round_trip() {
        for (duration, text) in [
            (Duration::ZERO, "0s"),
            (Duration::from_micros(10), "0s"),
            (Duration::from_millis(250), "250ms"),
            (Duration::from_millis(1_500), "1s 500ms"),
            (Duration::from_secs(5_405), "1h 30m 5s"),
            (Duration::from_secs(90_061), "1d 1h 1m 1s"),
        ] {
            assert_eq!(format_duration(duration), text);
        }
        let duration = Duration::from_millis(93_784_005);
        assert_eq!(parse_duration(&format_duration(duration)), Ok(duration));
    }
}
