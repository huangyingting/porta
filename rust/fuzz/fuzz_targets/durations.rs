//! Durations from command lines and configuration files.
#![no_main]

use libfuzzer_sys::fuzz_target;
use porta_wire::duration::{format_duration, parse_duration};

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(duration) = parse_duration(text) {
        let truncated = std::time::Duration::from_millis(duration.as_millis() as u64);
        if truncated.as_millis() == duration.as_millis() {
            assert_eq!(parse_duration(&format_duration(truncated)), Ok(truncated));
        }
    }
});
