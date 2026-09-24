pub mod device;
pub mod identity;
#[cfg(all(target_os = "linux", not(target_os = "android")))]
pub mod linux;
pub mod tls;
pub mod tunnel;
#[cfg(target_os = "windows")]
pub mod windows;

pub const VERSION: &str = include_str!("../../../internal/buildinfo/VERSION");

#[cfg(test)]
mod tests {
    #[test]
    fn cargo_and_application_versions_match() {
        assert_eq!(super::VERSION.trim(), env!("CARGO_PKG_VERSION"));
    }
}
