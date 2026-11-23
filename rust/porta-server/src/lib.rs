pub mod app;
pub mod config;
pub mod data;
pub mod dns;
pub mod http_handler;
pub mod integration;
pub mod ops;
pub mod proxy;
pub mod server;
pub mod state;
pub mod transport;
#[cfg(target_os = "linux")]
pub mod upstream;
pub mod web;
pub use porta_wire as wire;

pub const VERSION: &str = include_str!("../../../internal/buildinfo/VERSION");

#[cfg(test)]
mod tests {
    #[test]
    fn cargo_and_application_versions_match() {
        assert_eq!(super::VERSION.trim(), env!("CARGO_PKG_VERSION"));
    }
}
