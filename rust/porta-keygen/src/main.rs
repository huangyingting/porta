use std::path::PathBuf;
use std::time::Duration;

use clap::Parser;
use porta_keygen::{generate, Options};

#[derive(Debug, Parser)]
#[command(
    name = "porta-keygen",
    bin_name = "porta-keygen",
    about = "Generate a self-signed Porta development certificate",
    disable_version_flag = true
)]
struct Arguments {
    #[arg(
        long,
        default_value = "server.crt",
        help = "Output certificate path (must not exist)"
    )]
    cert: PathBuf,
    #[arg(
        long,
        default_value = "server.key",
        help = "Output private-key path (must not exist)"
    )]
    key: PathBuf,
    #[arg(
        long,
        default_value = "localhost,127.0.0.1",
        help = "Comma-separated certificate DNS names and IP addresses"
    )]
    hosts: String,
    #[arg(
        long,
        default_value = "720h",
        value_parser = parse_duration,
        help = "Certificate validity"
    )]
    valid_for: Duration,
}

fn parse_duration(value: &str) -> Result<Duration, String> {
    humantime::parse_duration(value).map_err(|error| error.to_string())
}

fn main() {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    if arguments.len() == 1 && matches!(arguments[0].as_str(), "--version" | "-version") {
        println!("{}", env!("CARGO_PKG_VERSION"));
        return;
    }
    let arguments = Arguments::parse();
    let hosts = arguments
        .hosts
        .split(',')
        .map(str::trim)
        .filter(|host| !host.is_empty())
        .map(str::to_owned)
        .collect::<Vec<_>>();
    if let Err(error) = generate(
        &arguments.cert,
        &arguments.key,
        Options {
            hosts,
            valid_for: arguments.valid_for,
        },
    ) {
        eprintln!("porta-keygen: {error}");
        std::process::exit(1);
    }
    println!(
        "created {} and {}",
        arguments.cert.display(),
        arguments.key.display()
    );
}
