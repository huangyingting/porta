use std::process::Command;

#[test]
fn help_and_version_exit_successfully() {
    for argument in ["--help", "--version"] {
        let output = Command::new(env!("CARGO_BIN_EXE_porta-server"))
            .arg(argument)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{argument} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
