use std::path::PathBuf;

fn main() {
    let arguments = std::env::args_os().skip(1).collect::<Vec<_>>();
    if arguments.len() != 2 {
        eprintln!("usage: porta-package-windows OUTPUT.zip INPUT_DIRECTORY");
        std::process::exit(2);
    }
    let output = PathBuf::from(&arguments[0]);
    let input = PathBuf::from(&arguments[1]);
    if let Err(error) = porta_windows_package::package_windows(&output, &input) {
        eprintln!("porta-package-windows: {error}");
        std::process::exit(1);
    }
}
