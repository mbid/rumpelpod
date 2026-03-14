use std::{env, process::ExitCode};

fn main() -> ExitCode {
    match rumpelpod::run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("Error: {e:?}");
            let has_backtrace = env::var("RUST_BACKTRACE").as_ref().map(|s| s.as_str()) == Ok("1");
            if has_backtrace {
                let bt = e.backtrace();
                eprintln!("Backtrace:\n{bt}");
            }

            ExitCode::FAILURE
        }
    }
}
