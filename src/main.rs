fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    if let Err(e) = sandbox::run() {
        eprintln!("Error: {:#}", e);
        if std::env::var("RUST_BACKTRACE").is_ok() {
            eprintln!("\nBacktrace:\n{}", e.backtrace());
        }
        std::process::exit(1);
    }
}
