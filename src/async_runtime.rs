use std::future::Future;
use std::sync::LazyLock;
use tokio::runtime::Runtime;

#[allow(dead_code)]
pub static RUNTIME: LazyLock<Runtime> =
    LazyLock::new(|| Runtime::new().expect("Failed to create tokio runtime"));

#[allow(dead_code)]
pub fn block_on<F: Future>(future: F) -> F::Output {
    RUNTIME.block_on(future)
}
