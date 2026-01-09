pub static RUNTIME: LazyLock<Runtime> = LazyLock::new(|| { Runtime::new() });

pub fn block_on<F: Future>(future: F) -> F::Output {
    RUNTIME.block_on(future)
}
