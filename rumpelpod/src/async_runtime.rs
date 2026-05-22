// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::future::Future;
use std::sync::LazyLock;
use tokio::runtime::Runtime;

pub static RUNTIME: LazyLock<Runtime> =
    LazyLock::new(|| Runtime::new().expect("Failed to create tokio runtime"));

pub fn block_on<F: Future>(future: F) -> F::Output {
    RUNTIME.block_on(future)
}
