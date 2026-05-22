// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Raw bidirectional TCP proxy for container-serve access via exec.
//!
//! Bridges stdin/stdout to a TCP connection on loopback, allowing the
//! daemon to reach container-serve by exec-ing this program into the
//! container instead of routing through bridge IPs or SSH forwards.

use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpStream};

pub fn run_tcp_proxy(port: u16) -> ! {
    let addr = format!("127.0.0.1:{port}");
    let stream = TcpStream::connect(&addr).unwrap_or_else(|e| {
        eprintln!("tcp-proxy: failed to connect to {addr}: {e}");
        std::process::exit(1);
    });

    let stream2 = stream.try_clone().unwrap_or_else(|e| {
        eprintln!("tcp-proxy: failed to clone socket: {e}");
        std::process::exit(1);
    });

    // stdin -> tcp.  Half-close the write side on EOF so the server
    // sees a clean end-of-stream (protocols like socat+cat rely on
    // this to drain and close their side of the connection).
    let t1 = std::thread::spawn(move || {
        let mut stdin = io::stdin().lock();
        let mut writer = stream2;
        let _ = io::copy(&mut stdin, &mut writer);
        let _ = writer.shutdown(Shutdown::Write);
    });

    // tcp -> stdout, flushing after each chunk so the host-side
    // reader gets data promptly rather than waiting for the pipe
    // buffer to fill (stdout is fully buffered when piped).
    let mut reader = stream;
    let mut stdout = io::stdout().lock();
    let mut buf = [0u8; 64 * 1024];
    loop {
        match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                if stdout.write_all(&buf[..n]).is_err() {
                    break;
                }
                if stdout.flush().is_err() {
                    break;
                }
            }
            Err(_) => break,
        }
    }

    drop(t1);
    std::process::exit(0);
}
