// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::io::Write;

use anyhow::Result;

use crate::cli::EventsCommand;
use crate::daemon;
use crate::daemon::protocol::{DaemonClient, DaemonEvent};

pub fn events(command: &EventsCommand) -> Result<()> {
    let socket_path = daemon::socket_path()?;
    let client = DaemonClient::new_unix(&socket_path);
    let events = client.daemon_events()?;
    let stdout = std::io::stdout();
    let mut stdout = stdout.lock();

    for event in events {
        let event = event?;
        if command.json {
            serde_json::to_writer(&mut stdout, &event)?;
        } else {
            write_event(&mut stdout, &event)?;
        }
        writeln!(stdout)?;
        stdout.flush()?;
    }
    Ok(())
}

fn write_event(output: &mut impl Write, event: &DaemonEvent) -> Result<()> {
    match event {
        DaemonEvent::Resync => write!(output, "resync")?,
        DaemonEvent::PodStatusChanged { repository, pod } => {
            write!(output, "pod status changed: {repository} {pod}")?;
        }
        DaemonEvent::PodReviewChanged { repository, pod } => {
            write!(output, "pod review changed: {repository} {pod}")?;
        }
    }
    Ok(())
}
