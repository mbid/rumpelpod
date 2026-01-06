//! Setup and installation of systemd user service for the sandbox daemon.

use anyhow::{anyhow, Context, Result};
use indoc::formatdoc;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

use crate::daemon;

const SERVICE_NAME: &str = "sandbox";

fn systemd_user_dir() -> Result<PathBuf> {
    let config_dir = dirs::config_dir().context("Could not determine config directory")?;
    Ok(config_dir.join("systemd/user"))
}

fn socket_unit_path() -> Result<PathBuf> {
    Ok(systemd_user_dir()?.join(format!("{SERVICE_NAME}.socket")))
}

fn service_unit_path() -> Result<PathBuf> {
    Ok(systemd_user_dir()?.join(format!("{SERVICE_NAME}.service")))
}

fn socket_unit_content() -> Result<String> {
    let socket_path = daemon::socket_path()?;
    Ok(formatdoc! {"
        [Unit]
        Description=Sandbox daemon socket

        [Socket]
        ListenStream={socket_path}
        SocketMode=0600

        [Install]
        WantedBy=sockets.target
    ", socket_path = socket_path.display()})
}

fn service_unit_content() -> Result<String> {
    let exe_path = std::env::current_exe().context("Could not determine executable path")?;
    let path = exe_path.display();
    let exe_path = exe_path
        .canonicalize()
        .with_context(|| format!("Could not resolve executable path: {path}"))?;
    let exe_path = exe_path.display();
    let service = SERVICE_NAME;

    Ok(formatdoc! {"
        [Unit]
        Description=Sandbox daemon for managing sandboxed LLM agents
        Requires={service}.socket

        [Service]
        Type=simple
        ExecStart={exe_path} daemon
        Restart=on-failure
        RestartSec=5

        [Install]
        WantedBy=default.target
    "})
}

fn systemctl(args: &[&str]) -> Result<()> {
    let status = Command::new("systemctl")
        .arg("--user")
        .args(args)
        .status()
        .context("Failed to run systemctl")?;

    if !status.success() {
        return Err(anyhow!("systemctl --user {} failed", args.join(" ")));
    }
    Ok(())
}

fn check_systemd_available() -> Result<()> {
    let output = Command::new("systemctl")
        .arg("--user")
        .arg("--version")
        .output()
        .context("Failed to run systemctl")?;

    if !output.status.success() {
        return Err(anyhow!(
            "systemd user session is not available.\n\
             Make sure you're running in a systemd-managed session."
        ));
    }
    Ok(())
}

pub fn system_install() -> Result<()> {
    check_systemd_available()?;

    let systemd_dir = systemd_user_dir()?;
    let socket_path = socket_unit_path()?;
    let service_path = service_unit_path()?;

    let dir = systemd_dir.display();
    fs::create_dir_all(&systemd_dir).with_context(|| format!("Failed to create {dir}"))?;

    let socket_content = socket_unit_content()?;
    let service_content = service_unit_content()?;

    let socket_display = socket_path.display();
    fs::write(&socket_path, &socket_content)
        .with_context(|| format!("Failed to write {socket_display}"))?;

    let service_display = service_path.display();
    fs::write(&service_path, &service_content)
        .with_context(|| format!("Failed to write {service_display}"))?;

    systemctl(&["daemon-reload"])?;
    systemctl(&["enable", &format!("{SERVICE_NAME}.socket")])?;
    systemctl(&["start", &format!("{SERVICE_NAME}.socket")])?;

    println!("Installed sandbox daemon.");

    Ok(())
}

pub fn system_uninstall() -> Result<()> {
    check_systemd_available()?;

    let socket_path = socket_unit_path()?;
    let service_path = service_unit_path()?;

    let _ = systemctl(&["stop", &format!("{SERVICE_NAME}.socket")]);
    let _ = systemctl(&["stop", &format!("{SERVICE_NAME}.service")]);
    let _ = systemctl(&["disable", &format!("{SERVICE_NAME}.socket")]);

    if socket_path.exists() {
        let path = socket_path.display();
        fs::remove_file(&socket_path).with_context(|| format!("Failed to remove {path}"))?;
    }

    if service_path.exists() {
        let path = service_path.display();
        fs::remove_file(&service_path).with_context(|| format!("Failed to remove {path}"))?;
    }

    systemctl(&["daemon-reload"])?;

    println!("Uninstalled sandbox daemon.");

    Ok(())
}
