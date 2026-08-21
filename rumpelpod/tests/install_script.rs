// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

use indoc::indoc;
use portable_pty::{native_pty_system, CommandBuilder, PtySize};
use tempfile::TempDir;

const PTY_ROWS: u16 = 24;
const PTY_COLS: u16 = 120;
const INSTALL_TIMEOUT: Duration = Duration::from_secs(15);

struct InstallerFixture {
    temp: TempDir,
    home: PathBuf,
    path: String,
    tarball: PathBuf,
    command_log: PathBuf,
}

struct InstallResult {
    success: bool,
    output: String,
}

impl InstallerFixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().expect("create installer test directory");
        let home = temp.path().join("home");
        let fake_bin = temp.path().join("fake-bin");
        let release = temp.path().join("release");
        fs::create_dir_all(&home).expect("create test home");
        fs::create_dir_all(&fake_bin).expect("create fake command directory");
        fs::create_dir_all(&release).expect("create fake release directory");

        let binary_name = platform_binary_name();
        let release_binary = release.join(binary_name);
        write_executable(
            &release_binary,
            indoc! {r#"
                #!/bin/sh
                set -eu
                case "${1:-}" in
                    system-install)
                        printf '%s\n' 'system-install' >> "$RUMPELPOD_TEST_COMMAND_LOG"
                        ;;
                    *)
                        exec "$RUMPELPOD_TEST_REAL_RUMPEL" "$@"
                        ;;
                esac
            "#},
        );

        let tarball = temp.path().join("rumpel-v-test.tar.gz");
        let status = Command::new("tar")
            .args(["czf"])
            .arg(&tarball)
            .arg("-C")
            .arg(&release)
            .arg(binary_name)
            .status()
            .expect("create fake release tarball");
        assert!(status.success(), "tar failed to create fake release");

        write_executable(
            &fake_bin.join("curl"),
            indoc! {r#"
                #!/bin/sh
                set -eu
                case "$*" in
                    *releases/latest*)
                        printf '%s\n' 'https://github.com/nvidia/rumpelpod/releases/tag/v-test'
                        exit 0
                        ;;
                esac

                output=''
                while [ "$#" -gt 0 ]; do
                    case "$1" in
                        -o)
                            shift
                            output="$1"
                            ;;
                    esac
                    shift
                done
                if [ -z "$output" ]; then
                    echo 'fake curl did not receive an output path' >&2
                    exit 1
                fi
                /bin/cp "$RUMPELPOD_TEST_TARBALL" "$output"
            "#},
        );

        Self {
            temp,
            home,
            path: format!("{}:/usr/bin:/bin", fake_bin.display()),
            tarball,
            command_log: release.join("system-install.log"),
        }
    }

    fn run(&self, responses: &str) -> InstallResult {
        self.run_with_install_dir(responses, None)
    }

    fn run_with_install_dir(&self, responses: &str, install_dir: Option<&str>) -> InstallResult {
        let pty_system = native_pty_system();
        let pair = pty_system
            .openpty(PtySize {
                rows: PTY_ROWS,
                cols: PTY_COLS,
                pixel_width: 0,
                pixel_height: 0,
            })
            .expect("create installer PTY");

        let mut command = CommandBuilder::new("sh");
        command.args(["-c", "cat \"$RUMPELPOD_TEST_INSTALL_SCRIPT\" | sh"]);
        command.cwd(self.temp.path());
        command.env_clear();
        command.env("HOME", &self.home);
        command.env("SHELL", "/bin/bash");
        command.env("PATH", &self.path);
        command.env("RUMPELPOD_TEST_TARBALL", &self.tarball);
        command.env("RUMPELPOD_TEST_COMMAND_LOG", &self.command_log);
        command.env("RUMPELPOD_TEST_REAL_RUMPEL", env!("CARGO_BIN_EXE_rumpel"));
        command.env(
            "RUMPELPOD_TEST_INSTALL_SCRIPT",
            workspace_root().join("install.sh"),
        );
        if let Some(install_dir) = install_dir {
            command.env("INSTALL_DIR", install_dir);
        }

        let mut child = pair
            .slave
            .spawn_command(command)
            .expect("start install script");
        drop(pair.slave);
        let mut reader = pair.master.try_clone_reader().expect("clone PTY reader");
        let mut writer = pair.master.take_writer().expect("take PTY writer");
        drop(pair.master);

        let reader_thread = thread::spawn(move || {
            let mut output = Vec::new();
            let mut buffer = [0u8; 4096];
            loop {
                match reader.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(count) => output.extend_from_slice(&buffer[..count]),
                    Err(error) if error.raw_os_error() == Some(libc::EIO) => break,
                    Err(error) => panic!("read installer PTY: {error}"),
                }
            }
            output
        });

        writer
            .write_all(responses.as_bytes())
            .expect("answer installer prompts");
        writer.flush().expect("flush installer responses");

        let deadline = Instant::now() + INSTALL_TIMEOUT;
        let mut timed_out = false;
        let status = loop {
            if let Some(status) = child.try_wait().expect("poll install script") {
                break status;
            }
            if Instant::now() >= deadline {
                timed_out = true;
                child.kill().expect("kill timed out install script");
                break child.wait().expect("wait for timed out install script");
            }
            thread::sleep(Duration::from_millis(20));
        };
        drop(writer);
        let output = String::from_utf8_lossy(
            &reader_thread
                .join()
                .expect("installer PTY reader thread panicked"),
        )
        .replace('\r', "");
        assert!(!timed_out, "install script timed out:\n{output}");

        InstallResult {
            success: status.success(),
            output,
        }
    }
}

#[test]
fn install_script_adds_install_dir_to_new_shell_path() {
    let fixture = InstallerFixture::new();
    let install_dir = fixture.home.join(".local/bin");
    let install_dir_str = install_dir.to_str().expect("install directory is UTF-8");
    assert!(
        !fixture
            .path
            .split(':')
            .any(|entry| entry == install_dir_str),
        "test PATH unexpectedly contains the install directory"
    );

    let result = fixture.run("y\nn\n");
    assert!(result.success, "install script failed:\n{}", result.output);
    assert!(
        result.output.contains(&format!(
            "Add {} to PATH in {}/.profile and {}/.bashrc? [y/N]",
            install_dir.display(),
            fixture.home.display(),
            fixture.home.display()
        )),
        "install script did not offer PATH setup:\n{}",
        result.output
    );
    assert!(
        result
            .output
            .contains("Install and start the rumpelpod background service? [y/N]"),
        "install script did not ask before service setup:\n{}",
        result.output
    );
    assert!(
        !fixture.command_log.exists(),
        "system-install ran after the prompt was declined"
    );

    for config_name in [".profile", ".bashrc"] {
        let config = fs::read_to_string(fixture.home.join(config_name))
            .unwrap_or_else(|error| panic!("read {config_name} written by installer: {error}"));
        assert!(
            config.contains(&format!(
                "export PATH='{}':\"$PATH\"",
                install_dir.display()
            )),
            "{config_name} did not contain the install directory:\n{config}"
        );
    }

    for (shell_kind, args) in [
        (
            "interactive non-login",
            [
                "--noprofile",
                "-ic",
                "printf 'PATH=%s\\n' \"$PATH\"; rumpel --version",
            ],
        ),
        (
            "login",
            [
                "--norc",
                "-lic",
                "printf 'PATH=%s\\n' \"$PATH\"; rumpel --version",
            ],
        ),
    ] {
        let fresh_shell = Command::new("bash")
            .args(args)
            .env_clear()
            .env("HOME", &fixture.home)
            .env("SHELL", "/bin/bash")
            .env("PATH", &fixture.path)
            .env("RUMPELPOD_TEST_COMMAND_LOG", &fixture.command_log)
            .env("RUMPELPOD_TEST_REAL_RUMPEL", env!("CARGO_BIN_EXE_rumpel"))
            .output()
            .unwrap_or_else(|error| panic!("start a fresh {shell_kind} shell: {error}"));
        assert!(
            fresh_shell.status.success(),
            "rumpel was not usable in a fresh {shell_kind} shell:\n{}",
            String::from_utf8_lossy(&fresh_shell.stderr)
        );
        let stdout = String::from_utf8_lossy(&fresh_shell.stdout);
        assert!(
            stdout.contains("rumpelpod"),
            "fresh {shell_kind} shell did not run the installed rumpel binary"
        );
        let configured_path = stdout
            .lines()
            .find_map(|line| line.strip_prefix("PATH="))
            .unwrap_or_else(|| panic!("fresh {shell_kind} shell did not print PATH:\n{stdout}"));
        assert_eq!(
            configured_path
                .split(':')
                .filter(|entry| *entry == install_dir_str)
                .count(),
            1,
            "fresh {shell_kind} shell added the install directory more than once: {configured_path}"
        );
    }
}

#[test]
fn install_script_runs_system_install_only_after_confirmation() {
    let fixture = InstallerFixture::new();
    let result = fixture.run("n\ny\n");
    assert!(result.success, "install script failed:\n{}", result.output);
    assert!(
        !fixture.home.join(".bashrc").exists(),
        "installer changed shell configuration after the prompt was declined"
    );
    assert!(
        !fixture.home.join(".profile").exists(),
        "installer changed login configuration after the prompt was declined"
    );
    assert_eq!(
        fs::read_to_string(&fixture.command_log).expect("read system-install invocation log"),
        "system-install\n"
    );
}

#[test]
fn install_script_persists_an_absolute_install_dir() {
    let fixture = InstallerFixture::new();
    let result = fixture.run_with_install_dir("y\nn\n", Some("relative-bin"));
    assert!(result.success, "install script failed:\n{}", result.output);

    let absolute_install_dir = fixture.temp.path().join("relative-bin");
    for config_name in [".profile", ".bashrc"] {
        let config = fs::read_to_string(fixture.home.join(config_name))
            .unwrap_or_else(|error| panic!("read {config_name} written by installer: {error}"));
        assert!(
            config.contains(&format!(
                "export PATH='{}':\"$PATH\"",
                absolute_install_dir.display()
            )),
            "relative install directory was persisted without normalization in {config_name}:\n{config}"
        );
    }
}

#[test]
fn install_script_updates_the_selected_bash_login_profile() {
    let fixture = InstallerFixture::new();
    let install_dir = fixture.home.join(".local/bin");
    let install_dir_display = install_dir.display();
    let expected = format!(
        "case \":$PATH:\" in *':{install_dir_display}:'*) ;; *) export PATH='{install_dir_display}':\"$PATH\" ;; esac"
    );
    fs::write(
        fixture.home.join(".bash_profile"),
        format!("# {expected}\n[ ! -f \"$HOME/.bashrc\" ] || . \"$HOME/.bashrc\"\n"),
    )
    .expect("write existing .bash_profile");
    fs::write(
        fixture.home.join(".profile"),
        "# shadowed by .bash_profile\n",
    )
    .expect("write shadowed .profile");

    let result = fixture.run("y\nn\n");
    assert!(result.success, "install script failed:\n{}", result.output);
    let bash_profile =
        fs::read_to_string(fixture.home.join(".bash_profile")).expect("read updated .bash_profile");
    assert_eq!(
        bash_profile
            .lines()
            .filter(|line| *line == expected)
            .count(),
        1,
        "installer treated commented configuration as active:\n{bash_profile}"
    );
    assert_eq!(
        fs::read_to_string(fixture.home.join(".profile")).expect("read shadowed .profile"),
        "# shadowed by .bash_profile\n",
        "installer updated a login profile Bash would not read"
    );
    let bashrc = fs::read_to_string(fixture.home.join(".bashrc")).expect("read updated .bashrc");
    assert!(
        bashrc.contains(&expected),
        "installer did not update interactive Bash configuration:\n{bashrc}"
    );

    let login_shell = Command::new("bash")
        .args(["--norc", "-lic", "printf '%s\\n' \"$PATH\""])
        .env_clear()
        .env("HOME", &fixture.home)
        .env("SHELL", "/bin/bash")
        .env("PATH", &fixture.path)
        .output()
        .expect("start login shell whose profile sources .bashrc");
    assert!(
        login_shell.status.success(),
        "login shell failed:\n{}",
        String::from_utf8_lossy(&login_shell.stderr)
    );
    let login_path = String::from_utf8(login_shell.stdout)
        .expect("login shell PATH is UTF-8")
        .trim()
        .to_string();
    let install_dir = install_dir.to_str().expect("install directory is UTF-8");
    assert_eq!(
        login_path
            .split(':')
            .filter(|entry| *entry == install_dir)
            .count(),
        1,
        "login profile and .bashrc added the install directory more than once: {login_path}"
    );
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root above rumpelpod crate")
        .to_path_buf()
}

fn platform_binary_name() -> &'static str {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("linux", "x86_64") => "rumpel-linux-amd64",
        ("linux", "aarch64") => "rumpel-linux-arm64",
        ("macos", "aarch64") => "rumpel-darwin-arm64",
        (os, arch) => panic!("installer test does not support {os}/{arch}"),
    }
}

fn write_executable(path: &Path, contents: &str) {
    fs::write(path, contents).unwrap_or_else(|error| panic!("write {}: {error}", path.display()));
    let mut permissions = fs::metadata(path)
        .unwrap_or_else(|error| panic!("read permissions for {}: {error}", path.display()))
        .permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(path, permissions)
        .unwrap_or_else(|error| panic!("make {} executable: {error}", path.display()));
}
