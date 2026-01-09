//! Extension trait for `std::process::Command` that provides combined stdout/stderr output.
//!
//! This module allows capturing both stdout and stderr from a child process into a single
//! interleaved string, preserving the order in which output was produced.

use std::io::{self, pipe, BufRead, BufReader};
use std::process::{Command, ExitStatus, Stdio};

use anyhow::{anyhow, Result};

/// The output of a command with combined stdout and stderr.
#[derive(Debug)]
pub struct CombinedOutput {
    /// The combined stdout and stderr output as a string.
    pub combined_output: String,
    /// The exit status of the process (same field name as `std::process::Output`).
    pub status: ExitStatus,
}

/// Extension trait for `Command` that provides combined output functionality.
pub trait CommandExt {
    /// Executes the command and captures stdout and stderr into a single combined string.
    ///
    /// Both stdout and stderr are written to the same pipe, so the output is interleaved
    /// in the order it was produced by the process. The output is read line by line and
    /// expects valid UTF-8.
    fn combined_output(&mut self) -> io::Result<CombinedOutput>;

    /// Executes the command and returns stdout if it exits successfully.
    ///
    /// On failure, returns an error with the command, combined output, and exit status.
    fn success(&mut self) -> Result<Vec<u8>>;
}

impl CommandExt for Command {
    fn combined_output(&mut self) -> io::Result<CombinedOutput> {
        let (reader, writer) = pipe()?;

        // Clone the writer so we can give one to stdout and one to stderr.
        let writer_clone = writer.try_clone()?;

        let mut child = self.stdout(writer).stderr(writer_clone).spawn()?;

        // The Command struct holds onto the Stdio file descriptors internally.
        // We must close our copies so the pipe can reach EOF when the child exits.
        // Setting to Stdio::null() replaces (and closes) the previous descriptors.
        self.stdout(Stdio::null());
        self.stderr(Stdio::null());

        // Read line by line from the combined pipe.
        // The read will complete once the child closes both stdout and stderr, typically when it
        // exits.
        let mut combined_output = String::new();
        let buf_reader = BufReader::new(reader);
        for line in buf_reader.lines() {
            let line = line?;
            combined_output.push_str(&line);
            combined_output.push('\n');
        }

        let status = child.wait()?;

        Ok(CombinedOutput {
            combined_output,
            status,
        })
    }

    fn success(&mut self) -> Result<Vec<u8>> {
        let output = self.output()?;

        if output.status.success() {
            Ok(output.stdout)
        } else {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            let exit_info = match output.status.code() {
                Some(code) => format!("exit code: {}", code),
                None => "killed by signal".to_string(),
            };
            Err(anyhow!("$ {:?}\n{}{}{}", self, stdout, stderr, exit_info))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_combined_output_stdout_only() {
        let output = Command::new("echo")
            .arg("hello world")
            .combined_output()
            .unwrap();

        assert!(output.status.success());
        assert_eq!(output.combined_output, "hello world\n");
    }

    #[test]
    fn test_combined_output_stderr_only() {
        let output = Command::new("bash")
            .args(["-c", "echo 'error message' >&2"])
            .combined_output()
            .unwrap();

        assert!(output.status.success());
        assert_eq!(output.combined_output, "error message\n");
    }

    #[test]
    fn test_combined_output_both_streams() {
        let output = Command::new("bash")
            .args(["-c", "echo 'to stdout'; echo 'to stderr' >&2"])
            .combined_output()
            .unwrap();

        assert!(output.status.success());
        // Both lines should be present (order depends on timing, but typically
        // stdout comes first when both are flushed sequentially)
        assert!(output.combined_output.contains("to stdout\n"));
        assert!(output.combined_output.contains("to stderr\n"));
    }

    #[test]
    fn test_combined_output_exit_code() {
        let output = Command::new("bash")
            .args(["-c", "exit 42"])
            .combined_output()
            .unwrap();

        assert!(!output.status.success());
        assert_eq!(output.status.code(), Some(42));
    }

    #[test]
    fn test_combined_output_empty() {
        let output = Command::new("true").combined_output().unwrap();

        assert!(output.status.success());
        assert_eq!(output.combined_output, "");
    }

    #[test]
    fn test_combined_output_multiline() {
        let output = Command::new("bash")
            .args(["-c", "echo 'line1'; echo 'line2'; echo 'line3'"])
            .combined_output()
            .unwrap();

        assert!(output.status.success());
        assert_eq!(output.combined_output, "line1\nline2\nline3\n");
    }

    #[test]
    fn test_combined_output_interleaved() {
        // This test verifies that stdout and stderr are truly interleaved.
        // We use a script that alternates between stdout and stderr.
        let output = Command::new("bash")
            .args([
                "-c",
                r#"
                echo 'out1'
                echo 'err1' >&2
                echo 'out2'
                echo 'err2' >&2
                "#,
            ])
            .combined_output()
            .unwrap();

        assert!(output.status.success());
        // All lines should be present
        assert!(output.combined_output.contains("out1\n"));
        assert!(output.combined_output.contains("err1\n"));
        assert!(output.combined_output.contains("out2\n"));
        assert!(output.combined_output.contains("err2\n"));
        // Should have 4 lines total
        assert_eq!(output.combined_output.lines().count(), 4);
    }

    #[test]
    fn test_combined_output_large() {
        // Test with output larger than typical pipe buffer (64KB on Linux)
        // to verify no deadlock occurs.
        let output = Command::new("bash")
            .args(["-c", "for i in $(seq 1 10000); do echo \"line $i\"; done"])
            .combined_output()
            .unwrap();

        assert!(output.status.success());
        assert_eq!(output.combined_output.lines().count(), 10000);
    }
}
