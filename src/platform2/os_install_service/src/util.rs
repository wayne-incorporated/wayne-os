// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::fmt;
use std::io::{self, BufRead};
use std::os::unix::process::CommandExt;
use std::process::{Command, Output, Stdio};

use log::{debug, info};

#[derive(Debug)]
pub enum ErrorKind {
    LaunchProcess(io::Error),
    ExitedNonZero(Output),
}

#[derive(Debug)]
pub struct ProcessError {
    command: String,
    kind: ErrorKind,
}

impl fmt::Display for ProcessError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        match &self.kind {
            ErrorKind::LaunchProcess(err) => {
                write!(f, "failed to launch process \"{}\": {}", self.command, err)
            }
            ErrorKind::ExitedNonZero(output) => write!(
                f,
                "command \"{}\" failed: {}\nstdout={}\nstderr={}",
                self.command,
                output.status,
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr),
            ),
        }
    }
}

impl std::error::Error for ProcessError {}

/// Format the command as a string for logging.
///
/// There's no good built-in method for this, so use the debug format
/// with quotes removed. The debug format puts quotes around the
/// program and each argument, e.g. `"cmd" "arg1" "arg2"`. Removing
/// all quotes isn't correct in all cases, but good enough for logging
/// purposes.
fn command_to_string(cmd: &Command) -> String {
    format!("{:?}", cmd).replace('"', "")
}

/// Run a command and get its stdout as raw bytes. An error is
/// returned if the process fails to launch, or if it exits non-zero.
pub fn get_command_output(mut command: Command) -> Result<Vec<u8>, ProcessError> {
    let cmd_str = command_to_string(&command);
    debug!("running command: {}", cmd_str);

    let output = match command.output() {
        Ok(output) => output,
        Err(err) => {
            return Err(ProcessError {
                command: cmd_str,
                kind: ErrorKind::LaunchProcess(err),
            });
        }
    };

    if !output.status.success() {
        return Err(ProcessError {
            command: cmd_str,
            kind: ErrorKind::ExitedNonZero(output),
        });
    }
    Ok(output.stdout)
}

/// Run a command and log its output (both stdout and stderr) at the
/// info level. An error is returned if the process fails to launch,
/// or if it exits non-zero.
pub fn run_command_log_output(mut command: Command) -> Result<(), ProcessError> {
    let cmd_str = command_to_string(&command);
    info!("running command: {}", cmd_str);

    // This function dups stdout to stderr so that writes to stderr
    // are sent to stdout. It's passed to Command::pre_exec, so it
    // runs after forking the child process but before execing the
    // child executable.
    fn pre_exec() -> io::Result<()> {
        nix::unistd::dup2(1, 2).map_err(|err| io::Error::new(io::ErrorKind::Other, err))?;
        Ok(())
    }
    unsafe {
        command.pre_exec(pre_exec);
    }

    // Spawn the child with its output piped so that it can be logged.
    let mut child = command
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|err| ProcessError {
            command: cmd_str.clone(),
            kind: ErrorKind::LaunchProcess(err),
        })?;
    // OK to unwrap because stdout is captured above.
    let output = child.stdout.take().unwrap();

    // Read each line as it comes in and log it at the info
    // level. Each line is prefixed with ">>> " to clearly indicate
    // it's coming from a separate executable. This loop will end when
    // the output pipe is broken, probably when the child exits.
    let reader = io::BufReader::new(output);
    reader
        .lines()
        .filter_map(|line| line.ok())
        .for_each(|line| info!(">>> {}", line));

    // Wait for the child process to exit completely.
    let status = child.wait().map_err(|err| ProcessError {
        command: cmd_str.clone(),
        kind: ErrorKind::LaunchProcess(err),
    })?;

    // Check the status to return an error if needed.
    if !status.success() {
        return Err(ProcessError {
            command: cmd_str,
            kind: ErrorKind::ExitedNonZero(Output {
                status,
                stdout: Vec::new(),
                stderr: Vec::new(),
            }),
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_command_to_string() {
        let mut cmd = Command::new("myCmd");
        cmd.args(["arg1", "arg2"]);
        assert_eq!(command_to_string(&cmd), "myCmd arg1 arg2");
    }

    #[test]
    fn test_get_command_output_bad_path() {
        let result = get_command_output(Command::new("/this/path/does/not/exist"));
        if let Err(err) = result {
            if matches!(err.kind, ErrorKind::LaunchProcess(_)) {
                return;
            }
        }
        panic!("get_command_output did not return a LaunchProcess error");
    }

    #[test]
    fn test_get_command_output_success() {
        let mut command = Command::new("echo");
        command.arg("myOutput");
        assert_eq!(get_command_output(command).unwrap(), b"myOutput\n");
    }

    #[test]
    fn test_get_command_output_exit_nonzero() {
        let result = get_command_output(Command::new("false"));
        if let Err(err) = result {
            if matches!(err.kind, ErrorKind::ExitedNonZero(_)) {
                return;
            }
        }
        panic!("get_command_output did not return ExitedNonZero");
    }
}
