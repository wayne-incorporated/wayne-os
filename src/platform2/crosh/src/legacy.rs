// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// The legacy module registers dispatcher commands from the original shell implementation.

use std::io::{copy, Write};
use std::process::{self, Stdio};

use crate::dispatcher::{self, wait_for_result, Arguments, Command, Dispatcher};
use crate::util;

const BASE_COMMANDS: &[&str] = &[
    "autest",
    "authpolicy_debug",
    "battery_firmware",
    "battery_test",
    "chaps_debug",
    "connectivity",
    "cras",
    "diag",
    "dump_emk",
    "enroll_status",
    "evtest",
    "exit", // Included for the "exit" help entry.
    "ff_debug",
    "free",
    "gesture_prop",
    "help",          // Included for the "help" help entry.
    "help_advanced", // Included for the "help_advanced" help entry.
    "ipaddrs",
    "meminfo",
    "memory_test",
    "modem",
    "network_diag",
    "p2p_update",
    "ping",
    "rlz",
    "route",
    "set_apn",
    "set_arpgw",
    "set_cellular_ppp",
    "set_wake_on_lan",
    "storage_test_1",
    "storage_test_2",
    "swap",
    "sync",
    "syslog",
    "time_info",
    "top",
    "tracepath",
    "u2f_flags",
    "uname",
    "upload_crashes",
    "upload_devcoredumps",
    "uptime",
    "vmstat",
    "vsh",
    "wifi_fw_dump",
    "wifi_power_save",
];

const DEV_COMMANDS: &[&str] = &["systrace"];

const USB_COMMANDS: &[&str] = &["update_firmware", "install", "upgrade"];

pub fn register(dispatcher: &mut Dispatcher) {
    register_legacy_commands(BASE_COMMANDS, dispatcher)
}

pub fn register_dev_mode_commands(dispatcher: &mut Dispatcher) {
    register_legacy_commands(DEV_COMMANDS, dispatcher)
}

pub fn register_removable_commands(dispatcher: &mut Dispatcher) {
    register_legacy_commands(USB_COMMANDS, dispatcher)
}

fn register_legacy_commands(commands: &[&str], dispatcher: &mut Dispatcher) {
    for cmd in commands {
        dispatcher.register_command(legacy_command(cmd));
    }
}

fn legacy_command(name: &str) -> dispatcher::Command {
    Command::new(name.to_string(), "".to_string(), "".to_string())
        .set_command_callback(Some(execute_legacy_command))
        .set_help_callback(legacy_help_callback)
}

fn legacy_crosh() -> process::Command {
    let mut sub = process::Command::new("crosh.sh");
    if util::dev_commands_included() {
        sub.arg("--dev");
    }
    if util::usb_commands_included() {
        // This includes '--removable'.
        sub.arg("--usb");
    }
    sub
}

fn execute_legacy_command(
    _cmd: &dispatcher::Command,
    args: &Arguments,
) -> Result<(), dispatcher::Error> {
    wait_for_result(
        legacy_crosh()
            .arg("--")
            .args(args.get_tokens())
            .spawn()
            .map_err(|_| dispatcher::Error::CommandReturnedError)?,
    )
}

fn legacy_help_callback(cmd: &Command, w: &mut dyn Write, _level: usize) {
    let mut sub = legacy_crosh()
        .arg("--")
        .arg("help")
        .arg(cmd.get_name())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();

    if copy(&mut sub.stdout.take().unwrap(), w).is_err() {
        panic!();
    }

    if sub.wait().is_err() {
        panic!();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::HashSet;
    use std::env;
    use std::fs::File;
    use std::io::{prelude::*, BufReader};
    use std::path::PathBuf;

    use crate::base;
    use crate::dev;

    const SOURCE_PATH_VAR: &str = "S";
    const BIN_DIR_SHELL: &str = "/usr/bin/crosh.sh";
    const DEFAULT_ROOT: &str = "/usr/share/crosh";

    const BASE_SHELL: &str = "crosh";
    const DEV_SHELL: &str = "dev.d/50-crosh.sh";
    const USB_SHELL: &str = "removable.d/50-crosh.sh";

    // Commands that are excluded from the checks because they are conditionally registered.
    const IGNORE_COMMANDS: &[&str] = &["ccd_pass", "verify_ro", "vmc"];

    enum ShellSource {
        Base,
        Dev,
        Usb,
    }

    fn get_shell_path(shell: &ShellSource) -> PathBuf {
        let mut path = PathBuf::new();

        // Try working directory first.
        path.push(match shell {
            ShellSource::Base => BASE_SHELL,
            ShellSource::Dev => DEV_SHELL,
            ShellSource::Usb => USB_SHELL,
        });
        if path.exists() {
            return path;
        } else {
            path = PathBuf::new();
        }

        // Fall back to source directory environmental variable, and lastly to installed path.
        match env::var(SOURCE_PATH_VAR) {
            Ok(s) => path.push(&s),
            Err(_) => {
                if let ShellSource::Base = shell {
                    path.push(BIN_DIR_SHELL);
                    return path;
                }
                path.push(DEFAULT_ROOT)
            }
        }
        path.push(match shell {
            ShellSource::Base => BASE_SHELL,
            ShellSource::Dev => DEV_SHELL,
            ShellSource::Usb => USB_SHELL,
        });
        path
    }

    fn get_dispatcher(shell: &ShellSource) -> Dispatcher {
        let mut dispatcher = Dispatcher::new();
        match shell {
            ShellSource::Base => {
                register(&mut dispatcher);
                base::register(&mut dispatcher);
            }
            ShellSource::Dev => {
                register_dev_mode_commands(&mut dispatcher);
                dev::register(&mut dispatcher);
            }
            ShellSource::Usb => {
                register_removable_commands(&mut dispatcher);
            }
        };
        dispatcher
    }

    fn get_cmds(shell: &ShellSource) -> Vec<String> {
        const PREFIX: &str = "cmd_";
        const SUFFIX: &str = "() (";

        let shell = File::open(get_shell_path(shell)).unwrap();
        let mut result: Vec<String> = Vec::new();
        for itr in BufReader::new(shell).lines() {
            let line = itr.unwrap();
            let trimmed = line.trim();
            if trimmed.starts_with(PREFIX) && trimmed.ends_with(SUFFIX) {
                result.push(
                    trimmed[PREFIX.len()..trimmed.len() - SUFFIX.len()]
                        .trim()
                        .to_string(),
                );
            }
        }
        result
    }

    fn verify_shell(shell: &ShellSource) {
        let dispatcher = get_dispatcher(shell);
        let command_list = get_cmds(shell);
        let mut missing_commands: Vec<&str> = Vec::new();
        let mut available_commands: HashSet<&str> = HashSet::new();

        // Verify all the crosh.sh commands are registered in rust-crosh.
        for command_name in &command_list {
            available_commands.insert(command_name);
            if dispatcher.find_by_name(command_name).is_none()
                && !IGNORE_COMMANDS.contains(&command_name.as_str())
            {
                missing_commands.push(command_name);
            }
        }
        assert!(
            missing_commands.is_empty(),
            "commands not registered: {:?}",
            missing_commands
        );

        // Verify all the legacy commands in rust-crosh have an implementation in crosh.sh.
        let mut extra_commands: Vec<&str> = Vec::new();
        for cmd in match shell {
            ShellSource::Base => BASE_COMMANDS,
            ShellSource::Dev => DEV_COMMANDS,
            ShellSource::Usb => USB_COMMANDS,
        } {
            if !available_commands.contains(cmd) && !IGNORE_COMMANDS.contains(cmd) {
                extra_commands.push(cmd);
            }
        }
        assert!(
            missing_commands.is_empty(),
            "commands registered without implementation: {:?}",
            missing_commands
        );
    }

    #[test]
    fn test_all_base_commands_registered() {
        verify_shell(&ShellSource::Base)
    }

    #[test]
    fn test_all_dev_commands_registered() {
        verify_shell(&ShellSource::Dev)
    }

    #[test]
    fn test_all_usb_commands_registered() {
        verify_shell(&ShellSource::Usb)
    }
}
