// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Provides the command "arc" for crosh which can run various ARC utilities and tools.

use std::io::Write;
use std::path::Path;
use std::process;

use crate::dispatcher::{self, wait_for_result, Arguments, Command, Dispatcher};

const HELP: &str = r#"Usage: arc
  [ ping [ NETWORK ] [ <ip address> | <hostname> ] |
    http [ NETWORK ] <url> |
    dns [ NETWORK ] <domain> |
    proxy <url> |
    list [ networks ] |
    stats [ sockets | traffic ]
  ]
  where NETWORK := [ wifi | eth | ethernet | cell | cellular | vpn ]

ping:           check the reachability of a host or IP address.
http:           do a GET request to an URL and print the response header.
dns:            perform a DNS lookup of a domain name.
proxy:          resolve the current proxy configuration for a given URL.
list networks:  show properties of all networks connected in Android.
stats sockets:  show TCP connect and DNS statistics by Android Apps.
stats traffic:  show traffic packet statistics by Android Apps.

If NETWORK is not specified, the default network is used.
"#;

type CommandRunner = dyn Fn(&[&str]) -> Result<(), dispatcher::Error>;

// We use adb shell for executing networking tools through dumpsys wifi.
// It is not possible to use android-sh because it has a different selinux context.
const ADB: &str = "/usr/bin/adb";

fn run_adb_command(args: &[&str]) -> Result<(), dispatcher::Error> {
    process::Command::new(ADB).args(args).spawn().map_or(
        Err(dispatcher::Error::CommandReturnedError),
        wait_for_result,
    )
}

pub fn register(dispatcher: &mut Dispatcher) {
    // Only register the arc command if adb is present.
    if !Path::new(ADB).exists() {
        return;
    }
    dispatcher.register_command(
        Command::new("arc".to_string(), "".to_string(), "".to_string())
            .set_command_callback(Some(arc_command_callback))
            .set_help_callback(arc_help),
    );
}

fn arc_help(_cmd: &Command, w: &mut dyn Write, _level: usize) {
    w.write_all(HELP.as_bytes()).unwrap();
    w.flush().unwrap();
}

// Wraps |execute_arc_command| to register it to crosh dispatcher. This facilitates testing.
fn arc_command_callback(_cmd: &Command, _args: &Arguments) -> Result<(), dispatcher::Error> {
    // Convert the slice of String to a vec of str for pattern matching.
    let args: Vec<&str> = _args.get_args().iter().map(String::as_str).collect();
    execute_arc_command(&args, &run_adb_command)
}

fn execute_arc_command(
    args: &[&str],
    adb_command_runner: &CommandRunner,
) -> Result<(), dispatcher::Error> {
    match args {
        [] => invalid_argument("no command"),

        // dumpsys wifi tools reach [NETWORK] [<ip addr> | <hosname>]
        ["ping"] => invalid_argument("missing IP address or hostname to ping"),
        ["ping", network, dst, ..] => {
            run_arc_networking_tool(adb_command_runner, "reach", dst, Some(network))
        }
        ["ping", dst, ..] => run_arc_networking_tool(adb_command_runner, "reach", dst, None),

        // dumpsys wifi tools http [NETWORK] <url>
        ["http"] => invalid_argument("missing url to connect to"),
        ["http", network, url, ..] => {
            run_arc_networking_tool(adb_command_runner, "http", url, Some(network))
        }
        ["http", url, ..] => run_arc_networking_tool(adb_command_runner, "http", url, None),

        // dumpsys wifi tools dns [NETWORK] <domain>
        ["dns"] => invalid_argument("missing domain name to resolve"),
        ["dns", network, domain, ..] => {
            run_arc_networking_tool(adb_command_runner, "dns", domain, Some(network))
        }
        ["dns", domain, ..] => run_arc_networking_tool(adb_command_runner, "dns", domain, None),

        // dumpsys wifi tools proxy <url>. Proxy resolution is always with the default network in
        // ARC.
        ["proxy"] => invalid_argument("missing url to resolve"),
        ["proxy", url, ..] => run_arc_networking_tool(adb_command_runner, "proxy", url, None),

        // Prints Android properties of all networks currently connected in ARC. This output
        // contains potential PIIs (IP addresses) and should not be stored or collected without
        // additional scrubbing.
        ["list", "networks"] => adb_command_runner(&["shell", "dumpsys", "wifi", "networks"]),
        // Prints the number of TCP connect() calls and DNS queries initiated by Android Apps.
        // This output does not contain any PII.
        ["stats", "sockets"] => adb_command_runner(&["shell", "dumpsys", "wifi", "sockets"]),
        // Prints tx and rx packets and bytes counter statistics for traffic initiated by Android
        // Apps. This output does not contain any PII.
        ["stats", "traffic"] => adb_command_runner(&["shell", "dumpsys", "wifi", "traffic"]),
        [other, ..] => invalid_argument(other),
    }
}

fn run_arc_networking_tool(
    adb_command_runner: &CommandRunner,
    tool: &str,
    arg: &str,
    network: Option<&str>,
) -> Result<(), dispatcher::Error> {
    let mut adb_args = vec!["shell", "dumpsys", "wifi", "tools", tool];
    match network {
        None => (),
        Some("wifi") | Some("eth") | Some("ethernet") | Some("cell") | Some("cellular")
        | Some("vpn") => adb_args.push(network.unwrap()),
        Some(n) => return invalid_argument(n),
    };
    adb_args.push(arg);

    adb_command_runner(&adb_args)
}

fn invalid_argument(msg: &str) -> Result<(), dispatcher::Error> {
    Err(dispatcher::Error::CommandInvalidArguments(msg.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_adb_command(_args: &[&str]) -> Result<(), dispatcher::Error> {
        Ok(())
    }

    fn expect_adb_command(expected_command: &str) -> Box<CommandRunner> {
        let c = expected_command.to_string();
        Box::new(move |args| -> Result<(), dispatcher::Error> {
            let command = args.join(" ");
            if c == command {
                Ok(())
            } else {
                invalid_argument(&command)
            }
        })
    }

    #[test]
    fn test_invalid_commands() {
        let invalid_commands = [
            "",
            "wopfhjf",
            "not a command",
            "ping ping ping",
            "ping",
            "http",
            "dns",
            "proxy",
            "ping invalid 1.1.1.1",
        ];

        for &command in &invalid_commands {
            let args: Vec<&str> = command.split(' ').collect();
            let r = execute_arc_command(&args, &fake_adb_command);
            assert!(r.is_err(), "\"{}\" should not be a valid command", command);
        }
    }

    #[test]
    fn test_valid_commands() {
        let valid_commands = [
            "ping 8.8.8.8",
            "ping eth 1.1.1.1",
            "ping wifi ipv6.google.com",
            "http https://google.com",
            "http cell https://google.com",
            "dns play.google.com",
            "dns vpn portal.corp.com",
            "proxy http://google.com",
        ];

        for &command in &valid_commands {
            let args: Vec<&str> = command.split(' ').collect();
            let r = execute_arc_command(&args, &fake_adb_command);
            assert!(
                r.is_ok(),
                "\"{}\" should be a valid command, but got: {}",
                command,
                r.unwrap_err()
            );
        }
    }

    #[test]
    fn test_arc_networking_commands() {
        let commands = [
            ("ping 8.8.8.8", "shell dumpsys wifi tools reach 8.8.8.8"),
            (
                "ping eth 1.1.1.1 extra1",
                "shell dumpsys wifi tools reach eth 1.1.1.1",
            ),
            (
                "ping wifi ipv6.google.com",
                "shell dumpsys wifi tools reach wifi ipv6.google.com",
            ),
            (
                "http https://google.com",
                "shell dumpsys wifi tools http https://google.com",
            ),
            (
                "http cell https://google.com",
                "shell dumpsys wifi tools http cell https://google.com",
            ),
            (
                "dns play.google.com",
                "shell dumpsys wifi tools dns play.google.com",
            ),
            (
                "dns vpn portal.corp.com",
                "shell dumpsys wifi tools dns vpn portal.corp.com",
            ),
            (
                "proxy http://google.com",
                "shell dumpsys wifi tools proxy http://google.com",
            ),
            ("list networks", "shell dumpsys wifi networks"),
            ("stats sockets", "shell dumpsys wifi sockets"),
            ("stats traffic", "shell dumpsys wifi traffic"),
        ];

        for (arc_command, adb_command) in &commands {
            let args: Vec<&str> = arc_command.split(' ').collect();
            let fake_command_runner = expect_adb_command(adb_command);
            let r = execute_arc_command(&args, &fake_command_runner);
            assert!(
                r.is_ok(),
                "expected \"{}\", but got: {}",
                adb_command,
                r.unwrap_err()
            );
        }
    }
}
