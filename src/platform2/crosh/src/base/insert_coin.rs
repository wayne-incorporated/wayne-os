// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// TODO(b/218403711): Remove this command once Borealis is fully released.
// Provides the command "insert_coin" for crosh, which enables Borealis.

use dbus::blocking::Connection;
use getopts::{self, Options};
use regex::Regex;
use std::borrow::Cow;
use std::io::Write;

use crate::dispatcher::{self, Arguments, Command, Dispatcher};
use crate::util::DEFAULT_DBUS_TIMEOUT;

const BEFORE_LINES: &str = r#"
  ________________________
 | /_____________________/
 ||                     |"#;

const AFTER_LINES: &str = r#"
 ||_____________________|
 |.\ ==  o    *  == o    \
 |..\    |:::       |:::  \
 |...\_____________________\
 |....| ___________________ |
 |.../     P1 |_||_| P2    /
 |...|        .-..-c      |
 |...|        |_||_|      |
  \..|        |    |      |
   \.|        |    |      |
    \|________|____|______|"#;

// Register insert_coin command with dispatcher.
pub fn register(dispatcher: &mut Dispatcher) {
    dispatcher.register_command(
        Command::new("insert_coin".to_string(), "".to_string(), "".to_string())
            .set_command_callback(Some(execute_insert_coin))
            .set_help_callback(insert_coin_help),
    );
}

// Override help formatter to keep insert_coin out of help_advanced.
fn insert_coin_help(_cmd: &Command, _w: &mut dyn Write, _level: usize) {}

// Add space to either side of |line| to center it |width| wide.
fn center(line: &str, width: usize) -> String {
    let left = (width - line.len()) / 2;
    let right = width - (line.len() + left);
    format!("{}{}{}", &" ".repeat(left), line, &" ".repeat(right))
}

// Pretty-print |message| on an arcade console.
fn ascii_art(message: &str) -> String {
    const SCREEN_WIDTH: usize = 19;
    // Wrap our string to fit inside the arcade console.
    let mut lines = textwrap::wrap(message.trim(), SCREEN_WIDTH);
    // Add whitespace so short messages don't result in a too-short console.
    while lines.len() < 3 {
        lines.push(Cow::from(""));
    }
    // Center the lines inside the arcade console image.
    format!(
        "{}{}{}",
        BEFORE_LINES,
        lines
            .iter()
            .map(|line| format!("\n || {} |", center(line, SCREEN_WIDTH)))
            .collect::<Vec<String>>()
            .join(""),
        AFTER_LINES
    )
}

// Parse insert_coin arguments into a token and a launch flag.
fn parse_arguments(args: &[String]) -> Result<(String, bool), dispatcher::Error> {
    let mut opts = Options::new();
    opts.optflag("n", "no-launch", "Don't launch Borealis");
    let matches = opts
        .parse(args)
        .map_err(|_| dispatcher::Error::CommandReturnedError)?;

    let raw_token = match matches.free.len() {
        0 => "",
        1 => &matches.free[0],
        _ => {
            eprintln!("Usage: insert_coin [--no-launch] <token>");
            return Err(dispatcher::Error::CommandReturnedError);
        }
    };

    let launch = !matches.opt_present("no-launch");

    // Cull characters that won't appear in the password and truncate long
    // passwords. Token-space is |2^192|.
    let re = Regex::new(r"[^a-zA-Z0-9_-]").unwrap();
    let mut token = String::from(re.replace_all(raw_token, ""));
    token.truncate(32);
    Ok((token, launch))
}

// insert_coin takes a token and sends it to org.chromium.VmLaunchService.ProvideVmToken.
// This token is stored, and checked when an attempt is made to launch Borealis.
fn execute_insert_coin(_cmd: &Command, args: &Arguments) -> Result<(), dispatcher::Error> {
    let (token, launch) = parse_arguments(&args.get_tokens()[1..])?;

    let connection = Connection::new_system().map_err(|err| {
        eprintln!("ERROR: Failed to get D-Bus connection: {}", err);
        dispatcher::Error::CommandReturnedError
    })?;

    let conn_path = connection.with_proxy(
        "org.chromium.VmLaunchService",
        "/org/chromium/VmLaunchService",
        DEFAULT_DBUS_TIMEOUT,
    );

    let (message,): (String,) = conn_path
        .method_call(
            "org.chromium.VmLaunchService",
            "ProvideVmToken",
            (&token, launch),
        )
        .map_err(|err| {
            // Long errors look pretty comical formatted this way, but why not? :)
            println!("{}", ascii_art(&err.to_string()));
            dispatcher::Error::CommandReturnedError
        })?;

    // Print the response, as ASCII art.
    println!("{}", ascii_art(&message));

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_arg_parsing() {
        // No arguments should result in token="", launch=true.
        assert_eq!(parse_arguments(&[]).unwrap(), (String::from(""), true));
        // Single argument should be parsed as a token.
        assert_eq!(
            parse_arguments(&[String::from("test-token")]).unwrap(),
            (String::from("test-token"), true)
        );
        // Two tokens should fail.
        assert!(parse_arguments(&[
            String::from("test-token"),
            String::from("unexpected-extra-token")
        ])
        .is_err());
        // Invalid chars should be stripped.
        assert_eq!(
            parse_arguments(&[String::from("te@#$st-to(*&ken(*&")]).unwrap(),
            (String::from("test-token"), true)
        );
        // Long tokens should be truncated.
        assert_eq!(
            parse_arguments(&[String::from("abcdefghijklmnopqrstuvwxyz789012asdf")]).unwrap(),
            (String::from("abcdefghijklmnopqrstuvwxyz789012"), true)
        );
        // Long tokens should be truncated after stripping.
        assert_eq!(
            parse_arguments(&[String::from("abcdefghi(*@#$jklmnopqrstuvwxyz789012asdf")]).unwrap(),
            (String::from("abcdefghijklmnopqrstuvwxyz789012"), true)
        );
        // --no-launch should result in token="", launch=false.
        assert_eq!(
            parse_arguments(&[String::from("--no-launch")]).unwrap(),
            (String::from(""), false)
        );
        // Try --no-launch with a token.
        assert_eq!(
            parse_arguments(&[String::from("--no-launch"), String::from("test")]).unwrap(),
            (String::from("test"), false)
        );
    }

    #[test]
    fn test_ascii_art() {
        assert_eq!(r#"
  ________________________
 | /_____________________/
 ||                     |
 ||   I was born in a   |
 ||  water moon. Some   |
 || people, especially  |
 ||  its inhabitants,   |
 || called it a planet, |
 || but as it was only  |
 ||  a little over two  |
 || hundred kilometres  |
 || in diameter, 'moon' |
 ||   seems the more    |
 || accurate term. The  |
 ||    moon was made    |
 || entirely of water,  |
 || by which I mean it  |
 ||  was a globe that   |
 ||   not only had no   |
 ||  land, but no rock  |
 ||  either, a sphere   |
 || with no solid core  |
 || at all, just liquid |
 || water, all the way  |
 ||  down to the very   |
 ||    centre of the    |
 ||       globe.        |
 ||_____________________|
 |.\ ==  o    *  == o    \
 |..\    |:::       |:::  \
 |...\_____________________\
 |....| ___________________ |
 |.../     P1 |_||_| P2    /
 |...|        .-..-c      |
 |...|        |_||_|      |
  \..|        |    |      |
   \.|        |    |      |
    \|________|____|______|"#, ascii_art("I was born in a water moon. Some people, especially its inhabitants, called it a planet, but as it was only a little over two hundred kilometres in diameter, 'moon' seems the more accurate term. The moon was made entirely of water, by which I mean it was a globe that not only had no land, but no rock either, a sphere with no solid core at all, just liquid water, all the way down to the very centre of the globe."));
        assert_eq!(
            r#"
  ________________________
 | /_____________________/
 ||                     |
 ||    Coin Invalid     |
 ||                     |
 ||                     |
 ||_____________________|
 |.\ ==  o    *  == o    \
 |..\    |:::       |:::  \
 |...\_____________________\
 |....| ___________________ |
 |.../     P1 |_||_| P2    /
 |...|        .-..-c      |
 |...|        |_||_|      |
  \..|        |    |      |
   \.|        |    |      |
    \|________|____|______|"#,
            ascii_art("Coin Invalid")
        );
    }
}
