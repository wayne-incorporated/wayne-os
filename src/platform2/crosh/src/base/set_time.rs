// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Provides the command "set_time" for crosh which provides a way to set the system time before the
// network time is available.

use std::error;
use std::fmt::{self, Display};
use std::io::Read;
use std::process::{self, Stdio};

use dbus::blocking::Connection;
use libchromeos::sys::error;
use remain::sorted;
use tlsdate_dbus::client::OrgTorprojectTlsdate;

use crate::dispatcher::{self, Arguments, Command, Dispatcher};
use crate::util::DEFAULT_DBUS_TIMEOUT;

#[sorted]
enum Error {
    Communication,
    DBus,
    InvalidTime,
    NetworkTimeSet,
    UnexpectedResponse(Option<u32>),
    Wrapped(String),
}

impl Display for Error {
    #[remain::check]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::Error::*;

        #[sorted]
        match self {
            Communication => write!(f, "Time not set. There was a Communication error."),
            DBus => write!(
                f,
                "Time not set. Unable to communicate with the time service."
            ),
            InvalidTime => write!(f, "Requested time was invalid (too large or too small)"),
            NetworkTimeSet => write!(f, "Time not set. Network time cannot be overridden."),
            UnexpectedResponse(code) => {
                if let Some(value) = code {
                    write!(f, "An unexpected response was received: {}", value)
                } else {
                    write!(f, "An unexpected response was received.")
                }
            }
            Wrapped(err) => write!(f, "{}", err),
        }
    }
}

impl<T: error::Error> From<T> for Error {
    fn from(err: T) -> Self {
        Error::Wrapped(format!("{:?}", err))
    }
}

pub fn register(dispatcher: &mut Dispatcher) {
    dispatcher.register_command(
        Command::new(
            "set_time".to_string(),
            "<time string>".to_string(),
            r#"Sets the system time if the the system has been unable to get it from the
  network. The <time string> uses the format of the GNU coreutils date command."#
                .to_string(),
        )
        .set_command_callback(Some(execute_set_time)),
    );
}

fn execute_set_time(_cmd: &Command, args: &Arguments) -> Result<(), dispatcher::Error> {
    if args.get_args().is_empty() {
        eprintln!(
            r#"A date/time specification is required.
E.g., set_time 10 February 2012 11:21am
(Remember to set your timezone in Settings first.)"#
        );
        return Err(dispatcher::Error::CommandReturnedError);
    }

    let timestamp = parse_date_string(&args.get_args().join(" ")).map_err(|err| {
        eprintln!("Unable to understand the specified time: {}", err);
        dispatcher::Error::CommandReturnedError
    })?;

    match set_time(timestamp) {
        Ok(()) => {
            println!("Time has been set.");
            Ok(())
        }
        Err(err) => {
            error!("{}", err);
            Err(dispatcher::Error::CommandReturnedError)
        }
    }
}

fn set_time(timestamp: i64) -> Result<(), Error> {
    let connection = Connection::new_system().or(Err(Error::DBus))?;
    let conn_path = connection.with_proxy(
        "org.torproject.tlsdate",
        "/org/torproject/tlsdate",
        DEFAULT_DBUS_TIMEOUT,
    );
    match conn_path.set_time(timestamp).or(Err(Error::DBus))? {
        0 => Ok(()),
        1 => Err(Error::InvalidTime),
        2 => Err(Error::NetworkTimeSet),
        3 => Err(Error::Communication),
        code => Err(Error::UnexpectedResponse(Some(code))),
    }
}

// Rather than reimplementing the human entered date parsing logic from coreutils, just use `date`
// for now.
fn parse_date_string(date: &str) -> Result<i64, Error> {
    let mut child = process::Command::new("date")
        .arg("+%s")
        .arg("-d")
        .arg(date)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .spawn()?;

    let mut string_result = String::new();
    child
        .stdout
        .take()
        .unwrap()
        .read_to_string(&mut string_result)?;
    child.wait()?;
    string_result
        .trim()
        .parse::<i64>()
        .map_err(|err| err.into())
}
