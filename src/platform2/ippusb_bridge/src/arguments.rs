// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
use std::error;
use std::fmt;
use std::num::ParseIntError;
use std::path::PathBuf;
use std::str::FromStr;

#[derive(Debug)]
pub enum Error {
    GetOpts(getopts::Fail),
    ParseArgument(String, String, ParseIntError),
    InvalidArgument(String, String, String),
    MissingArgument(String),
}

impl error::Error for Error {}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use Error::*;
        match self {
            GetOpts(e) => write!(f, "Getopts error: {}", e),
            ParseArgument(name, val, err) => {
                write!(f, "Failed to parse {} '{}' as u8: {}", name, val, err)
            }
            InvalidArgument(flag, value, error_msg) => {
                write!(f, "Invalid {} argument '{}': {}", flag, value, error_msg)
            }
            MissingArgument(subcommand) => write!(f, "Missing argument for {}", subcommand),
        }
    }
}

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, PartialEq)]
pub struct Args {
    pub bus_device: Option<(u8, u8)>,
    pub unix_socket: Option<PathBuf>,
    pub upstart_mode: bool,
    pub verbose_log: bool,
}

impl Args {
    pub fn parse<T: AsRef<str>>(args: &[T]) -> Result<Option<Self>> {
        let program_name = args.get(0).map(|s| s.as_ref()).unwrap_or("ippusb_bridge");

        let mut opts = getopts::Options::new();
        opts.optopt("d", "bus-device", "Identifier of device", "BUS:DEVICE")
            .optopt(
                "s",
                "unix-socket",
                "Path to unix socket to listen on",
                "PATH",
            )
            .optflag(
                "",
                "upstart",
                "Let upstart manage shutdown instead of immediately exiting after USB disconnect.",
            )
            .optflag("v", "verbose", "Enable verbose logging")
            .optflag("h", "help", "Print help message");

        let args = args.iter().map(|s| s.as_ref());
        let matches = match opts.parse(args) {
            Ok(m) => m,
            Err(e) => {
                show_usage(program_name, &opts);
                return Err(Error::GetOpts(e));
            }
        };
        if matches.opt_present("h") {
            show_usage(program_name, &opts);
            return Ok(None);
        }

        let bus_device = matches
            .opt_str("bus-device")
            .map(|param| {
                let tokens = param.split(':').collect::<Vec<_>>();
                if tokens.len() != 2 {
                    return Err(Error::InvalidArgument(
                        "bus-device".to_string(),
                        param.to_string(),
                        "should be formatted as '[bus-id]:[device-address]'".to_string(),
                    ));
                }

                let bus_id = u8::from_str(tokens[0]).map_err(|e| {
                    Error::ParseArgument("bus-id".to_string(), tokens[0].to_string(), e)
                })?;
                let device_address = u8::from_str(tokens[1]).map_err(|e| {
                    Error::ParseArgument("device-address".to_string(), tokens[1].to_string(), e)
                })?;
                Ok((bus_id, device_address))
            })
            .transpose()?;

        let unix_socket = matches.opt_str("unix-socket").map(PathBuf::from);
        let verbose_log = matches.opt_present("v");
        let upstart_mode = matches.opt_present("upstart");

        Ok(Some(Args {
            bus_device,
            unix_socket,
            upstart_mode,
            verbose_log,
        }))
    }
}

fn show_usage(program_name: &str, opts: &getopts::Options) {
    let brief = format!("Usage: {} [args]", program_name);
    eprint!("{}", opts.usage(&brief));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bus_device() {
        let args = Args::parse(&["ippusb-bridge", "--bus-device", "0:0"])
            .expect("Valid bus-device format should be properly parsed.")
            .expect("Options struct should be returned");
        assert_eq!(args.bus_device, Some((0, 0)));

        let args = Args::parse(&["ippusb-bridge", "--bus-device=255:17"])
            .expect("Valid bus-device format should be properly parsed.")
            .expect("Options struct should be returned");
        assert_eq!(args.bus_device, Some((255, 17)));

        let args = Args::parse(&["ippusb-bridge", "--bus-device=0:9"])
            .expect("Valid bus-device format should be properly parsed.")
            .expect("Options struct should be returned");
        assert_eq!(args.bus_device, Some((0, 9)));

        assert!(Args::parse(&["ippusb-bridge", "--bus-device"]).is_err());
        assert!(Args::parse(&["ippusb-bridge", "--bus-device=0"]).is_err());
        assert!(Args::parse(&["ippusb-bridge", "--bus-device", "0"]).is_err());
        assert!(Args::parse(&["ippusb-bridge", "--bus-device", "0:0xf"]).is_err());
        assert!(Args::parse(&["ippusb-bridge", "--bus-device", "a:14"]).is_err());
        assert!(Args::parse(&["ippusb-bridge", "--bus-device", "256:7"]).is_err());
        assert!(Args::parse(&["ippusb-bridge", "--bus-device", "91:256"]).is_err());
    }

    #[test]
    fn unix_socket() {
        let args = Args::parse(&["ippusb-bridge", "--unix-socket=/tmp/unixsocket.sock"])
            .expect("Valid unix-socket format should be properly parsed.")
            .expect("Options struct should be returned");
        assert_eq!(
            args.unix_socket,
            Some(PathBuf::from("/tmp/unixsocket.sock"))
        );

        let args = Args::parse(&["ippusb-bridge", "--unix-socket", "/tmp/unixsocket.sock"])
            .expect("Valid unix-socket format should be properly parsed.")
            .expect("Options struct should be returned");
        assert_eq!(
            args.unix_socket,
            Some(PathBuf::from("/tmp/unixsocket.sock"))
        );

        assert!(Args::parse(&["ippusb-bridge", "--unix-socket"]).is_err());
    }

    #[test]
    fn verbose() {
        let args = Args::parse(&["ippusb-bridge"])
            .expect("No args format should parse correctly")
            .expect("Options struct should be returned");
        assert!(!args.verbose_log);

        let args = Args::parse(&["ippusb-bridge", "-v"])
            .expect("Short verbose flag should parse correctly")
            .expect("Options struct should be returned");
        assert!(args.verbose_log);

        let args = Args::parse(&["ippusb-bridge", "--verbose"])
            .expect("Long verbose flag should parse correctly")
            .expect("Options struct should be returned");
        assert!(args.verbose_log);
    }

    #[test]
    fn help() {
        let args =
            Args::parse(&["ippusb-bridge", "-h"]).expect("Short help flag should parse correctly");
        assert!(args.is_none());

        let args = Args::parse(&["ippusb-bridge", "--help"])
            .expect("Long help flag should parse correctly");
        assert!(args.is_none());
    }

    #[test]
    fn error_messages() {
        let err = Error::GetOpts(getopts::Fail::ArgumentMissing("test".to_string()));
        assert!(err.to_string().contains("Getopts error"));

        let err = Error::ParseArgument(
            "name".to_string(),
            "val".to_string(),
            i8::from_str_radix("val", 16).unwrap_err(),
        );
        assert!(err.to_string().contains("Failed to parse"));

        let err = Error::InvalidArgument(
            "flag".to_string(),
            "val".to_string(),
            "error_msg".to_string(),
        );
        assert!(err.to_string().contains("Invalid"));

        let err = Error::MissingArgument("subcommand".to_string());
        assert!(err.to_string().contains("Missing argument"));
    }
}
