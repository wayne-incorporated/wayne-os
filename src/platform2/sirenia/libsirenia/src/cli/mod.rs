// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

pub mod trichechus;

use std::marker::PhantomData;
use std::process::exit;

use getopts;
use getopts::Matches;
use getopts::Options;
use thiserror::Error as ThisError;

use crate::transport;
use crate::transport::TransportType;
use crate::transport::LOOPBACK_DEFAULT;

#[derive(ThisError, Debug)]
pub enum Error {
    #[error("failed to parse transport type: {0}")]
    TransportParse(#[source] transport::Error),
}

/// The result of an operation in this crate.
pub type Result<T> = std::result::Result<T, Error>;

pub const DEFAULT_TRANSPORT_TYPE_SHORT_NAME: &str = "U";
pub const DEFAULT_TRANSPORT_TYPE_LONG_NAME: &str = "server-url";
pub const DEFAULT_TRANSPORT_TYPE_DESC: &str = "URL to the server";

pub const DEFAULT_VERBOSITY_SHORT_NAME: &str = "v";
pub const DEFAULT_VERBOSITY_LONG_NAME: &str = "verbose";
pub const DEFAULT_VERBOSITY_DESC: &str = "Set the logging level (Can be set more than once)";

pub const HELP_OPTION_SHORT_NAME: &str = "h";

/// A TransportType command-line option that allows for multiple transport options to be defined for
/// the same set of arguments.
pub struct TransportTypeOption {
    short_name: String,
}

impl TransportTypeOption {
    /// Add the default TransportTypeOption to the specified Options.
    pub fn default(opts: &mut Options) -> Self {
        Self::new(
            DEFAULT_TRANSPORT_TYPE_SHORT_NAME,
            DEFAULT_TRANSPORT_TYPE_LONG_NAME,
            DEFAULT_TRANSPORT_TYPE_DESC,
            LOOPBACK_DEFAULT,
            opts,
        )
    }

    /// Add a customized TransportTypeOption to the specified Options.
    /// Prefer Self::default unless it has already been used.
    pub fn new(
        short_name: &str,
        long_name: &str,
        desc: &str,
        hint: &str,
        opts: &mut Options,
    ) -> Self {
        opts.optflagopt(short_name, long_name, desc, hint);
        TransportTypeOption {
            short_name: short_name.to_string(),
        }
    }

    /// Checks the command line argument matches and returns:
    ///   * Ok(None) - if the option wasn't set.
    ///   * Ok(Some(_: TransportType)) - if parsing succeeded.
    ///   * Err(Error::TransportParse(_)) - if parsing failed.
    pub fn from_matches(&self, matches: &Matches) -> Result<Option<TransportType>> {
        match matches.opt_str(&self.short_name) {
            Some(value) => value
                .parse::<TransportType>()
                .map_err(Error::TransportParse)
                .map(Some),
            None => Ok(None),
        }
    }
}

pub struct VerbosityOption {
    short_name: String,
}

impl VerbosityOption {
    /// Add the default VerbosityOption to the specified Options.
    pub fn default(opts: &mut Options) -> Self {
        Self::new(
            DEFAULT_VERBOSITY_SHORT_NAME,
            DEFAULT_VERBOSITY_LONG_NAME,
            DEFAULT_VERBOSITY_DESC,
            opts,
        )
    }

    /// Add a customized VerbosityOption to the specified Options.
    /// Prefer Self::default unless it short_name or long_name are not available.
    pub fn new(short_name: &str, long_name: &str, desc: &str, opts: &mut Options) -> Self {
        opts.optflagmulti(short_name, long_name, desc);
        Self {
            short_name: short_name.to_string(),
        }
    }

    /// Returns the number of times the verbosity option was set.
    pub fn from_matches(&self, matches: &Matches) -> usize {
        matches.opt_count(&self.short_name)
    }
}

trait PrivateTrait {}

/// A help option that wraps commonly used logic. Specifically, it defines the "-h", "--help"
/// options and provides a helper for showing the usage strings when the option is set or when
/// the command line options fail to parse.
pub struct HelpOption {
    // Force use of the constructor through a private field.
    phantom: PhantomData<dyn PrivateTrait>,
}

impl HelpOption {
    /// Adds a newly created HelpOption to the specified Options.
    pub fn new(opts: &mut Options) -> Self {
        let help = HelpOption {
            phantom: PhantomData,
        };
        opts.optflag(help.get_short_name(), "help", "Show this help string.");
        help
    }

    /// Return the short_name used by the HelpOption for direct use with Options.
    pub fn get_short_name(&self) -> &str {
        HELP_OPTION_SHORT_NAME
    }

    /// Mocks process::exit for testability. See: parse_and_check_self
    fn parse_and_check_self_impl<F: Fn(i32)>(
        &self,
        opts: &Options,
        args: &[String],
        get_usage: fn() -> String,
        exit_fn: F,
    ) -> Option<Matches> {
        let matches = opts.parse(args).map(Some).unwrap_or_else(|e| {
            eprintln!("{}", e);
            println!("{}", opts.usage(&get_usage()));
            exit_fn(1);
            None
        })?;

        if matches.opt_present(self.get_short_name()) {
            println!("{}", opts.usage(&get_usage()));
            exit_fn(0);
        }

        Some(matches)
    }

    /// A wrapper around Options::parse that handles printing the help string on a parsing error or
    /// when the help option is set.
    pub fn parse_and_check_self(
        &self,
        opts: &Options,
        args: &[String],
        get_usage: fn() -> String,
    ) -> Matches {
        // See: https://github.com/rust-lang/rust-clippy/issues/8416
        #[allow(clippy::redundant_closure)]
        self.parse_and_check_self_impl(opts, args, get_usage, |x| exit(x))
            .unwrap()
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::rc::Rc;

    use assert_matches::assert_matches;

    use super::*;

    fn test_usage() -> String {
        "test usage string".to_string()
    }

    fn get_counted_mock_exit(expected: i32) -> (Rc<RefCell<usize>>, impl Fn(i32)) {
        let counter = Rc::new(RefCell::new(0usize));
        (counter.clone(), move |code: i32| {
            assert_eq!(code, expected);
            *counter.borrow_mut() += 1;
        })
    }

    #[test]
    fn transporttypeoption_frommatches_notset() {
        let test_args: Vec<String> = Vec::new();

        let mut opts = Options::new();
        let url_option = TransportTypeOption::default(&mut opts);

        let matches = opts.parse(&test_args).unwrap();

        assert_matches!(url_option.from_matches(&matches), Ok(None));
    }

    #[test]
    fn transporttypeoption_frommatches_valid() {
        let test_args: Vec<String> = vec!["-U".to_string(), LOOPBACK_DEFAULT.to_string()];

        let mut opts = Options::new();
        let url_option = TransportTypeOption::default(&mut opts);

        let matches = opts.parse(&test_args).unwrap();
        assert_matches!(url_option.from_matches(&matches), Ok(Some(_)));
    }

    #[test]
    fn transporttypeoption_frommatches_notvalid() {
        let test_args: Vec<String> =
            vec!["-U".to_string(), "not a valid transport type".to_string()];

        let mut opts = Options::new();
        let url_option = TransportTypeOption::default(&mut opts);

        let matches = opts.parse(&test_args).unwrap();
        assert_matches!(
            url_option.from_matches(&matches),
            Err(Error::TransportParse(_))
        );
    }

    #[test]
    fn helpoption_parseandcheckself_notset() {
        let test_args: Vec<String> = Vec::new();

        let mut opts = Options::new();
        let help_option = HelpOption::new(&mut opts);
        help_option.parse_and_check_self_impl(&opts, &test_args, test_usage, |_| panic!());
    }

    #[test]
    fn helpoption_parseandcheckself_set() {
        let test_args: Vec<String> = vec!["-h".to_string()];
        let (counter, exit_fn) = get_counted_mock_exit(0);

        let mut opts = Options::new();
        let help_option = HelpOption::new(&mut opts);
        let matches = help_option.parse_and_check_self_impl(&opts, &test_args, test_usage, exit_fn);
        assert!(matches.is_some());
        assert_eq!(*counter.borrow(), 1);
    }

    #[test]
    fn helpoption_parseandcheckself_invalid() {
        let test_args: Vec<String> = vec!["--not-an-option".to_string()];
        let (counter, exit_fn) = get_counted_mock_exit(1);

        let mut opts = Options::new();
        let help_option = HelpOption::new(&mut opts);
        let matches = help_option.parse_and_check_self_impl(&opts, &test_args, test_usage, exit_fn);
        assert!(matches.is_none());
        assert_eq!(*counter.borrow(), 1);
    }
}
