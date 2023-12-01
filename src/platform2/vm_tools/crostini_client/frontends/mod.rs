// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::collections::BTreeMap;
use std::error::Error;

mod vmc;

use crate::methods::Methods;
use vmc::Vmc;

/// A string to string mapping of environment variables to values.
pub type EnvMap<'a> = BTreeMap<&'a str, &'a str>;

/// Each frontend implements a command line style interface that executes against the given
/// `methods`.
pub trait Frontend {
    /// Get the name of this frontend.
    fn name(&self) -> &str;

    /// Prints the command line style usage of this frontend.
    fn print_usage(&self, program_name: &str);

    /// Parses the command line style `args` and environment variables and runs the chosen
    /// command against the given `methods`.
    fn run(
        &self,
        methods: &mut Methods,
        args: &[&str],
        environ: &EnvMap,
    ) -> Result<(), Box<dyn Error>>;
}

/// An array of all frontends.
pub const FRONTENDS: &[&dyn Frontend] = &[&Vmc];
