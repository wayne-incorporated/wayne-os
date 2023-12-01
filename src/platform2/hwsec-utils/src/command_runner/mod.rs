// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

mod real;
pub use real::*;

#[cfg(test)]
mod mock;
#[cfg(test)]
pub use mock::*;

use crate::output::HwsecOutput;

pub trait CommandRunner {
    fn run(&mut self, cmd_name: &str, args: Vec<&str>) -> Result<HwsecOutput, std::io::Error>;
    fn output(&mut self, cmd_name: &str, args: Vec<&str>) -> Result<String, std::io::Error>;
}
