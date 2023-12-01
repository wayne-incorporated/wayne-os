// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use crate::command_runner::CommandRunner;
use crate::error::HwsecError;

mod real;
pub use real::*;

#[cfg(test)]
pub(crate) mod mock;

pub trait Context {
    type CommandRunner: CommandRunner;
    fn cmd_runner(&mut self) -> &mut Self::CommandRunner;
    fn path_exists(&mut self, path_str: &str) -> bool;
    fn read_file_to_string(&mut self, path_str: &str) -> Result<String, HwsecError>;
    fn write_contents_to_file(&mut self, path_str: &str, contents: &[u8])
        -> Result<(), HwsecError>;
    fn sleep(&mut self, sec: u64);
}
