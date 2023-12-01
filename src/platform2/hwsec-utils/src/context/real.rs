// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use libchromeos::error;

use super::Context;
use crate::command_runner::RealCommandRunner;
use crate::error::HwsecError;

pub struct RealContext {
    cmd_runner: RealCommandRunner,
}
impl Default for RealContext {
    fn default() -> Self {
        Self::new()
    }
}
impl RealContext {
    pub fn new() -> Self {
        Self {
            cmd_runner: RealCommandRunner,
        }
    }
}

impl Context for RealContext {
    type CommandRunner = RealCommandRunner;
    fn cmd_runner(&mut self) -> &mut Self::CommandRunner {
        &mut self.cmd_runner
    }

    fn path_exists(&mut self, path_str: &str) -> bool {
        std::path::Path::new(path_str).exists()
    }

    fn read_file_to_string(&mut self, path_str: &str) -> Result<String, HwsecError> {
        match std::fs::read_to_string(path_str) {
            Ok(file_string) => Ok(file_string),
            Err(_) => {
                error!("Failed to read {}", path_str);
                Err(HwsecError::FileError)
            }
        }
    }

    fn write_contents_to_file(
        &mut self,
        path_str: &str,
        contents: &[u8],
    ) -> Result<(), HwsecError> {
        match std::fs::write(path_str, contents) {
            Ok(_) => Ok(()),
            Err(_) => {
                error!("Failed to write {}", path_str);
                Err(HwsecError::FileError)
            }
        }
    }

    fn sleep(&mut self, sec: u64) {
        use core::time;
        use std::thread;
        thread::sleep(time::Duration::from_secs(sec));
    }
}
