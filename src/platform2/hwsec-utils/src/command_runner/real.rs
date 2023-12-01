// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::process::Command;

use super::CommandRunner;
use crate::output::HwsecOutput;
pub struct RealCommandRunner;

impl CommandRunner for RealCommandRunner {
    fn run(&mut self, cmd_name: &str, args: Vec<&str>) -> Result<HwsecOutput, std::io::Error> {
        Command::new(cmd_name)
            .args(args)
            .output()
            .map(HwsecOutput::from_output)
    }
    fn output(&mut self, cmd_name: &str, args: Vec<&str>) -> Result<String, std::io::Error> {
        let run_result = self.run(cmd_name, args)?;
        Ok(String::from_utf8_lossy(&run_result.stdout).to_string())
    }
}
