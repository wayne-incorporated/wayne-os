// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::process::Output;

pub struct HwsecStatus {
    exit_code: i32,
}

impl HwsecStatus {
    pub fn from_raw(exit_status: i32) -> Self {
        Self {
            exit_code: exit_status,
        }
    }
    pub fn success(&self) -> bool {
        self.exit_code == 0
    }
    pub fn code(&self) -> Option<i32> {
        Some(self.exit_code)
    }
}

pub struct HwsecOutput {
    pub status: HwsecStatus,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

impl HwsecOutput {
    pub fn from_output(output: Output) -> Self {
        if output.status.code().is_none() {
            Self {
                status: HwsecStatus { exit_code: -1 },
                stdout: Vec::<u8>::new(),
                stderr: Vec::<u8>::new(),
            }
        } else {
            Self {
                status: HwsecStatus {
                    exit_code: output.status.code().unwrap(),
                },
                stdout: output.stdout,
                stderr: output.stderr,
            }
        }
    }
}
