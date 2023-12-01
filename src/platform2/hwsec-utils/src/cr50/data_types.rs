// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::fmt;
use std::fmt::Display;

pub type SnBits = [u8; 12];

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct RmaSnBits {
    pub sn_data_version: [u8; 3],
    pub rma_status: u8,
    pub sn_bits: SnBits,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Version {
    pub epoch: u8,
    pub major: u8,
    pub minor: u8,
}

impl Version {
    pub fn to_ord(&self) -> u32 {
        ((self.epoch as u32) << 16) | ((self.major as u32) << 8) | (self.minor as u32)
    }
    pub fn is_prod_image(&self) -> bool {
        self.major % 2 == 1
    }
}

impl Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}.{}.{}", self.epoch, self.major, self.minor)
    }
}
