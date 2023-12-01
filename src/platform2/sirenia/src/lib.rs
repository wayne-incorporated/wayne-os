// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Ties together the various modules that make up the Sirenia library used by
//! both Trichechus and Dugong.

#![deny(unsafe_op_in_unsafe_fn)]

include!("bindings/include_modules.rs");

pub mod pstore;

use std::fs;

use anyhow::Result;
use log::error;

const CORE_PATTERN_FILE: &str = "/proc/sys/kernel/core_pattern";
const CORE_PATTERN_LIMIT_FILE: &str = "/proc/sys/kernel/core_pipe_limit";
const CORE_PIPE_LIMIT: &str = "4";
const CORE_HANDLER_PATH: &str = "/bin/manatee_crash_handler";

pub fn log_error<T, E: std::fmt::Debug>(ret: Result<T, E>) -> Result<T, E> {
    if let Err(err) = &ret {
        error!("Got error: {:?}", err);
    }
    ret
}

pub fn install_crash_handler() -> Result<()> {
    let pattern = String::from("|") + CORE_HANDLER_PATH + " %P %I %s %u %g %f";
    fs::write(CORE_PATTERN_LIMIT_FILE, CORE_PIPE_LIMIT)?;
    fs::write(CORE_PATTERN_FILE, pattern)?;
    Ok(())
}
