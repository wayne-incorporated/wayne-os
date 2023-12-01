// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Ties together the various modules that make up the Sirenia library used by
//! both Trichechus and Dugong.

#![deny(unsafe_op_in_unsafe_fn)]

pub mod build_info {
    include!(concat!(env!("OUT_DIR"), "/build_info.rs"));
}
pub mod app_info;
pub mod cli;
pub mod communication;
pub mod linux;
pub mod rpc;
pub mod sandbox;
pub mod secrets;
pub mod storage;
pub mod sys;
pub mod transport;
