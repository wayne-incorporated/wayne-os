// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Module to contain all the protobuf generated code.

extern crate protobuf;

include!(concat!(env!("OUT_DIR"), "/proto_include.rs"));
