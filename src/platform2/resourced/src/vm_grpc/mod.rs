// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

mod proto;

#[cfg(feature = "vm_grpc")]
pub(crate) mod vm_grpc_server;

#[cfg(feature = "vm_grpc")]
pub(crate) mod vm_grpc_client;

#[cfg(feature = "vm_grpc")]
pub(crate) mod vm_grpc_util;

#[cfg(feature = "vm_grpc")]
pub(crate) mod battery_helper;
