// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#[cfg(feature = "vm_grpc")]
pub(crate) mod resourced_bridge;

#[cfg(feature = "vm_grpc")]
pub(crate) mod resourced_bridge_grpc;

#[cfg(feature = "vm_grpc")]
pub(crate) mod arc;

#[cfg(feature = "vm_grpc")]
pub(crate) mod concierge_service;
