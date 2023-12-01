// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::fmt;

#[derive(Copy, Clone)]
pub enum DiskOpType {
    Create,
    Resize,
}

impl Default for DiskOpType {
    fn default() -> Self {
        DiskOpType::Create
    }
}

#[derive(Copy, Clone, Debug)]
pub enum VmDiskImageType {
    Raw,
    Qcow2,
    Auto,
    PluginVm,
}

impl fmt::Display for VmDiskImageType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            VmDiskImageType::Raw => write!(f, "raw"),
            VmDiskImageType::Qcow2 => write!(f, "qcow2"),
            VmDiskImageType::Auto => write!(f, "auto"),
            VmDiskImageType::PluginVm => write!(f, "pvm"),
        }
    }
}

impl Default for VmDiskImageType {
    fn default() -> Self {
        VmDiskImageType::Auto
    }
}

/// Information about a single VM disk image.
#[derive(Default, Debug)]
pub struct DiskInfo {
    /// Name of the VM contained in this disk.
    pub name: String,
    /// Size of the disk in bytes.
    pub size: u64,
    /// Minimum size the disk image may be resized to, if known.
    pub min_size: Option<u64>,
    /// Disk image type (raw, QCOW2, etc.).
    pub image_type: VmDiskImageType,
    /// Whether the disk size is user-specified (true) or automatically sized (false).
    pub user_chosen_size: bool,
}
