// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// TODO(b/247385169): get these from system_api c++ header instead

pub const SERVICE_NAME: &str = "org.chromium.ShaderCache";
pub const PATH_NAME: &str = "/org/chromium/ShaderCache";
pub const INTERFACE_NAME: &str = SERVICE_NAME;

pub const INSTALL_METHOD: &str = "Install";
pub const UNINSTALL_METHOD: &str = "Uninstall";
pub const PURGE_METHOD: &str = "Purge";
pub const UNMOUNT_METHOD: &str = "Unmount";
pub const PREPARE_SHADER_CACHE_METHOD: &str = "PrepareShaderCache";

pub const MOUNT_STATUS_CHANGED_SIGNAL: &str = "ShaderCacheMountStatusChanged";

pub mod dlc_service {
    pub const SERVICE_NAME: &str = "org.chromium.DlcService";
    pub const PATH_NAME: &str = "/org/chromium/DlcService";
    pub const INTERFACE_NAME: &str = "org.chromium.DlcServiceInterface";

    pub const INSTALL_METHOD: &str = "InstallDlc";
    pub const UNINSTALL_METHOD: &str = "Uninstall";
    pub const GET_INSTALLED_METHOD: &str = "GetInstalled";

    pub const DLC_STATE_CHANGED_SIGNAL: &str = "DlcStateChanged";
}

pub mod vm_concierge {
    pub const SERVICE_NAME: &str = "org.chromium.VmConcierge";
    pub const PATH_NAME: &str = "/org/chromium/VmConcierge";
    pub const INTERFACE_NAME: &str = "org.chromium.VmConcierge";

    pub const ADD_GROUP_PERMISSION_MESA_METHOD: &str = "AddGroupPermissionMesa";
    pub const GET_VM_GPU_CACHE_PATH_METHOD: &str = "GetVmGpuCachePath";

    pub const VM_STOPPING_SIGNAL: &str = "VmStoppingSignal";
}

pub mod spaced {
    // pub const SERVICE_NAME: &str = "org.chromium.Spaced";
    // pub const PATH_NAME: &str = "/org/chromium/Spaced";
    pub const INTERFACE_NAME: &str = "org.chromium.Spaced";

    pub const STATEFUL_DISK_SPACE_UPDATE: &str = "StatefulDiskSpaceUpdate";
}
