// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SMBPROVIDER_MOUNT_CONFIG_H_
#define SMBPROVIDER_MOUNT_CONFIG_H_

namespace smbprovider {

struct MountConfig {
  explicit MountConfig(bool enable_ntlm) : enable_ntlm(enable_ntlm) {}

  MountConfig(MountConfig&& other) = default;
  MountConfig(const MountConfig&) = delete;
  MountConfig& operator=(const MountConfig&) = delete;

  MountConfig& operator=(MountConfig&& other) = default;

  // If true, NTLM will be the fallback authentication protocol. If false, NTLM
  // fallback is disabled and only kerberos authentication may be used.
  bool enable_ntlm;
};

}  // namespace smbprovider

#endif  // SMBPROVIDER_MOUNT_CONFIG_H_
