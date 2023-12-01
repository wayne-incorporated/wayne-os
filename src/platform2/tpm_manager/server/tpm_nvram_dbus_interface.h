// Copyright 2015 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TPM_MANAGER_SERVER_TPM_NVRAM_DBUS_INTERFACE_H_
#define TPM_MANAGER_SERVER_TPM_NVRAM_DBUS_INTERFACE_H_

namespace tpm_manager {

inline constexpr char kTpmNvramInterface[] = "org.chromium.TpmNvram";

// Methods exported by tpm_manager nvram D-Bus interface.
inline constexpr char kDefineSpace[] = "DefineSpace";
inline constexpr char kDestroySpace[] = "DestroySpace";
inline constexpr char kWriteSpace[] = "WriteSpace";
inline constexpr char kReadSpace[] = "ReadSpace";
inline constexpr char kLockSpace[] = "LockSpace";
inline constexpr char kListSpaces[] = "ListSpaces";
inline constexpr char kGetSpaceInfo[] = "GetSpaceInfo";

}  // namespace tpm_manager

#endif  // TPM_MANAGER_SERVER_TPM_NVRAM_DBUS_INTERFACE_H_
