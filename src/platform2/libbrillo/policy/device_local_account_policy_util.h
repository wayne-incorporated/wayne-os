// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBBRILLO_POLICY_DEVICE_LOCAL_ACCOUNT_POLICY_UTIL_H_
#define LIBBRILLO_POLICY_DEVICE_LOCAL_ACCOUNT_POLICY_UTIL_H_

#include <string>

#include <brillo/brillo_export.h>
#include "bindings/chrome_device_policy.pb.h"

namespace policy {
// Both CanonicalizeEmail and GenerateDeviceLocalAccountUserId is
// copied logic from chromium.
// CanonicalizeEmail -
// https://source.chromium.org/chromium/chromium/src/+/main:google_apis/gaia/gaia_auth_util.cc;l=33
// GenerateDeviceLocalAccountUserId -
// https://source.chromium.org/chromium/chromium/src/+/main:chrome/browser/ash/policy/core/device_local_account.cc;l=112
// TODO(b/274430070): Cleanup plan with more details in the bug link.
BRILLO_EXPORT std::string CanonicalizeEmail(const std::string& email_address);

BRILLO_EXPORT std::string GenerateDeviceLocalAccountUserId(
    const std::string& account_id,
    enterprise_management::DeviceLocalAccountInfoProto::AccountType type);

}  // namespace policy

#endif  // LIBBRILLO_POLICY_DEVICE_LOCAL_ACCOUNT_POLICY_UTIL_H_
