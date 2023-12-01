// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_STRUCTURES_PERMISSION_H_
#define LIBHWSEC_STRUCTURES_PERMISSION_H_

#include <optional>

#include <brillo/secure_blob.h>

#include "libhwsec/structures/device_config.h"

namespace hwsec {

// The way to provide the permission inside the command.
// For TPM1.2, we only support auth value.
// For TPM2.0, we supported both methods, but some commands may not work with
// the auth value mode. (e.g. KeyManagement::GetPolicyEndorsementKey)
enum class PermissionType {
  kAuthValue,
  kPolicyOR,
};

struct Permission {
  // The default permission mode is "auth value"
  PermissionType type = PermissionType::kAuthValue;
  std::optional<brillo::SecureBlob> auth_value;
};

}  // namespace hwsec

#endif  // LIBHWSEC_STRUCTURES_PERMISSION_H_
