// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TPM_MANAGER_COMMON_TYPEDEFS_H_
#define TPM_MANAGER_COMMON_TYPEDEFS_H_

#include <base/functional/callback.h>

namespace tpm_manager {
using OwnershipTakenCallBack = base::RepeatingClosure;
}  // namespace tpm_manager

#endif  // TPM_MANAGER_COMMON_TYPEDEFS_H_
