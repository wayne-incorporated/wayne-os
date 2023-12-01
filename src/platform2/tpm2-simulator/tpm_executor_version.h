// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TPM2_SIMULATOR_TPM_EXECUTOR_VERSION_H_
#define TPM2_SIMULATOR_TPM_EXECUTOR_VERSION_H_

#include "tpm2-simulator/export.h"

namespace tpm2_simulator {

enum class TpmExecutorVersion {
  kTpm2 = 0,
  kTpm1 = 1,
  kTi50 = 2,
};

// A function to get the TPM executor version.
TPM2_SIMULATOR_EXPORT TpmExecutorVersion GetTpmExecutorVersion();

}  // namespace tpm2_simulator

#endif  // TPM2_SIMULATOR_TPM_EXECUTOR_VERSION_H_
