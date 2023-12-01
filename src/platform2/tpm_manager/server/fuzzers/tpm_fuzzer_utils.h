// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TPM_MANAGER_SERVER_FUZZERS_TPM_FUZZER_UTILS_H_
#define TPM_MANAGER_SERVER_FUZZERS_TPM_FUZZER_UTILS_H_

#include "tpm_manager/server/tpm_manager_service.h"

namespace tpm_manager {

class TpmFuzzerUtils {
 public:
  TpmFuzzerUtils() = default;
  virtual ~TpmFuzzerUtils() = default;

  virtual void SetupTpm(TpmManagerService* tpm_manager) = 0;
};

}  // namespace tpm_manager

#endif  // TPM_MANAGER_SERVER_FUZZERS_TPM_FUZZER_UTILS_H_
