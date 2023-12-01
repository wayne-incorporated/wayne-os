// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TPM_MANAGER_SERVER_FUZZERS_TPM_FUZZER_UTILS_IMPL_H_
#define TPM_MANAGER_SERVER_FUZZERS_TPM_FUZZER_UTILS_IMPL_H_

#include <fuzzer/FuzzedDataProvider.h>

#include "tpm_manager/server/fuzzers/tpm_fuzzer_utils.h"
#include "tpm_manager/server/tpm_manager_service.h"

namespace tpm_manager {

class TpmFuzzerUtilsImpl : public TpmFuzzerUtils {
 public:
  explicit TpmFuzzerUtilsImpl(FuzzedDataProvider* data_provider)
      : data_provider_(data_provider) {}
  void SetupTpm(TpmManagerService* tpm_manager) override;

 private:
  FuzzedDataProvider* const data_provider_;
};

}  // namespace tpm_manager

#endif  // TPM_MANAGER_SERVER_FUZZERS_TPM_FUZZER_UTILS_IMPL_H_
