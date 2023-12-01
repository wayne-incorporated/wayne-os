// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "tpm_manager/server/fuzzers/tpm_fuzzer_utils_impl.h"

#include <libhwsec-foundation/fuzzed_trousers_utils.h>

namespace tpm_manager {

void TpmFuzzerUtilsImpl::SetupTpm(TpmManagerService* tpm_manager) {
  hwsec_foundation::FuzzedTrousersSetup(data_provider_);
}

}  // namespace tpm_manager
