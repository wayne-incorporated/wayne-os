// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <string>

#include <base/logging.h>
#include <brillo/hash/MurmurHash3.h>

#include "libhwsec/error/tpm_error.h"
#include "libhwsec/error/tpm_retry_action.h"

namespace hwsec {

namespace {

using unified_tpm_error::UnifiedError;

// Just a random number.
constexpr uint32_t kUnifiedErrorHashSeed = 42;

uint32_t HashStringWithMurmurHash3x8632(const std::string& s) {
  uint32_t result;
  brillo::MurmurHash3_x86_32(s.c_str(), s.size() + 1, kUnifiedErrorHashSeed,
                             &result);
  return result;
}

}  // namespace

int64_t TPMError::CalculateUnifiedErrorCode(const std::string& msg) {
  auto hashed = HashStringWithMurmurHash3x8632(msg);
  int64_t result = ((static_cast<int64_t>(hashed) &
                     unified_tpm_error::kUnifiedErrorHashedTpmErrorMask) |
                    unified_tpm_error::kUnifiedErrorHashedTpmErrorBase) |
                   unified_tpm_error::kUnifiedErrorBit;
  return result;
}

void TPMError::LogUnifiedErrorCodeMapping() const {
  LOG(INFO) << "TPMUnified" << UnifiedErrorCode()
            << " is mapped from generic TPM error message '" << ToString()
            << "'";
}

}  // namespace hwsec
