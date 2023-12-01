// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "libhwsec-foundation/tpm_error/auth_failure_analysis.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "libhwsec-foundation/tpm/tpm_version.h"
#include "libhwsec-foundation/tpm_error/tpm_error_constants.h"
#include "libhwsec-foundation/tpm_error/tpm_error_data.h"

namespace hwsec_foundation {

#if USE_TPM2
TEST(DoesCauseDAIncreaseTest, AlwaysReturnFalseForTpm2) {
  SET_TPM2_FOR_TESTING;
  TpmErrorData data = {};
  EXPECT_FALSE(DoesCauseDAIncrease(data));
  data.response = kTpm1AuthFailResponse;
  EXPECT_FALSE(DoesCauseDAIncrease(data));
  data.response = kTpm1Auth2FailResponse;
  EXPECT_FALSE(DoesCauseDAIncrease(data));
}
#endif

#if USE_TPM1
TEST(DoesCauseDAIncreaseTest, ReturnFalseForNonAuthFailure) {
  SET_TPM1_FOR_TESTING;
  TpmErrorData data = {};
  EXPECT_FALSE(DoesCauseDAIncrease(data));
}

TEST(DoesCauseDAIncreaseTest, ReturnTrueForAuthFailure) {
  SET_TPM1_FOR_TESTING;
  TpmErrorData data = {};
  data.response = kTpm1AuthFailResponse;
  EXPECT_TRUE(DoesCauseDAIncrease(data));
  data.response = kTpm1Auth2FailResponse;
  EXPECT_TRUE(DoesCauseDAIncrease(data));
}
#endif

}  // namespace hwsec_foundation
