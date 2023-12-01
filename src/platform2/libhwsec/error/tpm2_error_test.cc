// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "libhwsec/error/tpm2_error.h"
#include "libhwsec-foundation/error/testing_helper.h"

#include <type_traits>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

namespace hwsec {

using ::hwsec_foundation::error::testing::IsOk;
using ::hwsec_foundation::error::testing::NotOk;
using ::hwsec_foundation::status::MakeStatus;
using ::hwsec_foundation::status::StatusChain;

static_assert(unified_tpm_error::kHwsecTpmErrorBase == trunks::kTrunksErrorBase,
              "kHwsecTpmErrorBase and kTrunksErrorBase mismatch.");

class TestingTPM2ErrorTest : public ::testing::Test {
 public:
  TestingTPM2ErrorTest() {}
  ~TestingTPM2ErrorTest() override = default;
};

TEST_F(TestingTPM2ErrorTest, MakeStatus) {
  StatusChain<TPM2Error> status = MakeStatus<TPM2Error>(trunks::TPM_RC_SUCCESS);
  EXPECT_THAT(status, IsOk());

  status = MakeStatus<TPM2Error>(trunks::TPM_RC_HANDLE | trunks::TPM_RC_1);
  EXPECT_THAT(status, NotOk());
}

TEST_F(TestingTPM2ErrorTest, TPMRetryAction) {
  StatusChain<TPMErrorBase> status =
      MakeStatus<TPM2Error>(trunks::TPM_RC_HANDLE | trunks::TPM_RC_1);
  EXPECT_EQ(status->ToTPMRetryAction(), TPMRetryAction::kLater);

  StatusChain<TPMError> status2 =
      MakeStatus<TPMError>("OuO|||").Wrap(std::move(status));
  EXPECT_EQ("OuO|||: TPM2 error 0x18b (Handle 1: TPM_RC_HANDLE)",
            status2.ToFullString());
  EXPECT_EQ(status2->ToTPMRetryAction(), TPMRetryAction::kLater);
}

TEST_F(TestingTPM2ErrorTest, UnifiedErrorUsual) {
  StatusChain<TPMErrorBase> status =
      MakeStatus<TPM2Error>(trunks::TPM_RC_HANDLE | trunks::TPM_RC_1);
  EXPECT_EQ(status->UnifiedErrorCode(),
            unified_tpm_error::kUnifiedErrorBit |
                static_cast<int64_t>(trunks::TPM_RC_HANDLE | trunks::TPM_RC_1));
}

TEST_F(TestingTPM2ErrorTest, UnifiedErrorExtraLayers) {
  StatusChain<TPMErrorBase> status =
      MakeStatus<TPM2Error>(trunks::TRUNKS_RC_IPC_ERROR);
  EXPECT_EQ(status->UnifiedErrorCode(),
            static_cast<int64_t>(trunks::TRUNKS_RC_IPC_ERROR) |
                unified_tpm_error::kUnifiedErrorBit);
}

}  // namespace hwsec
