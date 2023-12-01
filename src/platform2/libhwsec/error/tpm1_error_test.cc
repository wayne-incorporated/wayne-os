// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
#include "libhwsec/error/tpm1_error.h"
#include "libhwsec-foundation/error/testing_helper.h"

#include <type_traits>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

namespace hwsec {

using ::hwsec_foundation::error::testing::IsOk;
using ::hwsec_foundation::error::testing::NotOk;
using ::hwsec_foundation::status::MakeStatus;
using ::hwsec_foundation::status::StatusChain;

class TestingTPM1ErrorTest : public ::testing::Test {
 public:
  TestingTPM1ErrorTest() {}
  ~TestingTPM1ErrorTest() override = default;
};

TEST_F(TestingTPM1ErrorTest, MakeStatus) {
  StatusChain<TPM1Error> status = MakeStatus<TPM1Error>(TSS_SUCCESS);
  EXPECT_THAT(status, IsOk());

  status = MakeStatus<TPM1Error>(TSS_LAYER_TCS | TSS_E_COMM_FAILURE);
  EXPECT_THAT(status, NotOk());
}

TEST_F(TestingTPM1ErrorTest, TPMRetryAction) {
  StatusChain<TPM1Error> status =
      MakeStatus<TPM1Error>(TSS_LAYER_TCS | TSS_E_COMM_FAILURE);
  ASSERT_NOT_OK(status);
  EXPECT_EQ(status->ToTPMRetryAction(), TPMRetryAction::kCommunication);
  EXPECT_EQ(status->UnifiedErrorCode(),
            unified_tpm_error::kUnifiedErrorBit |
                static_cast<int64_t>(TSS_LAYER_TCS | TSS_E_COMM_FAILURE));

  StatusChain<TPMError> status2 =
      MakeStatus<TPMError>("OuO").Wrap(std::move(status));
  EXPECT_EQ("OuO: TPM error 0x2011 (Communication failure)",
            status2.ToFullString());
  EXPECT_EQ(status2->ToTPMRetryAction(), TPMRetryAction::kCommunication);
}

TEST_F(TestingTPM1ErrorTest, UnifiedErrorCode) {
  StatusChain<TPM1Error> status = MakeStatus<TPM1Error>(TSS_E_COMM_FAILURE);
  ASSERT_NOT_OK(status);
  EXPECT_EQ(status->UnifiedErrorCode(),
            unified_tpm_error::kUnifiedErrorBit |
                static_cast<int64_t>(TSS_E_COMM_FAILURE));
}

}  // namespace hwsec
