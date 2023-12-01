// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <optional>
#include <set>
#include <utility>

#include <cryptohome/proto_bindings/UserDataAuth.pb.h>
#include <gtest/gtest.h>
#include <libhwsec/error/tpm2_error.h>
#include <libhwsec-foundation/status/status_chain.h>

#include "cryptohome/error/action.h"
#include "cryptohome/error/cryptohome_tpm_error.h"

namespace cryptohome {

namespace error {

class CryptohomeTPM2ErrorTest : public ::testing::Test {};

namespace {

using hwsec::TPM2Error;
using hwsec::TPMRetryAction;
using hwsec_foundation::status::MakeStatus;
using hwsec_foundation::status::StatusChain;

TEST_F(CryptohomeTPM2ErrorTest, FromTPM2ErrorHandle) {
  auto tpm_err = MakeStatus<TPM2Error>(trunks::TPM_RC_HANDLE);
  // TPM_RC_HANDLE results in TPMRetryAction::kLater and PossibleAction::kRetry.

  auto err1 = MakeStatus<CryptohomeTPMError>(std::move(tpm_err));

  ASSERT_FALSE(err1.ok());
  EXPECT_EQ(err1->local_location(),
            static_cast<CryptohomeError::ErrorLocation>(trunks::TPM_RC_HANDLE) |
                hwsec::unified_tpm_error::kUnifiedErrorBit);
  EXPECT_EQ(err1->local_actions(), ErrorActionSet({PossibleAction::kRetry}));
  EXPECT_EQ(err1->ToTPMRetryAction(), TPMRetryAction::kLater);
}

TEST_F(CryptohomeTPM2ErrorTest, FromTPM2Error) {
  auto tpm_err = MakeStatus<TPM2Error>(trunks::TRUNKS_RC_WRITE_ERROR);
  // trunks::TRUNKS_RC_WRITE_ERROR results in TPMRetryAction::kCommunication and
  // PossibleAction::kReboot.

  auto err1 = MakeStatus<CryptohomeTPMError>(std::move(tpm_err));

  ASSERT_FALSE(err1.ok());
  EXPECT_EQ(err1->local_location(),
            static_cast<CryptohomeError::ErrorLocation>(
                trunks::TRUNKS_RC_WRITE_ERROR) |
                hwsec::unified_tpm_error::kUnifiedErrorBit);
  EXPECT_EQ(err1->local_actions(), ErrorActionSet({PossibleAction::kReboot}));
  EXPECT_EQ(err1->ToTPMRetryAction(), TPMRetryAction::kCommunication);
}

TEST_F(CryptohomeTPM2ErrorTest, FromTPM2ErrorSuccess) {
  StatusChain<TPM2Error> tpm_err;
  auto err1 = MakeStatus<CryptohomeTPMError>(std::move(tpm_err));

  EXPECT_TRUE(err1.ok());
}

}  // namespace

}  // namespace error

}  // namespace cryptohome
