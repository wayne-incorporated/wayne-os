// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <optional>
#include <set>
#include <utility>

#include <cryptohome/proto_bindings/UserDataAuth.pb.h>
#include <gtest/gtest.h>
#include <libhwsec/error/tpm1_error.h>
#include <libhwsec-foundation/status/status_chain.h>

#include "cryptohome/error/action.h"
#include "cryptohome/error/cryptohome_tpm_error.h"

namespace cryptohome {

namespace error {

class CryptohomeTPM1ErrorTest : public ::testing::Test {};

namespace {

using hwsec::TPM1Error;
using hwsec::TPMRetryAction;
using hwsec_foundation::status::MakeStatus;
using hwsec_foundation::status::StatusChain;

TEST_F(CryptohomeTPM1ErrorTest, FromTPM1ErrorSize) {
  auto tpm_err = MakeStatus<TPM1Error>(TPM_E_SIZE);
  // TPM_E_SIZE results in TPMRetryAction::kReboot and PossibleAction::kReboot.

  auto err1 = MakeStatus<CryptohomeTPMError>(std::move(tpm_err));

  ASSERT_FALSE(err1.ok());
  EXPECT_EQ(err1->local_location(),
            static_cast<CryptohomeError::ErrorLocation>(TPM_E_SIZE) |
                hwsec::unified_tpm_error::kUnifiedErrorBit);
  EXPECT_EQ(err1->local_actions(), ErrorActionSet({PossibleAction::kReboot}));
  EXPECT_EQ(err1->ToTPMRetryAction(), TPMRetryAction::kReboot);
}

TEST_F(CryptohomeTPM1ErrorTest, FromTPM1ErrorDefend) {
  auto tpm_err = MakeStatus<TPM1Error>(TPM_E_DEFEND_LOCK_RUNNING);
  // TPM_E_DEFEND_LOCK_RUNNING results in TPMRetryAction::kDefend and
  // PrimaryAction::kTpmLockout.

  auto err1 = MakeStatus<CryptohomeTPMError>(std::move(tpm_err));

  ASSERT_FALSE(err1.ok());
  EXPECT_EQ(
      err1->local_location(),
      static_cast<CryptohomeError::ErrorLocation>(TPM_E_DEFEND_LOCK_RUNNING) |
          hwsec::unified_tpm_error::kUnifiedErrorBit);
  EXPECT_EQ(err1->local_actions(), ErrorActionSet(PrimaryAction::kTpmLockout));
  EXPECT_EQ(err1->ToTPMRetryAction(), TPMRetryAction::kDefend);
}

TEST_F(CryptohomeTPM1ErrorTest, FromTPM1ErrorComm) {
  auto tpm_err = MakeStatus<TPM1Error>(TSS_E_COMM_FAILURE);
  // TSS_E_COMM_FAILURE results in TPMRetryAction::kCommunication and
  // PossibleAction::kReboot.

  auto err1 = MakeStatus<CryptohomeTPMError>(std::move(tpm_err));

  ASSERT_FALSE(err1.ok());
  EXPECT_EQ(err1->local_location(),
            static_cast<CryptohomeError::ErrorLocation>(TSS_E_COMM_FAILURE) |
                hwsec::unified_tpm_error::kUnifiedErrorBit);
  EXPECT_EQ(err1->local_actions(), ErrorActionSet({PossibleAction::kReboot}));
  EXPECT_EQ(err1->ToTPMRetryAction(), TPMRetryAction::kCommunication);
}

TEST_F(CryptohomeTPM1ErrorTest, FromTPM1ErrorSuccess) {
  StatusChain<TPM1Error> tpm_err;
  auto err1 = MakeStatus<CryptohomeTPMError>(std::move(tpm_err));

  EXPECT_TRUE(err1.ok());
}

}  // namespace

}  // namespace error

}  // namespace cryptohome
