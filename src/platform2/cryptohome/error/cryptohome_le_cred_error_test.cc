// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <optional>
#include <set>
#include <string>
#include <utility>

#include <cryptohome/proto_bindings/UserDataAuth.pb.h>
#include <dbus/cryptohome/dbus-constants.h>
#include <gtest/gtest.h>
#include <libhwsec-foundation/status/status_chain.h>

#include "cryptohome/error/cryptohome_le_cred_error.h"

namespace cryptohome {

namespace error {

class CryptohomeLECredErrorTest : public ::testing::Test {
 protected:
  const CryptohomeError::ErrorLocationPair kErrorLocationForTesting1 =
      CryptohomeError::ErrorLocationPair(
          static_cast<::cryptohome::error::CryptohomeError::ErrorLocation>(1),
          std::string("Testing1"));
};

namespace {

using hwsec_foundation::status::MakeStatus;
using hwsec_foundation::status::StatusChain;

TEST_F(CryptohomeLECredErrorTest, BasicConstruction) {
  auto err1 = MakeStatus<CryptohomeLECredError>(
      kErrorLocationForTesting1, ErrorActionSet({PossibleAction::kFatal}),
      LECredError::LE_CRED_ERROR_TOO_MANY_ATTEMPTS);

  ASSERT_FALSE(err1.ok());
  EXPECT_EQ(err1->local_location(), kErrorLocationForTesting1.location());
  EXPECT_EQ(err1->local_actions(), ErrorActionSet({PossibleAction::kFatal}));
  EXPECT_EQ(
      err1->local_legacy_error().value(),
      user_data_auth::CryptohomeErrorCode::CRYPTOHOME_ERROR_TPM_DEFEND_LOCK);
  EXPECT_EQ(err1->local_crypto_error(), CryptoError::CE_TPM_DEFEND_LOCK);
}

TEST_F(CryptohomeLECredErrorTest, Success) {
  StatusChain<CryptohomeLECredError> err;
  EXPECT_TRUE(err.ok());
}

}  // namespace

}  // namespace error

}  // namespace cryptohome
