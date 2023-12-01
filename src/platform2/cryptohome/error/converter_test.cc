// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <set>
#include <string>
#include <utility>

#include <cryptohome/proto_bindings/UserDataAuth.pb.h>
#include <gtest/gtest.h>
#include <libhwsec-foundation/error/error.h>

#include "cryptohome/error/converter.h"
#include "cryptohome/error/cryptohome_error.h"

namespace cryptohome {

namespace error {

namespace {

using hwsec_foundation::status::MakeStatus;
using hwsec_foundation::status::StatusChain;

// Note that the RepeatedField field in protobuf for PossibleAction uses int,
// thus the need to for 2 template types.
template <typename T, typename S>
std::set<T> ToStdSet(const ::google::protobuf::RepeatedField<S>& input) {
  std::vector<T> list;
  for (int i = 0; i < input.size(); i++) {
    list.push_back(static_cast<T>(input[i]));
  }
  return std::set<T>(list.begin(), list.end());
}

class ErrorConverterTest : public ::testing::Test {
 public:
  ErrorConverterTest() {}
  ~ErrorConverterTest() override = default;

 protected:
  const CryptohomeError::ErrorLocationPair kErrorLocationForTesting1 =
      CryptohomeError::ErrorLocationPair(
          static_cast<::cryptohome::error::CryptohomeError::ErrorLocation>(1),
          std::string("Testing1"));
  const CryptohomeError::ErrorLocationPair kErrorLocationForTesting2 =
      CryptohomeError::ErrorLocationPair(
          static_cast<::cryptohome::error::CryptohomeError::ErrorLocation>(2),
          std::string("Testing2"));
};

TEST_F(ErrorConverterTest, BasicConversionTest) {
  StatusChain<CryptohomeError> err1 = MakeStatus<CryptohomeError>(
      kErrorLocationForTesting2, ErrorActionSet({PossibleAction::kPowerwash}),
      user_data_auth::CryptohomeErrorCode::
          CRYPTOHOME_ERROR_INTERNAL_ATTESTATION_ERROR);

  user_data_auth::CryptohomeErrorCode ec =
      static_cast<user_data_auth::CryptohomeErrorCode>(
          123451234);  // Intentionally invalid value.
  user_data_auth::CryptohomeErrorInfo info =
      CryptohomeErrorToUserDataAuthError(err1, &ec);
  EXPECT_EQ(ec, user_data_auth::CryptohomeErrorCode::
                    CRYPTOHOME_ERROR_INTERNAL_ATTESTATION_ERROR);
  EXPECT_EQ(info.error_id(),
            std::to_string(kErrorLocationForTesting2.location()));
  EXPECT_EQ(info.primary_action(), user_data_auth::PrimaryAction::PRIMARY_NONE);
  ASSERT_EQ(info.possible_actions_size(), 1);
  EXPECT_EQ(info.possible_actions(0),
            user_data_auth::PossibleAction::POSSIBLY_POWERWASH);
}

TEST_F(ErrorConverterTest, Success) {
  hwsec_foundation::status::StatusChain<CryptohomeError> err1;

  user_data_auth::CryptohomeErrorCode ec =
      static_cast<user_data_auth::CryptohomeErrorCode>(
          123451234);  // Intentionally invalid value.
  user_data_auth::CryptohomeErrorInfo info =
      CryptohomeErrorToUserDataAuthError(err1, &ec);
  EXPECT_EQ(ec, user_data_auth::CryptohomeErrorCode::CRYPTOHOME_ERROR_NOT_SET);
  EXPECT_EQ(info.error_id(), "");
  EXPECT_EQ(info.primary_action(),
            user_data_auth::PrimaryAction::PRIMARY_NO_ERROR);
  EXPECT_EQ(info.possible_actions_size(), 0);
}

TEST_F(ErrorConverterTest, WrappedPossibleAction) {
  StatusChain<CryptohomeError> err1 = MakeStatus<CryptohomeError>(
      kErrorLocationForTesting2, ErrorActionSet({PossibleAction::kPowerwash}),
      user_data_auth::CryptohomeErrorCode::
          CRYPTOHOME_ERROR_INTERNAL_ATTESTATION_ERROR);

  StatusChain<CryptohomeError> err2 =
      MakeStatus<CryptohomeError>(kErrorLocationForTesting1,
                                  ErrorActionSet({PossibleAction::kReboot}))
          .Wrap(std::move(err1));

  user_data_auth::CryptohomeErrorCode ec =
      static_cast<user_data_auth::CryptohomeErrorCode>(
          123451234);  // Intentionally invalid value.
  user_data_auth::CryptohomeErrorInfo info =
      CryptohomeErrorToUserDataAuthError(err2, &ec);
  EXPECT_EQ(ec, user_data_auth::CryptohomeErrorCode::
                    CRYPTOHOME_ERROR_INTERNAL_ATTESTATION_ERROR);
  EXPECT_EQ(info.error_id(),
            std::to_string(kErrorLocationForTesting1.location()) + "-" +
                std::to_string(kErrorLocationForTesting2.location()));
  EXPECT_EQ(info.primary_action(), user_data_auth::PrimaryAction::PRIMARY_NONE);
  EXPECT_EQ(ToStdSet<user_data_auth::PossibleAction>(info.possible_actions()),
            std::set<user_data_auth::PossibleAction>(
                {user_data_auth::PossibleAction::POSSIBLY_POWERWASH,
                 user_data_auth::PossibleAction::POSSIBLY_REBOOT}));
}

TEST_F(ErrorConverterTest, WrappedPrimaryAction) {
  StatusChain<CryptohomeError> err1 = MakeStatus<CryptohomeError>(
      kErrorLocationForTesting2,
      ErrorActionSet(PrimaryAction::kTpmUpdateRequired),
      user_data_auth::CryptohomeErrorCode::
          CRYPTOHOME_ERROR_INTERNAL_ATTESTATION_ERROR);

  StatusChain<CryptohomeError> err2 =
      MakeStatus<CryptohomeError>(kErrorLocationForTesting1,
                                  ErrorActionSet({PossibleAction::kReboot}))
          .Wrap(std::move(err1));

  user_data_auth::CryptohomeErrorCode ec;
  user_data_auth::CryptohomeErrorInfo info =
      CryptohomeErrorToUserDataAuthError(err2, &ec);

  EXPECT_EQ(info.primary_action(),
            user_data_auth::PrimaryAction::PRIMARY_TPM_UDPATE_REQUIRED);
  EXPECT_EQ(info.possible_actions_size(), 0);
}

// IncorrectAuth should be overridden by other primary actions.
TEST_F(ErrorConverterTest, WrappedPrimaryIncorrectAuthPlusOthers) {
  StatusChain<CryptohomeError> err1 = MakeStatus<CryptohomeError>(
      kErrorLocationForTesting2,
      ErrorActionSet(PrimaryAction::kTpmUpdateRequired),
      user_data_auth::CryptohomeErrorCode::
          CRYPTOHOME_ERROR_INTERNAL_ATTESTATION_ERROR);

  StatusChain<CryptohomeError> err2 =
      MakeStatus<CryptohomeError>(kErrorLocationForTesting1,
                                  ErrorActionSet(PrimaryAction::kIncorrectAuth))
          .Wrap(std::move(err1));

  user_data_auth::CryptohomeErrorCode ec;
  user_data_auth::CryptohomeErrorInfo info =
      CryptohomeErrorToUserDataAuthError(err2, &ec);

  EXPECT_EQ(info.primary_action(),
            user_data_auth::PrimaryAction::PRIMARY_TPM_UDPATE_REQUIRED);
  EXPECT_EQ(info.possible_actions_size(), 0);
}

}  // namespace

}  // namespace error

}  // namespace cryptohome
