// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <cstdint>
#include <optional>

#include <gtest/gtest.h>
#include <libhwsec-foundation/error/testing_helper.h>
#include <trunks/cr50_headers/u2f.h>
#include <trunks/mock_tpm_utility.h>

#include "libhwsec/backend/tpm2/backend_test_base.h"

using hwsec_foundation::error::testing::IsOk;
using hwsec_foundation::error::testing::IsOkAnd;
using hwsec_foundation::error::testing::IsOkAndHolds;
using hwsec_foundation::error::testing::NotOk;
using hwsec_foundation::error::testing::NotOkAnd;
using hwsec_foundation::error::testing::NotOkWith;
using testing::_;
using testing::DoAll;
using testing::Eq;
using testing::Optional;
using testing::Return;
using testing::SetArgPointee;
using testing::SizeIs;

namespace hwsec {

namespace {

constexpr uint32_t kCr50StatusNotAllowed = 0x507;
constexpr uint32_t kCr50StatusPasswordRequired = 0x50a;

brillo::Blob GetStubBlob() {
  return brillo::Blob(10, 10);
}

brillo::SecureBlob GetStubSecureBlob() {
  return brillo::SecureBlob(20, 20);
}

brillo::Blob GetValidAppId() {
  return brillo::Blob(U2F_APPID_SIZE, 30);
}

brillo::SecureBlob GetValidUserSecret() {
  return brillo::SecureBlob(U2F_USER_SECRET_SIZE, 40);
}

brillo::Blob GetValidPublicKey() {
  return brillo::Blob(U2F_EC_POINT_SIZE, 50);
}

brillo::Blob GetValidKeyHandle() {
  return brillo::Blob(U2F_V0_KH_SIZE, 60);
}

brillo::Blob GetValidVersionedKeyHandle() {
  return brillo::Blob(U2F_V1_KH_SIZE + SHA256_DIGEST_SIZE, 30);
}

brillo::Blob GetValidAuthTimeSecretHash() {
  return brillo::Blob(SHA256_DIGEST_SIZE, 30);
}

brillo::Blob GetValidG2fChallenge() {
  return brillo::Blob(U2F_CHAL_SIZE, 70);
}

brillo::Blob GetValidCorpChallenge() {
  return brillo::Blob(CORP_CHAL_SIZE, 80);
}

brillo::Blob GetValidSalt() {
  return brillo::Blob(CORP_SALT_SIZE, 90);
}

MATCHER_P(RetryAction, matcher, "") {
  if (arg.ok()) {
    return false;
  }
  return ExplainMatchResult(matcher, arg->ToTPMRetryAction(), result_listener);
}

}  // namespace

using BackendU2fTpm2Test = BackendTpm2TestBase;

TEST_F(BackendU2fTpm2Test, IsEnabledCr50) {
  EXPECT_CALL(proxy_->GetMockTpmUtility(), IsGsc).WillOnce(Return(true));

  EXPECT_THAT(backend_->GetU2fTpm2().IsEnabled(), IsOkAndHolds(true));
}

TEST_F(BackendU2fTpm2Test, IsEnabledOthers) {
  EXPECT_CALL(proxy_->GetMockTpmUtility(), IsGsc).WillOnce(Return(false));

  EXPECT_THAT(backend_->GetU2fTpm2().IsEnabled(), IsOkAndHolds(false));
}

TEST_F(BackendU2fTpm2Test, GenerateUpOnly) {
  const brillo::Blob kPublicKey(65, 1);
  const brillo::Blob kKeyHandle(32, 2);

  EXPECT_CALL(proxy_->GetMockTpmUtility(),
              U2fGenerate(0, _, _, _, _, Eq(std::nullopt), _, _))
      .WillOnce(DoAll(SetArgPointee<6>(kPublicKey),
                      SetArgPointee<7>(kKeyHandle),
                      Return(trunks::TPM_RC_SUCCESS)));

  auto result = backend_->GetU2fTpm2().GenerateUserPresenceOnly(
      GetStubBlob(), GetStubSecureBlob(), u2f::ConsumeMode::kNoConsume,
      u2f::UserPresenceMode::kNotRequired);
  ASSERT_OK(result);
  EXPECT_EQ(result->public_key->raw(), kPublicKey);
  EXPECT_EQ(result->key_handle, kKeyHandle);
}

TEST_F(BackendU2fTpm2Test, GenerateUpOnlyFailed) {
  EXPECT_CALL(proxy_->GetMockTpmUtility(),
              U2fGenerate(0, _, _, _, _, Eq(std::nullopt), _, _))
      .WillOnce(Return(trunks::TPM_RC_FAILURE));

  EXPECT_THAT(
      backend_->GetU2fTpm2().GenerateUserPresenceOnly(
          GetStubBlob(), GetStubSecureBlob(), u2f::ConsumeMode::kNoConsume,
          u2f::UserPresenceMode::kNotRequired),
      NotOkAnd(RetryAction(Eq(TPMRetryAction::kNoRetry))));
}

TEST_F(BackendU2fTpm2Test, GenerateUpOnlyMissingUp) {
  EXPECT_CALL(proxy_->GetMockTpmUtility(),
              U2fGenerate(0, _, _, _, _, Eq(std::nullopt), _, _))
      .WillOnce(Return(kCr50StatusNotAllowed));

  EXPECT_THAT(
      backend_->GetU2fTpm2().GenerateUserPresenceOnly(
          GetStubBlob(), GetStubSecureBlob(), u2f::ConsumeMode::kNoConsume,
          u2f::UserPresenceMode::kNotRequired),
      NotOkAnd(RetryAction(Eq(TPMRetryAction::kUserPresence))));
}

TEST_F(BackendU2fTpm2Test, Generate) {
  const brillo::Blob kPublicKey(65, 1);
  const brillo::Blob kKeyHandle(U2F_V1_KH_SIZE, 2);

  EXPECT_CALL(proxy_->GetMockTpmUtility(),
              U2fGenerate(1, _, _, _, _, Optional(_), _, _))
      .WillOnce(DoAll(SetArgPointee<6>(kPublicKey),
                      SetArgPointee<7>(kKeyHandle),
                      Return(trunks::TPM_RC_SUCCESS)));

  auto result = backend_->GetU2fTpm2().Generate(
      GetStubBlob(), GetStubSecureBlob(), u2f::ConsumeMode::kNoConsume,
      u2f::UserPresenceMode::kNotRequired, GetValidAuthTimeSecretHash());
  ASSERT_OK(result);
  EXPECT_EQ(result->public_key->raw(), kPublicKey);
  EXPECT_EQ(result->key_handle.size(), U2F_V1_KH_SIZE + SHA256_DIGEST_SIZE);
}

TEST_F(BackendU2fTpm2Test, GenerateFailed) {
  EXPECT_CALL(proxy_->GetMockTpmUtility(),
              U2fGenerate(1, _, _, _, _, Optional(_), _, _))
      .WillOnce(Return(trunks::TPM_RC_FAILURE));

  EXPECT_THAT(
      backend_->GetU2fTpm2().Generate(
          GetStubBlob(), GetStubSecureBlob(), u2f::ConsumeMode::kNoConsume,
          u2f::UserPresenceMode::kNotRequired, GetStubBlob()),
      NotOkAnd(RetryAction(Eq(TPMRetryAction::kNoRetry))));
}

TEST_F(BackendU2fTpm2Test, GenerateFailedMissingUp) {
  EXPECT_CALL(proxy_->GetMockTpmUtility(),
              U2fGenerate(1, _, _, _, _, Optional(_), _, _))
      .WillOnce(Return(kCr50StatusNotAllowed));

  EXPECT_THAT(
      backend_->GetU2fTpm2().Generate(
          GetStubBlob(), GetStubSecureBlob(), u2f::ConsumeMode::kConsume,
          u2f::UserPresenceMode::kRequired, GetStubBlob()),
      NotOkAnd(RetryAction(Eq(TPMRetryAction::kUserPresence))));
}

TEST_F(BackendU2fTpm2Test, GenerateFailedInvalidKeyHandle) {
  const brillo::Blob kPublicKey(65, 1);
  const brillo::Blob kKeyHandle(32, 2);

  EXPECT_CALL(proxy_->GetMockTpmUtility(),
              U2fGenerate(1, _, _, _, _, Optional(_), _, _))
      .WillOnce(DoAll(SetArgPointee<6>(kPublicKey),
                      SetArgPointee<7>(kKeyHandle),
                      Return(trunks::TPM_RC_SUCCESS)));

  EXPECT_THAT(
      backend_->GetU2fTpm2().Generate(
          GetStubBlob(), GetStubSecureBlob(), u2f::ConsumeMode::kNoConsume,
          u2f::UserPresenceMode::kNotRequired, GetStubBlob()),
      NotOkWith("Invalid U2F key handle is generated"));
}

TEST_F(BackendU2fTpm2Test, SignUpOnly) {
  const brillo::Blob kSigR(32, 1);
  const brillo::Blob kSigS(32, 2);

  EXPECT_CALL(
      proxy_->GetMockTpmUtility(),
      U2fSign(0, _, _, Eq(std::nullopt), Optional(_), false, _, _, _, _, _))
      .WillOnce(DoAll(SetArgPointee<9>(kSigR), SetArgPointee<10>(kSigS),
                      Return(trunks::TPM_RC_SUCCESS)));

  auto result = backend_->GetU2fTpm2().SignUserPresenceOnly(
      GetStubBlob(), GetStubSecureBlob(), GetStubBlob(),
      u2f::ConsumeMode::kNoConsume, u2f::UserPresenceMode::kNotRequired,
      GetStubBlob());
  ASSERT_OK(result);
  EXPECT_EQ(result->r, kSigR);
  EXPECT_EQ(result->s, kSigS);
}

TEST_F(BackendU2fTpm2Test, SignUpOnlyFailed) {
  EXPECT_CALL(
      proxy_->GetMockTpmUtility(),
      U2fSign(0, _, _, Eq(std::nullopt), Optional(_), false, _, _, _, _, _))
      .WillOnce(Return(trunks::TPM_RC_FAILURE));

  EXPECT_THAT(backend_->GetU2fTpm2().SignUserPresenceOnly(
                  GetStubBlob(), GetStubSecureBlob(), GetStubBlob(),
                  u2f::ConsumeMode::kNoConsume,
                  u2f::UserPresenceMode::kNotRequired, GetStubBlob()),
              NotOkAnd(RetryAction(Eq(TPMRetryAction::kNoRetry))));
}

TEST_F(BackendU2fTpm2Test, SignUpOnlyFailedIncorrectAuth) {
  EXPECT_CALL(
      proxy_->GetMockTpmUtility(),
      U2fSign(0, _, _, Eq(std::nullopt), Optional(_), false, _, _, _, _, _))
      .WillOnce(Return(kCr50StatusPasswordRequired));

  EXPECT_THAT(backend_->GetU2fTpm2().SignUserPresenceOnly(
                  GetStubBlob(), GetStubSecureBlob(), GetStubBlob(),
                  u2f::ConsumeMode::kNoConsume,
                  u2f::UserPresenceMode::kNotRequired, GetStubBlob()),
              NotOkAnd(RetryAction(Eq(TPMRetryAction::kUserAuth))));
}

TEST_F(BackendU2fTpm2Test, Sign) {
  const brillo::Blob kSigR(32, 1);
  const brillo::Blob kSigS(32, 2);

  EXPECT_CALL(proxy_->GetMockTpmUtility(),
              U2fSign(1, _, _, Optional(_), Optional(_), false, _, _, _, _, _))
      .WillOnce(DoAll(SetArgPointee<9>(kSigR), SetArgPointee<10>(kSigS),
                      Return(trunks::TPM_RC_SUCCESS)));

  auto result = backend_->GetU2fTpm2().Sign(
      GetStubBlob(), GetStubSecureBlob(), GetStubSecureBlob(), GetStubBlob(),
      u2f::ConsumeMode::kNoConsume, u2f::UserPresenceMode::kNotRequired,
      GetValidVersionedKeyHandle());
  ASSERT_OK(result);
  EXPECT_EQ(result->r, kSigR);
  EXPECT_EQ(result->s, kSigS);
}

TEST_F(BackendU2fTpm2Test, SignFailed) {
  EXPECT_CALL(proxy_->GetMockTpmUtility(),
              U2fSign(1, _, _, Optional(_), Optional(_), false, _, _, _, _, _))
      .WillOnce(Return(trunks::TPM_RC_FAILURE));

  EXPECT_THAT(backend_->GetU2fTpm2().Sign(GetStubBlob(), GetStubSecureBlob(),
                                          GetStubSecureBlob(), GetStubBlob(),
                                          u2f::ConsumeMode::kNoConsume,
                                          u2f::UserPresenceMode::kNotRequired,
                                          GetValidVersionedKeyHandle()),
              NotOkAnd(RetryAction(Eq(TPMRetryAction::kNoRetry))));
}

TEST_F(BackendU2fTpm2Test, SignFailedInvalidKeyHandle) {
  EXPECT_THAT(backend_->GetU2fTpm2().Sign(
                  GetStubBlob(), GetStubSecureBlob(), GetStubSecureBlob(),
                  GetStubBlob(), u2f::ConsumeMode::kNoConsume,
                  u2f::UserPresenceMode::kNotRequired, GetStubBlob()),
              NotOkWith("Invalid U2F key handle"));
}

TEST_F(BackendU2fTpm2Test, SignFailedIncorrectAuth) {
  EXPECT_CALL(proxy_->GetMockTpmUtility(),
              U2fSign(1, _, _, Optional(_), Optional(_), false, _, _, _, _, _))
      .WillOnce(Return(kCr50StatusPasswordRequired));

  EXPECT_THAT(backend_->GetU2fTpm2().Sign(GetStubBlob(), GetStubSecureBlob(),
                                          GetStubSecureBlob(), GetStubBlob(),
                                          u2f::ConsumeMode::kNoConsume,
                                          u2f::UserPresenceMode::kNotRequired,
                                          GetValidVersionedKeyHandle()),
              NotOkAnd(RetryAction(Eq(TPMRetryAction::kUserAuth))));
}

TEST_F(BackendU2fTpm2Test, Check) {
  EXPECT_CALL(proxy_->GetMockTpmUtility(),
              U2fSign(0, _, _, Eq(std::nullopt), Eq(std::nullopt), true, false,
                      false, _, _, _))
      .WillOnce(Return(trunks::TPM_RC_SUCCESS));
  EXPECT_CALL(proxy_->GetMockTpmUtility(),
              U2fSign(1, _, _, Eq(std::nullopt), Eq(std::nullopt), true, false,
                      false, _, _, _))
      .WillOnce(Return(trunks::TPM_RC_SUCCESS));

  EXPECT_THAT(backend_->GetU2fTpm2().CheckUserPresenceOnly(
                  GetStubBlob(), GetStubSecureBlob(), GetStubBlob()),
              IsOk());
  EXPECT_THAT(backend_->GetU2fTpm2().Check(GetStubBlob(), GetStubSecureBlob(),
                                           GetValidVersionedKeyHandle()),
              IsOk());
}

TEST_F(BackendU2fTpm2Test, CheckFailed) {
  EXPECT_CALL(proxy_->GetMockTpmUtility(),
              U2fSign(0, _, _, Eq(std::nullopt), Eq(std::nullopt), true, false,
                      false, _, _, _))
      .WillOnce(Return(trunks::TPM_RC_FAILURE));
  EXPECT_CALL(proxy_->GetMockTpmUtility(),
              U2fSign(1, _, _, Eq(std::nullopt), Eq(std::nullopt), true, false,
                      false, _, _, _))
      .WillOnce(Return(trunks::TPM_RC_FAILURE));

  EXPECT_THAT(backend_->GetU2fTpm2().CheckUserPresenceOnly(
                  GetStubBlob(), GetStubSecureBlob(), GetStubBlob()),
              NotOk());
  EXPECT_THAT(backend_->GetU2fTpm2().Check(GetStubBlob(), GetStubSecureBlob(),
                                           GetValidVersionedKeyHandle()),
              NotOk());
  EXPECT_THAT(backend_->GetU2fTpm2().Check(GetStubBlob(), GetStubSecureBlob(),
                                           GetStubBlob()),
              NotOkWith("Invalid U2F key handle"));
}

TEST_F(BackendU2fTpm2Test, G2fAttest) {
  const brillo::Blob kSigR(32, 1);
  const brillo::Blob kSigS(32, 2);

  EXPECT_CALL(proxy_->GetMockTpmUtility(),
              U2fAttest(_, U2F_ATTEST_FORMAT_REG_RESP,
                        SizeIs(sizeof(g2f_register_msg_v0)), _, _))
      .WillOnce(DoAll(SetArgPointee<3>(kSigR), SetArgPointee<4>(kSigS),
                      Return(trunks::TPM_RC_SUCCESS)));

  auto result = backend_->GetU2fTpm2().G2fAttest(
      GetValidAppId(), GetValidUserSecret(), GetValidG2fChallenge(),
      GetValidKeyHandle(), GetValidPublicKey());
  ASSERT_OK(result);
  EXPECT_EQ(result->r, kSigR);
  EXPECT_EQ(result->s, kSigS);
}

TEST_F(BackendU2fTpm2Test, G2fAttestInvalidParams) {
  EXPECT_THAT(backend_->GetU2fTpm2().G2fAttest(
                  GetStubBlob(), GetValidUserSecret(), GetValidG2fChallenge(),
                  GetValidKeyHandle(), GetValidPublicKey()),
              NotOkWith("Invalid parameters"));
  EXPECT_THAT(backend_->GetU2fTpm2().G2fAttest(
                  GetValidAppId(), GetStubSecureBlob(), GetValidG2fChallenge(),
                  GetValidKeyHandle(), GetValidPublicKey()),
              NotOkWith("Invalid parameters"));
  EXPECT_THAT(backend_->GetU2fTpm2().G2fAttest(
                  GetValidAppId(), GetValidUserSecret(), GetStubBlob(),
                  GetValidKeyHandle(), GetValidPublicKey()),
              NotOkWith("Invalid parameters"));
  EXPECT_THAT(backend_->GetU2fTpm2().G2fAttest(
                  GetValidAppId(), GetValidUserSecret(), GetValidG2fChallenge(),
                  GetStubBlob(), GetValidPublicKey()),
              NotOkWith("Invalid parameters"));
  EXPECT_THAT(backend_->GetU2fTpm2().G2fAttest(
                  GetValidAppId(), GetValidUserSecret(), GetValidG2fChallenge(),
                  GetValidKeyHandle(), GetStubBlob()),
              NotOkWith("Invalid parameters"));
}

TEST_F(BackendU2fTpm2Test, G2fAttestFailed) {
  EXPECT_CALL(proxy_->GetMockTpmUtility(),
              U2fAttest(_, U2F_ATTEST_FORMAT_REG_RESP,
                        SizeIs(sizeof(g2f_register_msg_v0)), _, _))
      .WillOnce(Return(trunks::TPM_RC_FAILURE));

  EXPECT_THAT(backend_->GetU2fTpm2().G2fAttest(
                  GetValidAppId(), GetValidUserSecret(), GetValidG2fChallenge(),
                  GetValidKeyHandle(), GetValidPublicKey()),
              NotOk());
}

TEST_F(BackendU2fTpm2Test, GetG2fAttestData) {
  EXPECT_THAT(backend_->GetU2fTpm2().GetG2fAttestData(
                  GetValidAppId(), GetValidG2fChallenge(), GetValidKeyHandle(),
                  GetValidPublicKey()),
              IsOkAnd(SizeIs(sizeof(g2f_register_msg_v0))));
}

TEST_F(BackendU2fTpm2Test, CorpAttest) {
  const brillo::Blob kSigR(32, 1);
  const brillo::Blob kSigS(32, 2);

  EXPECT_CALL(proxy_->GetMockTpmUtility(),
              U2fAttest(_, CORP_ATTEST_FORMAT_REG_RESP,
                        SizeIs(sizeof(corp_register_msg_v0)), _, _))
      .WillOnce(DoAll(SetArgPointee<3>(kSigR), SetArgPointee<4>(kSigS),
                      Return(trunks::TPM_RC_SUCCESS)));

  auto result = backend_->GetU2fTpm2().CorpAttest(
      GetValidAppId(), GetValidUserSecret(), GetValidCorpChallenge(),
      GetValidKeyHandle(), GetValidPublicKey(), GetValidSalt());
  ASSERT_OK(result);
  EXPECT_EQ(result->r, kSigR);
  EXPECT_EQ(result->s, kSigS);
}

TEST_F(BackendU2fTpm2Test, CorpAttestInvalidParams) {
  EXPECT_THAT(backend_->GetU2fTpm2().CorpAttest(
                  GetStubBlob(), GetValidUserSecret(), GetValidG2fChallenge(),
                  GetValidKeyHandle(), GetValidPublicKey(), GetValidSalt()),
              NotOkWith("Invalid parameters"));
  EXPECT_THAT(backend_->GetU2fTpm2().CorpAttest(
                  GetValidAppId(), GetStubSecureBlob(), GetValidG2fChallenge(),
                  GetValidKeyHandle(), GetValidPublicKey(), GetValidSalt()),
              NotOkWith("Invalid parameters"));
  EXPECT_THAT(backend_->GetU2fTpm2().CorpAttest(
                  GetValidAppId(), GetValidUserSecret(), GetStubBlob(),
                  GetValidKeyHandle(), GetValidPublicKey(), GetValidSalt()),
              NotOkWith("Invalid parameters"));
  EXPECT_THAT(backend_->GetU2fTpm2().CorpAttest(
                  GetValidAppId(), GetValidUserSecret(), GetValidG2fChallenge(),
                  GetStubBlob(), GetValidPublicKey(), GetValidSalt()),
              NotOkWith("Invalid parameters"));
  EXPECT_THAT(backend_->GetU2fTpm2().CorpAttest(
                  GetValidAppId(), GetValidUserSecret(), GetValidG2fChallenge(),
                  GetValidKeyHandle(), GetStubBlob(), GetValidSalt()),
              NotOkWith("Invalid parameters"));
  EXPECT_THAT(backend_->GetU2fTpm2().CorpAttest(
                  GetValidAppId(), GetValidUserSecret(), GetValidG2fChallenge(),
                  GetValidKeyHandle(), GetValidPublicKey(), GetStubBlob()),
              NotOkWith("Invalid parameters"));
}

TEST_F(BackendU2fTpm2Test, CorpAttestFailed) {
  EXPECT_CALL(proxy_->GetMockTpmUtility(),
              U2fAttest(_, CORP_ATTEST_FORMAT_REG_RESP,
                        SizeIs(sizeof(corp_register_msg_v0)), _, _))
      .WillOnce(Return(trunks::TPM_RC_FAILURE));

  EXPECT_THAT(
      backend_->GetU2fTpm2().CorpAttest(
          GetValidAppId(), GetValidUserSecret(), GetValidCorpChallenge(),
          GetValidKeyHandle(), GetValidPublicKey(), GetValidSalt()),
      NotOk());
}

}  // namespace hwsec
