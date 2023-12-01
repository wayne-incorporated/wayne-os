// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "trunks/tpm_u2f.h"

#include <optional>
#include <string>

#include <brillo/secure_blob.h>
#include <gtest/gtest.h>

#include "trunks/cr50_headers/u2f.h"
#include "trunks/error_codes.h"

namespace trunks {

namespace {

brillo::Blob GetAppId() {
  return brillo::Blob(U2F_APPID_SIZE, 0);
}

brillo::SecureBlob GetUserSecret() {
  return brillo::SecureBlob(U2F_USER_SECRET_SIZE, 1);
}

brillo::Blob GetAuthTimeSecretHash() {
  return brillo::Blob(SHA256_DIGEST_SIZE, 2);
}

brillo::Blob GetPublicKey() {
  return brillo::Blob(U2F_EC_POINT_SIZE, 3);
}

brillo::Blob GetKeyHandle() {
  return brillo::Blob(U2F_V0_KH_SIZE, 4);
}

brillo::Blob GetVersionedKeyHandle() {
  return brillo::Blob(U2F_V1_KH_SIZE, 5);
}

brillo::SecureBlob GetAuthTimeSecret() {
  return brillo::SecureBlob(U2F_AUTH_TIME_SECRET_SIZE, 6);
}

brillo::Blob GetHashToSign() {
  return brillo::Blob(U2F_P256_SIZE, 7);
}

brillo::Blob GetSignatureR() {
  return brillo::Blob(U2F_P256_SIZE, 8);
}

brillo::Blob GetSignatureS() {
  return brillo::Blob(U2F_P256_SIZE, 9);
}

brillo::Blob GetAttestData() {
  return brillo::Blob(100, 10);
}

std::string GetU2fGenerateResp() {
  return brillo::BlobToString(
      brillo::CombineBlobs({GetPublicKey(), GetKeyHandle()}));
}

std::string GetU2fGenerateVersionedResp() {
  return brillo::BlobToString(
      brillo::CombineBlobs({GetPublicKey(), GetVersionedKeyHandle()}));
}

std::string GetU2fSignResp() {
  return brillo::BlobToString(
      brillo::CombineBlobs({GetSignatureR(), GetSignatureS()}));
}

}  // namespace

// A placeholder test fixture to prevent typos.
class TpmU2fTest : public testing::Test {};

TEST_F(TpmU2fTest, SerializeU2fGenerate) {
  const brillo::Blob kInvalidAppId(31, 1);
  const brillo::SecureBlob kInvalidUserSecret(31, 1);
  std::string out;

  // Incorrect app_id size.
  EXPECT_EQ(Serialize_u2f_generate_t(0, kInvalidAppId, GetUserSecret(),
                                     /*consume=*/true,
                                     /*up_required=*/true, std::nullopt, &out),
            SAPI_RC_BAD_PARAMETER);
  EXPECT_TRUE(out.empty());

  // Incorrect user_secret size.
  EXPECT_EQ(Serialize_u2f_generate_t(0, GetAppId(), kInvalidUserSecret,
                                     /*consume=*/true,
                                     /*up_required=*/true, std::nullopt, &out),
            SAPI_RC_BAD_PARAMETER);
  EXPECT_TRUE(out.empty());

  // Invalid version.
  EXPECT_EQ(Serialize_u2f_generate_t(2, GetAppId(), GetUserSecret(),
                                     /*consume=*/true,
                                     /*up_required=*/true, std::nullopt, &out),
            SAPI_RC_BAD_PARAMETER);
  EXPECT_TRUE(out.empty());

  // auth_time_secret_hash should be nullopt for v0 requests.
  EXPECT_EQ(Serialize_u2f_generate_t(0, GetAppId(), GetUserSecret(),
                                     /*consume=*/true,
                                     /*up_required=*/true,
                                     GetAuthTimeSecretHash(), &out),
            SAPI_RC_BAD_PARAMETER);
  EXPECT_TRUE(out.empty());

  // auth_time_secret_hash shouldn't be nullopt for v1 requests.
  EXPECT_EQ(Serialize_u2f_generate_t(1, GetAppId(), GetUserSecret(),
                                     /*consume=*/true,
                                     /*up_required=*/true, std::nullopt, &out),
            SAPI_RC_BAD_PARAMETER);
  EXPECT_TRUE(out.empty());

  // Valid v0 requests.
  EXPECT_EQ(Serialize_u2f_generate_t(0, GetAppId(), GetUserSecret(),
                                     /*consume=*/false,
                                     /*up_required=*/false, std::nullopt, &out),
            TPM_RC_SUCCESS);
  EXPECT_EQ(out.length(), sizeof(u2f_generate_req));

  EXPECT_EQ(Serialize_u2f_generate_t(0, GetAppId(), GetUserSecret(),
                                     /*consume=*/false,
                                     /*up_required=*/true, std::nullopt, &out),
            TPM_RC_SUCCESS);
  EXPECT_EQ(out.length(), sizeof(u2f_generate_req));

  // Valid v1 requests.
  EXPECT_EQ(Serialize_u2f_generate_t(1, GetAppId(), GetUserSecret(),
                                     /*consume=*/true,
                                     /*up_required=*/false,
                                     GetAuthTimeSecretHash(), &out),
            TPM_RC_SUCCESS);
  EXPECT_EQ(out.length(), sizeof(u2f_generate_req));

  EXPECT_EQ(Serialize_u2f_generate_t(1, GetAppId(), GetUserSecret(),
                                     /*consume=*/true,
                                     /*up_required=*/true,
                                     GetAuthTimeSecretHash(), &out),
            TPM_RC_SUCCESS);
  EXPECT_EQ(out.length(), sizeof(u2f_generate_req));
}

TEST_F(TpmU2fTest, ParseU2fGenerate) {
  brillo::Blob public_key, key_handle;

  // Incorrect version.
  EXPECT_EQ(
      Parse_u2f_generate_t(GetU2fGenerateResp(), 2, &public_key, &key_handle),
      SAPI_RC_BAD_PARAMETER);
  EXPECT_TRUE(public_key.empty());
  EXPECT_TRUE(key_handle.empty());

  // Incorrect response size.
  EXPECT_EQ(
      Parse_u2f_generate_t(GetU2fGenerateResp(), 1, &public_key, &key_handle),
      SAPI_RC_BAD_SIZE);
  EXPECT_TRUE(public_key.empty());
  EXPECT_TRUE(key_handle.empty());

  EXPECT_EQ(Parse_u2f_generate_t(GetU2fGenerateVersionedResp(), 0, &public_key,
                                 &key_handle),
            SAPI_RC_BAD_SIZE);
  EXPECT_TRUE(public_key.empty());
  EXPECT_TRUE(key_handle.empty());

  // Valid responses.
  EXPECT_EQ(
      Parse_u2f_generate_t(GetU2fGenerateResp(), 0, &public_key, &key_handle),
      TPM_RC_SUCCESS);
  EXPECT_EQ(public_key, GetPublicKey());
  EXPECT_EQ(key_handle, GetKeyHandle());

  EXPECT_EQ(Parse_u2f_generate_t(GetU2fGenerateVersionedResp(), 1, &public_key,
                                 &key_handle),
            TPM_RC_SUCCESS);
  EXPECT_EQ(public_key, GetPublicKey());
  EXPECT_EQ(key_handle, GetVersionedKeyHandle());
}

TEST_F(TpmU2fTest, SerializeU2fSign) {
  const brillo::Blob kInvalidAppId(31, 1);
  const brillo::SecureBlob kInvalidUserSecret(31, 1);
  const brillo::Blob kInvalidHashToSign(31, 1);
  const brillo::SecureBlob kInvalidAuthTimeSecret(31, 1);
  std::string out;

  // Incorrect app_id size.
  EXPECT_EQ(Serialize_u2f_sign_t(0, kInvalidAppId, GetUserSecret(),
                                 std::nullopt, std::nullopt,
                                 /*check_only=*/true,
                                 /*consume=*/false,
                                 /*up_required=*/false, GetKeyHandle(), &out),
            SAPI_RC_BAD_PARAMETER);
  EXPECT_TRUE(out.empty());

  // Incorrect user_secret size.
  EXPECT_EQ(Serialize_u2f_sign_t(0, GetAppId(), kInvalidUserSecret,
                                 std::nullopt, std::nullopt,
                                 /*check_only=*/true,
                                 /*consume=*/false,
                                 /*up_required=*/false, GetKeyHandle(), &out),
            SAPI_RC_BAD_PARAMETER);
  EXPECT_TRUE(out.empty());

  // hash_to_sign should be nullopt for check_only requests.
  EXPECT_EQ(Serialize_u2f_sign_t(0, GetAppId(), GetUserSecret(), std::nullopt,
                                 GetHashToSign(),
                                 /*check_only=*/true,
                                 /*consume=*/false,
                                 /*up_required=*/false, GetKeyHandle(), &out),
            SAPI_RC_BAD_PARAMETER);
  EXPECT_TRUE(out.empty());

  // hash_to_sign should be valid for non-check_only requests.
  EXPECT_EQ(Serialize_u2f_sign_t(0, GetAppId(), GetUserSecret(), std::nullopt,
                                 std::nullopt,
                                 /*check_only=*/false,
                                 /*consume=*/false,
                                 /*up_required=*/false, GetKeyHandle(), &out),
            SAPI_RC_BAD_PARAMETER);
  EXPECT_TRUE(out.empty());

  EXPECT_EQ(Serialize_u2f_sign_t(0, GetAppId(), GetUserSecret(), std::nullopt,
                                 kInvalidHashToSign,
                                 /*check_only=*/false,
                                 /*consume=*/false,
                                 /*up_required=*/false, GetKeyHandle(), &out),
            SAPI_RC_BAD_PARAMETER);
  EXPECT_TRUE(out.empty());

  // auth_time_secret should be nullopt for v0 requests.
  EXPECT_EQ(Serialize_u2f_sign_t(0, GetAppId(), GetUserSecret(),
                                 GetAuthTimeSecret(), GetHashToSign(),
                                 /*check_only=*/false,
                                 /*consume=*/false,
                                 /*up_required=*/false, GetKeyHandle(), &out),
            SAPI_RC_BAD_PARAMETER);
  EXPECT_TRUE(out.empty());

  // auth_time_secret should be valid (if present) for v1 requests.
  EXPECT_EQ(Serialize_u2f_sign_t(1, GetAppId(), GetUserSecret(),
                                 kInvalidAuthTimeSecret, GetHashToSign(),
                                 /*check_only=*/false,
                                 /*consume=*/false,
                                 /*up_required=*/false, GetVersionedKeyHandle(),
                                 &out),
            SAPI_RC_BAD_PARAMETER);
  EXPECT_TRUE(out.empty());

  // key_handle size should correct for requests of each version.
  EXPECT_EQ(Serialize_u2f_sign_t(
                0, GetAppId(), GetUserSecret(), std::nullopt, std::nullopt,
                /*check_only=*/true,
                /*consume=*/false,
                /*up_required=*/false, GetVersionedKeyHandle(), &out),
            SAPI_RC_BAD_PARAMETER);
  EXPECT_TRUE(out.empty());

  EXPECT_EQ(Serialize_u2f_sign_t(1, GetAppId(), GetUserSecret(), std::nullopt,
                                 std::nullopt,
                                 /*check_only=*/true,
                                 /*consume=*/false,
                                 /*up_required=*/false, GetKeyHandle(), &out),
            SAPI_RC_BAD_PARAMETER);
  EXPECT_TRUE(out.empty());

  // Invalid version.
  EXPECT_EQ(Serialize_u2f_sign_t(2, GetAppId(), GetUserSecret(), std::nullopt,
                                 std::nullopt,
                                 /*check_only=*/true,
                                 /*consume=*/false,
                                 /*up_required=*/false, GetKeyHandle(), &out),
            SAPI_RC_BAD_PARAMETER);
  EXPECT_TRUE(out.empty());

  // Valid v0 requests.
  EXPECT_EQ(Serialize_u2f_sign_t(0, GetAppId(), GetUserSecret(), std::nullopt,
                                 std::nullopt,
                                 /*check_only=*/true,
                                 /*consume=*/false,
                                 /*up_required=*/false, GetKeyHandle(), &out),
            TPM_RC_SUCCESS);
  EXPECT_EQ(out.size(), sizeof(u2f_sign_req));

  EXPECT_EQ(Serialize_u2f_sign_t(0, GetAppId(), GetUserSecret(), std::nullopt,
                                 GetHashToSign(),
                                 /*check_only=*/false,
                                 /*consume=*/true,
                                 /*up_required=*/true, GetKeyHandle(), &out),
            TPM_RC_SUCCESS);
  EXPECT_EQ(out.size(), sizeof(u2f_sign_req));

  // Valid v1 requests.
  EXPECT_EQ(Serialize_u2f_sign_t(
                1, GetAppId(), GetUserSecret(), std::nullopt, std::nullopt,
                /*check_only=*/true,
                /*consume=*/false,
                /*up_required=*/false, GetVersionedKeyHandle(), &out),
            TPM_RC_SUCCESS);
  EXPECT_EQ(out.size(), sizeof(u2f_sign_versioned_req));

  EXPECT_EQ(Serialize_u2f_sign_t(
                1, GetAppId(), GetUserSecret(), std::nullopt, GetHashToSign(),
                /*check_only=*/false,
                /*consume=*/true,
                /*up_required=*/true, GetVersionedKeyHandle(), &out),
            TPM_RC_SUCCESS);
  EXPECT_EQ(out.size(), sizeof(u2f_sign_versioned_req));

  EXPECT_EQ(
      Serialize_u2f_sign_t(1, GetAppId(), GetUserSecret(), GetAuthTimeSecret(),
                           GetHashToSign(),
                           /*check_only=*/false,
                           /*consume=*/true,
                           /*up_required=*/true, GetVersionedKeyHandle(), &out),
      TPM_RC_SUCCESS);
  EXPECT_EQ(out.size(), sizeof(u2f_sign_versioned_req));
}

TEST_F(TpmU2fTest, ParseU2fSign) {
  const std::string kInvalidU2fSignResp(63, 1);
  brillo::Blob sig_r, sig_s;

  // Incorrect response size.
  EXPECT_EQ(Parse_u2f_sign_t(kInvalidU2fSignResp, &sig_r, &sig_s),
            SAPI_RC_BAD_SIZE);
  EXPECT_TRUE(sig_r.empty());
  EXPECT_TRUE(sig_s.empty());

  // Valid response.
  EXPECT_EQ(Parse_u2f_sign_t(GetU2fSignResp(), &sig_r, &sig_s), TPM_RC_SUCCESS);
  EXPECT_EQ(sig_r, GetSignatureR());
  EXPECT_EQ(sig_s, GetSignatureS());
}

TEST_F(TpmU2fTest, SerializeU2fAttest) {
  constexpr uint8_t kFormat = 0;
  const brillo::SecureBlob kInvalidUserSecret(31, 1);
  std::string out;

  // Incorrect user_secret size.
  EXPECT_EQ(Serialize_u2f_attest_t(kInvalidUserSecret, kFormat, GetAttestData(),
                                   &out),
            SAPI_RC_BAD_PARAMETER);
  EXPECT_TRUE(out.empty());

  // Invalid data size.
  EXPECT_EQ(
      Serialize_u2f_attest_t(GetUserSecret(), kFormat,
                             brillo::Blob(U2F_MAX_ATTEST_SIZE + 1, 1), &out),
      SAPI_RC_BAD_PARAMETER);
  EXPECT_TRUE(out.empty());

  // Valid response.
  brillo::Blob data = GetAttestData();
  EXPECT_EQ(Serialize_u2f_attest_t(GetUserSecret(), kFormat, data, &out),
            TPM_RC_SUCCESS);
  EXPECT_EQ(out.size(), offsetof(u2f_attest_req, data) + data.size());
}

}  // namespace trunks
