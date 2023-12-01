// Copyright 2014 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <string>

#include <gtest/gtest.h>

#include "trunks/hmac_authorization_delegate.h"

namespace trunks {

TEST(HmacAuthorizationDelegateTest, UninitializedSessionTest) {
  HmacAuthorizationDelegate delegate;
  std::string dummy;
  std::string p_hash("test");
  EXPECT_FALSE(delegate.GetCommandAuthorization(p_hash, false, false, &dummy));
  EXPECT_EQ(0u, dummy.size());
  EXPECT_FALSE(delegate.CheckResponseAuthorization(p_hash, dummy));
  EXPECT_FALSE(delegate.EncryptCommandParameter(&dummy));
  EXPECT_FALSE(delegate.DecryptResponseParameter(&dummy));
  EXPECT_FALSE(delegate.GetTpmNonce(&dummy));
}

TEST(HmacAuthorizationDelegateTest, SessionKeyTest) {
  HmacAuthorizationDelegate delegate;
  TPM2B_NONCE nonce;
  nonce.size = kAesKeySize;
  memset(nonce.buffer, 0, nonce.size);
  TPM_HANDLE dummy_handle = HMAC_SESSION_FIRST;
  EXPECT_TRUE(delegate.InitSession(dummy_handle, nonce, nonce, std::string(),
                                   std::string(), false));
  EXPECT_EQ(0u, delegate.session_key_.size());
  std::string tpm_nonce;
  EXPECT_TRUE(delegate.GetTpmNonce(&tpm_nonce));
  EXPECT_EQ(std::string(kAesKeySize, '\0'), tpm_nonce);

  std::string dummy_auth = std::string("authorization");
  std::string dummy_salt = std::string("salt");
  EXPECT_TRUE(delegate.InitSession(dummy_handle, nonce, nonce, dummy_salt,
                                   dummy_auth, false));
  EXPECT_EQ(kHashDigestSize, delegate.session_key_.size());
  // TODO(usanghi): Use TCG TPM2.0 test vectors when available.
  std::string expected_key(
      "\xfb\x2f\x3c\x33\x65\x3e\xdc\x47"
      "\xda\xbe\x4e\xb7\xf4\x6c\x19\x4d"
      "\xea\x50\xb2\x11\x54\x45\x32\x73"
      "\x47\x38\xef\xb3\x4a\x82\x29\x94",
      kHashDigestSize);
  EXPECT_EQ(0, expected_key.compare(delegate.session_key_));
  EXPECT_TRUE(delegate.GetTpmNonce(&tpm_nonce));
  EXPECT_EQ(std::string(kAesKeySize, '\0'), tpm_nonce);

  memset(nonce.buffer, 1, nonce.size);
  EXPECT_TRUE(delegate.InitSession(dummy_handle, nonce, nonce, dummy_salt,
                                   dummy_auth, false));
  EXPECT_TRUE(delegate.GetTpmNonce(&tpm_nonce));
  EXPECT_EQ(std::string(kAesKeySize, '\1'), tpm_nonce);
}

TEST(HmacAuthorizationDelegateTest, EncryptDecryptTest) {
  HmacAuthorizationDelegate delegate;
  std::string plaintext_parameter("parameter");
  std::string encrypted_parameter(plaintext_parameter);
  // Test with session not initialized.
  EXPECT_FALSE(delegate.EncryptCommandParameter(&encrypted_parameter));
  EXPECT_FALSE(delegate.DecryptResponseParameter(&encrypted_parameter));
  // Test with encryption not enabled.
  TPM_HANDLE dummy_handle = HMAC_SESSION_FIRST;
  TPM2B_NONCE nonce;
  nonce.size = kAesKeySize;
  memset(nonce.buffer, 0, nonce.size);
  std::string salt("salt");
  ASSERT_TRUE(delegate.InitSession(dummy_handle, nonce, nonce, salt,
                                   std::string(), false));
  EXPECT_TRUE(delegate.EncryptCommandParameter(&encrypted_parameter));
  EXPECT_EQ(0, plaintext_parameter.compare(encrypted_parameter));
  EXPECT_TRUE(delegate.DecryptResponseParameter(&encrypted_parameter));
  EXPECT_EQ(0, plaintext_parameter.compare(encrypted_parameter));
  // Test with encryption enabled.
  ASSERT_TRUE(delegate.InitSession(dummy_handle, nonce, nonce, salt,
                                   std::string(), true));
  EXPECT_TRUE(delegate.EncryptCommandParameter(&encrypted_parameter));
  EXPECT_NE(0, plaintext_parameter.compare(encrypted_parameter));
  // Calling EncryptCommandParameter regenerated the caller_nonce.
  // We need to manually switch tpm_nonce and caller_nonce to ensure
  // that DecryptResponseParameter has the correct nonces.
  delegate.tpm_nonce_ = delegate.caller_nonce_;
  delegate.caller_nonce_ = nonce;
  EXPECT_TRUE(delegate.DecryptResponseParameter(&encrypted_parameter));
  EXPECT_EQ(0, plaintext_parameter.compare(encrypted_parameter));
}

class HmacAuthorizationDelegateFixture : public testing::Test {
 public:
  HmacAuthorizationDelegateFixture() {}
  ~HmacAuthorizationDelegateFixture() override {}

  void SetUp() override {
    session_handle_ = HMAC_SESSION_FIRST;
    session_nonce_.size = kAesKeySize;
    memset(session_nonce_.buffer, 0, kAesKeySize);
    ASSERT_TRUE(delegate_.InitSession(session_handle_,
                                      session_nonce_,  // TPM nonce.
                                      session_nonce_,  // Caller nonce.
                                      std::string(),   // Salt.
                                      std::string(),   // Bind auth value.
                                      false));         // Enable encryption.
  }

 protected:
  TPM_HANDLE session_handle_;
  TPM2B_NONCE session_nonce_;
  HmacAuthorizationDelegate delegate_;
};

TEST_F(HmacAuthorizationDelegateFixture, NonceRegenerationTest) {
  ASSERT_TRUE(delegate_.InitSession(session_handle_,
                                    session_nonce_,  // TPM nonce.
                                    session_nonce_,  // Caller nonce.
                                    std::string(),   // Salt.
                                    std::string(),   // Bind auth value.
                                    true));          // Enable encryption.
  TPM2B_NONCE original_nonce = session_nonce_;
  EXPECT_EQ(delegate_.caller_nonce_.size, original_nonce.size);
  EXPECT_EQ(0, memcmp(delegate_.caller_nonce_.buffer, original_nonce.buffer,
                      original_nonce.size));
  // First we check that performing GetCommandAuthorization resets the nonce.
  std::string command_hash;
  std::string authorization;
  TPMS_AUTH_COMMAND auth_command;
  EXPECT_TRUE(delegate_.GetCommandAuthorization(command_hash, false, false,
                                                &authorization));
  EXPECT_EQ(TPM_RC_SUCCESS,
            Parse_TPMS_AUTH_COMMAND(&authorization, &auth_command, nullptr));
  EXPECT_TRUE(authorization.empty());
  EXPECT_EQ(delegate_.caller_nonce_.size, original_nonce.size);
  EXPECT_EQ(auth_command.nonce.size, original_nonce.size);
  EXPECT_NE(0, memcmp(delegate_.caller_nonce_.buffer, original_nonce.buffer,
                      original_nonce.size));
  EXPECT_EQ(0, memcmp(delegate_.caller_nonce_.buffer, auth_command.nonce.buffer,
                      auth_command.nonce.size));
  // Now we check that GetCommandAuthorization does not reset nonce
  // when EncryptCommandParameter is called first.
  original_nonce = delegate_.caller_nonce_;
  std::string parameter;
  EXPECT_TRUE(delegate_.EncryptCommandParameter(&parameter));
  EXPECT_EQ(delegate_.caller_nonce_.size, original_nonce.size);
  EXPECT_NE(0, memcmp(delegate_.caller_nonce_.buffer, original_nonce.buffer,
                      original_nonce.size));
  EXPECT_TRUE(delegate_.nonce_generated_);
  original_nonce = delegate_.caller_nonce_;
  EXPECT_TRUE(delegate_.GetCommandAuthorization(command_hash, false, false,
                                                &authorization));
  EXPECT_EQ(TPM_RC_SUCCESS,
            Parse_TPMS_AUTH_COMMAND(&authorization, &auth_command, nullptr));
  EXPECT_TRUE(authorization.empty());
  EXPECT_EQ(delegate_.caller_nonce_.size, original_nonce.size);
  EXPECT_EQ(auth_command.nonce.size, original_nonce.size);
  EXPECT_EQ(0, memcmp(delegate_.caller_nonce_.buffer, original_nonce.buffer,
                      original_nonce.size));
  EXPECT_EQ(0, memcmp(delegate_.caller_nonce_.buffer, auth_command.nonce.buffer,
                      auth_command.nonce.size));
}

TEST_F(HmacAuthorizationDelegateFixture, CommandAuthTest) {
  std::string command_hash;
  std::string authorization;
  EXPECT_TRUE(delegate_.GetCommandAuthorization(command_hash, false, false,
                                                &authorization));
  TPMS_AUTH_COMMAND auth_command;
  std::string auth_bytes;
  EXPECT_EQ(TPM_RC_SUCCESS, Parse_TPMS_AUTH_COMMAND(
                                &authorization, &auth_command, &auth_bytes));
  EXPECT_TRUE(authorization.empty());
  EXPECT_EQ(auth_command.session_handle, session_handle_);
  EXPECT_EQ(auth_command.nonce.size, session_nonce_.size);
  EXPECT_EQ(kContinueSession, auth_command.session_attributes);
  EXPECT_EQ(kHashDigestSize, auth_command.hmac.size);
}

TEST_F(HmacAuthorizationDelegateFixture, ResponseAuthTest) {
  TPMS_AUTH_RESPONSE auth_response;
  auth_response.session_attributes = kContinueSession;
  auth_response.nonce.size = kAesKeySize;
  memset(auth_response.nonce.buffer, 0, kAesKeySize);
  auth_response.hmac.size = kHashDigestSize;
  // TODO(usanghi): Use TCG TPM2.0 test vectors when available.
  uint8_t hmac_buffer[kHashDigestSize] = {
      0x37, 0x69, 0xaf, 0x12, 0xff, 0x4d, 0xbf, 0x44, 0xe5, 0x16, 0xa2,
      0x2d, 0x1d, 0x05, 0x12, 0xe8, 0xbc, 0x42, 0x51, 0x6d, 0x59, 0xe8,
      0xbf, 0x40, 0x1e, 0xa3, 0x46, 0xa4, 0xd6, 0x0d, 0xcc, 0xf7};
  memcpy(auth_response.hmac.buffer, hmac_buffer, kHashDigestSize);
  std::string response_hash;
  std::string authorization;
  EXPECT_EQ(TPM_RC_SUCCESS,
            Serialize_TPMS_AUTH_RESPONSE(auth_response, &authorization));
  EXPECT_TRUE(
      delegate_.CheckResponseAuthorization(response_hash, authorization));
  std::string tpm_nonce;
  EXPECT_TRUE(delegate_.GetTpmNonce(&tpm_nonce));
  EXPECT_EQ(std::string(kAesKeySize, '\0'), tpm_nonce);

  memset(auth_response.nonce.buffer, 1, kAesKeySize);
  auth_response.hmac.size = kHashDigestSize;
  uint8_t hmac_buffer_2[kHashDigestSize] = {
      0x89, 0xD0, 0x51, 0xAC, 0x25, 0x7F, 0x6D, 0x12, 0x59, 0x08, 0xAD,
      0x55, 0xDA, 0xB3, 0x9E, 0x2D, 0x34, 0xB1, 0xB5, 0x47, 0xB6, 0x45,
      0x17, 0x2F, 0x88, 0x0B, 0x60, 0xF9, 0x41, 0x73, 0x6F, 0xD1};
  memcpy(auth_response.hmac.buffer, hmac_buffer_2, kHashDigestSize);
  authorization.clear();
  EXPECT_EQ(TPM_RC_SUCCESS,
            Serialize_TPMS_AUTH_RESPONSE(auth_response, &authorization));
  EXPECT_TRUE(
      delegate_.CheckResponseAuthorization(response_hash, authorization));
  EXPECT_TRUE(delegate_.GetTpmNonce(&tpm_nonce));
  EXPECT_EQ(std::string(kAesKeySize, '\1'), tpm_nonce);
}

TEST_F(HmacAuthorizationDelegateFixture, SessionAttributes) {
  const uint8_t kDecryptSession = 1 << 5;
  const uint8_t kEncryptSession = 1 << 6;

  // Encryption disabled and not possible for command.
  std::string authorization;
  EXPECT_TRUE(delegate_.GetCommandAuthorization(std::string(), false, false,
                                                &authorization));
  TPMS_AUTH_COMMAND auth_command;
  std::string auth_bytes;
  EXPECT_EQ(TPM_RC_SUCCESS, Parse_TPMS_AUTH_COMMAND(
                                &authorization, &auth_command, &auth_bytes));
  EXPECT_TRUE(authorization.empty());
  EXPECT_EQ(kContinueSession, auth_command.session_attributes);

  // Encryption disabled and possible for command.
  EXPECT_TRUE(delegate_.GetCommandAuthorization(std::string(), true, true,
                                                &authorization));
  EXPECT_EQ(TPM_RC_SUCCESS, Parse_TPMS_AUTH_COMMAND(
                                &authorization, &auth_command, &auth_bytes));
  EXPECT_TRUE(authorization.empty());
  EXPECT_EQ(kContinueSession, auth_command.session_attributes);

  // Encryption enabled and not possible for command.
  ASSERT_TRUE(delegate_.InitSession(session_handle_,
                                    session_nonce_,  // TPM nonce.
                                    session_nonce_,  // Caller nonce.
                                    std::string(),   // Salt.
                                    std::string(),   // Bind auth value.
                                    true));          // Enable encryption.
  EXPECT_TRUE(delegate_.GetCommandAuthorization(std::string(), false, false,
                                                &authorization));
  EXPECT_EQ(TPM_RC_SUCCESS, Parse_TPMS_AUTH_COMMAND(
                                &authorization, &auth_command, &auth_bytes));
  EXPECT_TRUE(authorization.empty());
  EXPECT_EQ(kContinueSession, auth_command.session_attributes);

  // Encryption enabled and possible only for command input.
  EXPECT_TRUE(delegate_.GetCommandAuthorization(std::string(), true, false,
                                                &authorization));
  EXPECT_EQ(TPM_RC_SUCCESS, Parse_TPMS_AUTH_COMMAND(
                                &authorization, &auth_command, &auth_bytes));
  EXPECT_TRUE(authorization.empty());
  EXPECT_EQ(kContinueSession | kDecryptSession,
            auth_command.session_attributes);

  // Encryption enabled and possible only for command output.
  EXPECT_TRUE(delegate_.GetCommandAuthorization(std::string(), false, true,
                                                &authorization));
  EXPECT_EQ(TPM_RC_SUCCESS, Parse_TPMS_AUTH_COMMAND(
                                &authorization, &auth_command, &auth_bytes));
  EXPECT_TRUE(authorization.empty());
  EXPECT_EQ(kContinueSession | kEncryptSession,
            auth_command.session_attributes);

  // Encryption enabled and possible for command input and output.
  EXPECT_TRUE(delegate_.GetCommandAuthorization(std::string(), true, true,
                                                &authorization));
  EXPECT_EQ(TPM_RC_SUCCESS, Parse_TPMS_AUTH_COMMAND(
                                &authorization, &auth_command, &auth_bytes));
  EXPECT_TRUE(authorization.empty());
  EXPECT_EQ(kContinueSession | kEncryptSession | kDecryptSession,
            auth_command.session_attributes);
}

}  // namespace trunks
