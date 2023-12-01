// Copyright 2015 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "trunks/trunks_client_test.h"

#include <algorithm>
#include <iterator>
#include <map>
#include <memory>
#include <random>
#include <string>
#include <vector>

#include <base/check.h>
#include <base/check_op.h>
#include <base/functional/bind.h>
#include <base/functional/callback.h>
#include <base/functional/callback_helpers.h>
#include <base/logging.h>
#include <base/rand_util.h>
#include <crypto/openssl_util.h>
#include <crypto/libcrypto-compat.h>
#include <crypto/scoped_openssl_types.h>
#include <crypto/sha2.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/rsa.h>

#include "trunks/authorization_delegate.h"
#include "trunks/error_codes.h"
#include "trunks/hmac_session.h"
#include "trunks/policy_session.h"
#include "trunks/scoped_key_handle.h"
#include "trunks/tpm_constants.h"
#include "trunks/tpm_generated.h"
#include "trunks/tpm_state.h"
#include "trunks/tpm_utility.h"
#include "trunks/trunks_factory_impl.h"

namespace {

std::string GetOpenSSLError() {
  BIO* bio = BIO_new(BIO_s_mem());
  ERR_print_errors(bio);
  char* data = nullptr;
  int data_len = BIO_get_mem_data(bio, &data);
  std::string error_string(data, data_len);
  BIO_free(bio);
  return error_string;
}

}  // namespace

namespace trunks {

TrunksClientTest::TrunksClientTest(const TrunksFactory& factory)
    : factory_(factory) {
  crypto::EnsureOpenSSLInit();
}

TrunksClientTest::~TrunksClientTest() {}

bool TrunksClientTest::RNGTest() {
  std::unique_ptr<TpmUtility> utility = factory_.GetTpmUtility();
  std::unique_ptr<HmacSession> session = factory_.GetHmacSession();
  if (utility->StartSession(session.get()) != TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error starting hmac session.";
    return false;
  }
  std::string entropy_data("entropy_data");
  std::string random_data;
  size_t num_bytes = 70;
  TPM_RC result = utility->StirRandom(entropy_data, session->GetDelegate());
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error stirring TPM RNG: " << GetErrorString(result);
    return false;
  }
  result =
      utility->GenerateRandom(num_bytes, session->GetDelegate(), &random_data);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error getting random bytes from TPM: "
               << GetErrorString(result);
    return false;
  }
  if (num_bytes != random_data.size()) {
    LOG(ERROR) << "Error not enough random bytes received.";
    return false;
  }
  return true;
}

bool TrunksClientTest::SignTest() {
  std::unique_ptr<TpmUtility> utility = factory_.GetTpmUtility();
  std::unique_ptr<HmacSession> session = factory_.GetHmacSession();
  if (utility->StartSession(session.get()) != TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error starting hmac session.";
    return false;
  }
  std::string key_authorization("sign");
  std::string key_blob;
  TPM_RC result = utility->CreateRSAKeyPair(
      TpmUtility::AsymmetricKeyUsage::kSignKey, 2048, 0x10001,
      key_authorization, "", false,  // use_only_policy_authorization
      std::vector<uint32_t>(), session->GetDelegate(), &key_blob, nullptr);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error creating signing key: " << GetErrorString(result);
    return false;
  }
  TPM_HANDLE signing_key;
  result = utility->LoadKey(key_blob, session->GetDelegate(), &signing_key);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error loading signing key: " << GetErrorString(result);
  }
  ScopedKeyHandle scoped_key(factory_, signing_key);
  scoped_key.set_synchronized(true);
  session->SetEntityAuthorizationValue(key_authorization);
  std::string signature;
  result = utility->Sign(signing_key, TPM_ALG_RSASSA, TPM_ALG_SHA256,
                         std::string(32, 'a'), true /* generate_hash */,
                         session->GetDelegate(), &signature);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error using key to sign: " << GetErrorString(result);
    return false;
  }
  std::string public_key;
  if (!GetRSAPublicKeyFromHandle(scoped_key, &public_key,
                                 session->GetDelegate())) {
    LOG(ERROR) << "Error fetching the public key to verify: "
               << GetErrorString(result);
    return false;
  }
  return VerifyRSASignature(public_key, std::string(32, 'a'), signature);
}

bool TrunksClientTest::DecryptTest() {
  std::unique_ptr<TpmUtility> utility = factory_.GetTpmUtility();
  std::unique_ptr<HmacSession> session = factory_.GetHmacSession();
  if (utility->StartSession(session.get()) != TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error starting hmac session.";
    return false;
  }
  std::string key_authorization("decrypt");
  std::string key_blob;
  TPM_RC result = utility->CreateRSAKeyPair(
      TpmUtility::AsymmetricKeyUsage::kDecryptKey, 2048, 0x10001,
      key_authorization, "", false,  // use_only_policy_authorization
      std::vector<uint32_t>(), session->GetDelegate(), &key_blob, nullptr);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error creating decrypt key: " << GetErrorString(result);
    return false;
  }
  TPM_HANDLE decrypt_key;
  result = utility->LoadKey(key_blob, session->GetDelegate(), &decrypt_key);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error loading decrypt key: " << GetErrorString(result);
  }
  ScopedKeyHandle scoped_key(factory_, decrypt_key);
  scoped_key.set_synchronized(true);
  return PerformRSAEncryptAndDecrypt(scoped_key.get(), key_authorization,
                                     session.get());
}

bool TrunksClientTest::ImportTest() {
  std::unique_ptr<TpmUtility> utility = factory_.GetTpmUtility();
  std::unique_ptr<HmacSession> session = factory_.GetHmacSession();
  if (utility->StartSession(session.get()) != TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error starting hmac session.";
    return false;
  }
  std::string modulus;
  std::string prime_factor;
  GenerateRSAKeyPair(&modulus, &prime_factor, nullptr);
  std::string key_blob;
  std::string key_authorization("import");
  TPM_RC result = utility->ImportRSAKey(
      TpmUtility::AsymmetricKeyUsage::kDecryptAndSignKey, modulus, 0x10001,
      prime_factor, key_authorization, session->GetDelegate(), &key_blob);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error importing key into TPM: " << GetErrorString(result);
    return false;
  }
  TPM_HANDLE key_handle;
  result = utility->LoadKey(key_blob, session->GetDelegate(), &key_handle);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error loading key into TPM: " << GetErrorString(result);
    return false;
  }
  ScopedKeyHandle scoped_key(factory_, key_handle);
  scoped_key.set_synchronized(true);
  return PerformRSAEncryptAndDecrypt(scoped_key.get(), key_authorization,
                                     session.get());
}

bool TrunksClientTest::AuthChangeTest() {
  std::unique_ptr<TpmUtility> utility = factory_.GetTpmUtility();
  std::unique_ptr<HmacSession> session = factory_.GetHmacSession();
  if (utility->StartSession(session.get()) != TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error starting hmac session.";
    return false;
  }
  std::string key_authorization("new_pass");
  std::string key_blob;
  TPM_RC result = utility->CreateRSAKeyPair(
      TpmUtility::AsymmetricKeyUsage::kDecryptKey, 2048, 0x10001, "old_pass",
      "", false,  // use_only_policy_authorization
      std::vector<uint32_t>(), session->GetDelegate(), &key_blob, nullptr);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error creating change auth key: " << GetErrorString(result);
    return false;
  }
  TPM_HANDLE key_handle;
  result = utility->LoadKey(key_blob, session->GetDelegate(), &key_handle);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error loading change auth key: " << GetErrorString(result);
  }
  ScopedKeyHandle scoped_key(factory_, key_handle);
  scoped_key.set_synchronized(true);
  session->SetEntityAuthorizationValue("old_pass");
  result = utility->ChangeKeyAuthorizationData(
      key_handle, key_authorization, session->GetDelegate(), &key_blob);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error changing auth data: " << GetErrorString(result);
    return false;
  }
  session->SetEntityAuthorizationValue("");
  result = utility->LoadKey(key_blob, session->GetDelegate(), &key_handle);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error reloading key: " << GetErrorString(result);
    return false;
  }
  scoped_key.reset(key_handle);
  return PerformRSAEncryptAndDecrypt(scoped_key.get(), key_authorization,
                                     session.get());
}

bool TrunksClientTest::VerifyKeyCreationTest() {
  std::unique_ptr<TpmUtility> utility = factory_.GetTpmUtility();
  std::unique_ptr<HmacSession> session = factory_.GetHmacSession();
  if (utility->StartSession(session.get()) != TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error starting hmac session.";
    return false;
  }
  std::string key_blob;
  std::string creation_blob;
  session->SetEntityAuthorizationValue("");
  TPM_RC result = utility->CreateRSAKeyPair(
      TpmUtility::AsymmetricKeyUsage::kDecryptKey, 2048, 0x10001, "", "",
      false,  // use_only_policy_authorization
      std::vector<uint32_t>(), session->GetDelegate(), &key_blob,
      &creation_blob);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error creating certify key: " << GetErrorString(result);
    return false;
  }
  std::string alternate_key_blob;
  result = utility->CreateRSAKeyPair(
      TpmUtility::AsymmetricKeyUsage::kDecryptKey, 2048, 0x10001, "", "",
      false,  // use_only_policy_authorization
      std::vector<uint32_t>(), session->GetDelegate(), &alternate_key_blob,
      nullptr);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error creating alternate key: " << GetErrorString(result);
    return false;
  }
  TPM_HANDLE key_handle;
  result = utility->LoadKey(key_blob, session->GetDelegate(), &key_handle);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error loading certify key: " << GetErrorString(result);
    return false;
  }
  TPM_HANDLE alternate_key_handle;
  result = utility->LoadKey(alternate_key_blob, session->GetDelegate(),
                            &alternate_key_handle);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error loading alternate key: " << GetErrorString(result);
    return false;
  }
  ScopedKeyHandle certify_key(factory_, key_handle);
  certify_key.set_synchronized(true);
  ScopedKeyHandle alternate_key(factory_, alternate_key_handle);
  alternate_key.set_synchronized(true);
  result = utility->CertifyCreation(certify_key.get(), creation_blob);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error certifying key: " << GetErrorString(result);
    return false;
  }
  result = utility->CertifyCreation(alternate_key.get(), creation_blob);
  if (result == TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error alternate key certified with wrong creation data.";
    return false;
  }
  return true;
}

bool TrunksClientTest::SealedDataTest() {
  std::unique_ptr<TpmUtility> utility = factory_.GetTpmUtility();
  std::unique_ptr<HmacSession> session = factory_.GetHmacSession();
  if (utility->StartSession(session.get()) != TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error starting hmac session.";
    return false;
  }
  uint32_t pcr_index = 5;
  std::string policy_digest;
  TPM_RC result = utility->GetPolicyDigestForPcrValues(
      std::map<uint32_t, std::string>({{pcr_index, ""}}),
      true /* use_auth_value */, &policy_digest);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error getting policy_digest: " << GetErrorString(result);
    return false;
  }
  std::string data_to_seal("seal_data");
  std::string auth_value("auth_value");
  std::string sealed_data;
  result = utility->SealData(data_to_seal, policy_digest, auth_value,
                             /*require_admin_with_policy=*/true,
                             session->GetDelegate(), &sealed_data);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error creating Sealed Object: " << GetErrorString(result);
    return false;
  }
  std::unique_ptr<PolicySession> policy_session = factory_.GetPolicySession();
  result = policy_session->StartUnboundSession(true, false);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error starting policy session: " << GetErrorString(result);
    return false;
  }
  result = policy_session->PolicyAuthValue();
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << __func__ << ": Error setting session to use auth_value: "
               << GetErrorString(result);
    return result;
  }
  result = policy_session->PolicyPCR(
      std::map<uint32_t, std::string>({{pcr_index, ""}}));
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error restricting policy to pcr value: "
               << GetErrorString(result);
    return false;
  }
  // Check fail scenario when no authorization value is given.
  std::string unsealed_data;
  result = utility->UnsealData(sealed_data, policy_session->GetDelegate(),
                               &unsealed_data);
  if (result == TPM_RC_SUCCESS && data_to_seal == unsealed_data) {
    LOG(ERROR) << "Error: unseal succeeded without authorization.";
    return false;
  }
  // Check success scenario.
  policy_session->SetEntityAuthorizationValue(auth_value);
  result = utility->UnsealData(sealed_data, policy_session->GetDelegate(),
                               &unsealed_data);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error unsealing object: " << GetErrorString(result);
    return false;
  }
  if (data_to_seal != unsealed_data) {
    LOG(ERROR) << "Error unsealed data from TPM does not match original data.";
    return false;
  }
  result = utility->ExtendPCR(pcr_index, "extend", session->GetDelegate());
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error extending pcr: " << GetErrorString(result);
    return false;
  }
  result = policy_session->PolicyPCR(
      std::map<uint32_t, std::string>({{pcr_index, ""}}));
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error restricting policy to pcr value: "
               << GetErrorString(result);
    return false;
  }
  result = utility->UnsealData(sealed_data, policy_session->GetDelegate(),
                               &unsealed_data);
  if (result == TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error object was unsealed with wrong policy_digest.";
    return false;
  }
  return true;
}

bool TrunksClientTest::SealedToMultiplePCRDataTest() {
  std::unique_ptr<TpmUtility> utility = factory_.GetTpmUtility();
  std::unique_ptr<HmacSession> session = factory_.GetHmacSession();
  if (utility->StartSession(session.get()) != TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error starting hmac session.";
    return false;
  }
  uint32_t pcr_index1 = 0;
  uint32_t pcr_index2 = 2;
  // Build policy digest.
  std::string policy_digest;
  TPM_RC result = utility->GetPolicyDigestForPcrValues(
      std::map<uint32_t, std::string>({{pcr_index1, ""}, {pcr_index2, ""}}),
      false /* use_auth_value */, &policy_digest);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error getting policy_digest: " << GetErrorString(result);
    return false;
  }
  // Seal the data.
  std::string data_to_seal("seal_data");
  std::string sealed_data;
  result = utility->SealData(data_to_seal, policy_digest, "",
                             /*require_admin_with_policy=*/true,
                             session->GetDelegate(), &sealed_data);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error creating Sealed Object: " << GetErrorString(result);
    return false;
  }
  std::unique_ptr<PolicySession> policy_session = factory_.GetPolicySession();
  result = policy_session->StartUnboundSession(true, false);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error starting policy session: " << GetErrorString(result);
    return false;
  }
  result = policy_session->PolicyPCR(
      std::map<uint32_t, std::string>({{pcr_index1, ""}, {pcr_index2, ""}}));
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error restricting policy to pcr value: "
               << GetErrorString(result);
    return false;
  }
  // Unseal the data under the same PCR.
  std::string unsealed_data;
  result = utility->UnsealData(sealed_data, policy_session->GetDelegate(),
                               &unsealed_data);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error unsealing object: " << GetErrorString(result);
    return false;
  }
  if (data_to_seal != unsealed_data) {
    LOG(ERROR) << "Error unsealed data from TPM does not match original data.";
    return false;
  }
  // Extend the PCR, thus making the data impossible to unseal.
  result = utility->ExtendPCR(pcr_index1, "extend", session->GetDelegate());
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error extending pcr: " << GetErrorString(result);
    return false;
  }
  result = policy_session->PolicyPCR(
      std::map<uint32_t, std::string>({{pcr_index1, ""}, {pcr_index2, ""}}));
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error restricting policy to pcr value: "
               << GetErrorString(result);
    return false;
  }
  // Try to unseal the data, after PCR change. It should fail.
  result = utility->UnsealData(sealed_data, policy_session->GetDelegate(),
                               &unsealed_data);
  if (result == TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error object was unsealed with wrong policy_digest.";
    return false;
  }
  return true;
}

bool TrunksClientTest::PCRTest() {
  std::unique_ptr<TpmUtility> utility = factory_.GetTpmUtility();
  std::unique_ptr<HmacSession> session = factory_.GetHmacSession();
  if (utility->StartSession(session.get()) != TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error starting hmac session.";
    return false;
  }
  // We are using PCR 2 because it is currently not used by ChromeOS.
  uint32_t pcr_index = 2;
  std::string extend_data("data");
  std::string old_data;
  TPM_RC result = utility->ReadPCR(pcr_index, &old_data);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error reading from PCR: " << GetErrorString(result);
    return false;
  }
  result = utility->ExtendPCR(pcr_index, extend_data, session->GetDelegate());
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error extending PCR value: " << GetErrorString(result);
    return false;
  }
  std::string pcr_data;
  result = utility->ReadPCR(pcr_index, &pcr_data);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error reading from PCR: " << GetErrorString(result);
    return false;
  }
  std::string hashed_extend_data = crypto::SHA256HashString(extend_data);
  std::string expected_pcr_data =
      crypto::SHA256HashString(old_data + hashed_extend_data);
  if (pcr_data.compare(expected_pcr_data) != 0) {
    LOG(ERROR) << "PCR data does not match expected value.";
    return false;
  }
  return true;
}

bool TrunksClientTest::PolicyAuthValueTest() {
  std::unique_ptr<TpmUtility> utility = factory_.GetTpmUtility();
  std::unique_ptr<PolicySession> trial_session = factory_.GetTrialSession();
  TPM_RC result;
  result = trial_session->StartUnboundSession(true, true);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error starting policy session: " << GetErrorString(result);
    return false;
  }
  result = trial_session->PolicyAuthValue();
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error restricting policy to auth value knowledge: "
               << GetErrorString(result);
    return false;
  }
  std::string policy_digest;
  result = trial_session->GetDigest(&policy_digest);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error getting policy digest: " << GetErrorString(result);
    return false;
  }
  // Now that we have the digest, we can close the trial session and use hmac.
  trial_session.reset();

  std::unique_ptr<HmacSession> hmac_session = factory_.GetHmacSession();
  result = hmac_session->StartUnboundSession(true, true);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error starting hmac session: " << GetErrorString(result);
    return false;
  }

  std::string key_blob;
  result = utility->CreateRSAKeyPair(
      TpmUtility::AsymmetricKeyUsage::kDecryptAndSignKey, 2048, 0x10001,
      "password", policy_digest, true,  // use_only_policy_authorization
      std::vector<uint32_t>(), hmac_session->GetDelegate(), &key_blob, nullptr);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error creating RSA key: " << GetErrorString(result);
    return false;
  }

  TPM_HANDLE key_handle;
  result = utility->LoadKey(key_blob, hmac_session->GetDelegate(), &key_handle);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error loading RSA key: " << GetErrorString(result);
    return false;
  }
  ScopedKeyHandle scoped_key(factory_, key_handle);
  scoped_key.set_synchronized(true);
  // Now we can reset the hmac_session.
  hmac_session.reset();

  std::unique_ptr<PolicySession> policy_session = factory_.GetPolicySession();
  result = policy_session->StartUnboundSession(true, false);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error starting policy session: " << GetErrorString(result);
    return false;
  }
  result = policy_session->PolicyAuthValue();
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error restricting policy to auth value knowledge: "
               << GetErrorString(result);
    return false;
  }
  std::string signature;
  policy_session->SetEntityAuthorizationValue("password");
  result = utility->Sign(scoped_key.get(), TPM_ALG_RSASSA, TPM_ALG_SHA256,
                         std::string(32, 0), true /* generate_hash */,
                         policy_session->GetDelegate(), &signature);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error signing using RSA key: " << GetErrorString(result);
    return false;
  }
  std::string public_key;
  if (!GetRSAPublicKeyFromHandle(scoped_key, &public_key,
                                 policy_session->GetDelegate())) {
    LOG(ERROR) << "Error fetching the public key to verify: "
               << GetErrorString(result);
    return false;
  }
  if (!VerifyRSASignature(public_key, std::string(32, 0), signature)) {
    LOG(ERROR) << "Error verifying using RSA key: " << GetErrorString(result);
    return false;
  }
  std::string ciphertext;
  result =
      utility->AsymmetricEncrypt(scoped_key.get(), TPM_ALG_OAEP, TPM_ALG_SHA256,
                                 "plaintext", nullptr, &ciphertext);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error encrypting using RSA key: " << GetErrorString(result);
    return false;
  }
  result = policy_session->PolicyAuthValue();
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error restricting policy to auth value knowledge: "
               << GetErrorString(result);
    return false;
  }
  std::string plaintext;
  policy_session->SetEntityAuthorizationValue("password");
  result = utility->AsymmetricDecrypt(
      scoped_key.get(), TPM_ALG_OAEP, TPM_ALG_SHA256, ciphertext,
      policy_session->GetDelegate(), &plaintext);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error encrypting using RSA key: " << GetErrorString(result);
    return false;
  }
  if (plaintext.compare("plaintext") != 0) {
    LOG(ERROR) << "Plaintext changed after encrypt + decrypt.";
    return false;
  }
  return true;
}

bool TrunksClientTest::PolicyAndTest() {
  std::unique_ptr<TpmUtility> utility = factory_.GetTpmUtility();
  std::unique_ptr<PolicySession> trial_session = factory_.GetTrialSession();
  TPM_RC result;
  result = trial_session->StartUnboundSession(true, true);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error starting policy session: " << GetErrorString(result);
    return false;
  }
  result = trial_session->PolicyCommandCode(TPM_CC_Sign);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error restricting policy: " << GetErrorString(result);
    return false;
  }
  uint32_t pcr_index = 2;
  std::string pcr_value;
  result = utility->ReadPCR(pcr_index, &pcr_value);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error reading pcr: " << GetErrorString(result);
    return false;
  }
  std::string pcr_extend_data("extend");
  std::string next_pcr_value;
  std::string hashed_extend_data = crypto::SHA256HashString(pcr_extend_data);
  next_pcr_value = crypto::SHA256HashString(pcr_value + hashed_extend_data);

  result = trial_session->PolicyPCR(
      std::map<uint32_t, std::string>({{pcr_index, next_pcr_value}}));
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error restricting policy: " << GetErrorString(result);
    return false;
  }
  std::string policy_digest;
  result = trial_session->GetDigest(&policy_digest);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error getting policy digest: " << GetErrorString(result);
    return false;
  }
  // Now that we have the digest, we can close the trial session and use hmac.
  trial_session.reset();

  std::unique_ptr<HmacSession> hmac_session = factory_.GetHmacSession();
  result = hmac_session->StartUnboundSession(true, true);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error starting hmac session: " << GetErrorString(result);
    return false;
  }
  std::string key_authorization("password");
  std::string key_blob;
  // This key is created with a policy that dictates it can only be used
  // when pcr 2 remains unchanged, and when the command is TPM2_Sign.
  result = utility->CreateRSAKeyPair(
      TpmUtility::AsymmetricKeyUsage::kDecryptAndSignKey, 2048, 0x10001,
      key_authorization, policy_digest, true,  // use_only_policy_authorization
      std::vector<uint32_t>(), hmac_session->GetDelegate(), &key_blob, nullptr);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error creating RSA key: " << GetErrorString(result);
    return false;
  }
  TPM_HANDLE key_handle;
  result = utility->LoadKey(key_blob, hmac_session->GetDelegate(), &key_handle);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error loading RSA key: " << GetErrorString(result);
    return false;
  }
  ScopedKeyHandle scoped_key(factory_, key_handle);
  scoped_key.set_synchronized(true);
  // Now we can reset the hmac_session.
  hmac_session.reset();

  std::unique_ptr<PolicySession> policy_session = factory_.GetPolicySession();
  result = policy_session->StartUnboundSession(true, false);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error starting policy session: " << GetErrorString(result);
    return false;
  }
  result = policy_session->PolicyCommandCode(TPM_CC_Sign);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error restricting policy: " << GetErrorString(result);
    return false;
  }
  result = policy_session->PolicyPCR(
      std::map<uint32_t, std::string>({{pcr_index, ""}}));
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error restricting policy: " << GetErrorString(result);
    return false;
  }
  std::string signature;
  policy_session->SetEntityAuthorizationValue(key_authorization);
  // Signing with this key when pcr 2 is unchanged fails.
  result = utility->Sign(scoped_key.get(), TPM_ALG_RSASSA, TPM_ALG_SHA256,
                         std::string(32, 'a'), true /* generate_hash */,
                         policy_session->GetDelegate(), &signature);
  if (GetFormatOneError(result) != TPM_RC_POLICY_FAIL) {
    LOG(ERROR) << "Error using key to sign: " << GetErrorString(result);
    return false;
  }
  std::unique_ptr<AuthorizationDelegate> delegate =
      factory_.GetPasswordAuthorization("");
  result = utility->ExtendPCR(pcr_index, pcr_extend_data, delegate.get());
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error extending pcr: " << GetErrorString(result);
    return false;
  }
  // we have to restart the session because we changed the pcr values.
  result = policy_session->StartUnboundSession(true, false);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error starting policy session: " << GetErrorString(result);
    return false;
  }
  result = policy_session->PolicyCommandCode(TPM_CC_Sign);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error restricting policy: " << GetErrorString(result);
    return false;
  }
  result = policy_session->PolicyPCR(
      std::map<uint32_t, std::string>({{pcr_index, ""}}));
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error restricting policy: " << GetErrorString(result);
    return false;
  }
  policy_session->SetEntityAuthorizationValue(key_authorization);
  // Signing with this key when pcr 2 is changed succeeds.
  result = utility->Sign(scoped_key.get(), TPM_ALG_RSASSA, TPM_ALG_SHA256,
                         std::string(32, 'a'), true /* generate_hash */,
                         policy_session->GetDelegate(), &signature);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error using key to sign: " << GetErrorString(result);
    return false;
  }
  std::string public_key;
  if (!GetRSAPublicKeyFromHandle(scoped_key, &public_key,
                                 policy_session->GetDelegate())) {
    LOG(ERROR) << "Error fetching the public key to verify: "
               << GetErrorString(result);
    return false;
  }
  if (!VerifyRSASignature(public_key, std::string(32, 'a'), signature)) {
    LOG(ERROR) << "Error using key to verify: " << GetErrorString(result);
    return false;
  }
  std::string ciphertext;
  result = utility->AsymmetricEncrypt(key_handle, TPM_ALG_OAEP, TPM_ALG_SHA256,
                                      "plaintext", nullptr, &ciphertext);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error using key to encrypt: " << GetErrorString(result);
    return false;
  }
  result = policy_session->PolicyCommandCode(TPM_CC_Sign);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error restricting policy: " << GetErrorString(result);
    return false;
  }
  result = policy_session->PolicyPCR(
      std::map<uint32_t, std::string>({{pcr_index, ""}}));
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error restricting policy: " << GetErrorString(result);
    return false;
  }
  std::string plaintext;
  policy_session->SetEntityAuthorizationValue(key_authorization);
  // This call is not authorized with the policy, because its command code
  // is not TPM_CC_SIGN. It should fail with TPM_RC_POLICY_CC.
  result = utility->AsymmetricDecrypt(key_handle, TPM_ALG_OAEP, TPM_ALG_SHA256,
                                      ciphertext, policy_session->GetDelegate(),
                                      &plaintext);
  if (GetFormatOneError(result) != TPM_RC_POLICY_CC) {
    LOG(ERROR) << "Error: " << GetErrorString(result);
    return false;
  }
  return true;
}

bool TrunksClientTest::PolicyOrTest() {
  std::unique_ptr<TpmUtility> utility = factory_.GetTpmUtility();
  std::unique_ptr<PolicySession> trial_session = factory_.GetTrialSession();
  TPM_RC result;
  // Specify a policy that asserts either TPM_CC_Sign or TPM_CC_RSA_Decrypt.
  // A key created under this policy can only be used to sign or decrypt.
  result = trial_session->StartUnboundSession(true, true);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error starting policy session: " << GetErrorString(result);
    return false;
  }
  result = trial_session->PolicyCommandCode(TPM_CC_Sign);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error restricting policy: " << GetErrorString(result);
    return false;
  }
  std::string sign_digest;
  result = trial_session->GetDigest(&sign_digest);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error getting policy digest: " << GetErrorString(result);
    return false;
  }
  result = trial_session->StartUnboundSession(true, true);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error starting policy session: " << GetErrorString(result);
    return false;
  }
  result = trial_session->PolicyCommandCode(TPM_CC_RSA_Decrypt);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error restricting policy: " << GetErrorString(result);
    return false;
  }
  std::string decrypt_digest;
  result = trial_session->GetDigest(&decrypt_digest);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error getting policy digest: " << GetErrorString(result);
    return false;
  }
  std::vector<std::string> digests;
  digests.push_back(sign_digest);
  digests.push_back(decrypt_digest);
  result = trial_session->PolicyOR(digests);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error restricting policy: " << GetErrorString(result);
    return false;
  }
  std::string policy_digest;
  result = trial_session->GetDigest(&policy_digest);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error getting policy digest: " << GetErrorString(result);
    return false;
  }
  // Now that we have the digest, we can close the trial session and use hmac.
  trial_session.reset();

  std::unique_ptr<HmacSession> hmac_session = factory_.GetHmacSession();
  result = hmac_session->StartUnboundSession(true, true);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error starting hmac session: " << GetErrorString(result);
    return false;
  }
  std::string key_authorization("password");
  std::string key_blob;
  // This key is created with a policy that specifies that it can only be used
  // for sign and decrypt operations.
  result = utility->CreateRSAKeyPair(
      TpmUtility::AsymmetricKeyUsage::kDecryptAndSignKey, 2048, 0x10001,
      key_authorization, policy_digest, true,  // use_only_policy_authorization
      std::vector<uint32_t>(), hmac_session->GetDelegate(), &key_blob, nullptr);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error creating RSA key: " << GetErrorString(result);
    return false;
  }
  TPM_HANDLE key_handle;
  result = utility->LoadKey(key_blob, hmac_session->GetDelegate(), &key_handle);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error loading RSA key: " << GetErrorString(result);
    return false;
  }
  ScopedKeyHandle scoped_key(factory_, key_handle);
  scoped_key.set_synchronized(true);
  // Now we can reset the hmac_session.
  hmac_session.reset();

  std::unique_ptr<PolicySession> policy_session = factory_.GetPolicySession();
  result = policy_session->StartUnboundSession(true, false);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error starting policy session: " << GetErrorString(result);
    return false;
  }
  std::string ciphertext;
  result = utility->AsymmetricEncrypt(key_handle, TPM_ALG_OAEP, TPM_ALG_SHA256,
                                      "plaintext", nullptr, &ciphertext);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error using key to encrypt: " << GetErrorString(result);
    return false;
  }
  result = policy_session->PolicyCommandCode(TPM_CC_RSA_Decrypt);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error restricting policy: " << GetErrorString(result);
    return false;
  }
  result = policy_session->PolicyOR(digests);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error restricting policy: " << GetErrorString(result);
    return false;
  }
  std::string plaintext;
  policy_session->SetEntityAuthorizationValue(key_authorization);
  // We can freely use the key for decryption.
  result = utility->AsymmetricDecrypt(key_handle, TPM_ALG_OAEP, TPM_ALG_SHA256,
                                      ciphertext, policy_session->GetDelegate(),
                                      &plaintext);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error using key to decrypt: " << GetErrorString(result);
    return false;
  }
  if (plaintext.compare("plaintext") != 0) {
    LOG(ERROR) << "Plaintext changed after encrypt + decrypt.";
    return false;
  }
  result = policy_session->PolicyCommandCode(TPM_CC_Sign);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error restricting policy: " << GetErrorString(result);
    return false;
  }
  result = policy_session->PolicyOR(digests);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error restricting policy: " << GetErrorString(result);
    return false;
  }
  std::string signature;
  policy_session->SetEntityAuthorizationValue(key_authorization);
  // However signing with a key only authorized for encrypt/decrypt should
  // fail with TPM_RC_POLICY_CC.
  result = utility->Sign(scoped_key.get(), TPM_ALG_RSASSA, TPM_ALG_SHA256,
                         std::string(32, 'a'), true /* generate_hash */,
                         policy_session->GetDelegate(), &signature);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error using key to sign: " << GetErrorString(result);
    return false;
  }
  return true;
}

bool TrunksClientTest::NvramTest(const std::string& owner_password) {
  std::unique_ptr<TpmUtility> utility = factory_.GetTpmUtility();
  std::unique_ptr<HmacSession> session = factory_.GetHmacSession();
  TPM_RC result = session->StartUnboundSession(true /* salted */,
                                               true /* enable encryption */);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error starting hmac session: " << GetErrorString(result);
    return false;
  }
  uint32_t index = 1;
  session->SetEntityAuthorizationValue(owner_password);
  std::string nv_data("nv_data");
  TPMA_NV attributes = TPMA_NV_OWNERWRITE | TPMA_NV_AUTHREAD |
                       TPMA_NV_WRITE_STCLEAR | TPMA_NV_READ_STCLEAR;
  result = utility->DefineNVSpace(index, nv_data.size(), attributes, "", "",
                                  session->GetDelegate());
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error defining nvram: " << GetErrorString(result);
    return false;
  }
  // Setup auto-cleanup of the NVRAM space.
  auto cleanup = base::BindOnce(
      [](HmacSession* session, const std::string& owner_password,
         TpmUtility* utility, uint32_t index) {
        session->SetEntityAuthorizationValue(owner_password);
        TPM_RC result = utility->DestroyNVSpace(index, session->GetDelegate());
        if (result != TPM_RC_SUCCESS) {
          LOG(ERROR) << "Error destroying nvram: " << GetErrorString(result);
        }
      },
      session.get(), owner_password, utility.get(), index);
  base::ScopedClosureRunner scoper(std::move(cleanup));

  session->SetEntityAuthorizationValue(owner_password);
  result = utility->WriteNVSpace(index, 0, nv_data, true /*owner*/,
                                 false /*extend*/, session->GetDelegate());
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error writing nvram: " << GetErrorString(result);
    return false;
  }
  std::string new_nvdata;
  session->SetEntityAuthorizationValue("");
  result = utility->ReadNVSpace(index, 0, nv_data.size(), false /*owner*/,
                                &new_nvdata, session->GetDelegate());
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error reading nvram: " << GetErrorString(result);
    return false;
  }
  if (nv_data.compare(new_nvdata) != 0) {
    LOG(ERROR) << "NV space had different data than was written.";
    return false;
  }
  session->SetEntityAuthorizationValue(owner_password);
  result = utility->LockNVSpace(index, false /*lock_read*/, true /*lock_write*/,
                                false /*owner*/, session->GetDelegate());
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error locking nvram write: " << GetErrorString(result);
    return false;
  }
  session->SetEntityAuthorizationValue("");
  result = utility->ReadNVSpace(index, 0, nv_data.size(), false /*owner*/,
                                &new_nvdata, session->GetDelegate());
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error reading nvram: " << GetErrorString(result);
    return false;
  }
  if (nv_data.compare(new_nvdata) != 0) {
    LOG(ERROR) << "NV space had different data than was written.";
    return false;
  }
  session->SetEntityAuthorizationValue(owner_password);
  result = utility->WriteNVSpace(index, 0, nv_data, true /*owner*/,
                                 false /*extend*/, session->GetDelegate());
  if (result == TPM_RC_SUCCESS) {
    LOG(ERROR) << "Wrote nvram after locking!";
    return false;
  }
  result = utility->LockNVSpace(index, true /*lock_read*/, false /*lock_write*/,
                                true /*owner*/, session->GetDelegate());
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error locking nvram read: " << GetErrorString(result);
    return false;
  }
  result = utility->ReadNVSpace(index, 0, nv_data.size(), false /*owner*/,
                                &new_nvdata, session->GetDelegate());
  if (result == TPM_RC_SUCCESS) {
    LOG(ERROR) << "Read nvram after locking!";
    return false;
  }
  return true;
}

bool TrunksClientTest::ManyKeysTest() {
  const size_t kNumKeys = 20;
  std::vector<std::unique_ptr<ScopedKeyHandle>> key_handles;
  std::map<TPM_HANDLE, std::string> public_key_map;
  for (size_t i = 0; i < kNumKeys; ++i) {
    std::unique_ptr<ScopedKeyHandle> key_handle(new ScopedKeyHandle(factory_));
    key_handle->set_synchronized(true);
    std::string public_key;
    if (!LoadSigningKey(key_handle.get(), &public_key)) {
      LOG(ERROR) << "Error loading key " << i << " into TPM.";
    }
    public_key_map[key_handle->get()] = public_key;
    key_handles.push_back(std::move(key_handle));
  }
  CHECK_EQ(key_handles.size(), kNumKeys);
  CHECK_EQ(public_key_map.size(), kNumKeys);
  std::unique_ptr<AuthorizationDelegate> delegate =
      factory_.GetPasswordAuthorization("");
  for (size_t i = 0; i < kNumKeys; ++i) {
    const ScopedKeyHandle& key_handle = *key_handles[i];
    const std::string& public_key = public_key_map[key_handle.get()];
    if (!SignAndVerify(key_handle, public_key, delegate.get())) {
      LOG(ERROR) << "Error signing with key " << i;
    }
  }
  // TODO(emaxx): This needs to be replaced by base::RandomShuffle() introduced
  // by https://crrev.com/c/1023495.
  std::mt19937 urng(base::RandUint64());
  std::shuffle(key_handles.begin(), key_handles.end(), urng);
  for (size_t i = 0; i < kNumKeys; ++i) {
    const ScopedKeyHandle& key_handle = *key_handles[i];
    const std::string& public_key = public_key_map[key_handle.get()];
    if (!SignAndVerify(key_handle, public_key, delegate.get())) {
      LOG(ERROR) << "Error signing with shuffled key " << i;
    }
  }
  return true;
}

bool TrunksClientTest::ManySessionsTest() {
  const size_t kNumSessions = 20;
  std::unique_ptr<TpmUtility> utility = factory_.GetTpmUtility();
  std::vector<std::unique_ptr<HmacSession>> sessions;
  for (size_t i = 0; i < kNumSessions; ++i) {
    std::unique_ptr<HmacSession> session(factory_.GetHmacSession().release());
    TPM_RC result = session->StartUnboundSession(true /* salted */,
                                                 true /* enable encryption */);
    if (result != TPM_RC_SUCCESS) {
      LOG(ERROR) << "Error starting hmac session " << i << ": "
                 << GetErrorString(result);
      return false;
    }
    sessions.push_back(std::move(session));
  }
  CHECK_EQ(sessions.size(), kNumSessions);
  ScopedKeyHandle key_handle(factory_);
  key_handle.set_synchronized(true);
  std::string public_key;
  if (!LoadSigningKey(&key_handle, &public_key)) {
    return false;
  }
  for (size_t i = 0; i < kNumSessions; ++i) {
    if (!SignAndVerify(key_handle, public_key, sessions[i]->GetDelegate())) {
      LOG(ERROR) << "Error signing with hmac session " << i;
    }
  }
  // TODO(emaxx): This needs to be replaced by base::RandomShuffle() introduced
  // by https://crrev.com/c/1023495.
  std::mt19937 urng(base::RandUint64());
  std::shuffle(sessions.begin(), sessions.end(), urng);
  for (size_t i = 0; i < kNumSessions; ++i) {
    if (!SignAndVerify(key_handle, public_key, sessions[i]->GetDelegate())) {
      LOG(ERROR) << "Error signing with shuffled hmac session " << i;
    }
  }
  return true;
}

bool TrunksClientTest::EndorsementTest(const std::string& endorsement_password,
                                       const std::string& owner_password) {
  std::unique_ptr<TpmUtility> utility = factory_.GetTpmUtility();
  std::unique_ptr<HmacSession> session = factory_.GetHmacSession();
  TPM_RC result = session->StartUnboundSession(true /* salted */,
                                               false /* enable encryption */);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error starting hmac session: " << GetErrorString(result);
    return false;
  }
  session->SetEntityAuthorizationValue(endorsement_password);
  std::unique_ptr<HmacSession> session2 = factory_.GetHmacSession();
  result = session2->StartUnboundSession(true /* salted */,
                                         false /* enable encryption */);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error starting hmac session: " << GetErrorString(result);
    return false;
  }
  session2->SetEntityAuthorizationValue(owner_password);
  TPM_HANDLE key_handle;
  result = utility->GetEndorsementKey(TPM_ALG_RSA, session->GetDelegate(),
                                      session2->GetDelegate(), &key_handle);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << "GetEndorsementKey(RSA) failed: " << GetErrorString(result);
    return false;
  }
  result = utility->GetEndorsementKey(TPM_ALG_ECC, session->GetDelegate(),
                                      nullptr, &key_handle);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << "GetEndorsementKey(ECC) failed: " << GetErrorString(result);
    return false;
  }
  return true;
}

bool TrunksClientTest::IdentityKeyTest() {
  std::unique_ptr<TpmUtility> utility = factory_.GetTpmUtility();
  std::unique_ptr<HmacSession> session = factory_.GetHmacSession();
  TPM_RC result = session->StartUnboundSession(true /* salted */,
                                               false /* enable encryption */);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error starting hmac session: " << GetErrorString(result);
    return false;
  }
  std::string key_blob;
  result = utility->CreateIdentityKey(TPM_ALG_RSA, session->GetDelegate(),
                                      &key_blob);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << "CreateIdentityKey(RSA) failed: " << GetErrorString(result);
    return false;
  }
  std::unique_ptr<TpmState> tpm_state(factory_.GetTpmState());
  tpm_state->Initialize();
  if (tpm_state->IsECCSupported()) {
    result = utility->CreateIdentityKey(TPM_ALG_ECC, session->GetDelegate(),
                                        &key_blob);
    if (result != TPM_RC_SUCCESS) {
      LOG(ERROR) << "CreateIdentityKey(ECC) failed: " << GetErrorString(result);
      return false;
    }
  }
  return true;
}

bool TrunksClientTest::PerformRSAEncryptAndDecrypt(
    TPM_HANDLE key_handle,
    const std::string& key_authorization,
    HmacSession* session) {
  std::unique_ptr<TpmUtility> utility = factory_.GetTpmUtility();
  std::string ciphertext;
  session->SetEntityAuthorizationValue("");
  TPM_RC result = utility->AsymmetricEncrypt(
      key_handle, TPM_ALG_OAEP, TPM_ALG_SHA256, "plaintext",
      session->GetDelegate(), &ciphertext);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error using key to encrypt: " << GetErrorString(result);
    return false;
  }
  std::string plaintext;
  session->SetEntityAuthorizationValue(key_authorization);
  result = utility->AsymmetricDecrypt(key_handle, TPM_ALG_OAEP, TPM_ALG_SHA256,
                                      ciphertext, session->GetDelegate(),
                                      &plaintext);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error using key to decrypt: " << GetErrorString(result);
    return false;
  }
  if (plaintext.compare("plaintext") != 0) {
    LOG(ERROR) << "Plaintext changed after encrypt + decrypt.";
    return false;
  }
  return true;
}

void TrunksClientTest::GenerateRSAKeyPair(std::string* modulus,
                                          std::string* prime_factor,
                                          std::string* public_key) {
  crypto::ScopedRSA rsa(RSA_new());
  CHECK(rsa);
  crypto::ScopedBIGNUM exponent(BN_new());
  CHECK(exponent);
  CHECK(BN_set_word(exponent.get(), RSA_F4));
  CHECK(RSA_generate_key_ex(rsa.get(), 2048, exponent.get(), nullptr))
      << "Failed to generate RSA key: " << GetOpenSSLError();
  modulus->resize(RSA_size(rsa.get()), 0);
  const BIGNUM* n;
  RSA_get0_key(rsa.get(), &n, nullptr, nullptr);
  CHECK(BN_bn2bin(n, reinterpret_cast<unsigned char*>(std::data(*modulus))));
  const BIGNUM* p;
  RSA_get0_factors(rsa.get(), &p, nullptr);
  prime_factor->resize(BN_num_bytes(p), 0);
  CHECK(
      BN_bn2bin(p, reinterpret_cast<unsigned char*>(std::data(*prime_factor))));
  if (public_key) {
    unsigned char* buffer = NULL;
    int length = i2d_RSAPublicKey(rsa.get(), &buffer);
    CHECK_GT(length, 0);
    crypto::ScopedOpenSSLBytes scoped_buffer(buffer);
    public_key->assign(reinterpret_cast<char*>(buffer), length);
  }
}

bool TrunksClientTest::VerifyRSASignature(const std::string& public_key,
                                          const std::string& data,
                                          const std::string& signature) {
  auto asn1_ptr = reinterpret_cast<const unsigned char*>(public_key.data());
  crypto::ScopedRSA rsa(
      d2i_RSAPublicKey(nullptr, &asn1_ptr, public_key.size()));
  CHECK(rsa.get());
  std::string digest = crypto::SHA256HashString(data);
  auto digest_buffer = reinterpret_cast<const unsigned char*>(digest.data());
  std::string mutable_signature(signature);
  unsigned char* signature_buffer =
      reinterpret_cast<unsigned char*>(std::data(mutable_signature));
  return (RSA_verify(NID_sha256, digest_buffer, digest.size(), signature_buffer,
                     signature.size(), rsa.get()) == 1);
}

bool TrunksClientTest::LoadSigningKey(ScopedKeyHandle* key_handle,
                                      std::string* public_key) {
  std::string modulus;
  std::string prime_factor;
  GenerateRSAKeyPair(&modulus, &prime_factor, public_key);
  std::string key_blob;
  std::unique_ptr<TpmUtility> utility = factory_.GetTpmUtility();
  TPM_RC result = utility->ImportRSAKey(
      TpmUtility::AsymmetricKeyUsage::kSignKey, modulus, 0x10001, prime_factor,
      "",  // password
      factory_.GetPasswordAuthorization("").get(), &key_blob);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << "ImportRSAKey: " << GetErrorString(result);
    return false;
  }
  TPM_HANDLE raw_key_handle;
  result = utility->LoadKey(
      key_blob, factory_.GetPasswordAuthorization("").get(), &raw_key_handle);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << "LoadKey: " << GetErrorString(result);
    return false;
  }
  key_handle->reset(raw_key_handle);
  return true;
}

bool TrunksClientTest::SignAndVerify(const ScopedKeyHandle& key_handle,
                                     const std::string& public_key,
                                     AuthorizationDelegate* delegate) {
  std::string signature;
  std::string data_to_sign("sign_this");
  std::unique_ptr<TpmUtility> utility = factory_.GetTpmUtility();
  TPM_RC result = utility->Sign(key_handle.get(), TPM_ALG_RSASSA,
                                TPM_ALG_SHA256, data_to_sign,
                                true /* generate_hash */, delegate, &signature);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << "Sign: " << GetErrorString(result);
    return false;
  }
  if (!VerifyRSASignature(public_key, data_to_sign, signature)) {
    LOG(ERROR) << "Signature verification failed: " << GetOpenSSLError();
    return false;
  }
  return true;
}

bool TrunksClientTest::GetRSAPublicKeyFromHandle(
    const ScopedKeyHandle& key_handle,
    std::string* public_key,
    AuthorizationDelegate* delegate) {
  std::unique_ptr<TpmUtility> utility = factory_.GetTpmUtility();
  TPMT_PUBLIC public_area;
  TPM_RC result = utility->GetKeyPublicArea(key_handle.get(), &public_area);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << __func__ << GetErrorString(result);
    return false;
  }
  // Copied from cryptohome::PublicAreaToPublicKeyDER
  crypto::ScopedRSA rsa(RSA_new());
  CHECK(rsa);
  crypto::ScopedBIGNUM e(BN_new()), n(BN_new());
  CHECK(e);
  CHECK(n);
  CHECK(BN_set_word(e.get(), 0x10001)) << "Error setting exponent for RSA.";
  CHECK(BN_bin2bn(public_area.unique.rsa.buffer, public_area.unique.rsa.size,
                  n.get()))
      << "Error setting modulus for RSA.";
  CHECK(RSA_set0_key(rsa.get(), n.release(), e.release(), nullptr));

  int der_length = i2d_RSAPublicKey(rsa.get(), nullptr);
  if (der_length < 0) {
    LOG(ERROR) << "Failed to get DER-encoded public key length.";
    return false;
  }
  public_key->resize(der_length);
  unsigned char* der_buffer =
      reinterpret_cast<unsigned char*>(std::data(*public_key));
  der_length = i2d_RSAPublicKey(rsa.get(), &der_buffer);
  if (der_length < 0) {
    LOG(ERROR) << "Failed to DER-encode public key.";
    return false;
  }
  return true;
}

bool TrunksClientTest::PolicyFidoSignedTest(TPM_ALG_ID signing_algo) {
  std::unique_ptr<TpmUtility> utility = factory_.GetTpmUtility();
  std::unique_ptr<HmacSession> session = factory_.GetHmacSession();

  TPM_RC result;

  // 1. Prepare a key to sign.
  // 1-a) Create a key pair
  if (utility->StartSession(session.get()) != TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error starting hmac session.";
    return false;
  }

  std::string key_blob;

  switch (signing_algo) {
    case TPM_ALG_RSASSA:
    case TPM_ALG_RSAPSS:
      result = utility->CreateRSAKeyPair(
          TpmUtility::AsymmetricKeyUsage::kSignKey, 2048, 0x10001, "", "",
          false, std::vector<uint32_t>(), session->GetDelegate(), &key_blob,
          nullptr);
      break;

    case TPM_ALG_ECDSA:
    case TPM_ALG_ECDAA:
    case TPM_ALG_SM2:
    case TPM_ALG_ECSCHNORR:
      result = utility->CreateECCKeyPair(
          TpmUtility::AsymmetricKeyUsage::kSignKey, TPM_ECC_NIST_P256, "", "",
          false, std::vector<uint32_t>(), session->GetDelegate(), &key_blob,
          nullptr);
      break;

    default:
      result = TPM_RC_SCHEME;
      LOG(ERROR) << "Unknown hash algorithm: " << GetErrorString(result);
      return result;
  }
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error creating signing key: " << GetErrorString(result);
    return false;
  }

  // 1-b) Load the key
  TPM_HANDLE signing_key_handle;
  result =
      utility->LoadKey(key_blob, session->GetDelegate(), &signing_key_handle);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error loading signing key: " << GetErrorString(result);
    return false;
  }

  // 2. PolicyFidoSigned in trial session
  // 2-a) Start Auth session
  std::unique_ptr<PolicySession> trial_session = factory_.GetTrialSession();

  result = trial_session->StartUnboundSession(true, true);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error starting policy session: " << GetErrorString(result);
    return false;
  }

  // 2-b) Sign the authenticatorData and session nonce
  const std::string auth_data_fixed =
      crypto::SHA256HashString("chromeos:login:nobody");
  const std::string auth_data =
      std::string("ghijklmn", 8) + auth_data_fixed + std::string("opqrstuv", 8);

  const std::vector<trunks::FIDO_DATA_RANGE> auth_data_descr = {
      {.offset = 0x0008, .size = 0x0010}, {.offset = 0x0018, .size = 0x0010}};

  std::string nonce;
  trial_session->GetDelegate()->GetTpmNonce(&nonce);

  TPM_ALG_ID hash_algo = TPM_ALG_SHA256;

  TPMT_SIGNATURE auth;
  result = utility->RawSign(signing_key_handle, signing_algo, hash_algo,
                            auth_data + nonce,
                            true,  // generate_hash
                            session->GetDelegate(), &auth);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error using key to sign: " << GetErrorString(result);
    return false;
  }

  // 2-c) Policy Fido Signed (with loaded pub key from 1-b)
  std::string signing_key_name;

  result = utility->GetKeyName(signing_key_handle, &signing_key_name);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error in getting key name: " << GetErrorString(result);
    return false;
  }

  result = trial_session->PolicyFidoSigned(signing_key_handle, signing_key_name,
                                           auth_data, auth_data_descr, auth,
                                           nullptr);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error with PolicyFidoSigned in trial session: "
               << GetErrorString(result);
    return false;
  }

  // 2-d) Get Policy digest
  std::string policy_digest;
  result = trial_session->GetDigest(&policy_digest);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error getting policy digest: " << GetErrorString(result);
    return false;
  }

  // Now that we have the digest, we can close the trial session and use hmac.
  trial_session.reset();

  // 3. Seal an secret object.
  const std::string data_to_seal("sealed_data_for_PolicyFidoSigned");
  std::string sealed_data;

  result = utility->SealData(data_to_seal, policy_digest, "",
                             /*require_admin_with_policy=*/true,
                             session->GetDelegate(), &sealed_data);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error creating Sealed Object: " << GetErrorString(result);
    return false;
  }

  // 4. Test failing cases
  // 4-1. Start Auth Session ((TPM_SE_POLICY = 0x01))
  std::unique_ptr<PolicySession> policy_session = factory_.GetPolicySession();

  result = policy_session->StartUnboundSession(true, false);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error starting policy session: " << GetErrorString(result);
    return false;
  }

  const std::string auth_data2 =
      std::string("XXXXXXXX", 8) + auth_data_fixed + std::string("ZZZZZZZZ", 8);

  // 4-2. Check PolicyFidoSigned fail with the wrong data auth
  result = policy_session->PolicyFidoSigned(
      signing_key_handle, signing_key_name, auth_data2, auth_data_descr,
      TPMT_SIGNATURE(), session->GetDelegate());
  if (result == TPM_RC_SUCCESS) {
    LOG(ERROR) << "Unexpected success with PolicyFidoSigned "
               << "with the empty auth: " << GetErrorString(result);
    return false;
  }

  // 4-3. Check PolicyFidoSigned fail with the wrong auth data
  // 4-3-1. Sign the command parameters
  policy_session->GetDelegate()->GetTpmNonce(&nonce);
  result = utility->RawSign(signing_key_handle, signing_algo, hash_algo,
                            std::string(64, '0') + nonce,  // <- wrong authData
                            true,                          // generate_hash
                            session->GetDelegate(), &auth);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error using key to sign: " << GetErrorString(result);
    return false;
  }

  // 4-3-2. Call PolicyFidoSigned with the wrong authData
  result = policy_session->PolicyFidoSigned(
      signing_key_handle, signing_key_name,
      std::string(64, '0'),  // <- wrong authData
      auth_data_descr, auth, session->GetDelegate());
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error with PolicyFidoSigned in policy session: "
               << GetErrorString(result);
    return false;
  }

  // 4-3-3. check UnsealData fail
  std::string unsealed_data;
  result = utility->UnsealData(sealed_data, policy_session->GetDelegate(),
                               &unsealed_data);
  if (result == TPM_RC_SUCCESS) {
    LOG(ERROR) << "Unexpected success in unsealing object: "
               << GetErrorString(result);
    return false;
  }

  // 4-4. Check PolicyFidoSigned fail with the wrong auth_data_descr.
  policy_session->GetDelegate()->GetTpmNonce(&nonce);
  result = utility->RawSign(signing_key_handle, signing_algo, hash_algo,
                            auth_data2 + nonce,
                            true,  // generate_hash
                            session->GetDelegate(), &auth);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error using key to sign: " << GetErrorString(result);
    return false;
  }

  const std::vector<trunks::FIDO_DATA_RANGE> auth_data_descr2 = {
      {.offset = 0x0008, .size = 0x0010},
      {.offset = 0x0018, .size = 0x00f0}};  // <-- out of range

  result = policy_session->PolicyFidoSigned(
      signing_key_handle, signing_key_name, auth_data2, auth_data_descr2, auth,
      session->GetDelegate());
  if (result == TPM_RC_SUCCESS) {
    LOG(ERROR) << "Unexpected success with PolicyFidoSigned in policy session: "
               << GetErrorString(result);
    return false;
  }

  // 4-5. Check PolicyFidoSigned fail with a different auth_data_descr
  const std::vector<trunks::FIDO_DATA_RANGE> auth_data_descr3 = {
      {.offset = 0x0008, .size = 0x0020}};

  policy_session->GetDelegate()->GetTpmNonce(&nonce);
  result = utility->RawSign(signing_key_handle, signing_algo, hash_algo,
                            auth_data + nonce,
                            true,  // generate_hash
                            session->GetDelegate(), &auth);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error using key to sign: " << GetErrorString(result);
    return false;
  }

  result = policy_session->PolicyFidoSigned(
      signing_key_handle, signing_key_name, auth_data, auth_data_descr3, auth,
      session->GetDelegate());
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error with PolicyFidoSigned in policy session: "
               << GetErrorString(result);
    return false;
  }

  result = utility->UnsealData(sealed_data, policy_session->GetDelegate(),
                               &unsealed_data);
  if (result == TPM_RC_SUCCESS) {
    LOG(ERROR) << "Unexpected success in unsealing object: "
               << GetErrorString(result);
    return false;
  }

  policy_session.reset();

  // 5. Test success cases
  // 5-1. Check PolicyFidoSigned success
  policy_session = factory_.GetPolicySession();

  result = policy_session->StartUnboundSession(true, false);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error starting policy session: " << GetErrorString(result);
    return false;
  }

  // 5-1-1. Sign the command
  policy_session->GetDelegate()->GetTpmNonce(&nonce);
  result = utility->RawSign(signing_key_handle, signing_algo, hash_algo,
                            auth_data2 + nonce,
                            true,  // generate_hash
                            session->GetDelegate(), &auth);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error using key to sign: " << GetErrorString(result);
    return false;
  }

  // 5-1-2. PolicyFidoSigned
  result = policy_session->PolicyFidoSigned(
      signing_key_handle, signing_key_name, auth_data2, auth_data_descr, auth,
      session->GetDelegate());
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error with PolicyFidoSigned in policy session: "
               << GetErrorString(result);
    return false;
  }

  // 5-1-3. Unseal
  std::string unsealed_data2;
  result = utility->UnsealData(sealed_data, policy_session->GetDelegate(),
                               &unsealed_data2);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error unsealing object: " << GetErrorString(result);
    return false;
  }
  if (data_to_seal != unsealed_data2) {
    LOG(ERROR) << "Error unsealed data from TPM does not match original data.";
    return false;
  }

  policy_session.reset();

  return true;
}

}  // namespace trunks
