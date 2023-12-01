// Copyright 2015 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Test methods that run on a real TPM

#include "cryptohome/tpm_live_test.h"

#include <stdint.h>

#include <deque>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <utility>

#include <absl/container/flat_hash_set.h>
#include <base/check_op.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/memory/ptr_util.h>
#include <crypto/libcrypto-compat.h>
#include <crypto/scoped_openssl_types.h>
#include <crypto/sha2.h>
#include <libhwsec/factory/factory_impl.h>
#include <libhwsec/frontend/cryptohome/frontend.h>
#include <libhwsec/status.h>
#include <libhwsec/structures/key.h>
#include <libhwsec-foundation/crypto/big_num_util.h>
#include <libhwsec-foundation/crypto/elliptic_curve.h>
#include <libhwsec-foundation/crypto/rsa.h>
#include <libhwsec-foundation/crypto/secure_blob_util.h>
#include <libhwsec-foundation/crypto/sha.h>
#include <libhwsec-foundation/error/error.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

#include "cryptohome/auth_blocks/auth_block.h"
#include "cryptohome/auth_blocks/tpm_bound_to_pcr_auth_block.h"
#include "cryptohome/auth_blocks/tpm_ecc_auth_block.h"
#include "cryptohome/auth_blocks/tpm_not_bound_to_pcr_auth_block.h"
#include "cryptohome/crypto_error.h"
#include "cryptohome/cryptorecovery/recovery_crypto.h"
#include "cryptohome/error/cryptohome_crypto_error.h"
#include "cryptohome/error/utilities.h"
#include "cryptohome/flatbuffer_schemas/auth_block_state.h"
#include "cryptohome/key_objects.h"
#include "cryptohome/username.h"

using brillo::Blob;
using brillo::BlobFromString;
using brillo::BlobToString;
using brillo::SecureBlob;
using hwsec::TPMErrorBase;
using hwsec_foundation::Sha256;

namespace cryptohome {

namespace {

constexpr int kSecretSizeBytes = 32;
constexpr uint32_t kTpm12Family = 0x312E3200;
constexpr uint32_t kTpm20Family = 0x322E3000;
constexpr char kPassword[] = "pass";
constexpr char kWrongPassword[] = "wrong";
constexpr char kUser[] = "user";

void TestPasswordBasedAuthBlockOnIncorrectDerive(
    TPMTestCallback callback,
    CryptohomeStatus error,
    std::unique_ptr<KeyBlobs> key_blobs,
    std::optional<AuthBlock::SuggestedAction> suggested_action) {
  if (error.ok()) {
    LOG(ERROR) << "Derivation succeeded despite wrong password";
    std::move(callback).Run(false);
    return;
  }
  if (!error::PrimaryActionIs(error, error::PrimaryAction::kIncorrectAuth)) {
    LOG(ERROR) << "Derivation with wrong password returned wrong action: "
               << error.status();
    std::move(callback).Run(false);
    return;
  }

  std::move(callback).Run(true);
}

void TestPasswordBasedAuthBlockOnCorrectDerive(
    std::unique_ptr<AuthBlock> auth_block,
    std::unique_ptr<KeyBlobs> created_key_blobs,
    std::unique_ptr<AuthBlockState> created_auth_block_state,
    TPMTestCallback callback,
    CryptohomeStatus error,
    std::unique_ptr<KeyBlobs> key_blobs,
    std::optional<AuthBlock::SuggestedAction> suggested_action) {
  if (!error.ok()) {
    LOG(ERROR) << "Derivation failed: " << error;
    std::move(callback).Run(false);
    return;
  }
  if (!key_blobs->vkk_key.has_value() ||
      created_key_blobs->vkk_key.value() != key_blobs->vkk_key.value()) {
    LOG(ERROR) << "Derivation gave wrong VKK key: "
               << (key_blobs->vkk_key.has_value()
                       ? hwsec_foundation::SecureBlobToHex(
                             key_blobs->vkk_key.value())
                       : "<none>")
               << ", expected: "
               << hwsec_foundation::SecureBlobToHex(key_blobs->vkk_key.value());
    std::move(callback).Run(false);
    return;
  }
  const ObfuscatedUsername obfuscated_username(kUser);

  // Check derivation using a wrong password.
  auth_block->Derive(
      AuthInput{.user_input = SecureBlob(kWrongPassword),
                .obfuscated_username = obfuscated_username},
      *created_auth_block_state,
      base::BindOnce(&TestPasswordBasedAuthBlockOnIncorrectDerive,
                     std::move(callback)));
}

void TestPasswordBasedAuthBlockOnCreate(
    std::unique_ptr<AuthBlock> auth_block,
    TPMTestCallback callback,
    CryptohomeStatus error,
    std::unique_ptr<KeyBlobs> key_blobs,
    std::unique_ptr<AuthBlockState> auth_block_state) {
  if (!error.ok()) {
    LOG(ERROR) << "Creation failed: " << error;
    std::move(callback).Run(false);
    return;
  }
  if (!key_blobs->vkk_key.has_value()) {
    LOG(ERROR) << "Creation returned no VKK key";
    std::move(callback).Run(false);
    return;
  }

  const ObfuscatedUsername obfuscated_username(kUser);

  // Check derivation using the correct password.
  auth_block->Derive(
      AuthInput{.user_input = SecureBlob(kPassword),
                .obfuscated_username = obfuscated_username},
      *auth_block_state,
      base::BindOnce(&TestPasswordBasedAuthBlockOnCorrectDerive,
                     std::move(auth_block), std::move(key_blobs),
                     std::move(auth_block_state), std::move(callback)));
}
// Performs common tests for an auth block against correct/wrong passwords.
void TestPasswordBasedAuthBlock(std::unique_ptr<AuthBlock> auth_block,
                                TPMTestCallback callback) {
  const ObfuscatedUsername obfuscated_username(kUser);
  // Create auth block state.
  AuthBlockState auth_block_state;
  KeyBlobs key_blobs;
  auth_block->Create(
      AuthInput{.user_input = SecureBlob(kPassword),
                .obfuscated_username = obfuscated_username},
      base::BindOnce(&TestPasswordBasedAuthBlockOnCreate, std::move(auth_block),
                     std::move(callback)));
}

hwsec::GenerateDhSharedSecretRequest CloneDhSharedSecretRequest(
    const hwsec::GenerateDhSharedSecretRequest& original) {
  crypto::ScopedEC_POINT others_pub_key(
      EC_POINT_dup(original.others_pub_point.get(), original.ec.GetGroup()));
  EXPECT_TRUE(others_pub_key);

  hwsec::GenerateDhSharedSecretRequest clone{
      .ec = original.ec,
      .encrypted_own_priv_key = original.encrypted_own_priv_key,
      .extended_pcr_bound_own_priv_key =
          original.extended_pcr_bound_own_priv_key,
      .auth_value = original.auth_value,
      .current_user = original.current_user,
      .others_pub_point = std::move(others_pub_key),
  };

  return clone;
}

}  // namespace

TpmLiveTest::TpmLiveTest()
    : hwsec_factory_(std::make_unique<hwsec::FactoryImpl>()),
      hwsec_(hwsec_factory_->GetCryptohomeFrontend()),
      recovery_crypto_(hwsec_factory_->GetRecoveryCryptoFrontend()),
      cryptohome_keys_manager_(hwsec_.get(), &platform_) {
  cryptohome_keys_manager_.Init();
}

void TpmLiveTest::TpmEccAuthBlockTest(TPMTestCallback callback) {
  LOG(INFO) << "TpmEccAuthBlockTest started";

  // Skip the test if elliptic-curve cryptography is not supported on the
  // device.
  hwsec::StatusOr<absl::flat_hash_set<hwsec::KeyAlgoType>> algorithms_status =
      hwsec_->GetSupportedAlgo();
  if (!algorithms_status.ok()) {
    LOG(ERROR) << "Failed to get supported algorithms: "
               << algorithms_status.status();
    std::move(callback).Run(false);
    return;
  }
  if (!algorithms_status->count(hwsec::KeyAlgoType::kEcc)) {
    LOG(INFO) << "Skipping the test: ECC is not supported by the TPM.";
    std::move(callback).Run(true);
    return;
  }

  auto auth_block = std::make_unique<TpmEccAuthBlock>(
      hwsec_.get(), &cryptohome_keys_manager_);
  TestPasswordBasedAuthBlock(std::move(auth_block), std::move(callback));
}

void TpmLiveTest::TpmBoundToPcrAuthBlockTest(TPMTestCallback callback) {
  LOG(INFO) << "TpmBoundToPcrAuthBlockTest started";
  auto auth_block = std::make_unique<TpmBoundToPcrAuthBlock>(
      hwsec_.get(), &cryptohome_keys_manager_);
  TestPasswordBasedAuthBlock(std::move(auth_block), std::move(callback));
}

void TpmLiveTest::TpmNotBoundToPcrAuthBlockTest(TPMTestCallback callback) {
  LOG(INFO) << "TpmNotBoundToPcrAuthBlockTest started";
  auto auth_block = std::make_unique<TpmNotBoundToPcrAuthBlock>(
      hwsec_.get(), &cryptohome_keys_manager_);
  TestPasswordBasedAuthBlock(std::move(auth_block), std::move(callback));
}

bool TpmLiveTest::DecryptionKeyTest() {
  LOG(INFO) << "DecryptionKeyTest started";

  hwsec::StatusOr<hwsec::CryptohomeFrontend::CreateKeyResult> cryptohome_key =
      hwsec_->CreateCryptohomeKey(hwsec::KeyAlgoType::kRsa);
  if (!cryptohome_key.ok()) {
    LOG(ERROR) << "Failed to create RSA cryptohome key: "
               << cryptohome_key.status();
    return false;
  }

  hwsec::Key key = cryptohome_key->key.GetKey();

  SecureBlob plaintext(32, 'b');
  hwsec::StatusOr<Blob> ciphertext = hwsec_->Encrypt(key, plaintext);
  if (!ciphertext.ok()) {
    LOG(ERROR) << "Error encrypting blob: " << ciphertext.status();
    return false;
  }

  hwsec::StatusOr<SecureBlob> decrypted_plaintext =
      hwsec_->Decrypt(key, ciphertext.value());
  if (!decrypted_plaintext.ok()) {
    LOG(ERROR) << "Error decrypting blob: " << decrypted_plaintext.status();
    return false;
  }

  if (plaintext != decrypted_plaintext.value()) {
    LOG(ERROR) << "Decrypted plaintext does not match plaintext.";
    return false;
  }

  LOG(INFO) << "DecryptionKeyTest ended successfully.";
  return true;
}

bool TpmLiveTest::SealWithCurrentUserTest() {
  LOG(INFO) << "SealWithCurrentUserTest started";

  hwsec::StatusOr<hwsec::CryptohomeFrontend::CreateKeyResult> cryptohome_key =
      hwsec_->CreateCryptohomeKey(hwsec::KeyAlgoType::kRsa);
  if (!cryptohome_key.ok()) {
    LOG(ERROR) << "Failed to create RSA cryptohome key: "
               << cryptohome_key.status();
    return false;
  }

  hwsec::Key key = cryptohome_key->key.GetKey();

  SecureBlob plaintext(32, 'a');
  SecureBlob pass_blob(256, 'b');
  hwsec::StatusOr<SecureBlob> auth_value = hwsec_->GetAuthValue(key, pass_blob);
  if (!auth_value.ok()) {
    LOG(ERROR) << "Failed to get auth value: " << auth_value.status();
    return false;
  }

  hwsec::StatusOr<Blob> ciphertext =
      hwsec_->SealWithCurrentUser(std::nullopt, auth_value.value(), plaintext);
  if (!ciphertext.ok()) {
    LOG(ERROR) << "Error sealing the blob: " << ciphertext.status();
    return false;
  }

  hwsec::StatusOr<SecureBlob> unsealed_text = hwsec_->UnsealWithCurrentUser(
      std::nullopt, auth_value.value(), ciphertext.value());
  if (!unsealed_text.ok()) {
    LOG(ERROR) << "Error unsealing the blob: " << unsealed_text.status();
    return false;
  }

  if (plaintext != unsealed_text.value()) {
    LOG(ERROR) << "Unsealed plaintext does not match plaintext.";
    return false;
  }

  // Check that unsealing doesn't work with wrong pass_blob.
  pass_blob.char_data()[255] = 'a';
  auth_value = hwsec_->GetAuthValue(key, pass_blob);
  if (!auth_value.ok()) {
    LOG(ERROR) << "Failed to get auth value: " << auth_value.status();
    return false;
  }

  unsealed_text = hwsec_->UnsealWithCurrentUser(
      std::nullopt, auth_value.value(), ciphertext.value());
  if (unsealed_text.ok() && plaintext == unsealed_text.value()) {
    LOG(ERROR) << "SealWithCurrentUser failed to fail.";
    return false;
  }

  LOG(INFO) << "SealWithCurrentUserTest ended successfully.";
  return true;
}

namespace {

using HwsecAlgorithm = hwsec::CryptohomeFrontend::SignatureSealingAlgorithm;

struct SignatureSealedSecretTestCaseParam {
  SignatureSealedSecretTestCaseParam(
      const std::string& test_case_description,
      const hwsec::CryptohomeFrontend* hwsec,
      int key_size_bits,
      const std::vector<HwsecAlgorithm>& supported_algorithms,
      std::optional<HwsecAlgorithm> expected_algorithm,
      int openssl_algorithm_nid)
      : test_case_description(test_case_description),
        hwsec_(hwsec),
        key_size_bits(key_size_bits),
        supported_algorithms(supported_algorithms),
        expected_algorithm(expected_algorithm),
        openssl_algorithm_nid(openssl_algorithm_nid) {}

  SignatureSealedSecretTestCaseParam(SignatureSealedSecretTestCaseParam&&) =
      default;

  static SignatureSealedSecretTestCaseParam MakeSuccessful(
      const std::string& test_case_description,
      const hwsec::CryptohomeFrontend* hwsec,
      int key_size_bits,
      const std::vector<HwsecAlgorithm>& supported_algorithms,
      HwsecAlgorithm expected_algorithm,
      int openssl_algorithm_nid) {
    return SignatureSealedSecretTestCaseParam(
        test_case_description, hwsec, key_size_bits, supported_algorithms,
        expected_algorithm, openssl_algorithm_nid);
  }

  static SignatureSealedSecretTestCaseParam MakeFailing(
      const std::string& test_case_description,
      const hwsec::CryptohomeFrontend* hwsec,
      int key_size_bits,
      const std::vector<HwsecAlgorithm>& supported_algorithms) {
    return SignatureSealedSecretTestCaseParam(test_case_description, hwsec,
                                              key_size_bits,
                                              supported_algorithms, {}, 0);
  }

  bool expect_success() const { return expected_algorithm.has_value(); }

  std::string test_case_description;
  const hwsec::CryptohomeFrontend* hwsec_;
  int key_size_bits;
  std::vector<HwsecAlgorithm> supported_algorithms;
  std::optional<HwsecAlgorithm> expected_algorithm;
  int openssl_algorithm_nid;
};

class SignatureSealedSecretTestCase final {
 public:
  explicit SignatureSealedSecretTestCase(
      SignatureSealedSecretTestCaseParam param)
      : param_(std::move(param)) {
    LOG(INFO) << "SignatureSealedSecretTestCase: " << param_.key_size_bits
              << "-bit key, " << param_.test_case_description;
  }
  SignatureSealedSecretTestCase(const SignatureSealedSecretTestCase&) = delete;
  SignatureSealedSecretTestCase& operator=(
      const SignatureSealedSecretTestCase&) = delete;

  ~SignatureSealedSecretTestCase() = default;

  bool SetUp() {
    if (!GenerateRsaKey(param_.key_size_bits, &pkey_, &key_spki_der_)) {
      LOG(ERROR) << "Error generating the RSA key";
      return false;
    }
    return true;
  }

  bool RunStage1() {
    if (!param_.expect_success()) {
      if (!CheckSecretCreationFails()) {
        LOG(ERROR) << "Error: successfully created secret unexpectedly";
        return false;
      }
      return true;
    }
    // Create a secret.
    SecureBlob secret_value;
    hwsec::SignatureSealedData sealed_secret_data;
    if (!CreateSecret(&secret_value, &sealed_secret_data)) {
      LOG(ERROR) << "Error creating a secret";
      return false;
    }
    // Unseal the secret.
    Blob first_challenge_value;
    Blob first_challenge_signature;
    SecureBlob first_unsealed_value;
    if (!Unseal(sealed_secret_data, &first_challenge_value,
                &first_challenge_signature, &first_unsealed_value)) {
      LOG(ERROR) << "Error unsealing a secret";
      return false;
    }
    if (first_unsealed_value != secret_value) {
      LOG(ERROR)
          << "Error: unsealing returned different value than at creation time";
      return false;
    }
    // Unseal the secret again - the challenge is different, but the result is
    // the same.
    Blob second_challenge_value;
    Blob second_challenge_signature;
    SecureBlob second_unsealed_value;
    if (!Unseal(sealed_secret_data, &second_challenge_value,
                &second_challenge_signature, &second_unsealed_value)) {
      LOG(ERROR) << "Error unsealing secret for the second time";
      return false;
    }
    if (first_challenge_value == second_challenge_value) {
      LOG(ERROR) << "Error: challenge value collision";
      return false;
    }
    if (second_unsealed_value != secret_value) {
      LOG(ERROR)
          << "Error: unsealing returned different value than at creation time";
      return false;
    }
    // Unsealing with a bad challenge response fails.
    if (!CheckUnsealingFailsWithOldSignature(sealed_secret_data,
                                             first_challenge_signature) ||
        !CheckUnsealingFailsWithBadAlgorithmSignature(sealed_secret_data) ||
        !CheckUnsealingFailsWithBadSignature(sealed_secret_data)) {
      LOG(ERROR) << "Failed testing against bad challenge responses";
      return false;
    }
    // Unsealing with a bad key fails.
    if (!CheckUnsealingFailsWithWrongAlgorithm(sealed_secret_data) ||
        !CheckUnsealingFailsWithWrongKey(sealed_secret_data)) {
      LOG(ERROR) << "Failed testing against bad keys";
      return false;
    }
    // Create and unseal another secret - it has a different value.
    SecureBlob another_secret_value;
    if (!CreateSecret(&another_secret_value, &another_sealed_secret_data_)) {
      LOG(ERROR) << "Error creating another secret";
      return false;
    }
    if (another_secret_value == secret_value) {
      LOG(ERROR) << "Error: secret value collision";
      return false;
    }
    Blob third_challenge_value;
    Blob third_challenge_signature;
    SecureBlob third_unsealed_value;
    if (!Unseal(another_sealed_secret_data_, &third_challenge_value,
                &third_challenge_signature, &third_unsealed_value)) {
      LOG(ERROR) << "Error unsealing another secret";
      return false;
    }
    if (third_unsealed_value != another_secret_value) {
      LOG(ERROR)
          << "Error: unsealing returned different value than at creation time";
      return false;
    }
    return true;
  }

  bool RunStage2() {
    if (!param_.expect_success()) {
      return true;
    }

    // Unsealing after PCRs change fails.
    if (!CheckUnsealingFail(another_sealed_secret_data_)) {
      LOG(ERROR) << "Failed testing against changed PCRs";
      return false;
    }
    return true;
  }

 private:
  const std::string kObfuscatedUsername = "obfuscated_username";

  const hwsec::CryptohomeFrontend* hwsec() { return param_.hwsec_; }

  static bool GenerateRsaKey(int key_size_bits,
                             crypto::ScopedEVP_PKEY* pkey,
                             Blob* key_spki_der) {
    crypto::ScopedEVP_PKEY_CTX pkey_context(
        EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr));
    if (!pkey_context)
      return false;
    if (EVP_PKEY_keygen_init(pkey_context.get()) <= 0)
      return false;
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(pkey_context.get(), key_size_bits) <=
        0) {
      return false;
    }
    EVP_PKEY* pkey_raw = nullptr;
    if (EVP_PKEY_keygen(pkey_context.get(), &pkey_raw) <= 0)
      return false;
    pkey->reset(pkey_raw);
    // Obtain the DER-encoded Subject Public Key Info.
    const int key_spki_der_length = i2d_PUBKEY(pkey->get(), nullptr);
    if (key_spki_der_length < 0)
      return false;
    key_spki_der->resize(key_spki_der_length);
    unsigned char* key_spki_der_buffer = key_spki_der->data();
    return i2d_PUBKEY(pkey->get(), &key_spki_der_buffer) ==
           key_spki_der->size();
  }

  bool CreateSecret(SecureBlob* secret_value,
                    hwsec::SignatureSealedData* sealed_secret_data) {
    hwsec::StatusOr<SecureBlob> secret =
        hwsec()->GetRandomSecureBlob(kSecretSizeBytes);
    if (!secret.ok()) {
      LOG(ERROR) << "Failed to generated random secure blob: "
                 << std::move(secret).status();
      return false;
    }

    hwsec::StatusOr<hwsec::SignatureSealedData> sealed_data =
        hwsec()->SealWithSignatureAndCurrentUser(kObfuscatedUsername,
                                                 secret.value(), key_spki_der_,
                                                 param_.supported_algorithms);
    if (!sealed_data.ok()) {
      LOG(ERROR) << "Failed to generated random secure blob: "
                 << std::move(sealed_data).status();
      return false;
    }

    *secret_value = secret.value();
    *sealed_secret_data = sealed_data.value();
    return true;
  }

  bool CheckSecretCreationFails() {
    SecureBlob secret(kSecretSizeBytes, 'x');

    hwsec::StatusOr<hwsec::SignatureSealedData> sealed_data =
        hwsec()->SealWithSignatureAndCurrentUser(kObfuscatedUsername, secret,
                                                 key_spki_der_,
                                                 param_.supported_algorithms);
    if (!sealed_data.ok()) {
      // TODO(b/174816474): check the error message is expected.
      LOG(INFO) << "Successfully failed to create signature-sealed secret: "
                << std::move(sealed_data).status();
      return true;
    }

    LOG(ERROR) << "Error: secret creation completed unexpectedly";
    return false;
  }

  bool Unseal(const hwsec::SignatureSealedData& sealed_secret_data,
              Blob* challenge_value,
              Blob* challenge_signature,
              SecureBlob* unsealed_value) {
    hwsec::StatusOr<hwsec::CryptohomeFrontend::ChallengeResult> result =
        hwsec()->ChallengeWithSignatureAndCurrentUser(
            sealed_secret_data, key_spki_der_, param_.supported_algorithms);
    if (!result.ok()) {
      LOG(ERROR) << "Error starting the challenge: "
                 << std::move(result).status();
      return false;
    }
    if (result->algorithm != *param_.expected_algorithm) {
      LOG(ERROR) << "Wrong challenge signature algorithm";
      return false;
    }
    *challenge_value = result->challenge;
    if (challenge_value->empty()) {
      LOG(ERROR) << "The challenge is empty";
      return false;
    }
    if (!SignWithKey(*challenge_value, param_.openssl_algorithm_nid,
                     challenge_signature)) {
      LOG(ERROR) << "Error generating signature of challenge";
      return false;
    }
    hwsec::StatusOr<brillo::SecureBlob> secret = hwsec()->UnsealWithChallenge(
        result->challenge_id, *challenge_signature);
    if (!secret.ok()) {
      LOG(ERROR) << "Error unsealing the secret: "
                 << std::move(secret).status();
      return false;
    }
    if (secret.value().empty()) {
      LOG(ERROR) << "Error: empty unsealing result";
      return false;
    }
    *unsealed_value = std::move(secret).value();
    return true;
  }

  bool CheckUnsealingFailsWithOldSignature(
      const hwsec::SignatureSealedData& sealed_secret_data,
      const Blob& challenge_signature) {
    hwsec::StatusOr<hwsec::CryptohomeFrontend::ChallengeResult> result =
        hwsec()->ChallengeWithSignatureAndCurrentUser(
            sealed_secret_data, key_spki_der_, param_.supported_algorithms);
    if (!result.ok()) {
      LOG(ERROR) << "Error starting the challenge: "
                 << std::move(result).status();
      return false;
    }

    hwsec::StatusOr<brillo::SecureBlob> secret =
        hwsec()->UnsealWithChallenge(result->challenge_id, challenge_signature);
    if (secret.ok()) {
      LOG(ERROR)
          << "Error: unsealing completed with an old challenge signature";
      return false;
    }

    return true;
  }

  bool CheckUnsealingFailsWithBadAlgorithmSignature(
      const hwsec::SignatureSealedData& sealed_secret_data) {
    hwsec::StatusOr<hwsec::CryptohomeFrontend::ChallengeResult> result =
        hwsec()->ChallengeWithSignatureAndCurrentUser(
            sealed_secret_data, key_spki_der_, param_.supported_algorithms);
    if (!result.ok()) {
      LOG(ERROR) << "Error starting the challenge: "
                 << std::move(result).status();
      return false;
    }

    const int wrong_openssl_algorithm_nid =
        param_.openssl_algorithm_nid == NID_sha1 ? NID_sha256 : NID_sha1;
    Blob challenge_signature;
    if (!SignWithKey(result->challenge, wrong_openssl_algorithm_nid,
                     &challenge_signature)) {
      LOG(ERROR) << "Error generating signature of challenge";
      return false;
    }

    hwsec::StatusOr<brillo::SecureBlob> secret =
        hwsec()->UnsealWithChallenge(result->challenge_id, challenge_signature);
    if (secret.ok()) {
      LOG(ERROR) << "Error: unsealing completed with a wrong signature";
      return false;
    }

    return true;
  }

  bool CheckUnsealingFailsWithBadSignature(
      const hwsec::SignatureSealedData& sealed_secret_data) {
    hwsec::StatusOr<hwsec::CryptohomeFrontend::ChallengeResult> result =
        hwsec()->ChallengeWithSignatureAndCurrentUser(
            sealed_secret_data, key_spki_der_, param_.supported_algorithms);
    if (!result.ok()) {
      LOG(ERROR) << "Error starting the challenge: "
                 << std::move(result).status();
      return false;
    }

    Blob challenge_signature;
    if (!SignWithKey(result->challenge, param_.openssl_algorithm_nid,
                     &challenge_signature)) {
      LOG(ERROR) << "Error generating signature of challenge";
      return false;
    }
    challenge_signature.front() ^= 1;

    hwsec::StatusOr<brillo::SecureBlob> secret =
        hwsec()->UnsealWithChallenge(result->challenge_id, challenge_signature);
    if (secret.ok()) {
      LOG(ERROR) << "Error: unsealing completed with a wrong signature";
      return false;
    }

    return true;
  }

  bool CheckUnsealingFailsWithWrongAlgorithm(
      const hwsec::SignatureSealedData& sealed_secret_data) {
    const HwsecAlgorithm wrong_algorithm =
        *param_.expected_algorithm == HwsecAlgorithm::kRsassaPkcs1V15Sha1
            ? HwsecAlgorithm::kRsassaPkcs1V15Sha256
            : HwsecAlgorithm::kRsassaPkcs1V15Sha1;

    hwsec::StatusOr<hwsec::CryptohomeFrontend::ChallengeResult> result =
        hwsec()->ChallengeWithSignatureAndCurrentUser(
            sealed_secret_data, key_spki_der_,
            std::vector<HwsecAlgorithm>{wrong_algorithm});
    if (result.ok()) {
      LOG(ERROR) << "Error: unsealing session creation completed with a "
                    "wrong algorithm";
      return false;
    }

    // TODO(b/174816474): check the error message is expected.
    return true;
  }

  bool CheckUnsealingFailsWithWrongKey(
      const hwsec::SignatureSealedData& sealed_secret_data) {
    crypto::ScopedEVP_PKEY other_pkey;
    Blob other_key_spki_der;
    if (!GenerateRsaKey(param_.key_size_bits, &other_pkey,
                        &other_key_spki_der)) {
      LOG(ERROR) << "Error generating the other RSA key";
      return false;
    }

    hwsec::StatusOr<hwsec::CryptohomeFrontend::ChallengeResult> result =
        hwsec()->ChallengeWithSignatureAndCurrentUser(
            sealed_secret_data, other_key_spki_der,
            param_.supported_algorithms);
    if (result.ok()) {
      LOG(ERROR)
          << "Error: unsealing session creation completed with a wrong key";
      return false;
    }

    // TODO(b/174816474): check the error message is expected.
    return true;
  }

  bool CheckUnsealingFail(
      const hwsec::SignatureSealedData& sealed_secret_data) {
    hwsec::StatusOr<hwsec::CryptohomeFrontend::ChallengeResult> result =
        hwsec()->ChallengeWithSignatureAndCurrentUser(
            sealed_secret_data, key_spki_der_, param_.supported_algorithms);
    if (!result.ok()) {
      LOG(ERROR) << "Successful failed to create challenge: "
                 << std::move(result).status();
      return true;
    }

    Blob challenge_signature;
    if (!SignWithKey(result->challenge, param_.openssl_algorithm_nid,
                     &challenge_signature)) {
      LOG(ERROR) << "Error generating signature of challenge";
      return false;
    }

    hwsec::StatusOr<brillo::SecureBlob> secret =
        hwsec()->UnsealWithChallenge(result->challenge_id, challenge_signature);
    if (secret.ok()) {
      LOG(ERROR) << "Error: unsealing completed with changed PCRs";
      return false;
    }

    return true;
  }

  bool SignWithKey(const Blob& unhashed_data,
                   int algorithm_nid,
                   Blob* signature) {
    signature->resize(EVP_PKEY_size(pkey_.get()));
    crypto::ScopedEVP_MD_CTX sign_context(EVP_MD_CTX_new());
    unsigned signature_size = 0;
    if (!sign_context) {
      LOG(ERROR) << "Error creating signing context";
      return false;
    }
    if (!EVP_SignInit(sign_context.get(), EVP_get_digestbynid(algorithm_nid))) {
      LOG(ERROR) << "Error initializing signature operation";
      return false;
    }
    if (!EVP_SignUpdate(sign_context.get(), unhashed_data.data(),
                        unhashed_data.size())) {
      LOG(ERROR) << "Error updating signature operation with data";
      return false;
    }
    if (!EVP_SignFinal(sign_context.get(), signature->data(), &signature_size,
                       pkey_.get())) {
      LOG(ERROR) << "Error finalizing signature operation";
      return false;
    }
    CHECK_LE(signature_size, signature->size());
    signature->resize(signature_size);
    return true;
  }

  const SignatureSealedSecretTestCaseParam param_;
  crypto::ScopedEVP_PKEY pkey_;
  Blob key_spki_der_;

  hwsec::SignatureSealedData another_sealed_secret_data_;
};

}  // namespace

bool TpmLiveTest::SignatureSealedSecretTest() {
  using TestCaseParam = SignatureSealedSecretTestCaseParam;
  LOG(INFO) << "SignatureSealedSecretTest started";

  hwsec::StatusOr<uint32_t> family = hwsec_->GetFamily();
  if (!family.ok()) {
    LOG(ERROR) << "Failed to get the TPM family: " << family.status();
    return false;
  }

  std::vector<TestCaseParam> test_case_params;

  for (int key_size_bits : {1024, 2048}) {
    test_case_params.push_back(TestCaseParam::MakeSuccessful(
        "SHA-1", hwsec_.get(), key_size_bits,
        {HwsecAlgorithm::kRsassaPkcs1V15Sha1},
        HwsecAlgorithm::kRsassaPkcs1V15Sha1, NID_sha1));

    if (family.value() == kTpm12Family) {
      test_case_params.push_back(
          TestCaseParam::MakeFailing("SHA-256", hwsec_.get(), key_size_bits,
                                     {HwsecAlgorithm::kRsassaPkcs1V15Sha256}));
      test_case_params.push_back(
          TestCaseParam::MakeFailing("SHA-384", hwsec_.get(), key_size_bits,
                                     {HwsecAlgorithm::kRsassaPkcs1V15Sha384}));
      test_case_params.push_back(
          TestCaseParam::MakeFailing("SHA-512", hwsec_.get(), key_size_bits,
                                     {HwsecAlgorithm::kRsassaPkcs1V15Sha512}));
      test_case_params.push_back(TestCaseParam::MakeSuccessful(
          "{SHA-1,SHA-256}", hwsec_.get(), key_size_bits,
          {HwsecAlgorithm::kRsassaPkcs1V15Sha256,
           HwsecAlgorithm::kRsassaPkcs1V15Sha1},
          HwsecAlgorithm::kRsassaPkcs1V15Sha1, NID_sha1));
    } else if (family.value() == kTpm20Family) {
      test_case_params.push_back(TestCaseParam::MakeSuccessful(
          "SHA-256", hwsec_.get(), key_size_bits,
          {HwsecAlgorithm::kRsassaPkcs1V15Sha256},
          HwsecAlgorithm::kRsassaPkcs1V15Sha256, NID_sha256));
      test_case_params.push_back(TestCaseParam::MakeSuccessful(
          "SHA-384", hwsec_.get(), key_size_bits,
          {HwsecAlgorithm::kRsassaPkcs1V15Sha384},
          HwsecAlgorithm::kRsassaPkcs1V15Sha384, NID_sha384));
      test_case_params.push_back(TestCaseParam::MakeSuccessful(
          "SHA-512", hwsec_.get(), key_size_bits,
          {HwsecAlgorithm::kRsassaPkcs1V15Sha512},
          HwsecAlgorithm::kRsassaPkcs1V15Sha512, NID_sha512));
      test_case_params.push_back(TestCaseParam::MakeSuccessful(
          "{SHA-384,SHA-256,SHA-512}", hwsec_.get(), key_size_bits,
          {HwsecAlgorithm::kRsassaPkcs1V15Sha384,
           HwsecAlgorithm::kRsassaPkcs1V15Sha256,
           HwsecAlgorithm::kRsassaPkcs1V15Sha512},
          HwsecAlgorithm::kRsassaPkcs1V15Sha384, NID_sha384));
      test_case_params.push_back(TestCaseParam::MakeSuccessful(
          "{SHA-1,SHA-256}", hwsec_.get(), key_size_bits,
          {HwsecAlgorithm::kRsassaPkcs1V15Sha1,
           HwsecAlgorithm::kRsassaPkcs1V15Sha256},
          HwsecAlgorithm::kRsassaPkcs1V15Sha256, NID_sha256));
    } else {
    }
  }

  std::deque<SignatureSealedSecretTestCase> test_cases;

  for (auto&& test_case_param : test_case_params) {
    test_cases.emplace_back(std::move(test_case_param));
    if (!test_cases.back().SetUp() || !test_cases.back().RunStage1())
      return false;
  }

  if (hwsec::Status status = hwsec_->SetCurrentUser("another_user");
      !status.ok()) {
    LOG(ERROR) << "Failed to set current user: " << status;
    return false;
  }

  for (auto& test_case : test_cases) {
    if (!test_case.RunStage2())
      return false;
  }

  test_cases.clear();
  LOG(INFO) << "SignatureSealedSecretTest ended successfully.";
  return true;
}

bool TpmLiveTest::RecoveryTpmBackendTest() {
  constexpr char kObfuscatedUsername[] = "obfuscated_username";
  LOG(INFO) << "RecoveryTpmBackendTest started";

  hwsec_foundation::ScopedBN_CTX context_ =
      hwsec_foundation::CreateBigNumContext();
  std::optional<hwsec_foundation::EllipticCurve> ec_256 =
      hwsec_foundation::EllipticCurve::Create(
          hwsec_foundation::EllipticCurve::CurveType::kPrime256,
          context_.get());
  crypto::ScopedEC_KEY destination_share_key_pair =
      ec_256->GenerateKey(context_.get());
  if (!destination_share_key_pair) {
    LOG(ERROR) << "Failed to generate destination share key pair";
    return false;
  }
  hwsec::StatusOr<std::optional<brillo::SecureBlob>> key_auth_value =
      recovery_crypto_->GenerateKeyAuthValue();
  if (!key_auth_value.ok()) {
    LOG(ERROR) << "Failed go generate key auth value: "
               << key_auth_value.status();
    return false;
  }

  // Call key importing/sealing
  hwsec::EncryptEccPrivateKeyRequest encrypt_request_destination_share{
      .ec = ec_256.value(),
      .own_key_pair = std::move(destination_share_key_pair),
      .auth_value = key_auth_value.value(),
      .current_user = kObfuscatedUsername,
  };
  hwsec::StatusOr<hwsec::EncryptEccPrivateKeyResponse>
      encrypt_response_destination_share =
          recovery_crypto_->EncryptEccPrivateKey(
              std::move(encrypt_request_destination_share));
  if (!encrypt_response_destination_share.ok()) {
    LOG(ERROR) << "Failed to encrypt destination share: "
               << encrypt_response_destination_share.status();
    return false;
  }

  crypto::ScopedEC_KEY others_key_pair = ec_256->GenerateKey(context_.get());
  if (!others_key_pair) {
    LOG(ERROR) << "Failed to generate other's key pair.";
    return false;
  }
  const EC_POINT* others_pub_key_ptr =
      EC_KEY_get0_public_key(others_key_pair.get());
  if (!others_pub_key_ptr) {
    LOG(ERROR) << "Failed to get other's public key pointer.";
    return false;
  }
  crypto::ScopedEC_POINT others_pub_key(
      EC_POINT_dup(others_pub_key_ptr, ec_256->GetGroup()));
  if (!others_pub_key) {
    LOG(ERROR) << "Failed to get other's public key.";
    return false;
  }

  // Create standard decrypt request.
  hwsec::GenerateDhSharedSecretRequest decrypt_request_destination_share{
      .ec = ec_256.value(),
      .encrypted_own_priv_key =
          encrypt_response_destination_share->encrypted_own_priv_key,
      .extended_pcr_bound_own_priv_key =
          encrypt_response_destination_share->extended_pcr_bound_own_priv_key,
      .auth_value = key_auth_value.value(),
      .current_user = kObfuscatedUsername,
      .others_pub_point = std::move(others_pub_key),
  };

  // Call key loading/unsealing with the wrong EC curve.
  std::optional<hwsec_foundation::EllipticCurve> ec_521 =
      hwsec_foundation::EllipticCurve::Create(
          hwsec_foundation::EllipticCurve::CurveType::kPrime521,
          context_.get());
  hwsec::GenerateDhSharedSecretRequest
      decrypt_request_destination_share_wrong_ec{
          .ec = ec_521.value(),
          .encrypted_own_priv_key =
              decrypt_request_destination_share.encrypted_own_priv_key,
          .extended_pcr_bound_own_priv_key =
              decrypt_request_destination_share.extended_pcr_bound_own_priv_key,
          .auth_value = decrypt_request_destination_share.auth_value,
          .current_user = decrypt_request_destination_share.current_user,
      };

  crypto::ScopedEC_POINT wrong_ec_others_pub_key(
      EC_POINT_dup(decrypt_request_destination_share.others_pub_point.get(),
                   ec_256->GetGroup()));
  if (!wrong_ec_others_pub_key) {
    LOG(ERROR) << "Failed to copy the other's public point.";
    return false;
  }
  decrypt_request_destination_share_wrong_ec.others_pub_point =
      std::move(wrong_ec_others_pub_key);

  hwsec::StatusOr<crypto::ScopedEC_POINT> point_dh_wrong_ec =
      recovery_crypto_->GenerateDiffieHellmanSharedSecret(
          std::move(decrypt_request_destination_share_wrong_ec));
  if (point_dh_wrong_ec.ok()) {
    LOG(ERROR) << "Generated DH shared secret successfully without the correct "
                  "EC curve.";
    return false;
  }

  // Call key loading/unsealing with the wrong private key.
  hwsec::GenerateDhSharedSecretRequest
      decrypt_request_destination_share_wrong_priv_key =
          CloneDhSharedSecretRequest(decrypt_request_destination_share);
  decrypt_request_destination_share_wrong_priv_key.encrypted_own_priv_key =
      brillo::BlobFromString("wrong_private_key");
  hwsec::StatusOr<crypto::ScopedEC_POINT> point_dh_wrong_priv_key =
      recovery_crypto_->GenerateDiffieHellmanSharedSecret(
          std::move(decrypt_request_destination_share_wrong_priv_key));
  if (point_dh_wrong_priv_key.ok()) {
    LOG(ERROR) << "Generated DH shared secret successfully without the correct "
                  "private key.";
    return false;
  }

  // Call key loading/unsealing with the wrong auth value.
  hwsec::GenerateDhSharedSecretRequest
      decrypt_request_destination_share_wrong_auth_value =
          CloneDhSharedSecretRequest(decrypt_request_destination_share);
  decrypt_request_destination_share_wrong_auth_value.auth_value =
      brillo::SecureBlob("wrong_auth_value");
  hwsec::StatusOr<crypto::ScopedEC_POINT> point_dh_wrong_auth_value =
      recovery_crypto_->GenerateDiffieHellmanSharedSecret(
          std::move(decrypt_request_destination_share_wrong_auth_value));
  if (point_dh_wrong_auth_value.ok()) {
    LOG(ERROR) << "Generated DH shared secret successfully without the correct "
                  "auth value.";
    return false;
  }

  // Test case that are only applicable for TPM 2.0.
  hwsec::StatusOr<uint32_t> family = hwsec_->GetFamily();
  if (!family.ok()) {
    LOG(ERROR) << "Failed to get the TPM family: " << family.status();
    return false;
  }
  if (family.value() == kTpm20Family) {
    // Call key loading/unsealing with the wrong obfuscated username.
    hwsec::GenerateDhSharedSecretRequest
        decrypt_request_destination_share_wrong_username =
            CloneDhSharedSecretRequest(decrypt_request_destination_share);
    decrypt_request_destination_share_wrong_username.current_user =
        "wrong_obfuscated_username";
    hwsec::StatusOr<crypto::ScopedEC_POINT> point_dh_wrong_username =
        recovery_crypto_->GenerateDiffieHellmanSharedSecret(
            std::move(decrypt_request_destination_share_wrong_username));
    if (point_dh_wrong_username.ok()) {
      LOG(ERROR)
          << "Generated DH shared secret successfully without the correct "
             "obfuscated username.";
      return false;
    }
  }

  // Call key loading/unsealing.
  hwsec::StatusOr<crypto::ScopedEC_POINT> point_dh =
      recovery_crypto_->GenerateDiffieHellmanSharedSecret(
          std::move(decrypt_request_destination_share));
  if (!point_dh.ok()) {
    LOG(ERROR) << "Failed to perform scalar multiplication of others_pub_key "
                  "and destination_share: "
               << point_dh.status();
    return false;
  }

  if (hwsec::Status status = hwsec_->SetCurrentUser("another_user");
      !status.ok()) {
    LOG(ERROR) << "Failed to set current user: " << status;
    return false;
  }

  others_pub_key = crypto::ScopedEC_POINT(
      EC_POINT_dup(others_pub_key_ptr, ec_256->GetGroup()));
  if (!others_pub_key) {
    LOG(ERROR) << "Failed to get other's public key.";
    return false;
  }

  hwsec::GenerateDhSharedSecretRequest decrypt_failed_request_destination_share{
      .ec = ec_256.value(),
      .encrypted_own_priv_key =
          encrypt_response_destination_share->encrypted_own_priv_key,
      .extended_pcr_bound_own_priv_key =
          encrypt_response_destination_share->extended_pcr_bound_own_priv_key,
      .auth_value = key_auth_value.value(),
      .current_user = "obfuscated_username",
      .others_pub_point = std::move(others_pub_key),
  };

  hwsec::StatusOr<crypto::ScopedEC_POINT> point_dh_null =
      recovery_crypto_->GenerateDiffieHellmanSharedSecret(
          std::move(decrypt_failed_request_destination_share));
  if (point_dh_null.ok()) {
    LOG(ERROR) << "Generated DH shared secret successfully without the correct "
                  "PCR state.";
    return false;
  }
  LOG(INFO) << "RecoveryTpmBackendTest with PCR extended ended successfully.";

  return true;
}

}  // namespace cryptohome
