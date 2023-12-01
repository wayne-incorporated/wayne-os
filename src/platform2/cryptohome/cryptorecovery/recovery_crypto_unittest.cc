// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <algorithm>
#include <optional>
#include <utility>

#include <gtest/gtest.h>
#include <libhwsec/factory/tpm2_simulator_factory_for_test.h>
#include <libhwsec/frontend/recovery_crypto/mock_frontend.h>
#include <libhwsec-foundation/crypto/big_num_util.h>
#include <libhwsec-foundation/crypto/elliptic_curve.h>
#include <libhwsec-foundation/crypto/secure_blob_util.h>
#include <libhwsec-foundation/error/testing_helper.h>

#include "cryptohome/cryptorecovery/cryptorecovery.pb.h"
#include "cryptohome/cryptorecovery/fake_recovery_mediator_crypto.h"
#include "cryptohome/cryptorecovery/recovery_crypto_hsm_cbor_serialization.h"
#include "cryptohome/cryptorecovery/recovery_crypto_impl.h"
#include "cryptohome/cryptorecovery/recovery_crypto_util.h"
#include "cryptohome/fake_platform.h"
#include "cryptohome/filesystem_layout.h"
#include "cryptohome/username.h"

using brillo::SecureBlob;
using cryptohome::error::CryptohomeError;
using cryptohome::error::ErrorActionSet;
using cryptohome::error::PossibleAction;
using cryptohome::error::PrimaryAction;
using hwsec_foundation::BigNumToSecureBlob;
using hwsec_foundation::CreateBigNumContext;
using hwsec_foundation::EllipticCurve;
using hwsec_foundation::ScopedBN_CTX;
using hwsec_foundation::error::testing::IsOk;
using hwsec_foundation::error::testing::NotOk;

namespace cryptohome {
namespace cryptorecovery {

namespace {

constexpr EllipticCurve::CurveType kCurve = EllipticCurve::CurveType::kPrime256;
constexpr int kMaxRecoveryIdDepth = 10;
constexpr int kRecoveryIdDepth = 5;
const char kCorruptedRecoveryIdContainer[] = "Corrupted RecoveryId container";
const char kFakeDeviceId[] = "fake device id";
const char kFakeGaiaAccessToken[] = "fake access token";
const char kFakeGaiaId[] = "fake gaia id";
const char kFakeRapt[] = "fake rapt";
const char kFakeUserId[] = "fake user id";

SecureBlob GeneratePublicKey() {
  ScopedBN_CTX context = CreateBigNumContext();
  if (!context) {
    ADD_FAILURE() << "CreateBigNumContext failed";
    return SecureBlob();
  }
  std::optional<EllipticCurve> ec =
      EllipticCurve::Create(kCurve, context.get());
  if (!ec) {
    ADD_FAILURE() << "EllipticCurve::Create failed";
    return SecureBlob();
  }
  crypto::ScopedEC_KEY key = ec->GenerateKey(context.get());
  if (!key) {
    ADD_FAILURE() << "GenerateKey failed";
    return SecureBlob();
  }
  SecureBlob result;
  if (!ec->EncodeToSpkiDer(key, &result, context.get())) {
    ADD_FAILURE() << "EncodeToSpkiDer failed";
    return SecureBlob();
  }
  return result;
}

SecureBlob GenerateScalar() {
  ScopedBN_CTX context = CreateBigNumContext();
  if (!context) {
    ADD_FAILURE() << "CreateBigNumContext failed";
    return SecureBlob();
  }
  std::optional<EllipticCurve> ec =
      EllipticCurve::Create(kCurve, context.get());
  if (!ec) {
    ADD_FAILURE() << "EllipticCurve::Create failed";
    return SecureBlob();
  }
  crypto::ScopedBIGNUM random_bn = ec->RandomNonZeroScalar(context.get());
  if (!random_bn) {
    ADD_FAILURE() << "RandomNonZeroScalar failed";
    return SecureBlob();
  }
  SecureBlob result;
  if (!BigNumToSecureBlob(*random_bn, ec->ScalarSizeInBytes(), &result)) {
    ADD_FAILURE() << "BigNumToSecureBlob failed";
    return SecureBlob();
  }
  return result;
}

}  // namespace

class RecoveryCryptoTest : public testing::Test {
 public:
  RecoveryCryptoTest()
      : ledger_info_(FakeRecoveryMediatorCrypto::GetLedgerInfo()) {
    onboarding_metadata_.cryptohome_user_type = UserType::kGaiaId;
    onboarding_metadata_.cryptohome_user = kFakeGaiaId;
    onboarding_metadata_.device_user_id = kFakeDeviceId;
    onboarding_metadata_.board_name = "Board Name";
    onboarding_metadata_.form_factor = "Model Name";
    onboarding_metadata_.rlz_code = "Rlz Code";
    onboarding_metadata_.recovery_id = "Recovery ID";

    AuthClaim auth_claim;
    auth_claim.gaia_access_token = kFakeGaiaAccessToken;
    auth_claim.gaia_reauth_proof_token = kFakeRapt;
    request_metadata_.auth_claim = std::move(auth_claim);
    request_metadata_.requestor_user_id = kFakeUserId;
    request_metadata_.requestor_user_id_type = UserType::kGaiaId;
  }
  ~RecoveryCryptoTest() = default;

  void SetUp() override {
    recovery_crypto_fake_backend_ = hwsec_factory_.GetRecoveryCryptoFrontend();
    ASSERT_TRUE(FakeRecoveryMediatorCrypto::GetFakeMediatorPublicKey(
        &mediator_pub_key_));
    ASSERT_TRUE(FakeRecoveryMediatorCrypto::GetFakeMediatorPrivateKey(
        &mediator_priv_key_));
    ASSERT_TRUE(
        FakeRecoveryMediatorCrypto::GetFakeEpochPublicKey(&epoch_pub_key_));
    ASSERT_TRUE(
        FakeRecoveryMediatorCrypto::GetFakeEpochPrivateKey(&epoch_priv_key_));
    ASSERT_TRUE(
        FakeRecoveryMediatorCrypto::GetFakeEpochResponse(&epoch_response_));

    recovery_ = RecoveryCryptoImpl::Create(recovery_crypto_fake_backend_.get(),
                                           &platform_);
    ASSERT_TRUE(recovery_);
    mediator_ = FakeRecoveryMediatorCrypto::Create();
    ASSERT_TRUE(mediator_);
  }

 protected:
  void GenerateSecretsAndMediate(SecureBlob* recovery_key,
                                 SecureBlob* destination_share,
                                 SecureBlob* channel_priv_key,
                                 SecureBlob* ephemeral_pub_key,
                                 CryptoRecoveryRpcResponse* response_proto) {
    // Generates HSM payload that would be persisted on a chromebook.
    GenerateHsmPayloadRequest generate_hsm_payload_request(
        {.mediator_pub_key = mediator_pub_key_,
         .onboarding_metadata = onboarding_metadata_,
         .obfuscated_username = ObfuscatedUsername()});
    GenerateHsmPayloadResponse generate_hsm_payload_response;
    EXPECT_TRUE(recovery_->GenerateHsmPayload(generate_hsm_payload_request,
                                              &generate_hsm_payload_response));
    *destination_share =
        generate_hsm_payload_response.encrypted_destination_share;
    *recovery_key = generate_hsm_payload_response.recovery_key;
    *channel_priv_key =
        generate_hsm_payload_response.encrypted_channel_priv_key;

    // Start recovery process.
    GenerateRecoveryRequestRequest generate_recovery_request_input_param(
        {.hsm_payload = generate_hsm_payload_response.hsm_payload,
         .request_meta_data = request_metadata_,
         .epoch_response = epoch_response_,
         .encrypted_rsa_priv_key =
             generate_hsm_payload_response.encrypted_rsa_priv_key,
         .encrypted_channel_priv_key =
             generate_hsm_payload_response.encrypted_channel_priv_key,
         .channel_pub_key = generate_hsm_payload_response.channel_pub_key,
         .obfuscated_username = ObfuscatedUsername()});
    CryptoRecoveryRpcRequest recovery_request;
    EXPECT_TRUE(recovery_->GenerateRecoveryRequest(
        generate_recovery_request_input_param, &recovery_request,
        ephemeral_pub_key));

    // Simulates mediation performed by HSM.
    EXPECT_TRUE(mediator_->MediateRequestPayload(
        epoch_pub_key_, epoch_priv_key_, mediator_priv_key_, recovery_request,
        response_proto));
  }

  SecureBlob rsa_pub_key_;
  OnboardingMetadata onboarding_metadata_;
  RequestMetadata request_metadata_;

  FakePlatform platform_;
  hwsec::Tpm2SimulatorFactoryForTest hwsec_factory_;
  std::unique_ptr<const hwsec::RecoveryCryptoFrontend>
      recovery_crypto_fake_backend_;

  SecureBlob mediator_pub_key_;
  SecureBlob mediator_priv_key_;
  SecureBlob epoch_pub_key_;
  SecureBlob epoch_priv_key_;
  CryptoRecoveryEpochResponse epoch_response_;
  LedgerInfo ledger_info_;
  std::unique_ptr<RecoveryCryptoImpl> recovery_;
  std::unique_ptr<FakeRecoveryMediatorCrypto> mediator_;
};

TEST_F(RecoveryCryptoTest, RecoveryTestSuccess) {
  // Generates HSM payload that would be persisted on a chromebook.
  GenerateHsmPayloadRequest generate_hsm_payload_request(
      {.mediator_pub_key = mediator_pub_key_,
       .onboarding_metadata = onboarding_metadata_,
       .obfuscated_username = ObfuscatedUsername()});
  generate_hsm_payload_request.mediator_pub_key = mediator_pub_key_;
  generate_hsm_payload_request.onboarding_metadata = onboarding_metadata_;
  generate_hsm_payload_request.obfuscated_username = ObfuscatedUsername();
  GenerateHsmPayloadResponse generate_hsm_payload_response;
  EXPECT_TRUE(recovery_->GenerateHsmPayload(generate_hsm_payload_request,
                                            &generate_hsm_payload_response));

  // Start recovery process.
  GenerateRecoveryRequestRequest generate_recovery_request_input_param(
      {.hsm_payload = generate_hsm_payload_response.hsm_payload,
       .request_meta_data = request_metadata_,
       .epoch_response = epoch_response_,
       .encrypted_rsa_priv_key =
           generate_hsm_payload_response.encrypted_rsa_priv_key,
       .encrypted_channel_priv_key =
           generate_hsm_payload_response.encrypted_channel_priv_key,
       .channel_pub_key = generate_hsm_payload_response.channel_pub_key,
       .obfuscated_username = ObfuscatedUsername()});
  CryptoRecoveryRpcRequest recovery_request;
  SecureBlob ephemeral_pub_key;
  EXPECT_TRUE(recovery_->GenerateRecoveryRequest(
      generate_recovery_request_input_param, &recovery_request,
      &ephemeral_pub_key));

  // Simulates mediation performed by HSM.
  CryptoRecoveryRpcResponse response_proto;
  EXPECT_TRUE(mediator_->MediateRequestPayload(
      epoch_pub_key_, epoch_priv_key_, mediator_priv_key_, recovery_request,
      &response_proto));

  DecryptResponsePayloadRequest decrypt_response_payload_request(
      {.encrypted_channel_priv_key =
           generate_hsm_payload_response.encrypted_channel_priv_key,
       .epoch_response = epoch_response_,
       .recovery_response_proto = response_proto,
       .obfuscated_username = ObfuscatedUsername(),
       .ledger_info = ledger_info_});
  HsmResponsePlainText response_plain_text;
  EXPECT_THAT(recovery_->DecryptResponsePayload(
                  decrypt_response_payload_request, &response_plain_text),
              IsOk());

  RecoverDestinationRequest recover_destination_request(
      {.dealer_pub_key = response_plain_text.dealer_pub_key,
       .key_auth_value = response_plain_text.key_auth_value,
       .encrypted_destination_share =
           generate_hsm_payload_response.encrypted_destination_share,
       .extended_pcr_bound_destination_share =
           generate_hsm_payload_response.extended_pcr_bound_destination_share,
       .ephemeral_pub_key = ephemeral_pub_key,
       .mediated_publisher_pub_key = response_plain_text.mediated_point,
       .obfuscated_username = ObfuscatedUsername()});
  SecureBlob mediated_recovery_key;
  EXPECT_TRUE(recovery_->RecoverDestination(recover_destination_request,
                                            &mediated_recovery_key));

  // Checks that cryptohome encryption key generated at enrollment and the
  // one obtained after migration are identical.
  EXPECT_EQ(generate_hsm_payload_response.recovery_key, mediated_recovery_key);
}

TEST_F(RecoveryCryptoTest, GenerateHsmPayloadInvalidMediatorKey) {
  GenerateHsmPayloadRequest generate_hsm_payload_request(
      {.mediator_pub_key = SecureBlob("not a key"),
       .onboarding_metadata = onboarding_metadata_,
       .obfuscated_username = ObfuscatedUsername()});
  GenerateHsmPayloadResponse generate_hsm_payload_response;
  EXPECT_FALSE(recovery_->GenerateHsmPayload(generate_hsm_payload_request,
                                             &generate_hsm_payload_response));
}

TEST_F(RecoveryCryptoTest, MediateWithInvalidEpochPublicKey) {
  // Generates HSM payload that would be persisted on a chromebook.
  GenerateHsmPayloadRequest generate_hsm_payload_request(
      {.mediator_pub_key = mediator_pub_key_,
       .onboarding_metadata = onboarding_metadata_,
       .obfuscated_username = ObfuscatedUsername()});
  GenerateHsmPayloadResponse generate_hsm_payload_response;
  EXPECT_TRUE(recovery_->GenerateHsmPayload(generate_hsm_payload_request,
                                            &generate_hsm_payload_response));

  // Start recovery process.
  GenerateRecoveryRequestRequest generate_recovery_request_input_param(
      {.hsm_payload = generate_hsm_payload_response.hsm_payload,
       .request_meta_data = request_metadata_,
       .epoch_response = epoch_response_,
       .encrypted_rsa_priv_key =
           generate_hsm_payload_response.encrypted_rsa_priv_key,
       .encrypted_channel_priv_key =
           generate_hsm_payload_response.encrypted_channel_priv_key,
       .channel_pub_key = generate_hsm_payload_response.channel_pub_key,
       .obfuscated_username = ObfuscatedUsername()});
  CryptoRecoveryRpcRequest recovery_request;
  SecureBlob ephemeral_pub_key;
  EXPECT_TRUE(recovery_->GenerateRecoveryRequest(
      generate_recovery_request_input_param, &recovery_request,
      &ephemeral_pub_key));

  SecureBlob random_key = GeneratePublicKey();

  // Simulates mediation performed by HSM.
  CryptoRecoveryRpcResponse response_proto;
  EXPECT_TRUE(mediator_->MediateRequestPayload(
      /*epoch_pub_key=*/random_key, epoch_priv_key_, mediator_priv_key_,
      recovery_request, &response_proto));

  // `DecryptResponsePayload` fails if invalid epoch value was used for
  // `MediateRequestPayload`.
  DecryptResponsePayloadRequest decrypt_response_payload_request(
      {.encrypted_channel_priv_key =
           generate_hsm_payload_response.encrypted_channel_priv_key,
       .epoch_response = epoch_response_,
       .recovery_response_proto = response_proto,
       .obfuscated_username = ObfuscatedUsername(),
       .ledger_info = ledger_info_});
  HsmResponsePlainText response_plain_text;
  auto status = recovery_->DecryptResponsePayload(
      decrypt_response_payload_request, &response_plain_text);
  ASSERT_THAT(status, NotOk());
  EXPECT_EQ(status->local_crypto_error(), CryptoError::CE_OTHER_CRYPTO);
}

TEST_F(RecoveryCryptoTest, RecoverDestinationInvalidDealerPublicKey) {
  SecureBlob recovery_key, destination_share, channel_priv_key,
      ephemeral_pub_key;
  CryptoRecoveryRpcResponse response_proto;
  GenerateSecretsAndMediate(&recovery_key, &destination_share,
                            &channel_priv_key, &ephemeral_pub_key,
                            &response_proto);

  DecryptResponsePayloadRequest decrypt_response_payload_request(
      {.encrypted_channel_priv_key = channel_priv_key,
       .epoch_response = epoch_response_,
       .recovery_response_proto = response_proto,
       .obfuscated_username = ObfuscatedUsername(),
       .ledger_info = ledger_info_});
  HsmResponsePlainText response_plain_text;
  ASSERT_THAT(recovery_->DecryptResponsePayload(
                  decrypt_response_payload_request, &response_plain_text),
              IsOk());

  SecureBlob random_key = GeneratePublicKey();

  RecoverDestinationRequest recover_destination_request(
      {.dealer_pub_key = random_key,
       .key_auth_value = response_plain_text.key_auth_value,
       .encrypted_destination_share = destination_share,
       .extended_pcr_bound_destination_share = SecureBlob(),
       .ephemeral_pub_key = ephemeral_pub_key,
       .mediated_publisher_pub_key = response_plain_text.mediated_point,
       .obfuscated_username = ObfuscatedUsername()});
  SecureBlob mediated_recovery_key;
  EXPECT_TRUE(recovery_->RecoverDestination(recover_destination_request,
                                            &mediated_recovery_key));

  // `mediated_recovery_key` is different from `recovery_key` when
  // `dealer_pub_key` is set to a wrong value.
  EXPECT_NE(recovery_key, mediated_recovery_key);
}

TEST_F(RecoveryCryptoTest, RecoverDestinationInvalidDestinationShare) {
  SecureBlob recovery_key, destination_share, channel_priv_key,
      ephemeral_pub_key, response_cbor;
  CryptoRecoveryRpcResponse response_proto;
  GenerateSecretsAndMediate(&recovery_key, &destination_share,
                            &channel_priv_key, &ephemeral_pub_key,
                            &response_proto);

  DecryptResponsePayloadRequest decrypt_response_payload_request(
      {.encrypted_channel_priv_key = channel_priv_key,
       .epoch_response = epoch_response_,
       .recovery_response_proto = response_proto,
       .obfuscated_username = ObfuscatedUsername(),
       .ledger_info = ledger_info_});
  HsmResponsePlainText response_plain_text;
  EXPECT_THAT(recovery_->DecryptResponsePayload(
                  decrypt_response_payload_request, &response_plain_text),
              IsOk());

  SecureBlob random_scalar = GenerateScalar();

  RecoverDestinationRequest recover_destination_request(
      {.dealer_pub_key = response_plain_text.dealer_pub_key,
       .key_auth_value = response_plain_text.key_auth_value,
       .encrypted_destination_share = random_scalar,
       .extended_pcr_bound_destination_share = SecureBlob(),
       .ephemeral_pub_key = ephemeral_pub_key,
       .mediated_publisher_pub_key = response_plain_text.mediated_point,
       .obfuscated_username = ObfuscatedUsername()});
  SecureBlob mediated_recovery_key;

  // Recover with invalid destination share should fail.
  EXPECT_FALSE(recovery_->RecoverDestination(recover_destination_request,
                                             &mediated_recovery_key));
}

TEST_F(RecoveryCryptoTest, RecoverDestinationInvalidEphemeralKey) {
  SecureBlob recovery_key, destination_share, channel_priv_key,
      ephemeral_pub_key, response_cbor;
  CryptoRecoveryRpcResponse response_proto;
  GenerateSecretsAndMediate(&recovery_key, &destination_share,
                            &channel_priv_key, &ephemeral_pub_key,
                            &response_proto);

  DecryptResponsePayloadRequest decrypt_response_payload_request(
      {.encrypted_channel_priv_key = channel_priv_key,
       .epoch_response = epoch_response_,
       .recovery_response_proto = response_proto,
       .obfuscated_username = ObfuscatedUsername(),
       .ledger_info = ledger_info_});
  HsmResponsePlainText response_plain_text;
  EXPECT_THAT(recovery_->DecryptResponsePayload(
                  decrypt_response_payload_request, &response_plain_text),
              IsOk());

  SecureBlob random_key = GeneratePublicKey();

  RecoverDestinationRequest recover_destination_request(
      {.dealer_pub_key = response_plain_text.dealer_pub_key,
       .key_auth_value = response_plain_text.key_auth_value,
       .encrypted_destination_share = destination_share,
       .extended_pcr_bound_destination_share = SecureBlob(),
       .ephemeral_pub_key = random_key,
       .mediated_publisher_pub_key = response_plain_text.mediated_point,
       .obfuscated_username = ObfuscatedUsername("obfuscated_username")});
  SecureBlob mediated_recovery_key;

  // Recover with invalid ephemeral key should fail.
  EXPECT_FALSE(recovery_->RecoverDestination(recover_destination_request,
                                             &mediated_recovery_key));
}

TEST_F(RecoveryCryptoTest, RecoverDestinationInvalidMediatedPointValue) {
  SecureBlob recovery_key, destination_share, channel_priv_key,
      ephemeral_pub_key, response_cbor;
  CryptoRecoveryRpcResponse response_proto;
  GenerateSecretsAndMediate(&recovery_key, &destination_share,
                            &channel_priv_key, &ephemeral_pub_key,
                            &response_proto);

  DecryptResponsePayloadRequest decrypt_response_payload_request(
      {.encrypted_channel_priv_key = channel_priv_key,
       .epoch_response = epoch_response_,
       .recovery_response_proto = response_proto,
       .obfuscated_username = ObfuscatedUsername(),
       .ledger_info = ledger_info_});
  HsmResponsePlainText response_plain_text;
  EXPECT_THAT(recovery_->DecryptResponsePayload(
                  decrypt_response_payload_request, &response_plain_text),
              IsOk());

  SecureBlob random_key = GeneratePublicKey();

  RecoverDestinationRequest recover_destination_request(
      {.dealer_pub_key = response_plain_text.dealer_pub_key,
       .key_auth_value = response_plain_text.key_auth_value,
       .encrypted_destination_share = destination_share,
       .extended_pcr_bound_destination_share = SecureBlob(),
       .ephemeral_pub_key = ephemeral_pub_key,
       .mediated_publisher_pub_key = random_key,
       .obfuscated_username = ObfuscatedUsername()});
  SecureBlob mediated_recovery_key;
  EXPECT_TRUE(recovery_->RecoverDestination(recover_destination_request,
                                            &mediated_recovery_key));

  // `mediated_recovery_key` is different from `recovery_key` when
  // `mediated_point` is set to a wrong point.
  EXPECT_NE(recovery_key, mediated_recovery_key);
}

TEST_F(RecoveryCryptoTest, RecoverDestinationInvalidMediatedPoint) {
  SecureBlob recovery_key, destination_share, channel_priv_key,
      ephemeral_pub_key, response_cbor;
  CryptoRecoveryRpcResponse response_proto;
  GenerateSecretsAndMediate(&recovery_key, &destination_share,
                            &channel_priv_key, &ephemeral_pub_key,
                            &response_proto);

  DecryptResponsePayloadRequest decrypt_response_payload_request(
      {.encrypted_channel_priv_key = channel_priv_key,
       .epoch_response = epoch_response_,
       .recovery_response_proto = response_proto,
       .obfuscated_username = ObfuscatedUsername(),
       .ledger_info = ledger_info_});
  HsmResponsePlainText response_plain_text;
  EXPECT_THAT(recovery_->DecryptResponsePayload(
                  decrypt_response_payload_request, &response_plain_text),
              IsOk());

  // `RecoverDestination` fails when `mediated_point` is not a point.
  RecoverDestinationRequest recover_destination_request(
      {.dealer_pub_key = response_plain_text.dealer_pub_key,
       .key_auth_value = response_plain_text.key_auth_value,
       .encrypted_destination_share = destination_share,
       .extended_pcr_bound_destination_share = SecureBlob(),
       .ephemeral_pub_key = ephemeral_pub_key,
       .mediated_publisher_pub_key = SecureBlob("not a point"),
       .obfuscated_username = ObfuscatedUsername()});
  SecureBlob mediated_recovery_key;
  EXPECT_FALSE(recovery_->RecoverDestination(recover_destination_request,
                                             &mediated_recovery_key));
}

TEST_F(RecoveryCryptoTest, GenerateRecoveryId) {
  AccountIdentifier account_id;
  account_id.set_account_id(kFakeUserId);

  // Generate a new seed and compute recovery_id.
  EXPECT_TRUE(recovery_->GenerateRecoveryId(account_id));
  std::string recovery_id = recovery_->LoadStoredRecoveryId(account_id);
  EXPECT_FALSE(recovery_id.empty());
  // Re-generate a recovery id from the existing persisted data.
  EXPECT_TRUE(recovery_->GenerateRecoveryId(account_id));
  std::string new_recovery_id = recovery_->LoadStoredRecoveryId(account_id);
  EXPECT_FALSE(new_recovery_id.empty());
  EXPECT_NE(recovery_id, new_recovery_id);
}

TEST_F(RecoveryCryptoTest, NoRecoveryId) {
  AccountIdentifier account_id;
  account_id.set_account_id(kFakeUserId);

  // Try to load recovery_id before generating it.
  std::string recovery_id = recovery_->LoadStoredRecoveryId(account_id);
  EXPECT_THAT(recovery_id, testing::IsEmpty());
  std::vector<std::string> recovery_ids_history =
      recovery_->GetLastRecoveryIds(account_id, kMaxRecoveryIdDepth);
  EXPECT_THAT(recovery_ids_history, testing::IsEmpty());
}

TEST_F(RecoveryCryptoTest, VerifyRecoveryIdsHistory) {
  AccountIdentifier account_id;
  account_id.set_account_id(kFakeUserId);

  std::vector<std::string> recovery_id;
  // Generate an initial recovery_id and re-compute it a few times.
  for (int i = 0; i < kMaxRecoveryIdDepth; i++) {
    EXPECT_TRUE(recovery_->GenerateRecoveryId(account_id));
    std::string current_recovery_id =
        recovery_->LoadStoredRecoveryId(account_id);
    EXPECT_FALSE(current_recovery_id.empty());
    recovery_id.push_back(current_recovery_id);
  }

  std::vector<std::string> recovery_ids_history =
      recovery_->GetLastRecoveryIds(account_id, kMaxRecoveryIdDepth);
  // GetLastRecoveryIds orders recovery_ids from the latest to the oldest
  // so reversing it will match the order from recovery_id vector above.
  std::reverse(recovery_ids_history.begin(), recovery_ids_history.end());
  EXPECT_EQ(recovery_id, recovery_ids_history);
}

TEST_F(RecoveryCryptoTest, RecoveryIdsHistoryShorterThanRequested) {
  AccountIdentifier account_id;
  account_id.set_account_id(kFakeUserId);

  std::vector<std::string> recovery_id;
  // Generate an initial recovery_id and re-compute it a few times.
  for (int i = 0; i < kRecoveryIdDepth; i++) {
    EXPECT_TRUE(recovery_->GenerateRecoveryId(account_id));
    std::string current_recovery_id =
        recovery_->LoadStoredRecoveryId(account_id);
    EXPECT_FALSE(current_recovery_id.empty());
    recovery_id.push_back(current_recovery_id);
  }

  std::vector<std::string> recovery_ids_history =
      recovery_->GetLastRecoveryIds(account_id, kMaxRecoveryIdDepth);
  EXPECT_EQ(recovery_ids_history.size(), kRecoveryIdDepth);
  // Reverse recovery_id_depth to simplify comparison with recovery_id.
  std::reverse(recovery_ids_history.begin(), recovery_ids_history.end());
  EXPECT_EQ(recovery_id, recovery_ids_history);
}

TEST_F(RecoveryCryptoTest, GenerateOnboardingMetadataSuccess) {
  OnboardingMetadata onboarding_metadata;
  AccountIdentifier account_id;
  account_id.set_account_id(kFakeUserId);
  EXPECT_TRUE(recovery_->GenerateRecoveryId(account_id));
  std::string recovery_id = recovery_->LoadStoredRecoveryId(account_id);
  recovery_->GenerateOnboardingMetadata(kFakeGaiaId, kFakeDeviceId, recovery_id,
                                        &onboarding_metadata);
  EXPECT_EQ(onboarding_metadata.cryptohome_user, kFakeGaiaId);
  EXPECT_EQ(onboarding_metadata.device_user_id, kFakeDeviceId);
  EXPECT_EQ(onboarding_metadata.recovery_id, recovery_id);
}

TEST_F(RecoveryCryptoTest, GenerateOnboardingMetadataFileCorrupted) {
  OnboardingMetadata onboarding_metadata;
  AccountIdentifier account_id;
  account_id.set_account_id(kFakeUserId);
  EXPECT_TRUE(recovery_->GenerateRecoveryId(account_id));
  std::string recovery_id = recovery_->LoadStoredRecoveryId(account_id);
  EXPECT_TRUE(platform_.WriteStringToFileAtomicDurable(
      GetRecoveryIdPath(account_id), kCorruptedRecoveryIdContainer,
      kKeyFilePermissions));
  // recovery_id from a corrupted container is empty and must be re-generated.
  EXPECT_THAT(recovery_->LoadStoredRecoveryId(account_id), testing::IsEmpty());
  EXPECT_TRUE(recovery_->GenerateRecoveryId(account_id));
  std::string new_recovery_id = recovery_->LoadStoredRecoveryId(account_id);
  recovery_->GenerateOnboardingMetadata(kFakeGaiaId, kFakeDeviceId,
                                        new_recovery_id, &onboarding_metadata);
  EXPECT_NE(onboarding_metadata.recovery_id, recovery_id);
}

TEST_F(RecoveryCryptoTest, DecryptResponsePayloadServerError) {
  SecureBlob recovery_key, destination_share, channel_priv_key,
      ephemeral_pub_key, response_cbor;
  CryptoRecoveryRpcResponse response_proto;
  GenerateSecretsAndMediate(&recovery_key, &destination_share,
                            &channel_priv_key, &ephemeral_pub_key,
                            &response_proto);

  // Generate fake error response.
  response_proto.set_error_code(RecoveryError::RECOVERY_ERROR_FATAL);

  DecryptResponsePayloadRequest decrypt_response_payload_request(
      {.encrypted_channel_priv_key = channel_priv_key,
       .epoch_response = epoch_response_,
       .recovery_response_proto = response_proto,
       .obfuscated_username = ObfuscatedUsername(),
       .ledger_info = ledger_info_});
  HsmResponsePlainText response_plain_text;
  auto status = recovery_->DecryptResponsePayload(
      decrypt_response_payload_request, &response_plain_text);
  ASSERT_THAT(status, NotOk());
  EXPECT_EQ(status->local_crypto_error(), CryptoError::CE_RECOVERY_FATAL);
}

}  // namespace cryptorecovery
}  // namespace cryptohome
