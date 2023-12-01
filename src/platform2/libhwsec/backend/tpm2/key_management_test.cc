// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <cstdint>
#include <memory>
#include <utility>

#include <base/test/task_environment.h>
#include <brillo/secure_blob.h>
#include <crypto/scoped_openssl_types.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <libhwsec-foundation/crypto/sha.h>
#include <libhwsec-foundation/error/testing_helper.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <tpm_manager/proto_bindings/tpm_manager.pb.h>
#include <tpm_manager-client-test/tpm_manager/dbus-proxy-mocks.h>
#include <trunks/mock_policy_session.h>
#include <trunks/mock_tpm.h>
#include <trunks/mock_tpm_utility.h>

#include "base/time/time.h"
#include "libhwsec/backend/tpm2/backend_test_base.h"
#include "libhwsec/structures/key.h"
#include "libhwsec/structures/permission.h"
#include "trunks/tpm_generated.h"

// Prevent the conflict definition from tss.h
#undef TPM_ALG_RSA

using brillo::BlobFromString;
using hwsec_foundation::Sha256;
using hwsec_foundation::error::testing::IsOk;
using hwsec_foundation::error::testing::IsOkAndHolds;
using hwsec_foundation::error::testing::NotOk;
using hwsec_foundation::error::testing::NotOkWith;
using hwsec_foundation::error::testing::ReturnError;
using hwsec_foundation::error::testing::ReturnValue;
using testing::_;
using testing::DoAll;
using testing::Mock;
using testing::NiceMock;
using testing::Return;
using testing::SaveArg;
using testing::SetArgPointee;
using tpm_manager::TpmManagerStatus;
namespace hwsec {

namespace {

bool GenerateRsaKey(int key_size_bits,
                    crypto::ScopedEVP_PKEY* pkey,
                    brillo::Blob* key_spki_der) {
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
  return i2d_PUBKEY(pkey->get(), &key_spki_der_buffer) == key_spki_der->size();
}

}  // namespace

class BackendKeyManagementTpm2Test : public BackendTpm2TestBase {
 protected:
  base::test::TaskEnvironment task_environment_{
      base::test::TaskEnvironment::ThreadingMode::MAIN_THREAD_ONLY,
      base::test::TaskEnvironment::TimeSource::MOCK_TIME};
};

TEST_F(BackendKeyManagementTpm2Test, GetSupportedAlgo) {
  auto result = backend_->GetKeyManagementTpm2().GetSupportedAlgo();

  ASSERT_OK(result);
  EXPECT_TRUE(result->count(KeyAlgoType::kRsa));
  EXPECT_TRUE(result->count(KeyAlgoType::kEcc));
}

TEST_F(BackendKeyManagementTpm2Test, CreateSoftwareRsaKey) {
  const OperationPolicySetting kFakePolicy{};
  const KeyAlgoType kFakeAlgo = KeyAlgoType::kRsa;
  const std::string kFakeKeyBlob = "fake_key_blob";
  const uint32_t kFakeKeyHandle = 0x1337;

  EXPECT_CALL(proxy_->GetMockTpmUtility(),
              ImportRSAKey(trunks::TpmUtility::AsymmetricKeyUsage::kDecryptKey,
                           _, _, _, "", _, _))
      .WillOnce(DoAll(SetArgPointee<6>(kFakeKeyBlob),
                      Return(trunks::TPM_RC_SUCCESS)));

  EXPECT_CALL(proxy_->GetMockTpmUtility(), LoadKey(kFakeKeyBlob, _, _))
      .WillOnce(DoAll(SetArgPointee<2>(kFakeKeyHandle),
                      Return(trunks::TPM_RC_SUCCESS)));

  EXPECT_CALL(proxy_->GetMockTpmUtility(), GetKeyPublicArea(kFakeKeyHandle, _))
      .WillOnce(Return(trunks::TPM_RC_SUCCESS));

  auto result = backend_->GetKeyManagementTpm2().CreateKey(
      kFakePolicy, kFakeAlgo, Backend::KeyManagement::LoadKeyOptions{},
      Backend::KeyManagement::CreateKeyOptions{
          .allow_software_gen = true,
          .allow_decrypt = true,
          .allow_sign = false,
      });

  ASSERT_OK(result);
  EXPECT_EQ(result->key_blob, brillo::BlobFromString(kFakeKeyBlob));

  EXPECT_CALL(proxy_->GetMockTpm(), FlushContextSync(kFakeKeyHandle, _))
      .WillOnce(Return(trunks::TPM_RC_SUCCESS));
}

TEST_F(BackendKeyManagementTpm2Test, CreateRsaKey) {
  const OperationPolicySetting kFakePolicy{};
  const KeyAlgoType kFakeAlgo = KeyAlgoType::kRsa;
  const std::string kFakeKeyBlob = "fake_key_blob";
  const uint32_t kFakeKeyHandle = 0x1337;

  EXPECT_CALL(
      proxy_->GetMockTpmUtility(),
      CreateRSAKeyPair(trunks::TpmUtility::AsymmetricKeyUsage::kDecryptKey, _,
                       _, "", "", false, _, _, _, _))
      .WillOnce(DoAll(SetArgPointee<8>(kFakeKeyBlob),
                      Return(trunks::TPM_RC_SUCCESS)));

  EXPECT_CALL(proxy_->GetMockTpmUtility(), LoadKey(kFakeKeyBlob, _, _))
      .WillOnce(DoAll(SetArgPointee<2>(kFakeKeyHandle),
                      Return(trunks::TPM_RC_SUCCESS)));

  EXPECT_CALL(proxy_->GetMockTpmUtility(), GetKeyPublicArea(kFakeKeyHandle, _))
      .WillOnce(Return(trunks::TPM_RC_SUCCESS));

  auto result = backend_->GetKeyManagementTpm2().CreateKey(
      kFakePolicy, kFakeAlgo, Backend::KeyManagement::LoadKeyOptions{},
      Backend::KeyManagement::CreateKeyOptions{
          .allow_software_gen = false,
          .allow_decrypt = true,
          .allow_sign = false,
      });

  ASSERT_OK(result);
  EXPECT_EQ(result->key_blob, brillo::BlobFromString(kFakeKeyBlob));

  EXPECT_CALL(proxy_->GetMockTpm(), FlushContextSync(kFakeKeyHandle, _))
      .WillOnce(Return(trunks::TPM_RC_SUCCESS));
}

TEST_F(BackendKeyManagementTpm2Test, CreateRsaKeyWithParams) {
  const OperationPolicySetting kFakePolicy{};
  const KeyAlgoType kFakeAlgo = KeyAlgoType::kRsa;
  const std::string kFakeKeyBlob = "fake_key_blob";
  const uint32_t kFakeKeyHandle = 0x1337;
  const brillo::Blob kExponent{0x01, 0x00, 0x01};

  EXPECT_CALL(
      proxy_->GetMockTpmUtility(),
      CreateRSAKeyPair(trunks::TpmUtility::AsymmetricKeyUsage::kDecryptKey,
                       1024, 0x10001, "", "", false, _, _, _, _))
      .WillOnce(DoAll(SetArgPointee<8>(kFakeKeyBlob),
                      Return(trunks::TPM_RC_SUCCESS)));

  EXPECT_CALL(proxy_->GetMockTpmUtility(), LoadKey(kFakeKeyBlob, _, _))
      .WillOnce(DoAll(SetArgPointee<2>(kFakeKeyHandle),
                      Return(trunks::TPM_RC_SUCCESS)));

  EXPECT_CALL(proxy_->GetMockTpmUtility(), GetKeyPublicArea(kFakeKeyHandle, _))
      .WillOnce(Return(trunks::TPM_RC_SUCCESS));

  auto result = backend_->GetKeyManagementTpm2().CreateKey(
      kFakePolicy, kFakeAlgo, Backend::KeyManagement::LoadKeyOptions{},
      Backend::KeyManagement::CreateKeyOptions{
          .allow_software_gen = false,
          .allow_decrypt = true,
          .allow_sign = false,
          .rsa_modulus_bits = 1024,
          .rsa_exponent = kExponent,
      });

  ASSERT_OK(result);
  EXPECT_EQ(result->key_blob, brillo::BlobFromString(kFakeKeyBlob));

  EXPECT_CALL(proxy_->GetMockTpm(), FlushContextSync(kFakeKeyHandle, _))
      .WillOnce(Return(trunks::TPM_RC_SUCCESS));
}

TEST_F(BackendKeyManagementTpm2Test, CreateEccKey) {
  const OperationPolicySetting kFakePolicy{};
  const KeyAlgoType kFakeAlgo = KeyAlgoType::kEcc;
  const std::string kFakeKeyBlob = "fake_key_blob";
  const uint32_t kFakeKeyHandle = 0x1337;

  EXPECT_CALL(
      proxy_->GetMockTpmUtility(),
      CreateECCKeyPair(trunks::TpmUtility::AsymmetricKeyUsage::kDecryptKey, _,
                       "", "", false, _, _, _, _))
      .WillOnce(DoAll(SetArgPointee<7>(kFakeKeyBlob),
                      Return(trunks::TPM_RC_SUCCESS)));

  EXPECT_CALL(proxy_->GetMockTpmUtility(), LoadKey(kFakeKeyBlob, _, _))
      .WillOnce(DoAll(SetArgPointee<2>(kFakeKeyHandle),
                      Return(trunks::TPM_RC_SUCCESS)));

  EXPECT_CALL(proxy_->GetMockTpmUtility(), GetKeyPublicArea(kFakeKeyHandle, _))
      .WillOnce(Return(trunks::TPM_RC_SUCCESS));

  auto result = backend_->GetKeyManagementTpm2().CreateKey(
      kFakePolicy, kFakeAlgo, Backend::KeyManagement::LoadKeyOptions{},
      Backend::KeyManagement::CreateKeyOptions{
          .allow_software_gen = true,
          .allow_decrypt = true,
          .allow_sign = false,
          .ecc_nid = NID_X9_62_prime256v1,
      });

  ASSERT_OK(result);
  EXPECT_EQ(result->key_blob, brillo::BlobFromString(kFakeKeyBlob));

  EXPECT_THAT(
      backend_->GetKeyManagementTpm2().ReloadIfPossible(result->key.GetKey()),
      IsOk());

  EXPECT_CALL(proxy_->GetMockTpm(), FlushContextSync(kFakeKeyHandle, _))
      .WillOnce(Return(trunks::TPM_RC_SUCCESS));
}

TEST_F(BackendKeyManagementTpm2Test, LoadKey) {
  const OperationPolicy kFakePolicy{};
  const std::string kFakeKeyBlob = "fake_key_blob";
  const uint32_t kFakeKeyHandle = 0x1337;

  EXPECT_CALL(proxy_->GetMockTpmUtility(), LoadKey(kFakeKeyBlob, _, _))
      .WillOnce(DoAll(SetArgPointee<2>(kFakeKeyHandle),
                      Return(trunks::TPM_RC_SUCCESS)));

  EXPECT_CALL(proxy_->GetMockTpmUtility(), GetKeyPublicArea(kFakeKeyHandle, _))
      .WillOnce(Return(trunks::TPM_RC_SUCCESS));

  auto result = backend_->GetKeyManagementTpm2().LoadKey(
      kFakePolicy, brillo::BlobFromString(kFakeKeyBlob),
      Backend::KeyManagement::LoadKeyOptions{});

  ASSERT_OK(result);

  EXPECT_THAT(
      backend_->GetKeyManagementTpm2().ReloadIfPossible(result->GetKey()),
      IsOk());

  EXPECT_CALL(proxy_->GetMockTpm(), FlushContextSync(kFakeKeyHandle, _))
      .WillOnce(Return(trunks::TPM_RC_SUCCESS));
}

TEST_F(BackendKeyManagementTpm2Test, CreateAutoReloadKey) {
  const OperationPolicySetting kFakePolicy{};
  const KeyAlgoType kFakeAlgo = KeyAlgoType::kEcc;
  const std::string kFakeKeyBlob = "fake_key_blob";
  const uint32_t kFakeKeyHandle = 0x1337;
  const uint32_t kFakeKeyHandle2 = 0x7331;

  EXPECT_CALL(
      proxy_->GetMockTpmUtility(),
      CreateECCKeyPair(trunks::TpmUtility::AsymmetricKeyUsage::kDecryptKey, _,
                       "", "", false, _, _, _, _))
      .WillOnce(DoAll(SetArgPointee<7>(kFakeKeyBlob),
                      Return(trunks::TPM_RC_SUCCESS)));

  EXPECT_CALL(proxy_->GetMockTpmUtility(), LoadKey(kFakeKeyBlob, _, _))
      .WillOnce(DoAll(SetArgPointee<2>(kFakeKeyHandle),
                      Return(trunks::TPM_RC_SUCCESS)));

  EXPECT_CALL(proxy_->GetMockTpmUtility(), GetKeyPublicArea(kFakeKeyHandle, _))
      .WillOnce(Return(trunks::TPM_RC_SUCCESS));

  auto result = backend_->GetKeyManagementTpm2().CreateKey(
      kFakePolicy, kFakeAlgo,
      Backend::KeyManagement::LoadKeyOptions{.auto_reload = true},
      Backend::KeyManagement::CreateKeyOptions{
          .allow_software_gen = true,
          .allow_decrypt = true,
          .allow_sign = false,
      });

  ASSERT_OK(result);
  EXPECT_EQ(result->key_blob, brillo::BlobFromString(kFakeKeyBlob));

  EXPECT_CALL(proxy_->GetMockTpm(), FlushContextSync(kFakeKeyHandle, _))
      .WillOnce(Return(trunks::TPM_RC_SUCCESS));

  EXPECT_CALL(proxy_->GetMockTpmUtility(), LoadKey(kFakeKeyBlob, _, _))
      .WillOnce(DoAll(SetArgPointee<2>(kFakeKeyHandle2),
                      Return(trunks::TPM_RC_SUCCESS)));

  EXPECT_THAT(
      backend_->GetKeyManagementTpm2().ReloadIfPossible(result->key.GetKey()),
      IsOk());

  EXPECT_CALL(proxy_->GetMockTpm(), FlushContextSync(kFakeKeyHandle2, _))
      .WillOnce(Return(trunks::TPM_RC_SUCCESS));
}

TEST_F(BackendKeyManagementTpm2Test, LoadAutoReloadKey) {
  const OperationPolicy kFakePolicy{};
  const std::string kFakeKeyBlob = "fake_key_blob";
  const uint32_t kFakeKeyHandle = 0x1337;
  const uint32_t kFakeKeyHandle2 = 0x7331;

  EXPECT_CALL(proxy_->GetMockTpmUtility(), LoadKey(kFakeKeyBlob, _, _))
      .WillOnce(DoAll(SetArgPointee<2>(kFakeKeyHandle),
                      Return(trunks::TPM_RC_SUCCESS)));

  EXPECT_CALL(proxy_->GetMockTpmUtility(), GetKeyPublicArea(kFakeKeyHandle, _))
      .WillOnce(Return(trunks::TPM_RC_SUCCESS));

  auto result = backend_->GetKeyManagementTpm2().LoadKey(
      kFakePolicy, brillo::BlobFromString(kFakeKeyBlob),
      Backend::KeyManagement::LoadKeyOptions{.auto_reload = true});

  ASSERT_OK(result);

  EXPECT_CALL(proxy_->GetMockTpm(), FlushContextSync(kFakeKeyHandle, _))
      .WillOnce(Return(trunks::TPM_RC_SUCCESS));

  EXPECT_CALL(proxy_->GetMockTpmUtility(), LoadKey(kFakeKeyBlob, _, _))
      .WillOnce(DoAll(SetArgPointee<2>(kFakeKeyHandle2),
                      Return(trunks::TPM_RC_SUCCESS)));

  EXPECT_THAT(
      backend_->GetKeyManagementTpm2().ReloadIfPossible(result->GetKey()),
      IsOk());

  EXPECT_CALL(proxy_->GetMockTpm(), FlushContextSync(kFakeKeyHandle2, _))
      .WillOnce(Return(trunks::TPM_RC_SUCCESS));
}

TEST_F(BackendKeyManagementTpm2Test, GetPersistentKey) {
  const OperationPolicy kFakePolicy{};
  const std::string kFakeKeyBlob = "fake_key_blob";
  const uint32_t kFakeKeyHandle = 0x1337;

  EXPECT_CALL(proxy_->GetMockTpmUtility(),
              GetKeyPublicArea(trunks::kStorageRootKey, _))
      .WillOnce(Return(trunks::TPM_RC_SUCCESS));

  EXPECT_CALL(proxy_->GetMockTpm(), FlushContextSync(kFakeKeyHandle, _))
      .Times(0);

  {
    auto result = backend_->GetKeyManagementTpm2().GetPersistentKey(
        Backend::KeyManagement::PersistentKeyType::kStorageRootKey);

    EXPECT_THAT(result, IsOk());

    auto result2 = backend_->GetKeyManagementTpm2().GetPersistentKey(
        Backend::KeyManagement::PersistentKeyType::kStorageRootKey);

    EXPECT_THAT(result2, IsOk());
  }

  EXPECT_THAT(backend_->GetKeyManagementTpm2().GetPersistentKey(
                  Backend::KeyManagement::PersistentKeyType::kStorageRootKey),
              IsOk());
}

TEST_F(BackendKeyManagementTpm2Test, GetRsaPubkeyHash) {
  const OperationPolicy kFakePolicy{};
  const std::string kFakeKeyBlob = "fake_key_blob";
  const uint32_t kFakeKeyHandle = 0x1337;
  const trunks::TPMT_PUBLIC kFakePublic = {
      .type = trunks::TPM_ALG_RSA,
      .name_alg = trunks::TPM_ALG_SHA256,
      .object_attributes = trunks::kFixedTPM | trunks::kFixedParent,
      .auth_policy = trunks::TPM2B_DIGEST{.size = 0},
      .parameters =
          trunks::TPMU_PUBLIC_PARMS{
              .rsa_detail =
                  trunks::TPMS_RSA_PARMS{
                      .symmetric =
                          trunks::TPMT_SYM_DEF_OBJECT{
                              .algorithm = trunks::TPM_ALG_NULL,
                          },
                      .scheme =
                          trunks::TPMT_RSA_SCHEME{
                              .scheme = trunks::TPM_ALG_NULL,
                          },
                      .key_bits = 2048,
                      .exponent = 0,
                  },
          },
      .unique =
          trunks::TPMU_PUBLIC_ID{
              .rsa =
                  trunks::TPM2B_PUBLIC_KEY_RSA{
                      .size = 10,
                      .buffer = "9876543210",
                  },
          },
  };

  EXPECT_CALL(proxy_->GetMockTpmUtility(), LoadKey(kFakeKeyBlob, _, _))
      .WillOnce(DoAll(SetArgPointee<2>(kFakeKeyHandle),
                      Return(trunks::TPM_RC_SUCCESS)));

  EXPECT_CALL(proxy_->GetMockTpmUtility(), GetKeyPublicArea(kFakeKeyHandle, _))
      .WillOnce(
          DoAll(SetArgPointee<1>(kFakePublic), Return(trunks::TPM_RC_SUCCESS)));

  auto result = backend_->GetKeyManagementTpm2().LoadKey(
      kFakePolicy, brillo::BlobFromString(kFakeKeyBlob),
      Backend::KeyManagement::LoadKeyOptions{});

  ASSERT_OK(result);

  EXPECT_THAT(backend_->GetKeyManagementTpm2().GetPubkeyHash(result->GetKey()),
              IsOkAndHolds(Sha256(BlobFromString("9876543210"))));

  EXPECT_CALL(proxy_->GetMockTpm(), FlushContextSync(kFakeKeyHandle, _))
      .WillOnce(Return(trunks::TPM_RC_SUCCESS));
}

TEST_F(BackendKeyManagementTpm2Test, GetEccPubkeyHash) {
  const OperationPolicy kFakePolicy{};
  const std::string kFakeKeyBlob = "fake_key_blob";
  const uint32_t kFakeKeyHandle = 0x1337;
  const trunks::TPMT_PUBLIC kFakePublic = {
      .type = trunks::TPM_ALG_ECC,
      .name_alg = trunks::TPM_ALG_SHA256,
      .object_attributes = trunks::kFixedTPM | trunks::kFixedParent,
      .auth_policy = trunks::TPM2B_DIGEST{.size = 0},
      .parameters =
          trunks::TPMU_PUBLIC_PARMS{
              .ecc_detail =
                  trunks::TPMS_ECC_PARMS{
                      .symmetric =
                          trunks::TPMT_SYM_DEF_OBJECT{
                              .algorithm = trunks::TPM_ALG_NULL,
                          },
                      .scheme =
                          trunks::TPMT_ECC_SCHEME{
                              .scheme = trunks::TPM_ALG_NULL,
                          },
                      .curve_id = trunks::TPM_ECC_NIST_P256,
                      .kdf =
                          trunks::TPMT_KDF_SCHEME{
                              .scheme = trunks::TPM_ALG_NULL,
                          },
                  },
          },
      .unique =
          trunks::TPMU_PUBLIC_ID{
              .ecc =
                  trunks::TPMS_ECC_POINT{
                      .x =
                          trunks::TPM2B_ECC_PARAMETER{
                              .size = 10,
                              .buffer = "0123456789",
                          },
                      .y = trunks::TPM2B_ECC_PARAMETER{.size = 0},
                  },
          },
  };

  EXPECT_CALL(proxy_->GetMockTpmUtility(), LoadKey(kFakeKeyBlob, _, _))
      .WillOnce(DoAll(SetArgPointee<2>(kFakeKeyHandle),
                      Return(trunks::TPM_RC_SUCCESS)));

  EXPECT_CALL(proxy_->GetMockTpmUtility(), GetKeyPublicArea(kFakeKeyHandle, _))
      .WillOnce(
          DoAll(SetArgPointee<1>(kFakePublic), Return(trunks::TPM_RC_SUCCESS)));

  auto result = backend_->GetKeyManagementTpm2().LoadKey(
      kFakePolicy, brillo::BlobFromString(kFakeKeyBlob),
      Backend::KeyManagement::LoadKeyOptions{});

  ASSERT_OK(result);

  EXPECT_THAT(backend_->GetKeyManagementTpm2().GetPubkeyHash(result->GetKey()),
              IsOkAndHolds(Sha256(BlobFromString("0123456789"))));

  EXPECT_CALL(proxy_->GetMockTpm(), FlushContextSync(kFakeKeyHandle, _))
      .WillOnce(Return(trunks::TPM_RC_SUCCESS));
}

TEST_F(BackendKeyManagementTpm2Test, SideLoadKey) {
  const OperationPolicy kFakePolicy{};
  const std::string kFakeKeyBlob = "fake_key_blob";
  const uint32_t kFakeKeyHandle = 0x1337;

  EXPECT_CALL(proxy_->GetMockTpmUtility(), GetKeyPublicArea(kFakeKeyHandle, _))
      .WillOnce(Return(trunks::TPM_RC_SUCCESS));

  EXPECT_CALL(proxy_->GetMockTpm(), FlushContextSync(kFakeKeyHandle, _))
      .Times(0);

  auto result = backend_->GetKeyManagementTpm2().SideLoadKey(kFakeKeyHandle);

  ASSERT_OK(result);

  EXPECT_THAT(backend_->GetKeyManagementTpm2().GetKeyHandle(result->GetKey()),
              IsOkAndHolds(kFakeKeyHandle));
}

TEST_F(BackendKeyManagementTpm2Test, PolicyRsaKey) {
  const std::string kFakeAuthValue = "fake_auth_value";
  const OperationPolicySetting kFakePolicy{
      .device_config_settings =
          DeviceConfigSettings{
              .boot_mode =
                  DeviceConfigSettings::BootModeSetting{
                      .mode = std::nullopt,
                  },
          },
      .permission =
          Permission{
              .auth_value = brillo::SecureBlob(kFakeAuthValue),
          },
  };
  const KeyAlgoType kFakeAlgo = KeyAlgoType::kRsa;
  const std::string kFakeKeyBlob = "fake_key_blob";
  const std::string kFakePolicyDigest = "fake_policy_digest";
  const uint32_t kFakeKeyHandle = 0x1337;

  EXPECT_CALL(proxy_->GetMockTrialSession(), GetDigest(_))
      .WillOnce(DoAll(SetArgPointee<0>(kFakePolicyDigest),
                      Return(trunks::TPM_RC_SUCCESS)));

  EXPECT_CALL(
      proxy_->GetMockTpmUtility(),
      CreateRSAKeyPair(trunks::TpmUtility::AsymmetricKeyUsage::kDecryptKey, _,
                       _, kFakeAuthValue, kFakePolicyDigest, true, _, _, _, _))
      .WillOnce(DoAll(SetArgPointee<8>(kFakeKeyBlob),
                      Return(trunks::TPM_RC_SUCCESS)));

  EXPECT_CALL(proxy_->GetMockTpmUtility(), LoadKey(kFakeKeyBlob, _, _))
      .WillOnce(DoAll(SetArgPointee<2>(kFakeKeyHandle),
                      Return(trunks::TPM_RC_SUCCESS)));

  EXPECT_CALL(proxy_->GetMockTpmUtility(), GetKeyPublicArea(kFakeKeyHandle, _))
      .WillOnce(Return(trunks::TPM_RC_SUCCESS));

  auto result = backend_->GetKeyManagementTpm2().CreateKey(
      kFakePolicy, kFakeAlgo, Backend::KeyManagement::LoadKeyOptions{},
      Backend::KeyManagement::CreateKeyOptions{
          .allow_software_gen = true,
          .allow_decrypt = true,
          .allow_sign = false,
      });

  ASSERT_OK(result);
  EXPECT_EQ(result->key_blob, brillo::BlobFromString(kFakeKeyBlob));

  EXPECT_CALL(proxy_->GetMockTpm(), FlushContextSync(kFakeKeyHandle, _))
      .WillOnce(Return(trunks::TPM_RC_SUCCESS));
}

TEST_F(BackendKeyManagementTpm2Test, PolicyEccKey) {
  const std::string kFakeAuthValue = "fake_auth_value";
  const OperationPolicySetting kFakePolicy{
      .device_config_settings =
          DeviceConfigSettings{
              .boot_mode =
                  DeviceConfigSettings::BootModeSetting{
                      .mode = std::nullopt,
                  },
          },
      .permission =
          Permission{
              .auth_value = brillo::SecureBlob(kFakeAuthValue),
          },
  };
  const KeyAlgoType kFakeAlgo = KeyAlgoType::kEcc;
  const std::string kFakeKeyBlob = "fake_key_blob";
  const std::string kFakePolicyDigest = "fake_policy_digest";
  const uint32_t kFakeKeyHandle = 0x1337;

  EXPECT_CALL(proxy_->GetMockTrialSession(), GetDigest(_))
      .WillOnce(DoAll(SetArgPointee<0>(kFakePolicyDigest),
                      Return(trunks::TPM_RC_SUCCESS)));

  EXPECT_CALL(
      proxy_->GetMockTpmUtility(),
      CreateECCKeyPair(trunks::TpmUtility::AsymmetricKeyUsage::kDecryptKey, _,
                       kFakeAuthValue, kFakePolicyDigest, true, _, _, _, _))
      .WillOnce(DoAll(SetArgPointee<7>(kFakeKeyBlob),
                      Return(trunks::TPM_RC_SUCCESS)));

  EXPECT_CALL(proxy_->GetMockTpmUtility(), LoadKey(kFakeKeyBlob, _, _))
      .WillOnce(DoAll(SetArgPointee<2>(kFakeKeyHandle),
                      Return(trunks::TPM_RC_SUCCESS)));

  EXPECT_CALL(proxy_->GetMockTpmUtility(), GetKeyPublicArea(kFakeKeyHandle, _))
      .WillOnce(Return(trunks::TPM_RC_SUCCESS));

  auto result = backend_->GetKeyManagementTpm2().CreateKey(
      kFakePolicy, kFakeAlgo, Backend::KeyManagement::LoadKeyOptions{},
      Backend::KeyManagement::CreateKeyOptions{
          .allow_software_gen = true,
          .allow_decrypt = true,
          .allow_sign = false,
      });

  ASSERT_OK(result);
  EXPECT_EQ(result->key_blob, brillo::BlobFromString(kFakeKeyBlob));

  EXPECT_CALL(proxy_->GetMockTpm(), FlushContextSync(kFakeKeyHandle, _))
      .WillOnce(Return(trunks::TPM_RC_SUCCESS));
}

TEST_F(BackendKeyManagementTpm2Test, LoadPublicKeyFromSpki) {
  crypto::ScopedEVP_PKEY pkey;
  brillo::Blob public_key_spki_der;
  EXPECT_TRUE(GenerateRsaKey(2048, &pkey, &public_key_spki_der));

  EXPECT_THAT(
      backend_->GetKeyManagementTpm2().LoadPublicKeyFromSpki(
          public_key_spki_der, trunks::TPM_ALG_RSASSA, trunks::TPM_ALG_SHA384),
      IsOk());
}

TEST_F(BackendKeyManagementTpm2Test, LoadPublicKeyFromSpkiFailed) {
  // Wrong format key.
  brillo::Blob public_key_spki_der(64, '?');

  EXPECT_THAT(
      backend_->GetKeyManagementTpm2().LoadPublicKeyFromSpki(
          public_key_spki_der, trunks::TPM_ALG_RSASSA, trunks::TPM_ALG_SHA384),
      NotOk());
}

TEST_F(BackendKeyManagementTpm2Test, WrapRsaKey) {
  const std::string kFakeAuthValue = "auth_value";
  const OperationPolicySetting kFakePolicy{
      .permission =
          Permission{
              .auth_value = brillo::SecureBlob(kFakeAuthValue),
          },
  };
  const std::string kFakeKeyBlob = "fake_key_blob";
  const std::string kFakeModulus(1024 / 8, 'Z');
  const std::string kFakePrime(1024 / 8, 'X');
  const brillo::Blob kExponent{0x03};
  const uint32_t kFakeKeyHandle = 0x1337;

  EXPECT_CALL(proxy_->GetMockTpmUtility(),
              ImportRSAKey(trunks::TpmUtility::AsymmetricKeyUsage::kSignKey,
                           kFakeModulus, 3, kFakePrime, kFakeAuthValue, _, _))
      .WillOnce(DoAll(SetArgPointee<6>(kFakeKeyBlob),
                      Return(trunks::TPM_RC_SUCCESS)));

  EXPECT_CALL(proxy_->GetMockTpmUtility(), LoadKey(kFakeKeyBlob, _, _))
      .WillOnce(DoAll(SetArgPointee<2>(kFakeKeyHandle),
                      Return(trunks::TPM_RC_SUCCESS)));

  EXPECT_CALL(proxy_->GetMockTpmUtility(), GetKeyPublicArea(kFakeKeyHandle, _))
      .WillOnce(Return(trunks::TPM_RC_SUCCESS));

  auto result = backend_->GetKeyManagementTpm2().WrapRSAKey(
      kFakePolicy, brillo::BlobFromString(kFakeModulus),
      brillo::SecureBlob(kFakePrime), Backend::KeyManagement::LoadKeyOptions{},
      Backend::KeyManagement::CreateKeyOptions{
          .allow_software_gen = false,
          .allow_decrypt = false,
          .allow_sign = true,
          .rsa_modulus_bits = 1024,
          .rsa_exponent = kExponent,
      });

  ASSERT_OK(result);
  EXPECT_EQ(result->key_blob, brillo::BlobFromString(kFakeKeyBlob));

  EXPECT_CALL(proxy_->GetMockTpm(), FlushContextSync(kFakeKeyHandle, _))
      .WillOnce(Return(trunks::TPM_RC_SUCCESS));
}

TEST_F(BackendKeyManagementTpm2Test, WrapRsaKeyNotSupportedConfig) {
  const OperationPolicySetting kFakePolicy{
      .device_config_settings =
          DeviceConfigSettings{
              .boot_mode =
                  DeviceConfigSettings::BootModeSetting{
                      .mode = std::nullopt,
                  },
          },
  };
  const std::string kFakeKeyBlob = "fake_key_blob";
  const std::string kFakeModulus(1024 / 8, 'Z');
  const std::string kFakePrime(1024 / 8, 'X');
  const brillo::Blob kExponent{0x03};

  auto result = backend_->GetKeyManagementTpm2().WrapRSAKey(
      kFakePolicy, brillo::BlobFromString(kFakeModulus),
      brillo::SecureBlob(kFakePrime), Backend::KeyManagement::LoadKeyOptions{},
      Backend::KeyManagement::CreateKeyOptions{
          .allow_software_gen = false,
          .allow_decrypt = false,
          .allow_sign = true,
          .rsa_modulus_bits = 1024,
          .rsa_exponent = kExponent,
      });

  EXPECT_THAT(result, NotOkWith("Unsupported device config"));
}

TEST_F(BackendKeyManagementTpm2Test, WrapRsaKeyExponentTooLarge) {
  const OperationPolicySetting kFakePolicy{};
  const std::string kFakeKeyBlob = "fake_key_blob";
  const std::string kFakeModulus(1024 / 8, 'Z');
  const std::string kFakePrime(1024 / 8, 'X');
  const brillo::Blob kExponent{0x01, 0x00, 0x00, 0x00, 0x00, 0x01};

  auto result = backend_->GetKeyManagementTpm2().WrapRSAKey(
      kFakePolicy, brillo::BlobFromString(kFakeModulus),
      brillo::SecureBlob(kFakePrime), Backend::KeyManagement::LoadKeyOptions{},
      Backend::KeyManagement::CreateKeyOptions{
          .allow_software_gen = false,
          .allow_decrypt = false,
          .allow_sign = true,
          .rsa_modulus_bits = 1024,
          .rsa_exponent = kExponent,
      });

  EXPECT_THAT(result, NotOkWith("Exponent too large"));
}

TEST_F(BackendKeyManagementTpm2Test, WrapEccKey) {
  const std::string kFakeAuthValue = "auth_value";
  const OperationPolicySetting kFakePolicy{
      .permission =
          Permission{
              .auth_value = brillo::SecureBlob(kFakeAuthValue),
          },
  };
  const std::string kFakeKeyBlob = "fake_key_blob";
  const std::string kFakePointX = "point_x";
  const std::string kFakePointY = "point_y";
  const std::string kFakePrivateVal = "private_value";
  const uint32_t kFakeKeyHandle = 0x1337;

  EXPECT_CALL(
      proxy_->GetMockTpmUtility(),
      ImportECCKey(trunks::TpmUtility::AsymmetricKeyUsage::kDecryptAndSignKey,
                   trunks::TPM_ECC_NIST_P256, _, _, _, kFakeAuthValue, _, _))
      .WillOnce(DoAll(SetArgPointee<7>(kFakeKeyBlob),
                      Return(trunks::TPM_RC_SUCCESS)));

  EXPECT_CALL(proxy_->GetMockTpmUtility(), LoadKey(kFakeKeyBlob, _, _))
      .WillOnce(DoAll(SetArgPointee<2>(kFakeKeyHandle),
                      Return(trunks::TPM_RC_SUCCESS)));

  EXPECT_CALL(proxy_->GetMockTpmUtility(), GetKeyPublicArea(kFakeKeyHandle, _))
      .WillOnce(Return(trunks::TPM_RC_SUCCESS));

  auto result = backend_->GetKeyManagementTpm2().WrapECCKey(
      kFakePolicy, brillo::BlobFromString(kFakePointX),
      brillo::BlobFromString(kFakePointY), brillo::SecureBlob(kFakePrivateVal),
      Backend::KeyManagement::LoadKeyOptions{},
      Backend::KeyManagement::CreateKeyOptions{
          .allow_software_gen = false,
          .allow_decrypt = true,
          .allow_sign = true,
          .ecc_nid = NID_X9_62_prime256v1,
      });

  ASSERT_OK(result);
  EXPECT_EQ(result->key_blob, brillo::BlobFromString(kFakeKeyBlob));

  EXPECT_CALL(proxy_->GetMockTpm(), FlushContextSync(kFakeKeyHandle, _))
      .WillOnce(Return(trunks::TPM_RC_SUCCESS));
}

TEST_F(BackendKeyManagementTpm2Test, WrapEccKeyNotSupportedConfig) {
  const OperationPolicySetting kFakePolicy{
      .device_config_settings =
          DeviceConfigSettings{
              .boot_mode =
                  DeviceConfigSettings::BootModeSetting{
                      .mode = std::nullopt,
                  },
          },
  };
  const std::string kFakeKeyBlob = "fake_key_blob";
  const std::string kFakePointX = "point_x";
  const std::string kFakePointY = "point_y";
  const std::string kFakePrivateVal = "private_value";

  auto result = backend_->GetKeyManagementTpm2().WrapECCKey(
      kFakePolicy, brillo::BlobFromString(kFakePointX),
      brillo::BlobFromString(kFakePointY), brillo::SecureBlob(kFakePrivateVal),
      Backend::KeyManagement::LoadKeyOptions{},
      Backend::KeyManagement::CreateKeyOptions{
          .allow_software_gen = false,
          .allow_decrypt = true,
          .allow_sign = true,
          .ecc_nid = NID_X9_62_prime256v1,
      });

  EXPECT_THAT(result, NotOkWith("Unsupported device config"));
}

TEST_F(BackendKeyManagementTpm2Test, WrapEccKeyNotSupportedNID) {
  const OperationPolicySetting kFakePolicy{};
  const std::string kFakeKeyBlob = "fake_key_blob";
  const std::string kFakePointX = "point_x";
  const std::string kFakePointY = "point_y";
  const std::string kFakePrivateVal = "private_value";

  auto result = backend_->GetKeyManagementTpm2().WrapECCKey(
      kFakePolicy, brillo::BlobFromString(kFakePointX),
      brillo::BlobFromString(kFakePointY), brillo::SecureBlob(kFakePrivateVal),
      Backend::KeyManagement::LoadKeyOptions{},
      Backend::KeyManagement::CreateKeyOptions{
          .allow_software_gen = false,
          .allow_decrypt = true,
          .allow_sign = false,
          .ecc_nid = NID_X9_62_prime239v3,
      });

  EXPECT_THAT(result, NotOkWith("Unsupported curve"));
}

TEST_F(BackendKeyManagementTpm2Test, WrapEccKeyUseless) {
  const OperationPolicySetting kFakePolicy{};
  const std::string kFakeKeyBlob = "fake_key_blob";
  const std::string kFakePointX = "point_x";
  const std::string kFakePointY = "point_y";
  const std::string kFakePrivateVal = "private_value";

  auto result = backend_->GetKeyManagementTpm2().WrapECCKey(
      kFakePolicy, brillo::BlobFromString(kFakePointX),
      brillo::BlobFromString(kFakePointY), brillo::SecureBlob(kFakePrivateVal),
      Backend::KeyManagement::LoadKeyOptions{},
      Backend::KeyManagement::CreateKeyOptions{
          .allow_software_gen = false,
          .allow_decrypt = false,
          .allow_sign = false,
          .ecc_nid = NID_X9_62_prime256v1,
      });

  EXPECT_THAT(result, NotOkWith("Useless key"));
}

TEST_F(BackendKeyManagementTpm2Test, GetRSAPublicInfo) {
  const OperationPolicy kFakePolicy{};
  const std::string kFakeKeyBlob = "fake_key_blob";
  const uint32_t kFakeKeyHandle = 0x1337;
  const trunks::TPMT_PUBLIC kFakePublic = {
      .type = trunks::TPM_ALG_RSA,
      .name_alg = trunks::TPM_ALG_SHA256,
      .object_attributes = trunks::kFixedTPM | trunks::kFixedParent,
      .auth_policy = trunks::TPM2B_DIGEST{.size = 0},
      .parameters =
          trunks::TPMU_PUBLIC_PARMS{
              .rsa_detail =
                  trunks::TPMS_RSA_PARMS{
                      .symmetric =
                          trunks::TPMT_SYM_DEF_OBJECT{
                              .algorithm = trunks::TPM_ALG_NULL,
                          },
                      .scheme =
                          trunks::TPMT_RSA_SCHEME{
                              .scheme = trunks::TPM_ALG_NULL,
                          },
                      .key_bits = 2048,
                      .exponent = 3,
                  },
          },
      .unique =
          trunks::TPMU_PUBLIC_ID{
              .rsa =
                  trunks::TPM2B_PUBLIC_KEY_RSA{
                      .size = 10,
                      .buffer = "9876543210",
                  },
          },
  };

  EXPECT_CALL(proxy_->GetMockTpmUtility(), LoadKey(kFakeKeyBlob, _, _))
      .WillOnce(DoAll(SetArgPointee<2>(kFakeKeyHandle),
                      Return(trunks::TPM_RC_SUCCESS)));

  EXPECT_CALL(proxy_->GetMockTpmUtility(), GetKeyPublicArea(kFakeKeyHandle, _))
      .WillOnce(
          DoAll(SetArgPointee<1>(kFakePublic), Return(trunks::TPM_RC_SUCCESS)));

  auto key = backend_->GetKeyManagementTpm2().LoadKey(
      kFakePolicy, brillo::BlobFromString(kFakeKeyBlob),
      Backend::KeyManagement::LoadKeyOptions{});

  ASSERT_OK(key);

  auto result =
      backend_->GetKeyManagementTpm2().GetRSAPublicInfo(key->GetKey());

  ASSERT_OK(result);
  EXPECT_EQ(result->exponent, brillo::Blob({0x00, 0x00, 0x00, 0x03}));
  EXPECT_EQ(result->modulus, brillo::BlobFromString("9876543210"));
}

TEST_F(BackendKeyManagementTpm2Test, GetRSAPublicInfoWrongType) {
  const OperationPolicy kFakePolicy{};
  const std::string kFakeKeyBlob = "fake_key_blob";
  const uint32_t kFakeKeyHandle = 0x1337;
  const trunks::TPMT_PUBLIC kFakePublic = {
      .type = trunks::TPM_ALG_ECC,
      .name_alg = trunks::TPM_ALG_SHA256,
      .object_attributes = trunks::kFixedTPM | trunks::kFixedParent,
      .auth_policy = trunks::TPM2B_DIGEST{.size = 0},
  };

  EXPECT_CALL(proxy_->GetMockTpmUtility(), LoadKey(kFakeKeyBlob, _, _))
      .WillOnce(DoAll(SetArgPointee<2>(kFakeKeyHandle),
                      Return(trunks::TPM_RC_SUCCESS)));

  EXPECT_CALL(proxy_->GetMockTpmUtility(), GetKeyPublicArea(kFakeKeyHandle, _))
      .WillOnce(
          DoAll(SetArgPointee<1>(kFakePublic), Return(trunks::TPM_RC_SUCCESS)));

  auto key = backend_->GetKeyManagementTpm2().LoadKey(
      kFakePolicy, brillo::BlobFromString(kFakeKeyBlob),
      Backend::KeyManagement::LoadKeyOptions{});

  ASSERT_OK(key);

  EXPECT_THAT(backend_->GetKeyManagementTpm2().GetRSAPublicInfo(key->GetKey()),
              NotOkWith("Get RSA public info for none-RSA key"));
}

TEST_F(BackendKeyManagementTpm2Test, GetECCPublicInfo) {
  const OperationPolicy kFakePolicy{};
  const std::string kFakeKeyBlob = "fake_key_blob";
  const uint32_t kFakeKeyHandle = 0x1337;
  const trunks::TPMT_PUBLIC kFakePublic = {
      .type = trunks::TPM_ALG_ECC,
      .name_alg = trunks::TPM_ALG_SHA256,
      .object_attributes = trunks::kFixedTPM | trunks::kFixedParent,
      .auth_policy = trunks::TPM2B_DIGEST{.size = 0},
      .parameters =
          trunks::TPMU_PUBLIC_PARMS{
              .ecc_detail =
                  trunks::TPMS_ECC_PARMS{
                      .symmetric =
                          trunks::TPMT_SYM_DEF_OBJECT{
                              .algorithm = trunks::TPM_ALG_NULL,
                          },
                      .scheme =
                          trunks::TPMT_ECC_SCHEME{
                              .scheme = trunks::TPM_ALG_NULL,
                          },
                      .curve_id = trunks::TPM_ECC_NIST_P256,
                      .kdf =
                          trunks::TPMT_KDF_SCHEME{
                              .scheme = trunks::TPM_ALG_NULL,
                          },
                  },
          },
      .unique =
          trunks::TPMU_PUBLIC_ID{
              .ecc =
                  trunks::TPMS_ECC_POINT{
                      .x =
                          trunks::TPM2B_ECC_PARAMETER{
                              .size = 10,
                              .buffer = "0123456789",
                          },
                      .y =
                          trunks::TPM2B_ECC_PARAMETER{
                              .size = 10,
                              .buffer = "9876543210",
                          },
                  },
          },
  };

  EXPECT_CALL(proxy_->GetMockTpmUtility(), LoadKey(kFakeKeyBlob, _, _))
      .WillOnce(DoAll(SetArgPointee<2>(kFakeKeyHandle),
                      Return(trunks::TPM_RC_SUCCESS)));

  EXPECT_CALL(proxy_->GetMockTpmUtility(), GetKeyPublicArea(kFakeKeyHandle, _))
      .WillOnce(
          DoAll(SetArgPointee<1>(kFakePublic), Return(trunks::TPM_RC_SUCCESS)));

  auto key = backend_->GetKeyManagementTpm2().LoadKey(
      kFakePolicy, brillo::BlobFromString(kFakeKeyBlob),
      Backend::KeyManagement::LoadKeyOptions{});

  ASSERT_OK(key);

  auto result =
      backend_->GetKeyManagementTpm2().GetECCPublicInfo(key->GetKey());

  ASSERT_OK(result);
  EXPECT_EQ(result->nid, NID_X9_62_prime256v1);
  EXPECT_EQ(result->x_point, brillo::BlobFromString("0123456789"));
  EXPECT_EQ(result->y_point, brillo::BlobFromString("9876543210"));
}

TEST_F(BackendKeyManagementTpm2Test, GetECCPublicInfoUnsupportedCurve) {
  const OperationPolicy kFakePolicy{};
  const std::string kFakeKeyBlob = "fake_key_blob";
  const uint32_t kFakeKeyHandle = 0x1337;
  const trunks::TPMT_PUBLIC kFakePublic = {
      .type = trunks::TPM_ALG_ECC,
      .name_alg = trunks::TPM_ALG_SHA256,
      .object_attributes = trunks::kFixedTPM | trunks::kFixedParent,
      .auth_policy = trunks::TPM2B_DIGEST{.size = 0},
      .parameters =
          trunks::TPMU_PUBLIC_PARMS{
              .ecc_detail =
                  trunks::TPMS_ECC_PARMS{
                      .symmetric =
                          trunks::TPMT_SYM_DEF_OBJECT{
                              .algorithm = trunks::TPM_ALG_NULL,
                          },
                      .scheme =
                          trunks::TPMT_ECC_SCHEME{
                              .scheme = trunks::TPM_ALG_NULL,
                          },
                      .curve_id = trunks::TPM_ECC_NIST_P192,
                      .kdf =
                          trunks::TPMT_KDF_SCHEME{
                              .scheme = trunks::TPM_ALG_NULL,
                          },
                  },
          },
      .unique =
          trunks::TPMU_PUBLIC_ID{
              .ecc =
                  trunks::TPMS_ECC_POINT{
                      .x =
                          trunks::TPM2B_ECC_PARAMETER{
                              .size = 10,
                              .buffer = "0123456789",
                          },
                      .y =
                          trunks::TPM2B_ECC_PARAMETER{
                              .size = 10,
                              .buffer = "9876543210",
                          },
                  },
          },
  };

  EXPECT_CALL(proxy_->GetMockTpmUtility(), LoadKey(kFakeKeyBlob, _, _))
      .WillOnce(DoAll(SetArgPointee<2>(kFakeKeyHandle),
                      Return(trunks::TPM_RC_SUCCESS)));

  EXPECT_CALL(proxy_->GetMockTpmUtility(), GetKeyPublicArea(kFakeKeyHandle, _))
      .WillOnce(
          DoAll(SetArgPointee<1>(kFakePublic), Return(trunks::TPM_RC_SUCCESS)));

  auto key = backend_->GetKeyManagementTpm2().LoadKey(
      kFakePolicy, brillo::BlobFromString(kFakeKeyBlob),
      Backend::KeyManagement::LoadKeyOptions{});

  ASSERT_OK(key);

  EXPECT_THAT(backend_->GetKeyManagementTpm2().GetECCPublicInfo(key->GetKey()),
              NotOkWith("Unsupported curve"));
}

TEST_F(BackendKeyManagementTpm2Test, GetECCPublicInfoWrongType) {
  const OperationPolicy kFakePolicy{};
  const std::string kFakeKeyBlob = "fake_key_blob";
  const uint32_t kFakeKeyHandle = 0x1337;
  const trunks::TPMT_PUBLIC kFakePublic = {
      .type = trunks::TPM_ALG_RSA,
      .name_alg = trunks::TPM_ALG_SHA256,
      .object_attributes = trunks::kFixedTPM | trunks::kFixedParent,
      .auth_policy = trunks::TPM2B_DIGEST{.size = 0},
  };

  EXPECT_CALL(proxy_->GetMockTpmUtility(), LoadKey(kFakeKeyBlob, _, _))
      .WillOnce(DoAll(SetArgPointee<2>(kFakeKeyHandle),
                      Return(trunks::TPM_RC_SUCCESS)));

  EXPECT_CALL(proxy_->GetMockTpmUtility(), GetKeyPublicArea(kFakeKeyHandle, _))
      .WillOnce(
          DoAll(SetArgPointee<1>(kFakePublic), Return(trunks::TPM_RC_SUCCESS)));

  auto key = backend_->GetKeyManagementTpm2().LoadKey(
      kFakePolicy, brillo::BlobFromString(kFakeKeyBlob),
      Backend::KeyManagement::LoadKeyOptions{});

  ASSERT_OK(key);

  EXPECT_THAT(backend_->GetKeyManagementTpm2().GetECCPublicInfo(key->GetKey()),
              NotOkWith("Get ECC public info for none-ECC key"));
}

TEST_F(BackendKeyManagementTpm2Test, IsSupported) {
  EXPECT_THAT(backend_->GetKeyManagementTpm2().IsSupported(
                  KeyAlgoType::kRsa,
                  KeyManagement::CreateKeyOptions{
                      .allow_software_gen = false,
                      .allow_decrypt = true,
                      .allow_sign = true,
                  }),
              IsOk());

  EXPECT_THAT(backend_->GetKeyManagementTpm2().IsSupported(
                  KeyAlgoType::kRsa,
                  KeyManagement::CreateKeyOptions{
                      .allow_software_gen = false,
                      .allow_decrypt = true,
                      .allow_sign = true,
                      .rsa_modulus_bits = 2048,
                  }),
              IsOk());

  EXPECT_THAT(backend_->GetKeyManagementTpm2().IsSupported(
                  KeyAlgoType::kRsa,
                  KeyManagement::CreateKeyOptions{
                      .allow_software_gen = false,
                      .allow_decrypt = true,
                      .allow_sign = true,
                      .rsa_modulus_bits = 1024,
                      .rsa_exponent = brillo::Blob(
                          {0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}),
                  }),
              NotOkWith("Exponent too large"));

  EXPECT_THAT(backend_->GetKeyManagementTpm2().IsSupported(
                  KeyAlgoType::kRsa,
                  KeyManagement::CreateKeyOptions{
                      .allow_software_gen = false,
                      .allow_decrypt = true,
                      .allow_sign = true,
                      .rsa_modulus_bits = 16,
                  }),
              NotOkWith("Modulus bits too small"));

  EXPECT_THAT(backend_->GetKeyManagementTpm2().IsSupported(
                  KeyAlgoType::kRsa,
                  KeyManagement::CreateKeyOptions{
                      .allow_software_gen = false,
                      .allow_decrypt = true,
                      .allow_sign = true,
                      .rsa_modulus_bits = 2147483648U,
                  }),
              NotOkWith("Modulus bits too big"));

  EXPECT_THAT(backend_->GetKeyManagementTpm2().IsSupported(
                  KeyAlgoType::kEcc,
                  KeyManagement::CreateKeyOptions{
                      .allow_software_gen = false,
                      .allow_decrypt = true,
                      .allow_sign = true,
                  }),
              IsOk());

  EXPECT_THAT(backend_->GetKeyManagementTpm2().IsSupported(
                  KeyAlgoType::kEcc,
                  KeyManagement::CreateKeyOptions{
                      .allow_software_gen = false,
                      .allow_decrypt = true,
                      .allow_sign = true,
                      .ecc_nid = NID_X9_62_prime239v3,
                  }),
              NotOkWith("Unsupported curve"));
}

TEST_F(BackendKeyManagementTpm2Test, LoadRefCountReloadKey) {
  const OperationPolicy kFakePolicy{
      .permission = Permission{.auth_value = brillo::SecureBlob("auth_value")}};
  const std::string kFakeKeyBlob = "fake_key_blob";
  const uint32_t kFakeKeyHandle = 0x1337;
  const uint32_t kFakeKeyHandle2 = 0x7331;

  EXPECT_CALL(proxy_->GetMockTpmUtility(), LoadKey(kFakeKeyBlob, _, _))
      .WillOnce(DoAll(SetArgPointee<2>(kFakeKeyHandle),
                      Return(trunks::TPM_RC_SUCCESS)));

  EXPECT_CALL(proxy_->GetMockTpmUtility(), GetKeyPublicArea(kFakeKeyHandle, _))
      .WillOnce(Return(trunks::TPM_RC_SUCCESS));

  auto result1 = backend_->GetKeyManagementTpm2().LoadKey(
      kFakePolicy, brillo::BlobFromString(kFakeKeyBlob),
      Backend::KeyManagement::LoadKeyOptions{.auto_reload = true});

  ASSERT_OK(result1);

  auto result2 = backend_->GetKeyManagementTpm2().LoadKey(
      kFakePolicy, brillo::BlobFromString(kFakeKeyBlob),
      Backend::KeyManagement::LoadKeyOptions{.auto_reload = true});

  ASSERT_OK(result2);

  auto result3 = backend_->GetKeyManagementTpm2().LoadKey(
      kFakePolicy, brillo::BlobFromString(kFakeKeyBlob),
      Backend::KeyManagement::LoadKeyOptions{.auto_reload = true});

  ASSERT_OK(result3);

  EXPECT_EQ(result1->GetKey().token, result2->GetKey().token);
  EXPECT_EQ(result1->GetKey().token, result3->GetKey().token);

  {
    // Move out the key and drop it.
    ScopedKey drop_key = std::move(result1).value();
  }

  EXPECT_CALL(proxy_->GetMockTpm(), FlushContextSync(kFakeKeyHandle, _))
      .WillOnce(Return(trunks::TPM_RC_SUCCESS));

  EXPECT_CALL(proxy_->GetMockTpmUtility(), LoadKey(kFakeKeyBlob, _, _))
      .WillOnce(DoAll(SetArgPointee<2>(kFakeKeyHandle2),
                      Return(trunks::TPM_RC_SUCCESS)));

  EXPECT_THAT(
      backend_->GetKeyManagementTpm2().ReloadIfPossible(result2->GetKey()),
      IsOk());

  EXPECT_CALL(proxy_->GetMockTpm(), FlushContextSync(kFakeKeyHandle2, _))
      .WillOnce(Return(trunks::TPM_RC_SUCCESS));
}

TEST_F(BackendKeyManagementTpm2Test, LoadAndLazyFlushKey) {
  const OperationPolicy kFakePolicy{
      .permission = Permission{.auth_value = brillo::SecureBlob("auth_value")}};
  const std::string kFakeKeyBlob = "fake_key_blob";
  const uint32_t kFakeKeyHandle = 0x1337;
  const uint32_t kFakeKeyHandle2 = 0x7331;
  const uint32_t kFakeKeyHandle3 = 0x7133;

  EXPECT_CALL(proxy_->GetMockTpmUtility(), LoadKey(kFakeKeyBlob, _, _))
      .WillOnce(DoAll(SetArgPointee<2>(kFakeKeyHandle),
                      Return(trunks::TPM_RC_SUCCESS)));

  EXPECT_CALL(proxy_->GetMockTpmUtility(), GetKeyPublicArea(kFakeKeyHandle, _))
      .WillOnce(Return(trunks::TPM_RC_SUCCESS));

  auto result1 = backend_->GetKeyManagementTpm2().LoadKey(
      kFakePolicy, brillo::BlobFromString(kFakeKeyBlob),
      Backend::KeyManagement::LoadKeyOptions{
          .auto_reload = true,
          .lazy_expiration_time = base::Seconds(17),
      });

  ASSERT_OK(result1);

  auto result2 = backend_->GetKeyManagementTpm2().LoadKey(
      kFakePolicy, brillo::BlobFromString(kFakeKeyBlob),
      Backend::KeyManagement::LoadKeyOptions{
          .auto_reload = true,
          .lazy_expiration_time = base::Seconds(23),
      });

  ASSERT_OK(result2);

  // Nothing should happen if the we are still holding the keys.
  task_environment_.FastForwardBy(base::Seconds(100));

  {
    // Move out the key and drop it.
    ScopedKey drop_key1 = std::move(result1).value();
  }

  // Nothing should happen if the we are still holding the key.
  task_environment_.FastForwardBy(base::Seconds(100));

  {
    // Move out the key and drop it.
    ScopedKey drop_key2 = std::move(result2).value();
  }

  // Nothing should happen because the minimum lazy expiration time is 17 secs.
  task_environment_.FastForwardBy(base::Seconds(15));

  auto result3 = backend_->GetKeyManagementTpm2().LoadKey(
      kFakePolicy, brillo::BlobFromString(kFakeKeyBlob),
      Backend::KeyManagement::LoadKeyOptions{
          .auto_reload = true,
          .lazy_expiration_time = base::Seconds(7),
      });

  ASSERT_OK(result3);

  EXPECT_CALL(proxy_->GetMockTpm(), FlushContextSync(kFakeKeyHandle, _))
      .WillOnce(Return(trunks::TPM_RC_SUCCESS));

  EXPECT_CALL(proxy_->GetMockTpmUtility(), LoadKey(kFakeKeyBlob, _, _))
      .WillOnce(DoAll(SetArgPointee<2>(kFakeKeyHandle2),
                      Return(trunks::TPM_RC_SUCCESS)));

  EXPECT_THAT(
      backend_->GetKeyManagementTpm2().ReloadIfPossible(result3->GetKey()),
      IsOk());

  auto result4 = backend_->GetKeyManagementTpm2().LoadKey(
      kFakePolicy, brillo::BlobFromString(kFakeKeyBlob),
      Backend::KeyManagement::LoadKeyOptions{
          .auto_reload = true,
          .lazy_expiration_time = base::Seconds(37),
      });

  ASSERT_OK(result4);

  EXPECT_EQ(result3->GetKey().token, result4->GetKey().token);

  // Nothing should happen if the we are still holding the keys.
  task_environment_.FastForwardBy(base::Seconds(100));

  {
    // Move out the key and drop it.
    ScopedKey drop_key3 = std::move(result3).value();
  }

  // Nothing should happen if the we are still holding the key.
  task_environment_.FastForwardBy(base::Seconds(100));

  {
    // Move out the key and drop it.
    ScopedKey drop_key4 = std::move(result4).value();
  }

  // The key should be dropped after the minimum lazy expiration time (7secs).
  EXPECT_CALL(proxy_->GetMockTpm(), FlushContextSync(kFakeKeyHandle2, _))
      .WillOnce(Return(trunks::TPM_RC_SUCCESS));
  task_environment_.FastForwardBy(base::Seconds(7));

  // The LoadKey should load another new key.
  EXPECT_CALL(proxy_->GetMockTpmUtility(), LoadKey(kFakeKeyBlob, _, _))
      .WillOnce(DoAll(SetArgPointee<2>(kFakeKeyHandle3),
                      Return(trunks::TPM_RC_SUCCESS)));

  EXPECT_CALL(proxy_->GetMockTpmUtility(), GetKeyPublicArea(kFakeKeyHandle3, _))
      .WillOnce(Return(trunks::TPM_RC_SUCCESS));

  auto result5 = backend_->GetKeyManagementTpm2().LoadKey(
      kFakePolicy, brillo::BlobFromString(kFakeKeyBlob),
      Backend::KeyManagement::LoadKeyOptions{
          .auto_reload = true,
          .lazy_expiration_time = base::Seconds(17),
      });

  ASSERT_OK(result5);

  EXPECT_CALL(proxy_->GetMockTpm(), FlushContextSync(kFakeKeyHandle3, _))
      .WillOnce(Return(trunks::TPM_RC_SUCCESS));
}

TEST_F(BackendKeyManagementTpm2Test, LoadReloadKeyWithWrongAuth) {
  const OperationPolicy kFakePolicy{
      .permission = Permission{.auth_value = brillo::SecureBlob("auth_value")}};
  const OperationPolicy kWrongPolicy{
      .permission =
          Permission{.auth_value = brillo::SecureBlob("wrong_auth_value")}};
  const std::string kFakeKeyBlob = "fake_key_blob";
  const uint32_t kFakeKeyHandle = 0x1337;

  EXPECT_CALL(proxy_->GetMockTpmUtility(), LoadKey(kFakeKeyBlob, _, _))
      .WillOnce(DoAll(SetArgPointee<2>(kFakeKeyHandle),
                      Return(trunks::TPM_RC_SUCCESS)))
      .WillOnce(Return(trunks::TPM_RC_BAD_AUTH));

  EXPECT_CALL(proxy_->GetMockTpmUtility(), GetKeyPublicArea(kFakeKeyHandle, _))
      .WillOnce(Return(trunks::TPM_RC_SUCCESS));

  auto result1 = backend_->GetKeyManagementTpm2().LoadKey(
      kFakePolicy, brillo::BlobFromString(kFakeKeyBlob),
      Backend::KeyManagement::LoadKeyOptions{
          .auto_reload = true,
          .lazy_expiration_time = base::Seconds(17),
      });

  ASSERT_OK(result1);

  auto result2 = backend_->GetKeyManagementTpm2().LoadKey(
      kWrongPolicy, brillo::BlobFromString(kFakeKeyBlob),
      Backend::KeyManagement::LoadKeyOptions{
          .auto_reload = true,
          .lazy_expiration_time = base::Seconds(23),
      });

  EXPECT_THAT(result2, NotOk());
}

TEST_F(BackendKeyManagementTpm2Test, PolicyEndorsementKey) {
  for (auto [hwsec_algo, trunks_algo] :
       {std::pair(KeyAlgoType::kRsa, trunks::TPM_ALG_RSA),
        std::pair(KeyAlgoType::kEcc, trunks::TPM_ALG_ECC)}) {
    const std::string kFakeAuthValue = "fake_auth_value";
    const OperationPolicySetting kFakePolicy{
        .device_config_settings =
            DeviceConfigSettings{
                .boot_mode =
                    DeviceConfigSettings::BootModeSetting{
                        .mode = std::nullopt,
                    },
            },
        .permission =
            Permission{
                .type = PermissionType::kPolicyOR,
                .auth_value = brillo::SecureBlob(kFakeAuthValue),
            },
    };
    const std::string kFakeKeyBlob = "fake_key_blob";
    const std::string kFakePolicyDigest = "fake_policy_digest";
    const std::string kFakeEndorsementPass = "fake_endorsement_pass";
    const uint32_t kFakeKeyHandle = 0x1337;

    tpm_manager::GetTpmStatusReply reply;
    reply.set_status(TpmManagerStatus::STATUS_SUCCESS);
    reply.set_enabled(true);
    reply.set_owned(true);
    reply.mutable_local_data()->set_endorsement_password(kFakeEndorsementPass);
    EXPECT_CALL(proxy_->GetMockTpmManagerProxy(), GetTpmStatus(_, _, _, _))
        .WillOnce(DoAll(SetArgPointee<1>(reply), Return(true)));

    EXPECT_CALL(proxy_->GetMockTrialSession(), GetDigest(_))
        .WillOnce(DoAll(SetArgPointee<0>(kFakePolicyDigest),
                        Return(trunks::TPM_RC_SUCCESS)));

    EXPECT_CALL(
        proxy_->GetMockTpmUtility(),
        GetAuthPolicyEndorsementKey(trunks_algo, kFakePolicyDigest, _, _, _))
        .WillOnce(DoAll(SetArgPointee<3>(kFakeKeyHandle),
                        Return(trunks::TPM_RC_SUCCESS)));

    EXPECT_CALL(proxy_->GetMockTpmUtility(),
                GetKeyPublicArea(kFakeKeyHandle, _))
        .WillOnce(Return(trunks::TPM_RC_SUCCESS));

    auto result = backend_->GetKeyManagementTpm2().GetPolicyEndorsementKey(
        kFakePolicy, hwsec_algo);

    ASSERT_OK(result);

    EXPECT_CALL(proxy_->GetMockTpm(), FlushContextSync(kFakeKeyHandle, _))
        .WillOnce(Return(trunks::TPM_RC_SUCCESS));

    {
      // Move out the key and drop it.
      ScopedKey drop_key = std::move(result).value();
    }

    task_environment_.RunUntilIdle();
    Mock::VerifyAndClearExpectations(&proxy_->GetMockTpm());
  }
}

TEST_F(BackendKeyManagementTpm2Test, PolicyEndorsementKeyWrongPermissionType) {
  const std::string kFakeAuthValue = "fake_auth_value";
  const OperationPolicySetting kFakePolicy{
      .device_config_settings =
          DeviceConfigSettings{
              .boot_mode =
                  DeviceConfigSettings::BootModeSetting{
                      .mode = std::nullopt,
                  },
          },
      .permission =
          Permission{
              .type = PermissionType::kAuthValue,
              .auth_value = brillo::SecureBlob(kFakeAuthValue),
          },
  };

  auto result = backend_->GetKeyManagementTpm2().GetPolicyEndorsementKey(
      kFakePolicy, KeyAlgoType::kEcc);

  EXPECT_THAT(result, NotOk());
}

}  // namespace hwsec
