// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <cstdint>
#include <memory>
#include <utility>

#include <crypto/scoped_openssl_types.h>
#include <gtest/gtest.h>
#include <libhwsec-foundation/crypto/sha.h>
#include <libhwsec-foundation/error/testing_helper.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <tpm_manager/proto_bindings/tpm_manager.pb.h>
#include <tpm_manager-client-test/tpm_manager/dbus-proxy-mocks.h>

#include "libhwsec/backend/tpm1/backend_test_base.h"
#include "libhwsec/overalls/mock_overalls.h"

using hwsec_foundation::Sha1;
using hwsec_foundation::error::testing::IsOk;
using hwsec_foundation::error::testing::IsOkAndHolds;
using hwsec_foundation::error::testing::NotOk;
using hwsec_foundation::error::testing::NotOkWith;
using hwsec_foundation::error::testing::ReturnError;
using hwsec_foundation::error::testing::ReturnValue;
using testing::_;
using testing::Args;
using testing::DoAll;
using testing::ElementsAreArray;
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

using BackendKeyManagementTpm1Test = BackendTpm1TestBase;

TEST_F(BackendKeyManagementTpm1Test, GetSupportedAlgo) {
  auto result = backend_->GetKeyManagementTpm1().GetSupportedAlgo();

  ASSERT_OK(result);
  EXPECT_TRUE(result->count(KeyAlgoType::kRsa));
  EXPECT_FALSE(result->count(KeyAlgoType::kEcc));
}

TEST_F(BackendKeyManagementTpm1Test, GetPersistentKey) {
  const brillo::Blob kFakePubkey = brillo::BlobFromString("fake_pubkey");
  const uint32_t kFakeKeyHandle = 0x1337;
  const uint32_t kFakeSrkAuthUsage = 0x9876;
  const uint32_t kFakeSrkUsagePolicy = 0x1283;

  EXPECT_CALL(
      proxy_->GetMockOveralls(),
      Ospi_Context_LoadKeyByUUID(kDefaultContext, TSS_PS_TYPE_SYSTEM, _, _))
      .WillOnce(DoAll(SetArgPointee<3>(kFakeKeyHandle), Return(TPM_SUCCESS)));

  EXPECT_CALL(proxy_->GetMockOveralls(),
              Ospi_GetAttribUint32(kFakeKeyHandle, TSS_TSPATTRIB_KEY_INFO,
                                   TSS_TSPATTRIB_KEYINFO_AUTHUSAGE, _))
      .WillOnce(
          DoAll(SetArgPointee<3>(kFakeSrkAuthUsage), Return(TPM_SUCCESS)));

  EXPECT_CALL(proxy_->GetMockOveralls(),
              Ospi_GetPolicyObject(kFakeKeyHandle, TSS_POLICY_USAGE, _))
      .WillOnce(
          DoAll(SetArgPointee<2>(kFakeSrkUsagePolicy), Return(TPM_SUCCESS)));

  EXPECT_CALL(
      proxy_->GetMockOveralls(),
      Ospi_Policy_SetSecret(kFakeSrkUsagePolicy, TSS_SECRET_MODE_PLAIN, _, _))
      .WillOnce(Return(TPM_SUCCESS));

  brillo::Blob fake_pubkey = kFakePubkey;
  EXPECT_CALL(proxy_->GetMockOveralls(),
              Ospi_Key_GetPubKey(kFakeKeyHandle, _, _))
      .WillOnce(DoAll(SetArgPointee<1>(kFakePubkey.size()),
                      SetArgPointee<2>(fake_pubkey.data()),
                      Return(TPM_SUCCESS)));

  {
    auto result = backend_->GetKeyManagementTpm1().GetPersistentKey(
        Backend::KeyManagement::PersistentKeyType::kStorageRootKey);

    EXPECT_THAT(result, IsOk());

    auto result2 = backend_->GetKeyManagementTpm1().GetPersistentKey(
        Backend::KeyManagement::PersistentKeyType::kStorageRootKey);

    EXPECT_THAT(result2, IsOk());
  }

  auto result3 = backend_->GetKeyManagementTpm1().GetPersistentKey(
      Backend::KeyManagement::PersistentKeyType::kStorageRootKey);

  EXPECT_THAT(result3, IsOk());
}

TEST_F(BackendKeyManagementTpm1Test, CreateSoftwareGenRsaKey) {
  const OperationPolicySetting kFakePolicy{};
  const KeyAlgoType kFakeAlgo = KeyAlgoType::kRsa;
  const brillo::Blob kFakeKeyBlob = brillo::BlobFromString("fake_key_blob");
  const brillo::Blob kFakePubkey = brillo::BlobFromString("fake_pubkey");
  const uint32_t kFakeKeyHandle = 0x1337;
  const uint32_t kFakeKeyHandle2 = 0x1338;
  const uint32_t kFakePolicyHandle = 0x7331;

  SetupSrk();

  EXPECT_CALL(
      proxy_->GetMockOveralls(),
      Ospi_Context_CreateObject(kDefaultContext, TSS_OBJECT_TYPE_RSAKEY, _, _))
      .WillOnce(DoAll(SetArgPointee<3>(kFakeKeyHandle), Return(TPM_SUCCESS)));

  EXPECT_CALL(proxy_->GetMockOveralls(),
              Ospi_SetAttribUint32(kFakeKeyHandle, TSS_TSPATTRIB_KEY_INFO,
                                   TSS_TSPATTRIB_KEYINFO_SIGSCHEME, _))
      .WillOnce(Return(TPM_SUCCESS));

  EXPECT_CALL(proxy_->GetMockOveralls(),
              Ospi_SetAttribUint32(kFakeKeyHandle, TSS_TSPATTRIB_KEY_INFO,
                                   TSS_TSPATTRIB_KEYINFO_ENCSCHEME, _))
      .WillOnce(Return(TPM_SUCCESS));

  EXPECT_CALL(proxy_->GetMockOveralls(),
              Ospi_Context_CreateObject(kDefaultContext, TSS_OBJECT_TYPE_POLICY,
                                        TSS_POLICY_MIGRATION, _))
      .WillOnce(
          DoAll(SetArgPointee<3>(kFakePolicyHandle), Return(TPM_SUCCESS)));

  EXPECT_CALL(
      proxy_->GetMockOveralls(),
      Ospi_Policy_SetSecret(kFakePolicyHandle, TSS_SECRET_MODE_PLAIN, _, _))
      .WillOnce(Return(TPM_SUCCESS));

  EXPECT_CALL(proxy_->GetMockOveralls(),
              Ospi_Policy_AssignToObject(kFakePolicyHandle, kFakeKeyHandle))
      .WillOnce(Return(TPM_SUCCESS));

  EXPECT_CALL(proxy_->GetMockOveralls(),
              Ospi_SetAttribData(kFakeKeyHandle, TSS_TSPATTRIB_RSAKEY_INFO,
                                 TSS_TSPATTRIB_KEYINFO_RSA_MODULUS, _, _))
      .WillOnce(Return(TPM_SUCCESS));

  EXPECT_CALL(proxy_->GetMockOveralls(),
              Ospi_SetAttribData(kFakeKeyHandle, TSS_TSPATTRIB_KEY_BLOB,
                                 TSS_TSPATTRIB_KEYBLOB_PRIVATE_KEY, _, _))
      .WillOnce(Return(TPM_SUCCESS));

  EXPECT_CALL(proxy_->GetMockOveralls(),
              Ospi_Key_WrapKey(kFakeKeyHandle, kDefaultSrkHandle, 0))
      .WillOnce(Return(TPM_SUCCESS));

  brillo::Blob key_blob = kFakeKeyBlob;
  EXPECT_CALL(proxy_->GetMockOveralls(),
              Ospi_GetAttribData(kFakeKeyHandle, TSS_TSPATTRIB_KEY_BLOB,
                                 TSS_TSPATTRIB_KEYBLOB_BLOB, _, _))
      .WillOnce(DoAll(SetArgPointee<3>(key_blob.size()),
                      SetArgPointee<4>(key_blob.data()), Return(TPM_SUCCESS)));

  EXPECT_CALL(
      proxy_->GetMockOveralls(),
      Ospi_Context_LoadKeyByBlob(kDefaultContext, kDefaultSrkHandle, _, _, _))
      .WillOnce(DoAll(SetArgPointee<4>(kFakeKeyHandle2), Return(TPM_SUCCESS)));

  brillo::Blob fake_pubkey = kFakePubkey;
  EXPECT_CALL(proxy_->GetMockOveralls(),
              Ospi_Key_GetPubKey(kFakeKeyHandle2, _, _))
      .WillOnce(DoAll(SetArgPointee<1>(kFakePubkey.size()),
                      SetArgPointee<2>(fake_pubkey.data()),
                      Return(TPM_SUCCESS)));

  auto result = backend_->GetKeyManagementTpm1().CreateKey(
      kFakePolicy, kFakeAlgo, Backend::KeyManagement::LoadKeyOptions{},
      Backend::KeyManagement::CreateKeyOptions{
          .allow_software_gen = true,
          .allow_decrypt = true,
          .allow_sign = true,
      });

  ASSERT_OK(result);
  EXPECT_EQ(result->key_blob, kFakeKeyBlob);
}

TEST_F(BackendKeyManagementTpm1Test, CreateRsaKey) {
  const OperationPolicySetting kFakePolicy{
      .device_config_settings =
          DeviceConfigSettings{
              .boot_mode =
                  DeviceConfigSettings::BootModeSetting{
                      .mode = std::nullopt,
                  },
          },
  };
  const KeyAlgoType kFakeAlgo = KeyAlgoType::kRsa;
  const brillo::Blob kFakeKeyBlob = brillo::BlobFromString("fake_key_blob");
  const brillo::Blob kFakePubkey = brillo::BlobFromString("fake_pubkey");
  const uint32_t kFakeKeyHandle = 0x1337;
  const uint32_t kFakePcrHandle = 0x7331;

  SetupSrk();

  EXPECT_CALL(proxy_->GetMockOveralls(),
              Ospi_Context_CreateObject(kDefaultContext, TSS_OBJECT_TYPE_PCRS,
                                        TSS_PCRS_STRUCT_INFO, _))
      .WillOnce(DoAll(SetArgPointee<3>(kFakePcrHandle), Return(TPM_SUCCESS)));

  EXPECT_CALL(proxy_->GetMockOveralls(),
              Ospi_PcrComposite_SetPcrValue(kFakePcrHandle, 0, _, _))
      .WillOnce(Return(TPM_SUCCESS));

  EXPECT_CALL(
      proxy_->GetMockOveralls(),
      Ospi_Context_CreateObject(kDefaultContext, TSS_OBJECT_TYPE_RSAKEY, _, _))
      .WillOnce(DoAll(SetArgPointee<3>(kFakeKeyHandle), Return(TPM_SUCCESS)));

  EXPECT_CALL(proxy_->GetMockOveralls(),
              Ospi_SetAttribUint32(kFakeKeyHandle, TSS_TSPATTRIB_KEY_INFO,
                                   TSS_TSPATTRIB_KEYINFO_SIGSCHEME, _))
      .WillOnce(Return(TPM_SUCCESS));

  EXPECT_CALL(proxy_->GetMockOveralls(),
              Ospi_SetAttribUint32(kFakeKeyHandle, TSS_TSPATTRIB_KEY_INFO,
                                   TSS_TSPATTRIB_KEYINFO_ENCSCHEME, _))
      .WillOnce(Return(TPM_SUCCESS));

  EXPECT_CALL(
      proxy_->GetMockOveralls(),
      Ospi_Key_CreateKey(kFakeKeyHandle, kDefaultSrkHandle, kFakePcrHandle))
      .WillOnce(Return(TPM_SUCCESS));

  EXPECT_CALL(proxy_->GetMockOveralls(),
              Ospi_Key_LoadKey(kFakeKeyHandle, kDefaultSrkHandle))
      .WillOnce(Return(TPM_SUCCESS));

  brillo::Blob key_blob = kFakeKeyBlob;
  EXPECT_CALL(proxy_->GetMockOveralls(),
              Ospi_GetAttribData(kFakeKeyHandle, TSS_TSPATTRIB_KEY_BLOB,
                                 TSS_TSPATTRIB_KEYBLOB_BLOB, _, _))
      .WillOnce(DoAll(SetArgPointee<3>(key_blob.size()),
                      SetArgPointee<4>(key_blob.data()), Return(TPM_SUCCESS)));

  brillo::Blob fake_pubkey = kFakePubkey;
  EXPECT_CALL(proxy_->GetMockOveralls(),
              Ospi_Key_GetPubKey(kFakeKeyHandle, _, _))
      .WillOnce(DoAll(SetArgPointee<1>(kFakePubkey.size()),
                      SetArgPointee<2>(fake_pubkey.data()),
                      Return(TPM_SUCCESS)));

  auto result = backend_->GetKeyManagementTpm1().CreateKey(
      kFakePolicy, kFakeAlgo,
      Backend::KeyManagement::LoadKeyOptions{.auto_reload = true},
      Backend::KeyManagement::CreateKeyOptions{
          .allow_software_gen = true,
          .allow_decrypt = true,
          .allow_sign = true,
      });

  ASSERT_OK(result);
  EXPECT_EQ(result->key_blob, kFakeKeyBlob);
}

TEST_F(BackendKeyManagementTpm1Test, CreateRsaKeyWithParams) {
  const OperationPolicySetting kFakePolicy{
      .device_config_settings =
          DeviceConfigSettings{
              .boot_mode =
                  DeviceConfigSettings::BootModeSetting{
                      .mode = std::nullopt,
                  },
          },
  };
  const KeyAlgoType kFakeAlgo = KeyAlgoType::kRsa;
  const brillo::Blob kFakeKeyBlob = brillo::BlobFromString("fake_key_blob");
  const brillo::Blob kFakePubkey = brillo::BlobFromString("fake_pubkey");
  const brillo::Blob kExponent{0x03};
  const uint32_t kFakeKeyHandle = 0x1337;
  const uint32_t kFakePcrHandle = 0x7331;

  SetupSrk();

  EXPECT_CALL(proxy_->GetMockOveralls(),
              Ospi_Context_CreateObject(kDefaultContext, TSS_OBJECT_TYPE_PCRS,
                                        TSS_PCRS_STRUCT_INFO, _))
      .WillOnce(DoAll(SetArgPointee<3>(kFakePcrHandle), Return(TPM_SUCCESS)));

  EXPECT_CALL(proxy_->GetMockOveralls(),
              Ospi_PcrComposite_SetPcrValue(kFakePcrHandle, 0, _, _))
      .WillOnce(Return(TPM_SUCCESS));

  EXPECT_CALL(
      proxy_->GetMockOveralls(),
      Ospi_Context_CreateObject(kDefaultContext, TSS_OBJECT_TYPE_RSAKEY, _, _))
      .WillOnce(DoAll(SetArgPointee<3>(kFakeKeyHandle), Return(TPM_SUCCESS)));

  EXPECT_CALL(proxy_->GetMockOveralls(),
              Ospi_SetAttribUint32(kFakeKeyHandle, TSS_TSPATTRIB_KEY_INFO,
                                   TSS_TSPATTRIB_KEYINFO_SIGSCHEME, _))
      .WillOnce(Return(TPM_SUCCESS));

  EXPECT_CALL(proxy_->GetMockOveralls(),
              Ospi_SetAttribUint32(kFakeKeyHandle, TSS_TSPATTRIB_KEY_INFO,
                                   TSS_TSPATTRIB_KEYINFO_ENCSCHEME, _))
      .WillOnce(Return(TPM_SUCCESS));

  EXPECT_CALL(proxy_->GetMockOveralls(),
              Ospi_SetAttribData(kFakeKeyHandle, TSS_TSPATTRIB_RSAKEY_INFO,
                                 TSS_TSPATTRIB_KEYINFO_RSA_EXPONENT, _, _))
      .With(Args<4, 3>(ElementsAreArray(kExponent)))
      .WillOnce(Return(TPM_SUCCESS));

  EXPECT_CALL(
      proxy_->GetMockOveralls(),
      Ospi_Key_CreateKey(kFakeKeyHandle, kDefaultSrkHandle, kFakePcrHandle))
      .WillOnce(Return(TPM_SUCCESS));

  EXPECT_CALL(proxy_->GetMockOveralls(),
              Ospi_Key_LoadKey(kFakeKeyHandle, kDefaultSrkHandle))
      .WillOnce(Return(TPM_SUCCESS));

  brillo::Blob key_blob = kFakeKeyBlob;
  EXPECT_CALL(proxy_->GetMockOveralls(),
              Ospi_GetAttribData(kFakeKeyHandle, TSS_TSPATTRIB_KEY_BLOB,
                                 TSS_TSPATTRIB_KEYBLOB_BLOB, _, _))
      .WillOnce(DoAll(SetArgPointee<3>(key_blob.size()),
                      SetArgPointee<4>(key_blob.data()), Return(TPM_SUCCESS)));

  brillo::Blob fake_pubkey = kFakePubkey;
  EXPECT_CALL(proxy_->GetMockOveralls(),
              Ospi_Key_GetPubKey(kFakeKeyHandle, _, _))
      .WillOnce(DoAll(SetArgPointee<1>(kFakePubkey.size()),
                      SetArgPointee<2>(fake_pubkey.data()),
                      Return(TPM_SUCCESS)));

  auto result = backend_->GetKeyManagementTpm1().CreateKey(
      kFakePolicy, kFakeAlgo,
      Backend::KeyManagement::LoadKeyOptions{.auto_reload = true},
      Backend::KeyManagement::CreateKeyOptions{
          .allow_software_gen = true,
          .allow_decrypt = true,
          .allow_sign = true,
          .rsa_modulus_bits = 1024,
          .rsa_exponent = kExponent,
      });

  ASSERT_OK(result);
  EXPECT_EQ(result->key_blob, kFakeKeyBlob);
}

TEST_F(BackendKeyManagementTpm1Test, CreateRsaKeyWithAuth) {
  const brillo::SecureBlob kFakeAuthValue("auth_value");
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
              .auth_value = kFakeAuthValue,
          },
  };

  const KeyAlgoType kFakeAlgo = KeyAlgoType::kRsa;
  const brillo::Blob kFakeKeyBlob = brillo::BlobFromString("fake_key_blob");
  const brillo::Blob kFakePubkey = brillo::BlobFromString("fake_pubkey");
  const uint32_t kFakeKeyHandle = 0x1337;
  const uint32_t kFakePcrHandle = 0x7331;
  const uint32_t kFakeAuthPolicyHandle = 0x1773;

  SetupSrk();

  EXPECT_CALL(proxy_->GetMockOveralls(),
              Ospi_Context_CreateObject(kDefaultContext, TSS_OBJECT_TYPE_PCRS,
                                        TSS_PCRS_STRUCT_INFO, _))
      .WillOnce(DoAll(SetArgPointee<3>(kFakePcrHandle), Return(TPM_SUCCESS)));

  EXPECT_CALL(proxy_->GetMockOveralls(),
              Ospi_PcrComposite_SetPcrValue(kFakePcrHandle, 0, _, _))
      .WillOnce(Return(TPM_SUCCESS));

  EXPECT_CALL(
      proxy_->GetMockOveralls(),
      Ospi_Context_CreateObject(kDefaultContext, TSS_OBJECT_TYPE_RSAKEY, _, _))
      .WillOnce(DoAll(SetArgPointee<3>(kFakeKeyHandle), Return(TPM_SUCCESS)));

  EXPECT_CALL(proxy_->GetMockOveralls(),
              Ospi_SetAttribUint32(kFakeKeyHandle, TSS_TSPATTRIB_KEY_INFO,
                                   TSS_TSPATTRIB_KEYINFO_SIGSCHEME, _))
      .WillOnce(Return(TPM_SUCCESS));

  EXPECT_CALL(proxy_->GetMockOveralls(),
              Ospi_SetAttribUint32(kFakeKeyHandle, TSS_TSPATTRIB_KEY_INFO,
                                   TSS_TSPATTRIB_KEYINFO_ENCSCHEME, _))
      .WillOnce(Return(TPM_SUCCESS));

  EXPECT_CALL(
      proxy_->GetMockOveralls(),
      Ospi_Key_CreateKey(kFakeKeyHandle, kDefaultSrkHandle, kFakePcrHandle))
      .WillOnce(Return(TPM_SUCCESS));

  EXPECT_CALL(proxy_->GetMockOveralls(),
              Ospi_Context_CreateObject(kDefaultContext, TSS_OBJECT_TYPE_POLICY,
                                        TSS_POLICY_USAGE, _))
      .WillOnce(
          DoAll(SetArgPointee<3>(kFakeAuthPolicyHandle), Return(TPM_SUCCESS)));

  EXPECT_CALL(
      proxy_->GetMockOveralls(),
      Ospi_Policy_SetSecret(kFakeAuthPolicyHandle, TSS_SECRET_MODE_PLAIN, _, _))
      .With(Args<3, 2>(ElementsAreArray(kFakeAuthValue)))
      .WillOnce(Return(TPM_SUCCESS));

  EXPECT_CALL(proxy_->GetMockOveralls(),
              Ospi_Policy_AssignToObject(kFakeAuthPolicyHandle, kFakeKeyHandle))
      .WillOnce(Return(TPM_SUCCESS));

  EXPECT_CALL(proxy_->GetMockOveralls(),
              Ospi_Key_LoadKey(kFakeKeyHandle, kDefaultSrkHandle))
      .WillOnce(Return(TPM_SUCCESS));

  brillo::Blob key_blob = kFakeKeyBlob;
  EXPECT_CALL(proxy_->GetMockOveralls(),
              Ospi_GetAttribData(kFakeKeyHandle, TSS_TSPATTRIB_KEY_BLOB,
                                 TSS_TSPATTRIB_KEYBLOB_BLOB, _, _))
      .WillOnce(DoAll(SetArgPointee<3>(key_blob.size()),
                      SetArgPointee<4>(key_blob.data()), Return(TPM_SUCCESS)));

  brillo::Blob fake_pubkey = kFakePubkey;
  EXPECT_CALL(proxy_->GetMockOveralls(),
              Ospi_Key_GetPubKey(kFakeKeyHandle, _, _))
      .WillOnce(DoAll(SetArgPointee<1>(kFakePubkey.size()),
                      SetArgPointee<2>(fake_pubkey.data()),
                      Return(TPM_SUCCESS)));

  auto result = backend_->GetKeyManagementTpm1().CreateKey(
      kFakePolicy, kFakeAlgo,
      Backend::KeyManagement::LoadKeyOptions{.auto_reload = true},
      Backend::KeyManagement::CreateKeyOptions{
          .allow_software_gen = true,
          .allow_decrypt = true,
          .allow_sign = true,
      });

  ASSERT_OK(result);
  EXPECT_EQ(result->key_blob, kFakeKeyBlob);
}

TEST_F(BackendKeyManagementTpm1Test, CreateRsaKeyWithAuthSha1) {
  const brillo::SecureBlob kFakeAuthValue(20, 1);
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
              .auth_value = kFakeAuthValue,
          },
  };

  const KeyAlgoType kFakeAlgo = KeyAlgoType::kRsa;
  const brillo::Blob kFakeKeyBlob = brillo::BlobFromString("fake_key_blob");
  const brillo::Blob kFakePubkey = brillo::BlobFromString("fake_pubkey");
  const uint32_t kFakeKeyHandle = 0x1337;
  const uint32_t kFakePcrHandle = 0x7331;
  const uint32_t kFakeAuthPolicyHandle = 0x1773;

  SetupSrk();

  EXPECT_CALL(proxy_->GetMockOveralls(),
              Ospi_Context_CreateObject(kDefaultContext, TSS_OBJECT_TYPE_PCRS,
                                        TSS_PCRS_STRUCT_INFO, _))
      .WillOnce(DoAll(SetArgPointee<3>(kFakePcrHandle), Return(TPM_SUCCESS)));

  EXPECT_CALL(proxy_->GetMockOveralls(),
              Ospi_PcrComposite_SetPcrValue(kFakePcrHandle, 0, _, _))
      .WillOnce(Return(TPM_SUCCESS));

  EXPECT_CALL(
      proxy_->GetMockOveralls(),
      Ospi_Context_CreateObject(kDefaultContext, TSS_OBJECT_TYPE_RSAKEY, _, _))
      .WillOnce(DoAll(SetArgPointee<3>(kFakeKeyHandle), Return(TPM_SUCCESS)));

  EXPECT_CALL(proxy_->GetMockOveralls(),
              Ospi_SetAttribUint32(kFakeKeyHandle, TSS_TSPATTRIB_KEY_INFO,
                                   TSS_TSPATTRIB_KEYINFO_SIGSCHEME, _))
      .WillOnce(Return(TPM_SUCCESS));

  EXPECT_CALL(proxy_->GetMockOveralls(),
              Ospi_SetAttribUint32(kFakeKeyHandle, TSS_TSPATTRIB_KEY_INFO,
                                   TSS_TSPATTRIB_KEYINFO_ENCSCHEME, _))
      .WillOnce(Return(TPM_SUCCESS));

  EXPECT_CALL(
      proxy_->GetMockOveralls(),
      Ospi_Key_CreateKey(kFakeKeyHandle, kDefaultSrkHandle, kFakePcrHandle))
      .WillOnce(Return(TPM_SUCCESS));

  EXPECT_CALL(proxy_->GetMockOveralls(),
              Ospi_Context_CreateObject(kDefaultContext, TSS_OBJECT_TYPE_POLICY,
                                        TSS_POLICY_USAGE, _))
      .WillOnce(
          DoAll(SetArgPointee<3>(kFakeAuthPolicyHandle), Return(TPM_SUCCESS)));

  EXPECT_CALL(
      proxy_->GetMockOveralls(),
      Ospi_Policy_SetSecret(kFakeAuthPolicyHandle, TSS_SECRET_MODE_SHA1, 20, _))
      .With(Args<3, 2>(ElementsAreArray(kFakeAuthValue)))
      .WillOnce(Return(TPM_SUCCESS));

  EXPECT_CALL(proxy_->GetMockOveralls(),
              Ospi_Policy_AssignToObject(kFakeAuthPolicyHandle, kFakeKeyHandle))
      .WillOnce(Return(TPM_SUCCESS));

  EXPECT_CALL(proxy_->GetMockOveralls(),
              Ospi_Key_LoadKey(kFakeKeyHandle, kDefaultSrkHandle))
      .WillOnce(Return(TPM_SUCCESS));

  brillo::Blob key_blob = kFakeKeyBlob;
  EXPECT_CALL(proxy_->GetMockOveralls(),
              Ospi_GetAttribData(kFakeKeyHandle, TSS_TSPATTRIB_KEY_BLOB,
                                 TSS_TSPATTRIB_KEYBLOB_BLOB, _, _))
      .WillOnce(DoAll(SetArgPointee<3>(key_blob.size()),
                      SetArgPointee<4>(key_blob.data()), Return(TPM_SUCCESS)));

  brillo::Blob fake_pubkey = kFakePubkey;
  EXPECT_CALL(proxy_->GetMockOveralls(),
              Ospi_Key_GetPubKey(kFakeKeyHandle, _, _))
      .WillOnce(DoAll(SetArgPointee<1>(kFakePubkey.size()),
                      SetArgPointee<2>(fake_pubkey.data()),
                      Return(TPM_SUCCESS)));

  auto result = backend_->GetKeyManagementTpm1().CreateKey(
      kFakePolicy, kFakeAlgo,
      Backend::KeyManagement::LoadKeyOptions{.auto_reload = true},
      Backend::KeyManagement::CreateKeyOptions{
          .allow_software_gen = true,
          .allow_decrypt = true,
          .allow_sign = true,
      });

  ASSERT_OK(result);
  EXPECT_EQ(result->key_blob, kFakeKeyBlob);
}

TEST_F(BackendKeyManagementTpm1Test, LoadKey) {
  const OperationPolicy kFakePolicy{};
  const brillo::Blob kFakeKeyBlob = brillo::BlobFromString("fake_key_blob");
  const brillo::Blob kFakePubkey = brillo::BlobFromString("fake_pubkey");
  const uint32_t kFakeKeyHandle = 0x1337;

  SetupSrk();

  EXPECT_CALL(
      proxy_->GetMockOveralls(),
      Ospi_Context_LoadKeyByBlob(kDefaultContext, kDefaultSrkHandle, _, _, _))
      .WillOnce(DoAll(SetArgPointee<4>(kFakeKeyHandle), Return(TPM_SUCCESS)));

  brillo::Blob fake_pubkey = kFakePubkey;
  EXPECT_CALL(proxy_->GetMockOveralls(),
              Ospi_Key_GetPubKey(kFakeKeyHandle, _, _))
      .WillOnce(DoAll(SetArgPointee<1>(kFakePubkey.size()),
                      SetArgPointee<2>(fake_pubkey.data()),
                      Return(TPM_SUCCESS)));

  auto result = backend_->GetKeyManagementTpm1().LoadKey(
      kFakePolicy, kFakeKeyBlob, Backend::KeyManagement::LoadKeyOptions{});

  ASSERT_OK(result);

  EXPECT_THAT(
      backend_->GetKeyManagementTpm1().ReloadIfPossible(result->GetKey()),
      IsOk());

  EXPECT_THAT(backend_->GetKeyManagementTpm1().GetKeyHandle(result->GetKey()),
              IsOkAndHolds(kFakeKeyHandle));
}

TEST_F(BackendKeyManagementTpm1Test, LoadKeyWithAuth) {
  const brillo::SecureBlob kFakeAuthValue("auth_value");
  const OperationPolicy kFakePolicy{
      .permission =
          Permission{
              .auth_value = kFakeAuthValue,
          },
  };
  const brillo::Blob kFakeKeyBlob = brillo::BlobFromString("fake_key_blob");
  const brillo::Blob kFakePubkey = brillo::BlobFromString("fake_pubkey");
  const uint32_t kFakeKeyHandle = 0x1337;
  const uint32_t kFakeAuthPolicyHandle = 0x1773;

  SetupSrk();

  EXPECT_CALL(
      proxy_->GetMockOveralls(),
      Ospi_Context_LoadKeyByBlob(kDefaultContext, kDefaultSrkHandle, _, _, _))
      .WillOnce(DoAll(SetArgPointee<4>(kFakeKeyHandle), Return(TPM_SUCCESS)));

  brillo::Blob fake_pubkey = kFakePubkey;
  EXPECT_CALL(proxy_->GetMockOveralls(),
              Ospi_Key_GetPubKey(kFakeKeyHandle, _, _))
      .WillOnce(DoAll(SetArgPointee<1>(kFakePubkey.size()),
                      SetArgPointee<2>(fake_pubkey.data()),
                      Return(TPM_SUCCESS)));

  EXPECT_CALL(proxy_->GetMockOveralls(),
              Ospi_Context_CreateObject(kDefaultContext, TSS_OBJECT_TYPE_POLICY,
                                        TSS_POLICY_USAGE, _))
      .WillOnce(
          DoAll(SetArgPointee<3>(kFakeAuthPolicyHandle), Return(TPM_SUCCESS)));

  EXPECT_CALL(
      proxy_->GetMockOveralls(),
      Ospi_Policy_SetSecret(kFakeAuthPolicyHandle, TSS_SECRET_MODE_PLAIN, _, _))
      .With(Args<3, 2>(ElementsAreArray(kFakeAuthValue)))
      .WillOnce(Return(TPM_SUCCESS));

  EXPECT_CALL(proxy_->GetMockOveralls(),
              Ospi_Policy_AssignToObject(kFakeAuthPolicyHandle, kFakeKeyHandle))
      .WillOnce(Return(TPM_SUCCESS));

  auto result = backend_->GetKeyManagementTpm1().LoadKey(
      kFakePolicy, kFakeKeyBlob,
      Backend::KeyManagement::LoadKeyOptions{.auto_reload = false});

  ASSERT_OK(result);

  EXPECT_THAT(
      backend_->GetKeyManagementTpm1().ReloadIfPossible(result->GetKey()),
      IsOk());

  EXPECT_THAT(backend_->GetKeyManagementTpm1().GetKeyHandle(result->GetKey()),
              IsOkAndHolds(kFakeKeyHandle));
}

TEST_F(BackendKeyManagementTpm1Test, LoadAutoReloadKey) {
  const OperationPolicy kFakePolicy{};
  const brillo::Blob kFakeKeyBlob = brillo::BlobFromString("fake_key_blob");
  const brillo::Blob kFakePubkey = brillo::BlobFromString("fake_pubkey");
  const uint32_t kFakeKeyHandle = 0x1337;
  const uint32_t kFakeKeyHandle2 = 0x7331;

  SetupSrk();

  EXPECT_CALL(
      proxy_->GetMockOveralls(),
      Ospi_Context_LoadKeyByBlob(kDefaultContext, kDefaultSrkHandle, _, _, _))
      .WillOnce(DoAll(SetArgPointee<4>(kFakeKeyHandle), Return(TPM_SUCCESS)))
      .WillOnce(DoAll(SetArgPointee<4>(kFakeKeyHandle2), Return(TPM_SUCCESS)));

  brillo::Blob fake_pubkey = kFakePubkey;
  EXPECT_CALL(proxy_->GetMockOveralls(),
              Ospi_Key_GetPubKey(kFakeKeyHandle, _, _))
      .WillOnce(DoAll(SetArgPointee<1>(kFakePubkey.size()),
                      SetArgPointee<2>(fake_pubkey.data()),
                      Return(TPM_SUCCESS)));

  auto result = backend_->GetKeyManagementTpm1().LoadKey(
      kFakePolicy, kFakeKeyBlob,
      Backend::KeyManagement::LoadKeyOptions{.auto_reload = true});

  ASSERT_OK(result);

  EXPECT_THAT(
      backend_->GetKeyManagementTpm1().ReloadIfPossible(result->GetKey()),
      IsOk());

  EXPECT_THAT(backend_->GetKeyManagementTpm1().GetKeyHandle(result->GetKey()),
              IsOkAndHolds(kFakeKeyHandle2));
}

TEST_F(BackendKeyManagementTpm1Test, SideLoadKey) {
  const OperationPolicy kFakePolicy{};
  const brillo::Blob kFakePubkey = brillo::BlobFromString("fake_pubkey");
  const uint32_t kFakeKeyHandle = 0x1337;

  brillo::Blob fake_pubkey = kFakePubkey;
  EXPECT_CALL(proxy_->GetMockOveralls(),
              Ospi_Key_GetPubKey(kFakeKeyHandle, _, _))
      .WillOnce(DoAll(SetArgPointee<1>(kFakePubkey.size()),
                      SetArgPointee<2>(fake_pubkey.data()),
                      Return(TPM_SUCCESS)));

  auto result = backend_->GetKeyManagementTpm1().SideLoadKey(kFakeKeyHandle);

  ASSERT_OK(result);

  EXPECT_THAT(backend_->GetKeyManagementTpm1().GetKeyHandle(result->GetKey()),
              IsOkAndHolds(kFakeKeyHandle));
}

TEST_F(BackendKeyManagementTpm1Test, LoadPublicKeyFromSpki) {
  crypto::ScopedEVP_PKEY pkey;
  brillo::Blob public_key_spki_der;
  EXPECT_TRUE(GenerateRsaKey(2048, &pkey, &public_key_spki_der));

  EXPECT_THAT(
      backend_->GetKeyManagementTpm1().LoadPublicKeyFromSpki(
          public_key_spki_der, TSS_SS_RSASSAPKCS1V15_SHA1, TSS_ES_RSAESPKCSV15),
      IsOk());
}

TEST_F(BackendKeyManagementTpm1Test, LoadPublicKeyFromSpkiFailed) {
  // Wrong format key.
  brillo::Blob public_key_spki_der(64, '?');

  EXPECT_THAT(
      backend_->GetKeyManagementTpm1().LoadPublicKeyFromSpki(
          public_key_spki_der, TSS_SS_RSASSAPKCS1V15_SHA1, TSS_ES_RSAESPKCSV15),
      NotOk());
}

TEST_F(BackendKeyManagementTpm1Test, WrapRsaKey) {
  const OperationPolicySetting kFakePolicy{};
  const brillo::Blob kFakeKeyBlob = brillo::BlobFromString("fake_key_blob");
  const brillo::Blob kFakePubkey = brillo::BlobFromString("fake_pubkey");
  const brillo::Blob kFakeModulus(1024 / 8, 'Z');
  const brillo::SecureBlob kFakePrime(1024 / 8, 'X');
  const brillo::Blob kExponent{0x03};
  const uint32_t kFakeKeyHandle = 0x1337;
  const uint32_t kFakeKeyHandle2 = 0x1338;
  const uint32_t kFakePolicyHandle = 0x7331;

  SetupSrk();

  EXPECT_CALL(
      proxy_->GetMockOveralls(),
      Ospi_Context_CreateObject(kDefaultContext, TSS_OBJECT_TYPE_RSAKEY, _, _))
      .WillOnce(DoAll(SetArgPointee<3>(kFakeKeyHandle), Return(TPM_SUCCESS)));

  EXPECT_CALL(proxy_->GetMockOveralls(),
              Ospi_SetAttribUint32(kFakeKeyHandle, TSS_TSPATTRIB_KEY_INFO,
                                   TSS_TSPATTRIB_KEYINFO_SIGSCHEME, _))
      .WillOnce(Return(TPM_SUCCESS));

  EXPECT_CALL(proxy_->GetMockOveralls(),
              Ospi_Context_CreateObject(kDefaultContext, TSS_OBJECT_TYPE_POLICY,
                                        TSS_POLICY_MIGRATION, _))
      .WillOnce(
          DoAll(SetArgPointee<3>(kFakePolicyHandle), Return(TPM_SUCCESS)));

  EXPECT_CALL(
      proxy_->GetMockOveralls(),
      Ospi_Policy_SetSecret(kFakePolicyHandle, TSS_SECRET_MODE_PLAIN, _, _))
      .WillOnce(Return(TPM_SUCCESS));

  EXPECT_CALL(proxy_->GetMockOveralls(),
              Ospi_Policy_AssignToObject(kFakePolicyHandle, kFakeKeyHandle))
      .WillOnce(Return(TPM_SUCCESS));

  EXPECT_CALL(proxy_->GetMockOveralls(),
              Ospi_SetAttribData(kFakeKeyHandle, TSS_TSPATTRIB_RSAKEY_INFO,
                                 TSS_TSPATTRIB_KEYINFO_RSA_EXPONENT, _, _))
      .With(Args<4, 3>(ElementsAreArray(kExponent)))
      .WillOnce(Return(TPM_SUCCESS));

  EXPECT_CALL(proxy_->GetMockOveralls(),
              Ospi_SetAttribData(kFakeKeyHandle, TSS_TSPATTRIB_RSAKEY_INFO,
                                 TSS_TSPATTRIB_KEYINFO_RSA_MODULUS, _, _))
      .With(Args<4, 3>(ElementsAreArray(kFakeModulus)))
      .WillOnce(Return(TPM_SUCCESS));

  EXPECT_CALL(proxy_->GetMockOveralls(),
              Ospi_SetAttribData(kFakeKeyHandle, TSS_TSPATTRIB_KEY_BLOB,
                                 TSS_TSPATTRIB_KEYBLOB_PRIVATE_KEY, _, _))
      .With(Args<4, 3>(ElementsAreArray(kFakePrime)))
      .WillOnce(Return(TPM_SUCCESS));

  EXPECT_CALL(proxy_->GetMockOveralls(),
              Ospi_Key_WrapKey(kFakeKeyHandle, kDefaultSrkHandle, 0))
      .WillOnce(Return(TPM_SUCCESS));

  brillo::Blob key_blob = kFakeKeyBlob;
  EXPECT_CALL(proxy_->GetMockOveralls(),
              Ospi_GetAttribData(kFakeKeyHandle, TSS_TSPATTRIB_KEY_BLOB,
                                 TSS_TSPATTRIB_KEYBLOB_BLOB, _, _))
      .WillOnce(DoAll(SetArgPointee<3>(key_blob.size()),
                      SetArgPointee<4>(key_blob.data()), Return(TPM_SUCCESS)));

  EXPECT_CALL(
      proxy_->GetMockOveralls(),
      Ospi_Context_LoadKeyByBlob(kDefaultContext, kDefaultSrkHandle, _, _, _))
      .WillOnce(DoAll(SetArgPointee<4>(kFakeKeyHandle2), Return(TPM_SUCCESS)));

  brillo::Blob fake_pubkey = kFakePubkey;
  EXPECT_CALL(proxy_->GetMockOveralls(),
              Ospi_Key_GetPubKey(kFakeKeyHandle2, _, _))
      .WillOnce(DoAll(SetArgPointee<1>(kFakePubkey.size()),
                      SetArgPointee<2>(fake_pubkey.data()),
                      Return(TPM_SUCCESS)));

  auto result = backend_->GetKeyManagementTpm1().WrapRSAKey(
      kFakePolicy, kFakeModulus, kFakePrime,
      Backend::KeyManagement::LoadKeyOptions{},
      Backend::KeyManagement::CreateKeyOptions{
          .allow_software_gen = false,
          .allow_decrypt = false,
          .allow_sign = true,
          .rsa_modulus_bits = 1024,
          .rsa_exponent = kExponent,
      });

  ASSERT_OK(result);
  EXPECT_EQ(result->key_blob, kFakeKeyBlob);
}

TEST_F(BackendKeyManagementTpm1Test, WrapRsaKeyWithAuth) {
  const brillo::SecureBlob kFakeAuthValue("");  // Empty auth value.
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
              .auth_value = kFakeAuthValue,
          },
  };
  const brillo::Blob kFakeKeyBlob = brillo::BlobFromString("fake_key_blob");
  const brillo::Blob kFakePubkey = brillo::BlobFromString("fake_pubkey");
  const brillo::Blob kFakeModulus(1024 / 8, 'Z');
  const brillo::SecureBlob kFakePrime(1024 / 8, 'X');
  const brillo::Blob kExponent{0x03};
  const uint32_t kFakeKeyHandle = 0x1337;
  const uint32_t kFakeKeyHandle2 = 0x1338;
  const uint32_t kFakePolicyHandle = 0x7331;
  const uint32_t kFakeAuthPolicyHandle = 0x7131;
  const uint32_t kFakeAuthPolicyHandle2 = 0x7132;

  SetupSrk();

  EXPECT_CALL(
      proxy_->GetMockOveralls(),
      Ospi_Context_CreateObject(kDefaultContext, TSS_OBJECT_TYPE_RSAKEY, _, _))
      .WillOnce(DoAll(SetArgPointee<3>(kFakeKeyHandle), Return(TPM_SUCCESS)));

  EXPECT_CALL(proxy_->GetMockOveralls(),
              Ospi_SetAttribUint32(kFakeKeyHandle, TSS_TSPATTRIB_KEY_INFO,
                                   TSS_TSPATTRIB_KEYINFO_SIGSCHEME, _))
      .WillOnce(Return(TPM_SUCCESS));

  EXPECT_CALL(proxy_->GetMockOveralls(),
              Ospi_Context_CreateObject(kDefaultContext, TSS_OBJECT_TYPE_POLICY,
                                        TSS_POLICY_MIGRATION, _))
      .WillOnce(
          DoAll(SetArgPointee<3>(kFakePolicyHandle), Return(TPM_SUCCESS)));

  EXPECT_CALL(
      proxy_->GetMockOveralls(),
      Ospi_Policy_SetSecret(kFakePolicyHandle, TSS_SECRET_MODE_PLAIN, _, _))
      .WillOnce(Return(TPM_SUCCESS));

  EXPECT_CALL(proxy_->GetMockOveralls(),
              Ospi_Policy_AssignToObject(kFakePolicyHandle, kFakeKeyHandle))
      .WillOnce(Return(TPM_SUCCESS));

  EXPECT_CALL(proxy_->GetMockOveralls(),
              Ospi_SetAttribData(kFakeKeyHandle, TSS_TSPATTRIB_RSAKEY_INFO,
                                 TSS_TSPATTRIB_KEYINFO_RSA_EXPONENT, _, _))
      .With(Args<4, 3>(ElementsAreArray(kExponent)))
      .WillOnce(Return(TPM_SUCCESS));

  EXPECT_CALL(proxy_->GetMockOveralls(),
              Ospi_SetAttribData(kFakeKeyHandle, TSS_TSPATTRIB_RSAKEY_INFO,
                                 TSS_TSPATTRIB_KEYINFO_RSA_MODULUS, _, _))
      .With(Args<4, 3>(ElementsAreArray(kFakeModulus)))
      .WillOnce(Return(TPM_SUCCESS));

  EXPECT_CALL(proxy_->GetMockOveralls(),
              Ospi_SetAttribData(kFakeKeyHandle, TSS_TSPATTRIB_KEY_BLOB,
                                 TSS_TSPATTRIB_KEYBLOB_PRIVATE_KEY, _, _))
      .With(Args<4, 3>(ElementsAreArray(kFakePrime)))
      .WillOnce(Return(TPM_SUCCESS));

  EXPECT_CALL(proxy_->GetMockOveralls(),
              Ospi_Context_CreateObject(kDefaultContext, TSS_OBJECT_TYPE_POLICY,
                                        TSS_POLICY_USAGE, _))
      .WillOnce(
          DoAll(SetArgPointee<3>(kFakeAuthPolicyHandle), Return(TPM_SUCCESS)))
      .WillOnce(
          DoAll(SetArgPointee<3>(kFakeAuthPolicyHandle2), Return(TPM_SUCCESS)));

  EXPECT_CALL(proxy_->GetMockOveralls(),
              Ospi_Policy_SetSecret(kFakeAuthPolicyHandle, TSS_SECRET_MODE_NONE,
                                    0, nullptr))
      .WillOnce(Return(TPM_SUCCESS));

  EXPECT_CALL(proxy_->GetMockOveralls(),
              Ospi_Policy_SetSecret(kFakeAuthPolicyHandle2,
                                    TSS_SECRET_MODE_NONE, 0, nullptr))
      .WillOnce(Return(TPM_SUCCESS));

  EXPECT_CALL(proxy_->GetMockOveralls(),
              Ospi_Policy_AssignToObject(kFakeAuthPolicyHandle, kFakeKeyHandle))
      .WillOnce(Return(TPM_SUCCESS));

  EXPECT_CALL(
      proxy_->GetMockOveralls(),
      Ospi_Policy_AssignToObject(kFakeAuthPolicyHandle2, kFakeKeyHandle2))
      .WillOnce(Return(TPM_SUCCESS));

  EXPECT_CALL(proxy_->GetMockOveralls(),
              Ospi_Key_WrapKey(kFakeKeyHandle, kDefaultSrkHandle, 0))
      .WillOnce(Return(TPM_SUCCESS));

  brillo::Blob key_blob = kFakeKeyBlob;
  EXPECT_CALL(proxy_->GetMockOveralls(),
              Ospi_GetAttribData(kFakeKeyHandle, TSS_TSPATTRIB_KEY_BLOB,
                                 TSS_TSPATTRIB_KEYBLOB_BLOB, _, _))
      .WillOnce(DoAll(SetArgPointee<3>(key_blob.size()),
                      SetArgPointee<4>(key_blob.data()), Return(TPM_SUCCESS)));

  EXPECT_CALL(
      proxy_->GetMockOveralls(),
      Ospi_Context_LoadKeyByBlob(kDefaultContext, kDefaultSrkHandle, _, _, _))
      .WillOnce(DoAll(SetArgPointee<4>(kFakeKeyHandle2), Return(TPM_SUCCESS)));

  brillo::Blob fake_pubkey = kFakePubkey;
  EXPECT_CALL(proxy_->GetMockOveralls(),
              Ospi_Key_GetPubKey(kFakeKeyHandle2, _, _))
      .WillOnce(DoAll(SetArgPointee<1>(kFakePubkey.size()),
                      SetArgPointee<2>(fake_pubkey.data()),
                      Return(TPM_SUCCESS)));

  auto result = backend_->GetKeyManagementTpm1().WrapRSAKey(
      kFakePolicy, kFakeModulus, kFakePrime,
      Backend::KeyManagement::LoadKeyOptions{},
      Backend::KeyManagement::CreateKeyOptions{
          .allow_software_gen = false,
          .allow_decrypt = false,
          .allow_sign = true,
          .rsa_modulus_bits = 1024,
          .rsa_exponent = kExponent,
      });

  ASSERT_OK(result);
  EXPECT_EQ(result->key_blob, kFakeKeyBlob);
}

TEST_F(BackendKeyManagementTpm1Test, WrapECCKeyUnsupported) {
  EXPECT_THAT(
      backend_->GetKeyManagementTpm1().WrapECCKey(
          OperationPolicySetting{}, brillo::Blob(), brillo::Blob(),
          brillo::SecureBlob(), Backend::KeyManagement::LoadKeyOptions{},
          KeyManagement::CreateKeyOptions{}),
      NotOkWith("Unsupported"));
}

TEST_F(BackendKeyManagementTpm1Test, GetPubkeyHash) {
  const OperationPolicy kFakePolicy{};
  const brillo::Blob kFakeKeyBlob = brillo::BlobFromString("fake_key_blob");
  const brillo::Blob kFakePubkey = brillo::BlobFromString("fake_pubkey");
  const uint32_t kFakeKeyHandle = 0x1337;

  SetupSrk();

  EXPECT_CALL(
      proxy_->GetMockOveralls(),
      Ospi_Context_LoadKeyByBlob(kDefaultContext, kDefaultSrkHandle, _, _, _))
      .WillOnce(DoAll(SetArgPointee<4>(kFakeKeyHandle), Return(TPM_SUCCESS)));

  brillo::Blob fake_pubkey = kFakePubkey;
  EXPECT_CALL(proxy_->GetMockOveralls(),
              Ospi_Key_GetPubKey(kFakeKeyHandle, _, _))
      .WillOnce(DoAll(SetArgPointee<1>(kFakePubkey.size()),
                      SetArgPointee<2>(fake_pubkey.data()),
                      Return(TPM_SUCCESS)));

  auto key = backend_->GetKeyManagementTpm1().LoadKey(
      kFakePolicy, kFakeKeyBlob, Backend::KeyManagement::LoadKeyOptions{});

  ASSERT_OK(key);

  EXPECT_THAT(backend_->GetKeyManagementTpm1().GetPubkeyHash(key->GetKey()),
              IsOkAndHolds(Sha1(kFakePubkey)));
}

TEST_F(BackendKeyManagementTpm1Test, GetRSAPublicInfo) {
  const OperationPolicy kFakePolicy{};
  const brillo::Blob kFakeKeyBlob = brillo::BlobFromString("fake_key_blob");
  const brillo::Blob kFakePubkey = brillo::BlobFromString("fake_pubkey");
  const brillo::Blob kExponent = brillo::BlobFromString("exponent");
  const brillo::Blob kModulus = brillo::BlobFromString("modulus");
  const uint32_t kFakeKeyHandle = 0x1337;

  SetupSrk();

  EXPECT_CALL(
      proxy_->GetMockOveralls(),
      Ospi_Context_LoadKeyByBlob(kDefaultContext, kDefaultSrkHandle, _, _, _))
      .WillOnce(DoAll(SetArgPointee<4>(kFakeKeyHandle), Return(TPM_SUCCESS)));

  brillo::Blob fake_pubkey = kFakePubkey;
  EXPECT_CALL(proxy_->GetMockOveralls(),
              Ospi_Key_GetPubKey(kFakeKeyHandle, _, _))
      .WillOnce(DoAll(SetArgPointee<1>(kFakePubkey.size()),
                      SetArgPointee<2>(fake_pubkey.data()),
                      Return(TPM_SUCCESS)));

  auto key = backend_->GetKeyManagementTpm1().LoadKey(
      kFakePolicy, kFakeKeyBlob, Backend::KeyManagement::LoadKeyOptions{});

  ASSERT_OK(key);

  brillo::Blob exponent = kExponent;
  EXPECT_CALL(proxy_->GetMockOveralls(),
              Ospi_GetAttribData(kFakeKeyHandle, TSS_TSPATTRIB_RSAKEY_INFO,
                                 TSS_TSPATTRIB_KEYINFO_RSA_EXPONENT, _, _))
      .WillOnce(DoAll(SetArgPointee<3>(exponent.size()),
                      SetArgPointee<4>(exponent.data()), Return(TPM_SUCCESS)));

  brillo::Blob modulus = kModulus;
  EXPECT_CALL(proxy_->GetMockOveralls(),
              Ospi_GetAttribData(kFakeKeyHandle, TSS_TSPATTRIB_RSAKEY_INFO,
                                 TSS_TSPATTRIB_KEYINFO_RSA_MODULUS, _, _))
      .WillOnce(DoAll(SetArgPointee<3>(modulus.size()),
                      SetArgPointee<4>(modulus.data()), Return(TPM_SUCCESS)));

  auto result =
      backend_->GetKeyManagementTpm1().GetRSAPublicInfo(key->GetKey());

  ASSERT_OK(result);
  EXPECT_EQ(result->exponent, kExponent);
  EXPECT_EQ(result->modulus, kModulus);
}

TEST_F(BackendKeyManagementTpm1Test, IsSupported) {
  EXPECT_THAT(backend_->GetKeyManagementTpm1().IsSupported(
                  KeyAlgoType::kRsa,
                  KeyManagement::CreateKeyOptions{
                      .allow_software_gen = false,
                      .allow_decrypt = true,
                      .allow_sign = true,
                  }),
              IsOk());

  EXPECT_THAT(backend_->GetKeyManagementTpm1().IsSupported(
                  KeyAlgoType::kRsa,
                  KeyManagement::CreateKeyOptions{
                      .allow_software_gen = false,
                      .allow_decrypt = true,
                      .allow_sign = true,
                      .rsa_modulus_bits = 16,
                  }),
              NotOkWith("Modulus bits too small"));

  EXPECT_THAT(backend_->GetKeyManagementTpm1().IsSupported(
                  KeyAlgoType::kRsa,
                  KeyManagement::CreateKeyOptions{
                      .allow_software_gen = false,
                      .allow_decrypt = true,
                      .allow_sign = true,
                      .rsa_modulus_bits = 2147483648U,
                  }),
              NotOkWith("Modulus bits too big"));

  EXPECT_THAT(backend_->GetKeyManagementTpm1().IsSupported(
                  KeyAlgoType::kEcc,
                  KeyManagement::CreateKeyOptions{
                      .allow_software_gen = false,
                      .allow_decrypt = true,
                      .allow_sign = true,
                  }),
              NotOkWith("Unsupported key creation algorithm"));
}

}  // namespace hwsec
