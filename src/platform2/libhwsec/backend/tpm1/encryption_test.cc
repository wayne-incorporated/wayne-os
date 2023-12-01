// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <cstdint>
#include <memory>
#include <utility>

#include <gtest/gtest.h>
#include <libhwsec-foundation/error/testing_helper.h>

#include "libhwsec/backend/tpm1/backend_test_base.h"
#include "libhwsec/overalls/mock_overalls.h"

using hwsec_foundation::error::testing::IsOkAndHolds;
using hwsec_foundation::error::testing::ReturnError;
using hwsec_foundation::error::testing::ReturnValue;
using testing::_;
using testing::DoAll;
using testing::NiceMock;
using testing::Return;
using testing::SaveArg;
using testing::SetArgPointee;
using tpm_manager::TpmManagerStatus;
namespace hwsec {

using BackendEncryptionTpm1Test = BackendTpm1TestBase;

TEST_F(BackendEncryptionTpm1Test, Encrypt) {
  const OperationPolicy kFakePolicy{};
  const brillo::Blob kFakeKeyBlob = brillo::BlobFromString("fake_key_blob");
  const brillo::Blob kFakePubkey = brillo::BlobFromString("fake_pubkey");
  const brillo::SecureBlob kPlaintext = brillo::SecureBlob("plaintext");
  const brillo::Blob kCiphertext = brillo::BlobFromString("ciphertext");
  const uint32_t kFakeKeyHandle = 0x1337;
  const uint32_t kFakeEncHandle = 0x9527;

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

  EXPECT_CALL(
      proxy_->GetMockOveralls(),
      Ospi_Context_CreateObject(kDefaultContext, TSS_OBJECT_TYPE_ENCDATA,
                                TSS_ENCDATA_SEAL, _))
      .WillOnce(DoAll(SetArgPointee<3>(kFakeEncHandle), Return(TPM_SUCCESS)));

  EXPECT_CALL(proxy_->GetMockOveralls(),
              Ospi_Data_Bind(kFakeEncHandle, kFakeKeyHandle, _, _))
      .WillOnce(Return(TPM_SUCCESS));

  brillo::Blob mutable_ciphertext = kCiphertext;
  EXPECT_CALL(proxy_->GetMockOveralls(),
              Ospi_GetAttribData(kFakeEncHandle, TSS_TSPATTRIB_ENCDATA_BLOB,
                                 TSS_TSPATTRIB_ENCDATABLOB_BLOB, _, _))
      .WillOnce(DoAll(SetArgPointee<3>(mutable_ciphertext.size()),
                      SetArgPointee<4>(mutable_ciphertext.data()),
                      Return(TPM_SUCCESS)));

  EXPECT_THAT(
      backend_->GetEncryptionTpm1().Encrypt(
          key->GetKey(), kPlaintext, Backend::Encryption::EncryptionOptions{}),
      IsOkAndHolds(kCiphertext));
}

TEST_F(BackendEncryptionTpm1Test, Decrypt) {
  const OperationPolicy kFakePolicy{};
  const brillo::Blob kFakeKeyBlob = brillo::BlobFromString("fake_key_blob");
  const brillo::Blob kFakePubkey = brillo::BlobFromString("fake_pubkey");
  const brillo::SecureBlob kPlaintext = brillo::SecureBlob("plaintext");
  const brillo::Blob kCiphertext = brillo::BlobFromString("ciphertext");
  const uint32_t kFakeKeyHandle = 0x1337;
  const uint32_t kFakeEncHandle = 0x9527;

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

  EXPECT_CALL(
      proxy_->GetMockOveralls(),
      Ospi_Context_CreateObject(kDefaultContext, TSS_OBJECT_TYPE_ENCDATA,
                                TSS_ENCDATA_SEAL, _))
      .WillOnce(DoAll(SetArgPointee<3>(kFakeEncHandle), Return(TPM_SUCCESS)));

  EXPECT_CALL(proxy_->GetMockOveralls(),
              Ospi_SetAttribData(kFakeEncHandle, TSS_TSPATTRIB_ENCDATA_BLOB,
                                 TSS_TSPATTRIB_ENCDATABLOB_BLOB, _, _))
      .WillOnce(Return(TPM_SUCCESS));

  brillo::SecureBlob mutable_plaintext = kPlaintext;
  EXPECT_CALL(proxy_->GetMockOveralls(),
              Ospi_Data_Unbind(kFakeEncHandle, kFakeKeyHandle, _, _))
      .WillOnce(DoAll(SetArgPointee<2>(mutable_plaintext.size()),
                      SetArgPointee<3>(mutable_plaintext.data()),
                      Return(TPM_SUCCESS)));

  EXPECT_THAT(
      backend_->GetEncryptionTpm1().Decrypt(
          key->GetKey(), kCiphertext, Backend::Encryption::EncryptionOptions{}),
      IsOkAndHolds(kPlaintext));
}

}  // namespace hwsec
