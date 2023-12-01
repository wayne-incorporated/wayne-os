// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "libhwsec/frontend/oobe_config/frontend_impl.h"

#include <optional>
#include <utility>
#include <vector>

#include <brillo/secure_blob.h>
#include <libhwsec-foundation/crypto/aes.h>
#include <libhwsec-foundation/crypto/sha.h>
#include <libhwsec-foundation/status/status_chain_macros.h>

#include "libhwsec/backend/backend.h"
#include "libhwsec/error/tpm_error.h"
#include "libhwsec/frontend/oobe_config/encrypted_data.pb.h"
#include "libhwsec/middleware/middleware.h"
#include "libhwsec/status.h"
#include "libhwsec/structures/permission.h"

using hwsec_foundation::Sha256;
using hwsec_foundation::status::MakeStatus;

namespace hwsec {

namespace {

constexpr uint32_t kRollbackSpaceSize = 32;
constexpr uint32_t kEncrypteDataVersion = 1;
constexpr char kDeriveContext[] = "OOBE Config derive";

OperationPolicySetting GetPolicy(const brillo::SecureBlob& secret) {
  return OperationPolicySetting{
      .device_config_settings =
          DeviceConfigSettings{
              .boot_mode =
                  DeviceConfigSettings::BootModeSetting{
                      // Use current boot mode setting.
                      .mode = std::nullopt,
                  },
          },
      .permission =
          Permission{
              .type = PermissionType::kPolicyOR,
              .auth_value = secret,
          },
  };
}

}  // namespace

Status OobeConfigFrontendImpl::IsRollbackSpaceReady() const {
  ASSIGN_OR_RETURN(
      Storage::ReadyState state,
      middleware_.CallSync<&Backend::Storage::IsReady>(
          Space::kEnterpriseRollback),
      _.WithStatus<TPMError>("Failed to get enterprise rollback space state"));

  if (!state.readable || !state.writable) {
    return MakeStatus<TPMError>("Not ready", TPMRetryAction::kNoRetry);
  }

  return OkStatus();
}

Status OobeConfigFrontendImpl::ResetRollbackSpace() const {
  brillo::Blob zero(kRollbackSpaceSize);
  return middleware_.CallSync<&Backend::Storage::Store>(
      Space::kEnterpriseRollback, zero);
}

StatusOr<brillo::Blob> OobeConfigFrontendImpl::Encrypt(
    const brillo::SecureBlob& plain_data) const {
  ASSIGN_OR_RETURN(const brillo::SecureBlob& secret,
                   middleware_.CallSync<&Backend::Random::RandomSecureBlob>(
                       kRollbackSpaceSize),
                   _.WithStatus<TPMError>("Failed to generate random"));

  ASSIGN_OR_RETURN(
      ScopedKey policy_ek,
      middleware_.CallSync<&Backend::KeyManagement::GetPolicyEndorsementKey>(
          GetPolicy(secret), KeyAlgoType::kEcc));

  ASSIGN_OR_RETURN(
      brillo::SecureBlob derived_key,
      middleware_.CallSync<&Backend::Deriving::SecureDerive>(
          policy_ek.GetKey(), Sha256(brillo::SecureBlob(kDeriveContext))));

  brillo::Blob secret_blob(secret.begin(), secret.end());
  RETURN_IF_ERROR(middleware_.CallSync<&Backend::Storage::Store>(
                      Space::kEnterpriseRollback, secret_blob))
      .WithStatus<TPMError>("Failed to store enterprise rollback space");

  brillo::SecureBlob iv;
  brillo::SecureBlob tag;
  brillo::SecureBlob ciphertext;
  if (!hwsec_foundation::AesGcmEncrypt(plain_data, std::nullopt, derived_key,
                                       &iv, &tag, &ciphertext)) {
    return MakeStatus<TPMError>("Failed to encrypt the data",
                                TPMRetryAction::kNoRetry);
  }

  OobeConfigEncryptedData encrypted;
  encrypted.set_version(kEncrypteDataVersion);
  encrypted.set_iv(iv.to_string());
  encrypted.set_tag(tag.to_string());
  encrypted.set_ciphertext(ciphertext.to_string());

  return brillo::BlobFromString(encrypted.SerializeAsString());
}

StatusOr<brillo::SecureBlob> OobeConfigFrontendImpl::Decrypt(
    const brillo::Blob& encrypted_data) const {
  OobeConfigEncryptedData encrypted;
  if (!encrypted.ParseFromString(brillo::BlobToString(encrypted_data))) {
    return MakeStatus<TPMError>("Failed to parse the encrypted data",
                                TPMRetryAction::kNoRetry);
  }

  if (encrypted.version() != kEncrypteDataVersion) {
    return MakeStatus<TPMError>("Unsupported encrypted data version",
                                TPMRetryAction::kNoRetry);
  }

  ASSIGN_OR_RETURN(
      const brillo::Blob& secret_blob,
      middleware_.CallSync<&Backend::Storage::Load>(Space::kEnterpriseRollback),
      _.WithStatus<TPMError>("Failed to load enterprise rollback space"));

  brillo::SecureBlob secret(secret_blob);

  ASSIGN_OR_RETURN(
      ScopedKey policy_ek,
      middleware_.CallSync<&Backend::KeyManagement::GetPolicyEndorsementKey>(
          GetPolicy(secret), KeyAlgoType::kEcc));

  ASSIGN_OR_RETURN(
      brillo::SecureBlob derived_key,
      middleware_.CallSync<&Backend::Deriving::SecureDerive>(
          policy_ek.GetKey(), Sha256(brillo::SecureBlob(kDeriveContext))));

  brillo::SecureBlob plain_data;
  if (!hwsec_foundation::AesGcmDecrypt(
          brillo::SecureBlob(encrypted.ciphertext()), std::nullopt,
          brillo::SecureBlob(encrypted.tag()), derived_key,
          brillo::SecureBlob(encrypted.iv()), &plain_data)) {
    return MakeStatus<TPMError>("Failed to decrypt the data",
                                TPMRetryAction::kNoRetry);
  }

  return plain_data;
}

}  // namespace hwsec
