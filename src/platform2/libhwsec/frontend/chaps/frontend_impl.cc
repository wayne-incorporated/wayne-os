// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "libhwsec/frontend/chaps/frontend_impl.h"

#include <string>
#include <utility>
#include <vector>

#include <base/functional/callback.h>
#include <base/time/time.h>
#include <brillo/secure_blob.h>
#include <libhwsec-foundation/status/status_chain_macros.h>

#include "libhwsec/backend/backend.h"
#include "libhwsec/middleware/middleware.h"
#include "libhwsec/status.h"

using hwsec_foundation::status::MakeStatus;

namespace {
constexpr base::TimeDelta kDefaultLazyExpirationTime = base::Seconds(10);
}  // namespace

namespace hwsec {

StatusOr<uint32_t> ChapsFrontendImpl::GetFamily() const {
  return middleware_.CallSync<&Backend::Vendor::GetFamily>();
}

StatusOr<bool> ChapsFrontendImpl::IsEnabled() const {
  return middleware_.CallSync<&Backend::State::IsEnabled>();
}

StatusOr<bool> ChapsFrontendImpl::IsReady() const {
  return middleware_.CallSync<&Backend::State::IsReady>();
}

StatusOr<brillo::Blob> ChapsFrontendImpl::GetRandomBlob(size_t size) const {
  return middleware_.CallSync<&Backend::Random::RandomBlob>(size);
}

StatusOr<brillo::SecureBlob> ChapsFrontendImpl::GetRandomSecureBlob(
    size_t size) const {
  return middleware_.CallSync<&Backend::Random::RandomSecureBlob>(size);
}

Status ChapsFrontendImpl::IsRSAModulusSupported(uint32_t modulus_bits) const {
  return middleware_.CallSync<&Backend::KeyManagement::IsSupported>(
      KeyAlgoType::kRsa, Backend::KeyManagement::CreateKeyOptions{
                             .allow_software_gen = false,
                             .allow_decrypt = true,
                             .allow_sign = true,
                             .rsa_modulus_bits = modulus_bits,
                         });
}

Status ChapsFrontendImpl::IsECCurveSupported(int nid) const {
  return middleware_.CallSync<&Backend::KeyManagement::IsSupported>(
      KeyAlgoType::kEcc, Backend::KeyManagement::CreateKeyOptions{
                             .allow_software_gen = false,
                             .allow_decrypt = true,
                             .allow_sign = true,
                             .ecc_nid = nid,
                         });
}

StatusOr<ChapsFrontend::CreateKeyResult> ChapsFrontendImpl::GenerateRSAKey(
    int modulus_bits,
    const brillo::Blob& public_exponent,
    const brillo::SecureBlob& auth_value,
    AllowSoftwareGen allow_soft_gen,
    AllowDecrypt allow_decrypt,
    AllowSign allow_sign) const {
  return middleware_.CallSync<&Backend::KeyManagement::CreateKey>(
      OperationPolicySetting{
          .permission =
              Permission{
                  .auth_value = auth_value,
              },
      },
      KeyAlgoType::kRsa,
      KeyManagement::LoadKeyOptions{
          .auto_reload = true,
          .lazy_expiration_time = kDefaultLazyExpirationTime,
      },
      Backend::KeyManagement::CreateKeyOptions{
          .allow_software_gen = (allow_soft_gen == AllowSoftwareGen::kAllow),
          .allow_decrypt = (allow_decrypt == AllowDecrypt::kAllow),
          .allow_sign = (allow_sign == AllowSign::kAllow),
          .rsa_modulus_bits = modulus_bits,
          .rsa_exponent = public_exponent,
      });
}

StatusOr<RSAPublicInfo> ChapsFrontendImpl::GetRSAPublicKey(Key key) const {
  return middleware_.CallSync<&Backend::KeyManagement::GetRSAPublicInfo>(key);
}

StatusOr<ChapsFrontend::CreateKeyResult> ChapsFrontendImpl::GenerateECCKey(
    int nid,
    const brillo::SecureBlob& auth_value,
    AllowDecrypt allow_decrypt,
    AllowSign allow_sign) const {
  return middleware_.CallSync<&Backend::KeyManagement::CreateKey>(
      OperationPolicySetting{
          .permission =
              Permission{
                  .auth_value = auth_value,
              },
      },
      KeyAlgoType::kEcc,
      KeyManagement::LoadKeyOptions{
          .auto_reload = true,
          .lazy_expiration_time = kDefaultLazyExpirationTime,
      },
      KeyManagement::CreateKeyOptions{
          .allow_software_gen = false,
          .allow_decrypt = (allow_decrypt == AllowDecrypt::kAllow),
          .allow_sign = (allow_sign == AllowSign::kAllow),
          .ecc_nid = nid,
      });
}

StatusOr<ECCPublicInfo> ChapsFrontendImpl::GetECCPublicKey(Key key) const {
  return middleware_.CallSync<&Backend::KeyManagement::GetECCPublicInfo>(key);
}

StatusOr<ChapsFrontend::CreateKeyResult> ChapsFrontendImpl::WrapRSAKey(
    const brillo::Blob& exponent,
    const brillo::Blob& modulus,
    const brillo::SecureBlob& prime_factor,
    const brillo::SecureBlob& auth_value,
    AllowDecrypt allow_decrypt,
    AllowSign allow_sign) const {
  return middleware_.CallSync<&Backend::KeyManagement::WrapRSAKey>(
      OperationPolicySetting{
          .permission =
              Permission{
                  .auth_value = auth_value,
              },
      },
      modulus, prime_factor,
      KeyManagement::LoadKeyOptions{
          .auto_reload = true,
          .lazy_expiration_time = kDefaultLazyExpirationTime,
      },
      KeyManagement::CreateKeyOptions{
          .allow_software_gen = false,
          .allow_decrypt = (allow_decrypt == AllowDecrypt::kAllow),
          .allow_sign = (allow_sign == AllowSign::kAllow),
          .rsa_modulus_bits = modulus.size() * 8,
          .rsa_exponent = exponent,
      });
}

StatusOr<ChapsFrontend::CreateKeyResult> ChapsFrontendImpl::WrapECCKey(
    int curve_nid,
    const brillo::Blob& public_point_x,
    const brillo::Blob& public_point_y,
    const brillo::SecureBlob& private_value,
    const brillo::SecureBlob& auth_value,
    AllowDecrypt allow_decrypt,
    AllowSign allow_sign) const {
  return middleware_.CallSync<&Backend::KeyManagement::WrapECCKey>(
      OperationPolicySetting{
          .permission =
              Permission{
                  .auth_value = auth_value,
              },
      },
      public_point_x, public_point_y, private_value,
      KeyManagement::LoadKeyOptions{
          .auto_reload = true,
          .lazy_expiration_time = kDefaultLazyExpirationTime,
      },
      KeyManagement::CreateKeyOptions{
          .allow_software_gen = false,
          .allow_decrypt = (allow_decrypt == AllowDecrypt::kAllow),
          .allow_sign = (allow_sign == AllowSign::kAllow),
          .ecc_nid = curve_nid,
      });
}

StatusOr<ScopedKey> ChapsFrontendImpl::LoadKey(
    const brillo::Blob& key_blob, const brillo::SecureBlob& auth_value) const {
  return middleware_.CallSync<&Backend::KeyManagement::LoadKey>(
      OperationPolicy{
          .permission =
              Permission{
                  .auth_value = auth_value,
              },
      },
      key_blob,
      KeyManagement::LoadKeyOptions{
          .auto_reload = true,
          .lazy_expiration_time = kDefaultLazyExpirationTime,
      });
}

StatusOr<brillo::SecureBlob> ChapsFrontendImpl::Unbind(
    Key key, const brillo::Blob& ciphertext) const {
  return middleware_.CallSync<&Backend::Encryption::Decrypt>(
      key, ciphertext,
      Encryption::EncryptionOptions{
          .schema = Encryption::EncryptionOptions::Schema::kRsaesSha1,
      });
}

StatusOr<brillo::Blob> ChapsFrontendImpl::Sign(
    Key key, const brillo::Blob& data, const SigningOptions& options) const {
  return middleware_.CallSync<&Backend::Signing::RawSign>(key, data, options);
}

StatusOr<ChapsSealedData> ChapsFrontendImpl::SealData(
    const brillo::SecureBlob& unsealed_data,
    const brillo::SecureBlob& auth_value) const {
  ASSIGN_OR_RETURN(brillo::Blob sealed_data,
                   middleware_.CallSync<&Backend::Sealing::Seal>(
                       OperationPolicySetting{
                           .permission =
                               Permission{
                                   .auth_value = auth_value,
                               },
                       },
                       unsealed_data));

  return ChapsSealedData{
      .key_blob = std::move(sealed_data),
  };
}

StatusOr<brillo::SecureBlob> ChapsFrontendImpl::UnsealData(
    const ChapsSealedData& sealed_data,
    const brillo::SecureBlob& auth_value) const {
  // Backward compatible check.
  if (!sealed_data.encrypted_data.empty()) {
    ASSIGN_OR_RETURN(ScopedKey key,
                     middleware_.CallSync<&Backend::KeyManagement::LoadKey>(
                         OperationPolicy{
                             .permission =
                                 Permission{
                                     .auth_value = auth_value,
                                 },
                         },
                         sealed_data.key_blob,
                         KeyManagement::LoadKeyOptions{
                             .auto_reload = true,
                             .lazy_expiration_time = kDefaultLazyExpirationTime,
                         }));

    return middleware_.CallSync<&Backend::Encryption::Decrypt>(
        key.GetKey(), sealed_data.encrypted_data,
        Encryption::EncryptionOptions{
            .schema = Encryption::EncryptionOptions::Schema::kRsaesSha1,
        });
  }

  return middleware_.CallSync<&Backend::Sealing::Unseal>(
      OperationPolicy{
          .permission =
              Permission{
                  .auth_value = auth_value,
              },
      },
      sealed_data.key_blob, Sealing::UnsealOptions{});
}

void ChapsFrontendImpl::GetRandomSecureBlobAsync(
    size_t size, GetRandomSecureBlobCallback callback) const {
  middleware_.CallAsync<&Backend::Random::RandomSecureBlob>(std::move(callback),
                                                            size);
}

void ChapsFrontendImpl::SealDataAsync(const brillo::SecureBlob& unsealed_data,
                                      const brillo::SecureBlob& auth_value,
                                      SealDataCallback callback) const {
  base::OnceCallback<void(StatusOr<brillo::Blob>)> on_seal_done =
      base::BindOnce(
          [](SealDataCallback callback, StatusOr<brillo::Blob> sealed_data) {
            if (!sealed_data.ok()) {
              std::move(callback).Run(std::move(sealed_data).err_status());
              return;
            }
            std::move(callback).Run(ChapsSealedData{
                .key_blob = std::move(sealed_data).value(),
            });
          },
          std::move(callback));

  middleware_.CallAsync<&Backend::Sealing::Seal>(
      std::move(on_seal_done),
      OperationPolicySetting{
          .permission =
              Permission{
                  .auth_value = auth_value,
              },
      },
      unsealed_data);
}

void ChapsFrontendImpl::UnsealDataAsync(const ChapsSealedData& sealed_data,
                                        const brillo::SecureBlob& auth_value,
                                        UnsealDataCallback callback) const {
  // Backward compatible check.
  if (!sealed_data.encrypted_data.empty()) {
    base::OnceCallback<void(StatusOr<ScopedKey>)> on_load_done = base::BindOnce(
        [](UnsealDataCallback callback, MiddlewareDerivative derivative,
           brillo::Blob encrypted_data, StatusOr<ScopedKey> key) {
          if (!key.ok()) {
            std::move(callback).Run(std::move(key).err_status());
            return;
          }
          Middleware(derivative)
              .CallAsync<&Backend::Encryption::Decrypt>(
                  std::move(callback), key->GetKey(), encrypted_data,
                  Encryption::EncryptionOptions{
                      .schema =
                          Encryption::EncryptionOptions::Schema::kRsaesSha1,
                  });
        },
        std::move(callback), middleware_.Derive(), sealed_data.encrypted_data);

    middleware_.CallAsync<&Backend::KeyManagement::LoadKey>(
        std::move(on_load_done),
        OperationPolicy{
            .permission =
                Permission{
                    .auth_value = auth_value,
                },
        },
        sealed_data.key_blob,
        KeyManagement::LoadKeyOptions{
            .auto_reload = true,
            .lazy_expiration_time = kDefaultLazyExpirationTime,
        });
    return;
  }

  return middleware_.CallAsync<&Backend::Sealing::Unseal>(
      std::move(callback),
      OperationPolicy{
          .permission =
              Permission{
                  .auth_value = auth_value,
              },
      },
      sealed_data.key_blob, Sealing::UnsealOptions{});
}

}  // namespace hwsec
