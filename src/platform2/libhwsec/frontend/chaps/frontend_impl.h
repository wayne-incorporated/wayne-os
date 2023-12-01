// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_FRONTEND_CHAPS_FRONTEND_IMPL_H_
#define LIBHWSEC_FRONTEND_CHAPS_FRONTEND_IMPL_H_

#include <string>
#include <vector>

#include <brillo/secure_blob.h>

#include "libhwsec/frontend/chaps/frontend.h"
#include "libhwsec/frontend/frontend_impl.h"
#include "libhwsec/status.h"
#include "libhwsec/structures/key.h"

namespace hwsec {

class ChapsFrontendImpl : public ChapsFrontend, public FrontendImpl {
 public:
  using FrontendImpl::FrontendImpl;
  ~ChapsFrontendImpl() override = default;

  StatusOr<uint32_t> GetFamily() const override;
  StatusOr<bool> IsEnabled() const override;
  StatusOr<bool> IsReady() const override;
  StatusOr<brillo::Blob> GetRandomBlob(size_t size) const override;
  StatusOr<brillo::SecureBlob> GetRandomSecureBlob(size_t size) const override;
  Status IsRSAModulusSupported(uint32_t modulus_bits) const override;
  Status IsECCurveSupported(int nid) const override;
  StatusOr<CreateKeyResult> GenerateRSAKey(int modulus_bits,
                                           const brillo::Blob& public_exponent,
                                           const brillo::SecureBlob& auth_value,
                                           AllowSoftwareGen allow_soft_gen,
                                           AllowDecrypt allow_decrypt,
                                           AllowSign allow_sign) const override;
  StatusOr<RSAPublicInfo> GetRSAPublicKey(Key key) const override;
  StatusOr<CreateKeyResult> GenerateECCKey(int nid,
                                           const brillo::SecureBlob& auth_value,
                                           AllowDecrypt allow_decrypt,
                                           AllowSign allow_sign) const override;
  StatusOr<ECCPublicInfo> GetECCPublicKey(Key key) const override;
  StatusOr<CreateKeyResult> WrapRSAKey(const brillo::Blob& exponent,
                                       const brillo::Blob& modulus,
                                       const brillo::SecureBlob& prime_factor,
                                       const brillo::SecureBlob& auth_value,
                                       AllowDecrypt allow_decrypt,
                                       AllowSign allow_sign) const override;
  StatusOr<CreateKeyResult> WrapECCKey(int curve_nid,
                                       const brillo::Blob& public_point_x,
                                       const brillo::Blob& public_point_y,
                                       const brillo::SecureBlob& private_value,
                                       const brillo::SecureBlob& auth_value,
                                       AllowDecrypt allow_decrypt,
                                       AllowSign allow_sign) const override;
  StatusOr<ScopedKey> LoadKey(
      const brillo::Blob& key_blob,
      const brillo::SecureBlob& auth_value) const override;
  StatusOr<brillo::SecureBlob> Unbind(
      Key key, const brillo::Blob& ciphertext) const override;
  StatusOr<brillo::Blob> Sign(Key key,
                              const brillo::Blob& data,
                              const SigningOptions& options) const override;
  StatusOr<ChapsSealedData> SealData(
      const brillo::SecureBlob& unsealed_data,
      const brillo::SecureBlob& auth_value) const override;
  StatusOr<brillo::SecureBlob> UnsealData(
      const ChapsSealedData& sealed_data,
      const brillo::SecureBlob& auth_value) const override;
  void GetRandomSecureBlobAsync(
      size_t size, GetRandomSecureBlobCallback callback) const override;
  void SealDataAsync(const brillo::SecureBlob& unsealed_data,
                     const brillo::SecureBlob& auth_value,
                     SealDataCallback callback) const override;
  void UnsealDataAsync(const ChapsSealedData& sealed_data,
                       const brillo::SecureBlob& auth_value,
                       UnsealDataCallback callback) const override;
};

}  // namespace hwsec

#endif  // LIBHWSEC_FRONTEND_CHAPS_FRONTEND_IMPL_H_
