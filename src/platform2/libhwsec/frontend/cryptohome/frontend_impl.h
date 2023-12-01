// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_FRONTEND_CRYPTOHOME_FRONTEND_IMPL_H_
#define LIBHWSEC_FRONTEND_CRYPTOHOME_FRONTEND_IMPL_H_

#include <string>
#include <vector>

#include <brillo/secure_blob.h>

#include "libhwsec/frontend/cryptohome/frontend.h"
#include "libhwsec/frontend/frontend_impl.h"
#include "libhwsec/status.h"
#include "libhwsec/structures/key.h"

namespace hwsec {

class CryptohomeFrontendImpl : public CryptohomeFrontend, public FrontendImpl {
 public:
  using FrontendImpl::FrontendImpl;
  ~CryptohomeFrontendImpl() override = default;

  void RegisterOnReadyCallback(
      base::OnceCallback<void(Status)> callback) const override;
  StatusOr<bool> IsEnabled() const override;
  StatusOr<bool> IsReady() const override;
  StatusOr<bool> IsSrkRocaVulnerable() const override;
  StatusOr<brillo::Blob> GetRsuDeviceId() const override;
  StatusOr<absl::flat_hash_set<KeyAlgoType>> GetSupportedAlgo() const override;
  StatusOr<CreateKeyResult> CreateCryptohomeKey(
      KeyAlgoType key_algo) const override;
  StatusOr<ScopedKey> LoadKey(const brillo::Blob& key_blob) const override;
  StatusOr<brillo::Blob> GetPubkeyHash(Key key) const override;
  StatusOr<ScopedKey> SideLoadKey(uint32_t key_handle) const override;
  StatusOr<uint32_t> GetKeyHandle(Key key) const override;
  Status SetCurrentUser(const std::string& current_user) const override;
  StatusOr<bool> IsCurrentUserSet() const override;
  StatusOr<bool> IsSealingSupported() const override;
  StatusOr<brillo::Blob> SealWithCurrentUser(
      const std::optional<std::string>& current_user,
      const brillo::SecureBlob& auth_value,
      const brillo::SecureBlob& unsealed_data) const override;
  StatusOr<std::optional<ScopedKey>> PreloadSealedData(
      const brillo::Blob& sealed_data) const override;
  StatusOr<brillo::SecureBlob> UnsealWithCurrentUser(
      std::optional<Key> preload_data,
      const brillo::SecureBlob& auth_value,
      const brillo::Blob& sealed_data) const override;
  StatusOr<brillo::Blob> Encrypt(
      Key key, const brillo::SecureBlob& plaintext) const override;
  StatusOr<brillo::SecureBlob> Decrypt(
      Key key, const brillo::Blob& ciphertext) const override;
  StatusOr<brillo::SecureBlob> GetAuthValue(
      Key key, const brillo::SecureBlob& pass_blob) const override;
  StatusOr<brillo::Blob> GetRandomBlob(size_t size) const override;
  StatusOr<brillo::SecureBlob> GetRandomSecureBlob(size_t size) const override;
  StatusOr<uint32_t> GetManufacturer() const override;
  StatusOr<bool> IsPinWeaverEnabled() const override;
  StatusOr<bool> IsBiometricsPinWeaverEnabled() const override;
  StatusOr<StorageState> GetSpaceState(Space space) const override;
  Status PrepareSpace(Space space, uint32_t size) const override;
  StatusOr<brillo::Blob> LoadSpace(Space space) const override;
  Status StoreSpace(Space space, const brillo::Blob& blob) const override;
  Status DestroySpace(Space space) const override;
  Status DeclareTpmFirmwareStable() const override;
  StatusOr<SignatureSealedData> SealWithSignatureAndCurrentUser(
      const std::string& current_user,
      const brillo::SecureBlob& unsealed_data,
      const brillo::Blob& public_key_spki_der,
      const std::vector<SignatureSealingAlgorithm>& key_algorithms)
      const override;
  StatusOr<ChallengeResult> ChallengeWithSignatureAndCurrentUser(
      const SignatureSealedData& sealed_data,
      const brillo::Blob& public_key_spki_der,
      const std::vector<SignatureSealingAlgorithm>& key_algorithms)
      const override;
  StatusOr<brillo::SecureBlob> UnsealWithChallenge(
      ChallengeID challenge,
      const brillo::Blob& challenge_response) const override;
  StatusOr<uint32_t> GetFamily() const override;
};

}  // namespace hwsec

#endif  // LIBHWSEC_FRONTEND_CRYPTOHOME_FRONTEND_IMPL_H_
