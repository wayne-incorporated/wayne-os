// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_FRONTEND_CRYPTOHOME_MOCK_FRONTEND_H_
#define LIBHWSEC_FRONTEND_CRYPTOHOME_MOCK_FRONTEND_H_

#include <string>
#include <vector>

#include <absl/container/flat_hash_set.h>
#include <brillo/secure_blob.h>
#include <gmock/gmock.h>

#include "libhwsec/frontend/cryptohome/frontend.h"
#include "libhwsec/frontend/mock_frontend.h"

namespace hwsec {

class MockCryptohomeFrontend : public MockFrontend, public CryptohomeFrontend {
 public:
  MockCryptohomeFrontend() = default;
  ~MockCryptohomeFrontend() override = default;

  MOCK_METHOD(StatusOr<bool>, IsEnabled, (), (const override));
  MOCK_METHOD(StatusOr<bool>, IsReady, (), (const override));
  MOCK_METHOD(StatusOr<bool>, IsSrkRocaVulnerable, (), (const override));
  MOCK_METHOD(StatusOr<brillo::Blob>, GetRsuDeviceId, (), (const override));
  MOCK_METHOD(StatusOr<absl::flat_hash_set<KeyAlgoType>>,
              GetSupportedAlgo,
              (),
              (const override));
  MOCK_METHOD(StatusOr<CreateKeyResult>,
              CreateCryptohomeKey,
              (KeyAlgoType),
              (const override));
  MOCK_METHOD(StatusOr<ScopedKey>,
              LoadKey,
              (const brillo::Blob&),
              (const override));
  MOCK_METHOD(StatusOr<brillo::Blob>, GetPubkeyHash, (Key), (const override));
  MOCK_METHOD(StatusOr<ScopedKey>, SideLoadKey, (uint32_t), (const override));
  MOCK_METHOD(StatusOr<uint32_t>, GetKeyHandle, (Key), (const override));
  MOCK_METHOD(Status, SetCurrentUser, (const std::string&), (const override));
  MOCK_METHOD(StatusOr<bool>, IsCurrentUserSet, (), (const override));
  MOCK_METHOD(StatusOr<bool>, IsSealingSupported, (), (const override));
  MOCK_METHOD(StatusOr<brillo::Blob>,
              SealWithCurrentUser,
              (const std::optional<std::string>&,
               const brillo::SecureBlob&,
               const brillo::SecureBlob&),
              (const override));
  MOCK_METHOD(StatusOr<std::optional<ScopedKey>>,
              PreloadSealedData,
              (const brillo::Blob&),
              (const override));
  MOCK_METHOD(StatusOr<brillo::SecureBlob>,
              UnsealWithCurrentUser,
              (std::optional<Key>,
               const brillo::SecureBlob&,
               const brillo::Blob&),
              (const override));
  MOCK_METHOD(StatusOr<brillo::Blob>,
              Encrypt,
              (Key, const brillo::SecureBlob&),
              (const override));
  MOCK_METHOD(StatusOr<brillo::SecureBlob>,
              Decrypt,
              (Key, const brillo::Blob&),
              (const override));
  MOCK_METHOD(StatusOr<brillo::SecureBlob>,
              GetAuthValue,
              (Key, const brillo::SecureBlob&),
              (const override));
  MOCK_METHOD(StatusOr<brillo::Blob>,
              GetRandomBlob,
              (size_t),
              (const override));
  MOCK_METHOD(StatusOr<brillo::SecureBlob>,
              GetRandomSecureBlob,
              (size_t),
              (const override));
  MOCK_METHOD(StatusOr<uint32_t>, GetManufacturer, (), (const override));
  MOCK_METHOD(StatusOr<bool>, IsPinWeaverEnabled, (), (const override));
  MOCK_METHOD(StatusOr<bool>,
              IsBiometricsPinWeaverEnabled,
              (),
              (const override));
  MOCK_METHOD(StatusOr<StorageState>, GetSpaceState, (Space), (const override));
  MOCK_METHOD(Status, PrepareSpace, (Space, uint32_t), (const override));
  MOCK_METHOD(StatusOr<brillo::Blob>, LoadSpace, (Space), (const override));
  MOCK_METHOD(Status,
              StoreSpace,
              (Space, const brillo::Blob&),
              (const override));
  MOCK_METHOD(Status, DestroySpace, (Space), (const override));
  MOCK_METHOD(Status, DeclareTpmFirmwareStable, (), (const override));
  MOCK_METHOD(StatusOr<SignatureSealedData>,
              SealWithSignatureAndCurrentUser,
              (const std::string& current_user,
               const brillo::SecureBlob&,
               const brillo::Blob&,
               const std::vector<SignatureSealingAlgorithm>&),
              (const override));
  MOCK_METHOD(StatusOr<ChallengeResult>,
              ChallengeWithSignatureAndCurrentUser,
              (const SignatureSealedData& sealed_data,
               const brillo::Blob& public_key_spki_der,
               const std::vector<SignatureSealingAlgorithm>& key_algorithms),
              (const override));
  MOCK_METHOD(StatusOr<brillo::SecureBlob>,
              UnsealWithChallenge,
              (ChallengeID challenge, const brillo::Blob& challenge_response),
              (const override));
  MOCK_METHOD(StatusOr<uint32_t>, GetFamily, (), (const override));
  MOCK_METHOD(void,
              RegisterOnReadyCallback,
              (base::OnceCallback<void(Status)> callback),
              (const override));
};

}  // namespace hwsec

#endif  // LIBHWSEC_FRONTEND_CRYPTOHOME_MOCK_FRONTEND_H_
