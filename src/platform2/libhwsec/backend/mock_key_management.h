// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_BACKEND_MOCK_KEY_MANAGEMENT_H_
#define LIBHWSEC_BACKEND_MOCK_KEY_MANAGEMENT_H_

#include <cstdint>

#include <absl/container/flat_hash_set.h>
#include <brillo/secure_blob.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "libhwsec/backend/key_management.h"
#include "libhwsec/status.h"
#include "libhwsec/structures/key.h"
#include "libhwsec/structures/operation_policy.h"

namespace hwsec {

class BackendTpm2;

class MockKeyManagement : public KeyManagement {
 public:
  MockKeyManagement() = default;
  explicit MockKeyManagement(KeyManagement* on_call) : default_(on_call) {
    using testing::Invoke;
    if (!default_)
      return;
    ON_CALL(*this, GetSupportedAlgo)
        .WillByDefault(Invoke(default_, &KeyManagement::GetSupportedAlgo));
    ON_CALL(*this, IsSupported)
        .WillByDefault(Invoke(default_, &KeyManagement::IsSupported));
    ON_CALL(*this, CreateKey)
        .WillByDefault(Invoke(default_, &KeyManagement::CreateKey));
    ON_CALL(*this, LoadKey)
        .WillByDefault(Invoke(default_, &KeyManagement::LoadKey));
    ON_CALL(*this, GetPolicyEndorsementKey)
        .WillByDefault(
            Invoke(default_, &KeyManagement::GetPolicyEndorsementKey));
    ON_CALL(*this, GetPersistentKey)
        .WillByDefault(Invoke(default_, &KeyManagement::GetPersistentKey));
    ON_CALL(*this, GetPubkeyHash)
        .WillByDefault(Invoke(default_, &KeyManagement::GetPubkeyHash));
    ON_CALL(*this, Flush)
        .WillByDefault(Invoke(default_, &KeyManagement::Flush));
    ON_CALL(*this, ReloadIfPossible)
        .WillByDefault(Invoke(default_, &KeyManagement::ReloadIfPossible));
    ON_CALL(*this, SideLoadKey)
        .WillByDefault(Invoke(default_, &KeyManagement::SideLoadKey));
    ON_CALL(*this, GetKeyHandle)
        .WillByDefault(Invoke(default_, &KeyManagement::GetKeyHandle));
    ON_CALL(*this, WrapRSAKey)
        .WillByDefault(Invoke(default_, &KeyManagement::WrapRSAKey));
    ON_CALL(*this, WrapECCKey)
        .WillByDefault(Invoke(default_, &KeyManagement::WrapECCKey));
    ON_CALL(*this, GetRSAPublicInfo)
        .WillByDefault(Invoke(default_, &KeyManagement::GetRSAPublicInfo));
    ON_CALL(*this, GetECCPublicInfo)
        .WillByDefault(Invoke(default_, &KeyManagement::GetECCPublicInfo));
  }

  MOCK_METHOD(StatusOr<absl::flat_hash_set<KeyAlgoType>>,
              GetSupportedAlgo,
              (),
              (override));
  MOCK_METHOD(Status,
              IsSupported,
              (KeyAlgoType key_algo, const CreateKeyOptions& options),
              (override));
  MOCK_METHOD(StatusOr<CreateKeyResult>,
              CreateKey,
              (const OperationPolicySetting& policy,
               KeyAlgoType key_algo,
               const LoadKeyOptions& load_key_options,
               const CreateKeyOptions& options),
              (override));
  MOCK_METHOD(StatusOr<ScopedKey>,
              LoadKey,
              (const OperationPolicy& policy,
               const brillo::Blob& key_blob,
               const LoadKeyOptions& load_key_options),
              (override));
  MOCK_METHOD(StatusOr<ScopedKey>,
              GetPolicyEndorsementKey,
              (const OperationPolicySetting& policy, KeyAlgoType key_algo),
              (override));
  MOCK_METHOD(StatusOr<ScopedKey>,
              GetPersistentKey,
              (PersistentKeyType key_type),
              (override));
  MOCK_METHOD(StatusOr<brillo::Blob>, GetPubkeyHash, (Key key), (override));
  MOCK_METHOD(Status, Flush, (Key key), (override));
  MOCK_METHOD(Status, ReloadIfPossible, (Key key), (override));
  MOCK_METHOD(StatusOr<ScopedKey>,
              SideLoadKey,
              (uint32_t key_handle),
              (override));
  MOCK_METHOD(StatusOr<uint32_t>, GetKeyHandle, (Key key), (override));
  MOCK_METHOD(StatusOr<CreateKeyResult>,
              WrapRSAKey,
              (const OperationPolicySetting& policy,
               const brillo::Blob& public_modulus,
               const brillo::SecureBlob& private_prime_factor,
               const LoadKeyOptions& load_key_options,
               const CreateKeyOptions& options),
              (override));
  MOCK_METHOD(StatusOr<CreateKeyResult>,
              WrapECCKey,
              (const OperationPolicySetting& policy,
               const brillo::Blob& public_point_x,
               const brillo::Blob& public_point_y,
               const brillo::SecureBlob& private_value,
               const LoadKeyOptions& load_key_options,
               const CreateKeyOptions& options),
              (override));
  MOCK_METHOD(StatusOr<RSAPublicInfo>, GetRSAPublicInfo, (Key key), (override));
  MOCK_METHOD(StatusOr<ECCPublicInfo>, GetECCPublicInfo, (Key key), (override));

 private:
  KeyManagement* default_;
};

}  // namespace hwsec

#endif  // LIBHWSEC_BACKEND_MOCK_KEY_MANAGEMENT_H_
