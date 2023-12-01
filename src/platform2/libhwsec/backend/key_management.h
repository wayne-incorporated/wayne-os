// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_BACKEND_KEY_MANAGEMENT_H_
#define LIBHWSEC_BACKEND_KEY_MANAGEMENT_H_

#include <cstdint>

#include <absl/container/flat_hash_set.h>
#include <base/time/time.h>
#include <brillo/secure_blob.h>

#include "libhwsec/status.h"
#include "libhwsec/structures/key.h"
#include "libhwsec/structures/operation_policy.h"

namespace hwsec {

struct RSAPublicInfo {
  brillo::Blob exponent;
  brillo::Blob modulus;
};

struct ECCPublicInfo {
  int nid;
  brillo::Blob x_point;
  brillo::Blob y_point;
};

// KeyManagement provide the functions to manager key.
class KeyManagement {
 public:
  enum class PersistentKeyType {
    kStorageRootKey,
  };
  struct CreateKeyOptions {
    bool allow_software_gen = false;
    bool allow_decrypt = false;
    bool allow_sign = false;
    std::optional<uint32_t> rsa_modulus_bits;
    std::optional<brillo::Blob> rsa_exponent;
    std::optional<uint32_t> ecc_nid;
  };
  struct LoadKeyOptions {
    bool auto_reload = false;
    base::TimeDelta lazy_expiration_time = base::Seconds(0);
  };
  struct CreateKeyResult {
    ScopedKey key;
    brillo::Blob key_blob;
  };

  // Gets the supported algorithm.
  virtual StatusOr<absl::flat_hash_set<KeyAlgoType>> GetSupportedAlgo() = 0;

  // Checks a specific key creation combination is valid or not.
  virtual Status IsSupported(KeyAlgoType key_algo,
                             const CreateKeyOptions& options) = 0;

  // Creates a key with |key_algo| algorithm, |policy| and optional |options|.
  virtual StatusOr<CreateKeyResult> CreateKey(
      const OperationPolicySetting& policy,
      KeyAlgoType key_algo,
      const LoadKeyOptions& load_key_options,
      const CreateKeyOptions& options) = 0;

  // Loads a key from |key_blob| with |policy|.
  virtual StatusOr<ScopedKey> LoadKey(
      const OperationPolicy& policy,
      const brillo::Blob& key_blob,
      const LoadKeyOptions& load_key_options) = 0;

  // Gets the endorsement key that is protected by the policy.
  // Note: The resulting key is different to the EK that was created by the the
  // EK template.
  virtual StatusOr<ScopedKey> GetPolicyEndorsementKey(
      const OperationPolicySetting& policy, KeyAlgoType key_algo) = 0;

  // Loads the persistent key with specific |key_type|.
  virtual StatusOr<ScopedKey> GetPersistentKey(PersistentKeyType key_type) = 0;

  // Loads the hash of public part of the |key|.
  virtual StatusOr<brillo::Blob> GetPubkeyHash(Key key) = 0;

  // Flushes the |key| to reclaim the resource.
  virtual Status Flush(Key key) = 0;

  // Reloads the |key| if possible.
  virtual Status ReloadIfPossible(Key key) = 0;

  // Loads the key with raw |key_handle|.
  // TODO(174816474): deprecated legacy APIs.
  virtual StatusOr<ScopedKey> SideLoadKey(uint32_t key_handle) = 0;

  // Loads the raw |key_handle| from key.
  // TODO(174816474): deprecated legacy APIs.
  virtual StatusOr<uint32_t> GetKeyHandle(Key key) = 0;

  // Wraps a RSA key with the |policy| and the given parameters.
  virtual StatusOr<CreateKeyResult> WrapRSAKey(
      const OperationPolicySetting& policy,
      const brillo::Blob& public_modulus,
      const brillo::SecureBlob& private_prime_factor,
      const LoadKeyOptions& load_key_options,
      const CreateKeyOptions& options) = 0;

  // Wraps an ECC key with the |policy| and the given parameters.
  virtual StatusOr<CreateKeyResult> WrapECCKey(
      const OperationPolicySetting& policy,
      const brillo::Blob& public_point_x,
      const brillo::Blob& public_point_y,
      const brillo::SecureBlob& private_value,
      const LoadKeyOptions& load_key_options,
      const CreateKeyOptions& options) = 0;

  // Gets the public information of a RSA |key|.
  virtual StatusOr<RSAPublicInfo> GetRSAPublicInfo(Key key) = 0;

  // Gets the public information of a ECC |key|.
  virtual StatusOr<ECCPublicInfo> GetECCPublicInfo(Key key) = 0;

 protected:
  KeyManagement() = default;
  ~KeyManagement() = default;
};

}  // namespace hwsec

#endif  // LIBHWSEC_BACKEND_KEY_MANAGEMENT_H_
