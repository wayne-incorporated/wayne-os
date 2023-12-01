// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_BACKEND_TPM1_KEY_MANAGEMENT_H_
#define LIBHWSEC_BACKEND_TPM1_KEY_MANAGEMENT_H_

#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <utility>

#include <absl/container/flat_hash_map.h>
#include <absl/container/flat_hash_set.h>
#include <brillo/secure_blob.h>

#include "libhwsec/backend/key_management.h"
#include "libhwsec/backend/tpm1/config.h"
#include "libhwsec/backend/tpm1/tss_helper.h"
#include "libhwsec/middleware/middleware_derivative.h"
#include "libhwsec/proxy/proxy.h"
#include "libhwsec/status.h"
#include "libhwsec/structures/key.h"
#include "libhwsec/structures/no_default_init.h"
#include "libhwsec/structures/operation_policy.h"
#include "libhwsec/tss_utils/scoped_tss_type.h"

namespace hwsec {

struct KeyReloadDataTpm1 {
  OperationPolicy policy;
  brillo::Blob key_blob;
};

struct KeyTpm1 {
  enum class Type {
    kPersistentKey,
    kTransientKey,
    kReloadableTransientKey,
  };

  struct Cache {
    brillo::Blob pubkey_blob;
  };

  NoDefault<Type> type;
  NoDefault<TSS_HKEY> key_handle;
  NoDefault<Cache> cache;
  std::optional<ScopedTssKey> scoped_key;
  std::optional<ScopedTssPolicy> scoped_policy;
  std::optional<KeyReloadDataTpm1> reload_data;
};

class KeyManagementTpm1 : public KeyManagement {
 public:
  KeyManagementTpm1(overalls::Overalls& overalls,
                    TssHelper& tss_helper,
                    ConfigTpm1& config,
                    MiddlewareDerivative& middleware_derivative)
      : overalls_(overalls),
        tss_helper_(tss_helper),
        config_(config),
        middleware_derivative_(middleware_derivative) {}

  ~KeyManagementTpm1();
  StatusOr<absl::flat_hash_set<KeyAlgoType>> GetSupportedAlgo() override;
  Status IsSupported(KeyAlgoType key_algo,
                     const CreateKeyOptions& options) override;
  StatusOr<CreateKeyResult> CreateKey(const OperationPolicySetting& policy,
                                      KeyAlgoType key_algo,
                                      const LoadKeyOptions& load_key_options,
                                      const CreateKeyOptions& options) override;
  StatusOr<ScopedKey> LoadKey(const OperationPolicy& policy,
                              const brillo::Blob& key_blob,
                              const LoadKeyOptions& load_key_options) override;
  StatusOr<ScopedKey> GetPolicyEndorsementKey(
      const OperationPolicySetting& policy, KeyAlgoType key_algo) override;
  StatusOr<ScopedKey> GetPersistentKey(PersistentKeyType key_type) override;
  StatusOr<brillo::Blob> GetPubkeyHash(Key key) override;
  Status Flush(Key key) override;
  Status ReloadIfPossible(Key key) override;

  StatusOr<ScopedKey> SideLoadKey(uint32_t key_handle) override;
  StatusOr<uint32_t> GetKeyHandle(Key key) override;

  StatusOr<CreateKeyResult> WrapRSAKey(
      const OperationPolicySetting& policy,
      const brillo::Blob& public_modulus,
      const brillo::SecureBlob& private_prime_factor,
      const LoadKeyOptions& load_key_options,
      const CreateKeyOptions& options) override;
  StatusOr<CreateKeyResult> WrapECCKey(
      const OperationPolicySetting& policy,
      const brillo::Blob& public_point_x,
      const brillo::Blob& public_point_y,
      const brillo::SecureBlob& private_value,
      const LoadKeyOptions& load_key_options,
      const CreateKeyOptions& options) override;
  StatusOr<RSAPublicInfo> GetRSAPublicInfo(Key key) override;
  StatusOr<ECCPublicInfo> GetECCPublicInfo(Key key) override;

  // Below are TPM1.2 specific code.

  // Gets the reference of the internal key data.
  StatusOr<std::reference_wrapper<KeyTpm1>> GetKeyData(Key key);

  // Creates a key object for the RSA public key, given its public modulus in
  // |key_modulus|, creation flags in |key_flags|, signature scheme or
  // |TSS_SS_NONE| in |signature_scheme|, encryption scheme or |TSS_ES_NONE|
  // in |encryption_scheme|. The key's public exponent is assumed to be 65537.
  StatusOr<ScopedKey> CreateRsaPublicKeyObject(brillo::Blob key_modulus,
                                               uint32_t key_flags,
                                               uint32_t signature_scheme,
                                               uint32_t encryption_scheme);

  // Loads the key from its DER-encoded Subject Public Key Info.
  // Currently, only the RSA signing keys are supported.
  StatusOr<ScopedKey> LoadPublicKeyFromSpki(
      const brillo::Blob& public_key_spki_der,
      uint32_t signature_scheme,
      uint32_t encryption_scheme);

 private:
  struct KeyPolicyPair {
    ScopedTssKey tss_key;
    ScopedTssPolicy tss_policy;
  };

  StatusOr<CreateKeyResult> CreateRsaKey(
      const OperationPolicySetting& policy,
      const CreateKeyOptions& options,
      const LoadKeyOptions& load_key_options);
  StatusOr<CreateKeyResult> CreateSoftwareGenRsaKey(
      const OperationPolicySetting& policy,
      const CreateKeyOptions& options,
      const LoadKeyOptions& load_key_options);
  StatusOr<KeyPolicyPair> LoadKeyBlob(const OperationPolicy& policy,
                                      const brillo::Blob& key_blob);
  StatusOr<ScopedKey> LoadKeyInternal(
      KeyTpm1::Type key_type,
      uint32_t key_handle,
      std::optional<KeyPolicyPair> key_policy_pair,
      std::optional<KeyReloadDataTpm1> reload_data);
  StatusOr<brillo::Blob> GetPubkeyBlob(uint32_t key_handle);
  StatusOr<uint32_t> GetSrk();

  overalls::Overalls& overalls_;
  TssHelper& tss_helper_;
  ConfigTpm1& config_;
  MiddlewareDerivative& middleware_derivative_;

  KeyToken current_token_ = 0;
  absl::flat_hash_map<KeyToken, KeyTpm1> key_map_;
  absl::flat_hash_map<PersistentKeyType, KeyToken> persistent_key_map_;
  std::optional<ScopedTssKey> srk_cache_;
};

}  // namespace hwsec

#endif  // LIBHWSEC_BACKEND_TPM1_KEY_MANAGEMENT_H_
