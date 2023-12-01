// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_BACKEND_TPM2_KEY_MANAGEMENT_H_
#define LIBHWSEC_BACKEND_TPM2_KEY_MANAGEMENT_H_

#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <utility>

#include <absl/container/flat_hash_map.h>
#include <absl/container/flat_hash_set.h>
#include <base/timer/timer.h>
#include <brillo/secure_blob.h>
#include <trunks/tpm_generated.h>

#include "libhwsec/backend/key_management.h"
#include "libhwsec/backend/tpm2/config.h"
#include "libhwsec/backend/tpm2/trunks_context.h"
#include "libhwsec/proxy/proxy.h"
#include "libhwsec/status.h"
#include "libhwsec/structures/key.h"
#include "libhwsec/structures/no_default_init.h"
#include "libhwsec/structures/operation_policy.h"

namespace hwsec {

struct KeyReloadDataTpm2 {
  brillo::Blob key_blob;
  uint32_t client_count;
  base::TimeDelta lazy_expiration_time;
  std::unique_ptr<base::OneShotTimer> flush_timer;
};

struct KeyTpm2 {
  enum class Type {
    kPersistentKey,
    kTransientKey,
    kReloadableTransientKey,
  };

  struct Cache {
    OperationPolicy policy;
    NoDefault<trunks::TPMT_PUBLIC> public_area;
  };

  NoDefault<Type> type;
  NoDefault<trunks::TPM_HANDLE> key_handle;
  NoDefault<Cache> cache;
  std::optional<KeyReloadDataTpm2> reload_data;
};

class KeyManagementTpm2 : public KeyManagement {
 public:
  KeyManagementTpm2(TrunksContext& context,
                    ConfigTpm2& config,
                    org::chromium::TpmManagerProxyInterface& tpm_manager,
                    MiddlewareDerivative& middleware_derivative)
      : context_(context),
        config_(config),
        tpm_manager_(tpm_manager),
        middleware_derivative_(middleware_derivative) {}

  ~KeyManagementTpm2();

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

  // Below are TPM2.0 specific code.

  // Gets the reference of the internal key data.
  StatusOr<std::reference_wrapper<KeyTpm2>> GetKeyData(Key key);

  // Loads the key from its DER-encoded Subject Public Key Info. Algorithm
  // scheme and hashing algorithm are passed via |scheme| and |hash_alg|.
  // Currently, only the RSA signing keys are supported.
  StatusOr<ScopedKey> LoadPublicKeyFromSpki(
      const brillo::Blob& public_key_spki_der,
      trunks::TPM_ALG_ID scheme,
      trunks::TPM_ALG_ID hash_alg);

 private:
  StatusOr<CreateKeyResult> CreateRsaKey(
      const OperationPolicySetting& policy,
      const CreateKeyOptions& options,
      const LoadKeyOptions& load_key_options);
  StatusOr<CreateKeyResult> CreateSoftwareGenRsaKey(
      const OperationPolicySetting& policy,
      const CreateKeyOptions& options,
      const LoadKeyOptions& load_key_options);
  StatusOr<CreateKeyResult> CreateEccKey(
      const OperationPolicySetting& policy,
      const CreateKeyOptions& options,
      const LoadKeyOptions& load_key_options);
  StatusOr<ScopedKey> LoadKeyInternal(
      const OperationPolicy& policy,
      KeyTpm2::Type key_type,
      uint32_t key_handle,
      std::optional<KeyReloadDataTpm2> reload_data);
  Status FlushTransientKey(Key key, KeyTpm2& key_data);
  Status FlushKeyTokenAndHandle(KeyToken token, trunks::TPM_HANDLE handle);

  TrunksContext& context_;
  ConfigTpm2& config_;
  org::chromium::TpmManagerProxyInterface& tpm_manager_;
  MiddlewareDerivative& middleware_derivative_;

  KeyToken current_token_ = 0;
  absl::flat_hash_map<KeyToken, KeyTpm2> key_map_;
  absl::flat_hash_map<PersistentKeyType, KeyToken> persistent_key_map_;
  bool shall_flush_immediately_ = false;
};

}  // namespace hwsec

#endif  // LIBHWSEC_BACKEND_TPM2_KEY_MANAGEMENT_H_
