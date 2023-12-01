// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "libhwsec/backend/tpm2/key_management.h"

#include <algorithm>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include <absl/container/flat_hash_set.h>
#include <base/functional/callback_helpers.h>
#include <base/numerics/safe_conversions.h>
#include <base/task/sequenced_task_runner.h>
#include <base/timer/timer.h>
#include <brillo/secure_blob.h>
#include <crypto/scoped_openssl_types.h>
#include <libhwsec-foundation/crypto/rsa.h>
#include <libhwsec-foundation/crypto/sha.h>
#include <libhwsec-foundation/status/status_chain_macros.h>
#include <tpm_manager/proto_bindings/tpm_manager.pb.h>
#include <tpm_manager-client/tpm_manager/dbus-constants.h>
#include <tpm_manager-client/tpm_manager/dbus-proxies.h>
#include <trunks/tpm_utility.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

#include "libhwsec/error/tpm2_error.h"
#include "libhwsec/error/tpm_manager_error.h"
#include "libhwsec/status.h"
#include "trunks/tpm_generated.h"

using brillo::BlobFromString;
using brillo::BlobToString;
using hwsec_foundation::Sha256;
using hwsec_foundation::status::MakeStatus;

namespace hwsec {

namespace {

constexpr uint32_t kDefaultTpmRsaKeyBits = 2048;
constexpr uint32_t kDefaultTpmPublicExponent = 0x10001;
constexpr trunks::TPMI_ECC_CURVE kDefaultTpmCurveId = trunks::TPM_ECC_NIST_P256;
constexpr uint32_t kMaxPasswordLength = sizeof(trunks::TPMU_HA);
constexpr uint32_t kMaxRsaPublicKeySize = 256;
constexpr uint32_t kMaxRsaPrivateKeySize = 128;

// Min and max supported RSA modulus sizes (in bytes).
constexpr uint32_t kMinModulusSize = 128;
constexpr uint32_t kMaxModulusSize = 256;

constexpr struct {
  trunks::TPM_ALG_ID trunks_id;
  int openssl_nid;
} kSupportedECCurveAlgorithms[] = {
    {trunks::TPM_ECC_NIST_P256, NID_X9_62_prime256v1},
};

StatusOr<trunks::TpmUtility::AsymmetricKeyUsage> GetKeyUsage(
    const KeyManagementTpm2::CreateKeyOptions& options) {
  if (options.allow_decrypt == true && options.allow_sign == true) {
    return trunks::TpmUtility::AsymmetricKeyUsage::kDecryptAndSignKey;
  } else if (options.allow_decrypt == true && options.allow_sign == false) {
    return trunks::TpmUtility::AsymmetricKeyUsage::kDecryptKey;
  } else if (options.allow_decrypt == false && options.allow_sign == true) {
    return trunks::TpmUtility::AsymmetricKeyUsage::kSignKey;
  } else {
    return MakeStatus<TPMError>("Useless key", TPMRetryAction::kNoRetry);
  }
}

struct RsaParameters {
  uint32_t key_exponent;
  brillo::Blob key_modulus;
};

StatusOr<RsaParameters> ParseSpkiDer(const brillo::Blob& public_key_spki_der) {
  // Parse the SPKI.
  const unsigned char* asn1_ptr = public_key_spki_der.data();
  const crypto::ScopedEVP_PKEY pkey(
      d2i_PUBKEY(nullptr, &asn1_ptr, public_key_spki_der.size()));
  if (!pkey) {
    return MakeStatus<TPMError>("Failed to parse Subject Public Key Info DER",
                                TPMRetryAction::kNoRetry);
  }

  const crypto::ScopedRSA rsa(EVP_PKEY_get1_RSA(pkey.get()));
  if (!rsa) {
    return MakeStatus<TPMError>("non-RSA key was supplied",
                                TPMRetryAction::kNoRetry);
  }

  brillo::Blob key_modulus(RSA_size(rsa.get()));
  const BIGNUM* n;
  const BIGNUM* e;
  RSA_get0_key(rsa.get(), &n, &e, nullptr);
  if (BN_bn2bin(n, key_modulus.data()) != key_modulus.size()) {
    return MakeStatus<TPMError>("Failed to extract public key modulus",
                                TPMRetryAction::kNoRetry);
  }

  constexpr BN_ULONG kInvalidBnWord = ~static_cast<BN_ULONG>(0);
  const BN_ULONG exponent_word = BN_get_word(e);
  if (exponent_word == kInvalidBnWord ||
      !base::IsValueInRangeForNumericType<uint32_t>(exponent_word)) {
    return MakeStatus<TPMError>("Failed to extract public key exponent",
                                TPMRetryAction::kNoRetry);
  }

  const uint32_t key_exponent = static_cast<uint32_t>(exponent_word);

  return RsaParameters{
      .key_exponent = key_exponent,
      .key_modulus = std::move(key_modulus),
  };
}

StatusOr<uint32_t> GetIntegerExponent(const brillo::Blob& public_exponent) {
  if (public_exponent.size() > 4) {
    return MakeStatus<TPMError>("Exponent too large", TPMRetryAction::kNoRetry);
  }

  uint32_t exponent = 0;
  for (uint8_t byte : public_exponent) {
    exponent = exponent << 8;
    exponent += byte;
  }

  return exponent;
}

StatusOr<trunks::TPMI_ECC_CURVE> ConvertNIDToTrunksCurveID(int curve_nid) {
  for (const auto& curve_info : kSupportedECCurveAlgorithms) {
    if (curve_info.openssl_nid == curve_nid) {
      return curve_info.trunks_id;
    }
  }
  return MakeStatus<TPMError>("Unsupported curve", TPMRetryAction::kNoRetry);
}

StatusOr<int> ConvertTrunksCurveIDToNID(trunks::TPMI_ECC_CURVE trunks_id) {
  for (auto curve_info : kSupportedECCurveAlgorithms) {
    if (curve_info.trunks_id == trunks_id) {
      return curve_info.openssl_nid;
    }
  }
  return MakeStatus<TPMError>("Unsupported curve", TPMRetryAction::kNoRetry);
}

// Padding '\0' at the beginning of the string until it matches the length.
// This is for padding elliptic curve points and keys, and not for ordinary
// string. It's needed to normalize the format of the curve point.
std::string PaddingStringToLength(const std::string& in, size_t length) {
  if (in.length() < length) {
    return std::string(length - in.length(), '\0') + in;
  }
  return in;
}

bool IsKeyDataMatch(const KeyTpm2& key_data,
                    const brillo::Blob& key_blob,
                    const OperationPolicy& policy) {
  if (!key_data.reload_data.has_value()) {
    return false;
  }

  if (key_data.reload_data->key_blob != key_blob) {
    return false;
  }

  if (key_data.cache.policy.permission.auth_value !=
      policy.permission.auth_value) {
    return false;
  }

  if (key_data.cache.policy.device_configs != policy.device_configs) {
    return false;
  }

  return true;
}

StatusOr<brillo::SecureBlob> GetEndorsementPassword(
    org::chromium::TpmManagerProxyInterface& tpm_manager) {
  tpm_manager::GetTpmStatusRequest status_request;
  tpm_manager::GetTpmStatusReply status_reply;

  if (brillo::ErrorPtr err; !tpm_manager.GetTpmStatus(
          status_request, &status_reply, &err, Proxy::kDefaultDBusTimeoutMs)) {
    return MakeStatus<TPMError>(TPMRetryAction::kCommunication)
        .Wrap(std::move(err));
  }

  RETURN_IF_ERROR(MakeStatus<TPMManagerError>(status_reply.status()));

  brillo::SecureBlob password(status_reply.local_data().endorsement_password());

  if (password.empty()) {
    return MakeStatus<TPMError>("Empty endorsement password",
                                TPMRetryAction::kLater);
  }

  if (password.size() > kMaxPasswordLength) {
    return MakeStatus<TPMError>("Endorsement password too large",
                                TPMRetryAction::kLater);
  }

  return password;
}

}  // namespace

KeyManagementTpm2::~KeyManagementTpm2() {
  shall_flush_immediately_ = true;

  std::vector<Key> key_list;
  for (auto& [token, data] : key_map_) {
    if (data.reload_data.has_value() &&
        data.reload_data->flush_timer != nullptr) {
      data.reload_data->flush_timer->Stop();
      data.reload_data->flush_timer.reset();
    }
    key_list.push_back(Key{.token = token});
  }

  for (Key key : key_list) {
    if (Status status = Flush(key); !status.ok()) {
      LOG(WARNING) << "Failed to flush key: " << status;
    }
  }
}

StatusOr<absl::flat_hash_set<KeyAlgoType>>
KeyManagementTpm2::GetSupportedAlgo() {
  return absl::flat_hash_set<KeyAlgoType>({
      KeyAlgoType::kRsa,
      KeyAlgoType::kEcc,
  });
}

Status KeyManagementTpm2::IsSupported(KeyAlgoType key_algo,
                                      const CreateKeyOptions& options) {
  switch (key_algo) {
    case KeyAlgoType::kRsa: {
      if (options.rsa_exponent.has_value()) {
        RETURN_IF_ERROR(
            GetIntegerExponent(options.rsa_exponent.value()).status());
      }
      if (options.rsa_modulus_bits.has_value()) {
        uint32_t bits = options.rsa_modulus_bits.value();
        if (bits < kMinModulusSize * 8) {
          return MakeStatus<TPMError>("Modulus bits too small",
                                      TPMRetryAction::kNoRetry);
        }
        if (bits > kMaxModulusSize * 8) {
          return MakeStatus<TPMError>("Modulus bits too big",
                                      TPMRetryAction::kNoRetry);
        }
      }
      return OkStatus();
    }
    case KeyAlgoType::kEcc: {
      if (options.ecc_nid.has_value()) {
        RETURN_IF_ERROR(
            ConvertNIDToTrunksCurveID(options.ecc_nid.value()).status());
      }
      return OkStatus();
    }
    default:
      return MakeStatus<TPMError>("Unsupported key creation algorithm",
                                  TPMRetryAction::kNoRetry);
  }
}

StatusOr<KeyManagementTpm2::CreateKeyResult> KeyManagementTpm2::CreateKey(
    const OperationPolicySetting& policy,
    KeyAlgoType key_algo,
    const LoadKeyOptions& load_key_options,
    const CreateKeyOptions& options) {
  switch (key_algo) {
    case KeyAlgoType::kRsa:
      return CreateRsaKey(policy, options, load_key_options);
    case KeyAlgoType::kEcc:
      return CreateEccKey(policy, options, load_key_options);
    default:
      return MakeStatus<TPMError>("Unsupported key creation algorithm",
                                  TPMRetryAction::kNoRetry);
  }
}

StatusOr<KeyManagementTpm2::CreateKeyResult> KeyManagementTpm2::CreateRsaKey(
    const OperationPolicySetting& policy,
    const CreateKeyOptions& options,
    const LoadKeyOptions& load_key_options) {
  ASSIGN_OR_RETURN(const std::string& policy_digest,
                   config_.GetPolicyDigest(policy),
                   _.WithStatus<TPMError>("Failed to get policy digest"));

  if (options.allow_software_gen && policy_digest.empty()) {
    return CreateSoftwareGenRsaKey(policy, options, load_key_options);
  }

  ASSIGN_OR_RETURN(trunks::TpmUtility::AsymmetricKeyUsage usage,
                   GetKeyUsage(options),
                   _.WithStatus<TPMError>("Failed to get key usage"));

  bool use_only_policy_authorization = false;

  if (!policy_digest.empty()) {
    // We should not allow using the key without policy when the policy had been
    // set.
    use_only_policy_authorization = true;
  }

  uint32_t exponent = kDefaultTpmPublicExponent;
  if (options.rsa_exponent.has_value()) {
    ASSIGN_OR_RETURN(exponent,
                     GetIntegerExponent(options.rsa_exponent.value()));
  }

  std::string auth_value;
  if (policy.permission.type == PermissionType::kAuthValue &&
      policy.permission.auth_value.has_value()) {
    auth_value = policy.permission.auth_value.value().to_string();
  }

  // Cleanup the data from secure blob.
  base::ScopedClosureRunner cleanup_auth_value(base::BindOnce(
      brillo::SecureClearContainer<std::string>, std::ref(auth_value)));

  if (auth_value.size() > kMaxPasswordLength) {
    return MakeStatus<TPMError>("Auth value too large", TPMRetryAction::kLater);
  }

  std::unique_ptr<trunks::AuthorizationDelegate> delegate =
      context_.GetTrunksFactory().GetPasswordAuthorization("");

  std::string tpm_key_blob;

  RETURN_IF_ERROR(
      MakeStatus<TPM2Error>(context_.GetTpmUtility().CreateRSAKeyPair(
          usage, options.rsa_modulus_bits.value_or(kDefaultTpmRsaKeyBits),
          exponent, auth_value, policy_digest, use_only_policy_authorization,
          /*creation_pcr_indexes=*/{}, delegate.get(), &tpm_key_blob,
          /*creation_blob=*/nullptr)))
      .WithStatus<TPMError>("Failed to create RSA key");

  brillo::Blob key_blob = BlobFromString(tpm_key_blob);

  ASSIGN_OR_RETURN(
      const OperationPolicy& op_policy, config_.ToOperationPolicy(policy),
      _.WithStatus<TPMError>("Failed to convert setting to policy"));

  ASSIGN_OR_RETURN(ScopedKey key,
                   LoadKey(op_policy, key_blob, load_key_options),
                   _.WithStatus<TPMError>("Failed to load created RSA key"));

  return CreateKeyResult{
      .key = std::move(key),
      .key_blob = std::move(key_blob),
  };
}

StatusOr<KeyManagementTpm2::CreateKeyResult>
KeyManagementTpm2::CreateSoftwareGenRsaKey(
    const OperationPolicySetting& policy,
    const CreateKeyOptions& options,
    const LoadKeyOptions& load_key_options) {
  uint32_t key_bits = options.rsa_modulus_bits.value_or(kDefaultTpmRsaKeyBits);
  if (key_bits > kMaxModulusSize * 8) {
    return MakeStatus<TPMError>("Modulus bits too big",
                                TPMRetryAction::kNoRetry);
  }

  brillo::SecureBlob n;
  brillo::SecureBlob p;
  if (!hwsec_foundation::CreateRsaKey(key_bits, &n, &p)) {
    return MakeStatus<TPMError>("Failed to creating software RSA key",
                                TPMRetryAction::kNoRetry);
  }

  return WrapRSAKey(policy, brillo::Blob(std::begin(n), std::end(n)), p,
                    load_key_options, options);
}

StatusOr<KeyManagementTpm2::CreateKeyResult> KeyManagementTpm2::WrapRSAKey(
    const OperationPolicySetting& policy,
    const brillo::Blob& public_modulus,
    const brillo::SecureBlob& private_prime_factor,
    const LoadKeyOptions& load_key_options,
    const CreateKeyOptions& options) {
  ASSIGN_OR_RETURN(
      const ConfigTpm2::PcrMap& setting,
      config_.ToSettingsPcrMap(policy.device_config_settings),
      _.WithStatus<TPMError>("Failed to convert setting to PCR map"));

  if (!setting.empty()) {
    return MakeStatus<TPMError>("Unsupported device config",
                                TPMRetryAction::kNoRetry);
  }

  ASSIGN_OR_RETURN(trunks::TpmUtility::AsymmetricKeyUsage usage,
                   GetKeyUsage(options),
                   _.WithStatus<TPMError>("Failed to get key usage"));

  if (public_modulus.size() > kMaxRsaPublicKeySize) {
    return MakeStatus<TPMError>("RSA public key too large",
                                TPMRetryAction::kLater);
  }

  if (private_prime_factor.size() > kMaxRsaPrivateKeySize) {
    return MakeStatus<TPMError>("RSA private key too large",
                                TPMRetryAction::kLater);
  }

  std::string prime_factor = private_prime_factor.to_string();

  std::string auth_value;
  if (policy.permission.auth_value.has_value()) {
    auth_value = policy.permission.auth_value.value().to_string();
  }

  // Cleanup the data from secure blob.
  base::ScopedClosureRunner cleanup_prime_factor(base::BindOnce(
      brillo::SecureClearContainer<std::string>, std::ref(prime_factor)));
  base::ScopedClosureRunner cleanup_auth_value(base::BindOnce(
      brillo::SecureClearContainer<std::string>, std::ref(auth_value)));

  if (auth_value.size() > kMaxPasswordLength) {
    return MakeStatus<TPMError>("Auth value too large", TPMRetryAction::kLater);
  }

  uint32_t exponent = kDefaultTpmPublicExponent;
  if (options.rsa_exponent.has_value()) {
    ASSIGN_OR_RETURN(exponent,
                     GetIntegerExponent(options.rsa_exponent.value()));
  }

  std::string tpm_key_blob;
  std::unique_ptr<trunks::AuthorizationDelegate> delegate =
      context_.GetTrunksFactory().GetPasswordAuthorization("");

  RETURN_IF_ERROR(MakeStatus<TPM2Error>(context_.GetTpmUtility().ImportRSAKey(
                      usage, brillo::BlobToString(public_modulus), exponent,
                      prime_factor, auth_value, delegate.get(), &tpm_key_blob)))
      .WithStatus<TPMError>("Failed to import software RSA key");

  brillo::Blob key_blob = BlobFromString(tpm_key_blob);

  ASSIGN_OR_RETURN(
      const OperationPolicy& op_policy, config_.ToOperationPolicy(policy),
      _.WithStatus<TPMError>("Failed to convert setting to policy"));

  ASSIGN_OR_RETURN(
      ScopedKey key, LoadKey(op_policy, key_blob, load_key_options),
      _.WithStatus<TPMError>("Failed to load created software RSA key"));

  return CreateKeyResult{
      .key = std::move(key),
      .key_blob = std::move(key_blob),
  };
}

StatusOr<KeyManagementTpm2::CreateKeyResult> KeyManagementTpm2::WrapECCKey(
    const OperationPolicySetting& policy,
    const brillo::Blob& public_point_x,
    const brillo::Blob& public_point_y,
    const brillo::SecureBlob& private_value,
    const LoadKeyOptions& load_key_options,
    const CreateKeyOptions& options) {
  ASSIGN_OR_RETURN(
      const ConfigTpm2::PcrMap& setting,
      config_.ToSettingsPcrMap(policy.device_config_settings),
      _.WithStatus<TPMError>("Failed to convert setting to PCR map"));

  if (!setting.empty()) {
    return MakeStatus<TPMError>("Unsupported device config",
                                TPMRetryAction::kNoRetry);
  }

  if (public_point_x.size() > MAX_ECC_KEY_BYTES ||
      public_point_y.size() > MAX_ECC_KEY_BYTES ||
      private_value.size() > MAX_ECC_KEY_BYTES) {
    return MakeStatus<TPMError>("ECC key too large", TPMRetryAction::kNoRetry);
  }

  ASSIGN_OR_RETURN(trunks::TpmUtility::AsymmetricKeyUsage usage,
                   GetKeyUsage(options),
                   _.WithStatus<TPMError>("Failed to get key usage"));

  std::string auth_value;
  if (policy.permission.auth_value.has_value()) {
    auth_value = policy.permission.auth_value.value().to_string();
  }

  // Cleanup the data from secure blob.
  base::ScopedClosureRunner cleanup_auth_value(base::BindOnce(
      brillo::SecureClearContainer<std::string>, std::ref(auth_value)));

  if (auth_value.size() > kMaxPasswordLength) {
    return MakeStatus<TPMError>("Auth value too large", TPMRetryAction::kLater);
  }

  trunks::TPMI_ECC_CURVE curve = kDefaultTpmCurveId;

  if (options.ecc_nid.has_value()) {
    ASSIGN_OR_RETURN(curve, ConvertNIDToTrunksCurveID(options.ecc_nid.value()));
  }

  std::string tpm_key_blob;
  std::unique_ptr<trunks::AuthorizationDelegate> delegate =
      context_.GetTrunksFactory().GetPasswordAuthorization("");

  RETURN_IF_ERROR(
      MakeStatus<TPM2Error>(context_.GetTpmUtility().ImportECCKey(
          usage, curve,
          PaddingStringToLength(brillo::BlobToString(public_point_x),
                                MAX_ECC_KEY_BYTES),
          PaddingStringToLength(brillo::BlobToString(public_point_y),
                                MAX_ECC_KEY_BYTES),
          PaddingStringToLength(private_value.to_string(), MAX_ECC_KEY_BYTES),
          auth_value, delegate.get(), &tpm_key_blob)))
      .WithStatus<TPMError>("Failed to import software RSA key");

  brillo::Blob key_blob = BlobFromString(tpm_key_blob);

  ASSIGN_OR_RETURN(
      const OperationPolicy& op_policy, config_.ToOperationPolicy(policy),
      _.WithStatus<TPMError>("Failed to convert setting to policy"));

  ASSIGN_OR_RETURN(
      ScopedKey key, LoadKey(op_policy, key_blob, load_key_options),
      _.WithStatus<TPMError>("Failed to load created software RSA key"));

  return CreateKeyResult{
      .key = std::move(key),
      .key_blob = std::move(key_blob),
  };
}

StatusOr<KeyManagementTpm2::CreateKeyResult> KeyManagementTpm2::CreateEccKey(
    const OperationPolicySetting& policy,
    const CreateKeyOptions& options,
    const LoadKeyOptions& load_key_options) {
  ASSIGN_OR_RETURN(trunks::TpmUtility::AsymmetricKeyUsage usage,
                   GetKeyUsage(options),
                   _.WithStatus<TPMError>("Failed to get key usage"));

  bool use_only_policy_authorization = false;

  ASSIGN_OR_RETURN(const std::string& policy_digest,
                   config_.GetPolicyDigest(policy),
                   _.WithStatus<TPMError>("Failed to get policy digest"));

  if (!policy_digest.empty()) {
    // We should not allow using the key without policy when the policy had been
    // set.
    use_only_policy_authorization = true;
  }

  std::string auth_value;
  if (policy.permission.type == PermissionType::kAuthValue &&
      policy.permission.auth_value.has_value()) {
    auth_value = policy.permission.auth_value.value().to_string();
  }

  // Cleanup the data from secure blob.
  base::ScopedClosureRunner cleanup_auth_value(base::BindOnce(
      brillo::SecureClearContainer<std::string>, std::ref(auth_value)));

  if (auth_value.size() > kMaxPasswordLength) {
    return MakeStatus<TPMError>("Auth value too large", TPMRetryAction::kLater);
  }

  trunks::TPMI_ECC_CURVE curve = kDefaultTpmCurveId;

  if (options.ecc_nid.has_value()) {
    ASSIGN_OR_RETURN(curve, ConvertNIDToTrunksCurveID(options.ecc_nid.value()));
  }

  std::unique_ptr<trunks::AuthorizationDelegate> delegate =
      context_.GetTrunksFactory().GetPasswordAuthorization("");

  std::string tpm_key_blob;

  RETURN_IF_ERROR(
      MakeStatus<TPM2Error>(context_.GetTpmUtility().CreateECCKeyPair(
          usage, curve, auth_value, policy_digest,
          use_only_policy_authorization, /*creation_pcr_indexes=*/{},
          delegate.get(), &tpm_key_blob, /*creation_blob=*/nullptr)))
      .WithStatus<TPMError>("Failed to create ECC key");

  brillo::Blob key_blob = BlobFromString(tpm_key_blob);

  ASSIGN_OR_RETURN(
      const OperationPolicy& op_policy, config_.ToOperationPolicy(policy),
      _.WithStatus<TPMError>("Failed to convert setting to policy"));

  ASSIGN_OR_RETURN(ScopedKey key,
                   LoadKey(op_policy, key_blob, load_key_options),
                   _.WithStatus<TPMError>("Failed to load created RSA key"));

  return CreateKeyResult{
      .key = std::move(key),
      .key_blob = std::move(key_blob),
  };
}

StatusOr<ScopedKey> KeyManagementTpm2::LoadKey(
    const OperationPolicy& policy,
    const brillo::Blob& key_blob,
    const LoadKeyOptions& load_key_options) {
  if (load_key_options.auto_reload == true && policy.device_configs.none()) {
    for (auto& [token, key_data] : key_map_) {
      if (IsKeyDataMatch(key_data, key_blob, policy)) {
        if (key_data.reload_data->flush_timer != nullptr) {
          key_data.reload_data->flush_timer->Stop();
          key_data.reload_data->flush_timer.reset();
        }

        key_data.reload_data->lazy_expiration_time =
            std::min(key_data.reload_data->lazy_expiration_time,
                     load_key_options.lazy_expiration_time);
        key_data.reload_data->client_count++;
        return ScopedKey(Key{.token = token}, middleware_derivative_);
      }
    }
  }

  uint32_t key_handle;
  std::unique_ptr<trunks::AuthorizationDelegate> delegate =
      context_.GetTrunksFactory().GetPasswordAuthorization("");

  if (auto status = MakeStatus<TPM2Error>(context_.GetTpmUtility().LoadKey(
          BlobToString(key_blob), delegate.get(), &key_handle));
      !status.ok() && trunks::GetFormatOneError(status->ErrorCode()) ==
                          trunks::TPM_RC_INTEGRITY) {
    return MakeStatus<TPMError>(
               "Failed to load SRK wrapped key due to integrity",
               TPMRetryAction::kNoRetry)
        .Wrap(std::move(status));
  } else if (!status.ok()) {
    return MakeStatus<TPMError>("Failed to load SRK wrapped key")
        .Wrap(std::move(status));
  }

  KeyTpm2::Type key_type = KeyTpm2::Type::kTransientKey;
  std::optional<KeyReloadDataTpm2> reload_data;
  if (load_key_options.auto_reload == true) {
    key_type = KeyTpm2::Type::kReloadableTransientKey;
    reload_data = KeyReloadDataTpm2{
        .key_blob = key_blob,
        .client_count = 1,
        .lazy_expiration_time = load_key_options.lazy_expiration_time,
    };
  }

  return LoadKeyInternal(policy, key_type, key_handle, std::move(reload_data));
}

StatusOr<ScopedKey> KeyManagementTpm2::GetPolicyEndorsementKey(
    const OperationPolicySetting& policy, KeyAlgoType key_algo) {
  trunks::TPM_ALG_ID key_type;

  switch (key_algo) {
    case KeyAlgoType::kRsa:
      key_type = trunks::TPM_ALG_RSA;
      break;
    case KeyAlgoType::kEcc:
      key_type = trunks::TPM_ALG_ECC;
      break;
    default:
      return MakeStatus<TPMError>(
          "Unsupported policy endorsement key algorithm",
          TPMRetryAction::kNoRetry);
  }

  if (policy.permission.auth_value.has_value() &&
      policy.permission.type == PermissionType::kAuthValue) {
    return MakeStatus<TPMError>(
        "Policy endorsement key doesn't support session auth permission",
        TPMRetryAction::kNoRetry);
  }

  ASSIGN_OR_RETURN(const std::string& policy_digest,
                   config_.GetPolicyDigest(policy),
                   _.WithStatus<TPMError>("Failed to get policy digest"));

  ASSIGN_OR_RETURN(
      const brillo::SecureBlob& endorsement_pass,
      GetEndorsementPassword(tpm_manager_),
      _.WithStatus<TPMError>("Failed to get endorsement password"));

  std::unique_ptr<trunks::AuthorizationDelegate> delegate =
      context_.GetTrunksFactory().GetPasswordAuthorization(
          endorsement_pass.to_string());

  trunks::TPM_HANDLE key_handle;
  trunks::TPM2B_NAME key_name;

  RETURN_IF_ERROR(
      MakeStatus<TPM2Error>(
          context_.GetTpmUtility().GetAuthPolicyEndorsementKey(
              key_type, policy_digest, delegate.get(), &key_handle, &key_name)))
      .WithStatus<TPMError>("Failed to get auth policy endorsement key");

  ASSIGN_OR_RETURN(
      const OperationPolicy& op_policy, config_.ToOperationPolicy(policy),
      _.WithStatus<TPMError>("Failed to convert setting to policy"));

  ASSIGN_OR_RETURN(
      ScopedKey key,
      LoadKeyInternal(op_policy, KeyTpm2::Type::kTransientKey, key_handle,
                      /*reload_data=*/std::nullopt),
      _.WithStatus<TPMError>("Failed to side load policy endorsement key"));

  return key;
}

StatusOr<ScopedKey> KeyManagementTpm2::GetPersistentKey(
    PersistentKeyType key_type) {
  auto it = persistent_key_map_.find(key_type);
  if (it != persistent_key_map_.end()) {
    return ScopedKey(Key{.token = it->second}, middleware_derivative_);
  }

  uint32_t key_handle = 0;

  switch (key_type) {
    case PersistentKeyType::kStorageRootKey:
      key_handle = trunks::kStorageRootKey;
      break;
    default:
      return MakeStatus<TPMError>("Unknown persistent key type",
                                  TPMRetryAction::kNoRetry);
  }

  ASSIGN_OR_RETURN(
      ScopedKey key,
      LoadKeyInternal(OperationPolicy{}, KeyTpm2::Type::kPersistentKey,
                      key_handle,
                      /*reload_data=*/std::nullopt),
      _.WithStatus<TPMError>("Failed to side load persistent key"));

  persistent_key_map_[key_type] = key.GetKey().token;

  return key;
}

StatusOr<brillo::Blob> KeyManagementTpm2::GetPubkeyHash(Key key) {
  ASSIGN_OR_RETURN(const KeyTpm2& key_data, GetKeyData(key));

  const trunks::TPMT_PUBLIC& public_data = key_data.cache.public_area;
  if (public_data.type == trunks::TPM_ALG_RSA) {
    std::string public_modulus =
        trunks::StringFrom_TPM2B_PUBLIC_KEY_RSA(public_data.unique.rsa);
    return Sha256(BlobFromString(public_modulus));
  } else if (public_data.type == trunks::TPM_ALG_ECC) {
    std::string x_point =
        trunks::StringFrom_TPM2B_ECC_PARAMETER(public_data.unique.ecc.x);
    return Sha256(BlobFromString(x_point));
  }

  return MakeStatus<TPMError>("Unknown key algorithm",
                              TPMRetryAction::kNoRetry);
}

StatusOr<RSAPublicInfo> KeyManagementTpm2::GetRSAPublicInfo(Key key) {
  ASSIGN_OR_RETURN(const KeyTpm2& key_data, GetKeyData(key));

  const trunks::TPMT_PUBLIC& public_data = key_data.cache.public_area;

  if (public_data.type != trunks::TPM_ALG_RSA) {
    return MakeStatus<TPMError>("Get RSA public info for none-RSA key",
                                TPMRetryAction::kNoRetry);
  }

  std::string exponent;
  RETURN_IF_ERROR(MakeStatus<TPM2Error>(trunks::Serialize_UINT32(
                      public_data.parameters.rsa_detail.exponent, &exponent)))
      .WithStatus<TPMError>("Failed to serialize uint32");

  std::string modulus =
      trunks::StringFrom_TPM2B_PUBLIC_KEY_RSA(public_data.unique.rsa);

  return RSAPublicInfo{
      .exponent = brillo::BlobFromString(exponent),
      .modulus = brillo::BlobFromString(modulus),
  };
}

StatusOr<ECCPublicInfo> KeyManagementTpm2::GetECCPublicInfo(Key key) {
  ASSIGN_OR_RETURN(const KeyTpm2& key_data, GetKeyData(key));

  const trunks::TPMT_PUBLIC& public_data = key_data.cache.public_area;

  if (public_data.type != trunks::TPM_ALG_ECC) {
    return MakeStatus<TPMError>("Get ECC public info for none-ECC key",
                                TPMRetryAction::kNoRetry);
  }

  ASSIGN_OR_RETURN(int nid, ConvertTrunksCurveIDToNID(
                                public_data.parameters.ecc_detail.curve_id));

  std::string x_point =
      trunks::StringFrom_TPM2B_ECC_PARAMETER(public_data.unique.ecc.x);
  std::string y_point =
      trunks::StringFrom_TPM2B_ECC_PARAMETER(public_data.unique.ecc.y);

  return ECCPublicInfo{
      .nid = nid,
      .x_point = brillo::BlobFromString(x_point),
      .y_point = brillo::BlobFromString(y_point),
  };
}

StatusOr<ScopedKey> KeyManagementTpm2::SideLoadKey(uint32_t key_handle) {
  return LoadKeyInternal(OperationPolicy{}, KeyTpm2::Type::kPersistentKey,
                         key_handle,
                         /*reload_data=*/std::nullopt);
}

StatusOr<uint32_t> KeyManagementTpm2::GetKeyHandle(Key key) {
  ASSIGN_OR_RETURN(const KeyTpm2& key_data, GetKeyData(key));

  return key_data.key_handle;
}

StatusOr<ScopedKey> KeyManagementTpm2::LoadKeyInternal(
    const OperationPolicy& policy,
    KeyTpm2::Type key_type,
    uint32_t key_handle,
    std::optional<KeyReloadDataTpm2> reload_data) {
  trunks::TPMT_PUBLIC public_area;
  RETURN_IF_ERROR(
      MakeStatus<TPM2Error>(
          context_.GetTpmUtility().GetKeyPublicArea(key_handle, &public_area)))
      .WithStatus<TPMError>("Failed to Get key public area");

  if (public_area.type == trunks::TPM_ALG_RSA) {
    if (public_area.unique.rsa.size > sizeof(public_area.unique.rsa.buffer)) {
      return MakeStatus<TPMError>("RSA pubkey overflow",
                                  TPMRetryAction::kNoRetry);
    }
  } else if (public_area.type == trunks::TPM_ALG_ECC) {
    if (public_area.unique.ecc.x.size >
            sizeof(public_area.unique.ecc.x.buffer) ||
        public_area.unique.ecc.y.size >
            sizeof(public_area.unique.ecc.y.buffer)) {
      return MakeStatus<TPMError>("ECC pubkey overflow",
                                  TPMRetryAction::kNoRetry);
    }
  }

  KeyToken token = current_token_++;
  key_map_.emplace(token, KeyTpm2{
                              .type = key_type,
                              .key_handle = key_handle,
                              .cache =
                                  KeyTpm2::Cache{
                                      .policy = policy,
                                      .public_area = std::move(public_area),
                                  },
                              .reload_data = std::move(reload_data),
                          });

  return ScopedKey(Key{.token = token}, middleware_derivative_);
}

Status KeyManagementTpm2::Flush(Key key) {
  ASSIGN_OR_RETURN(KeyTpm2 & key_data, GetKeyData(key));

  switch (key_data.type) {
    case KeyTpm2::Type::kPersistentKey:
      // We don't need to unload these kinds of key.
      return OkStatus();

    case KeyTpm2::Type::kTransientKey:
    case KeyTpm2::Type::kReloadableTransientKey:
      return FlushTransientKey(key, key_data);

    default:
      return MakeStatus<TPMError>("Unknown key type", TPMRetryAction::kNoRetry);
  }
}

Status KeyManagementTpm2::FlushTransientKey(Key key, KeyTpm2& key_data) {
  if (shall_flush_immediately_) {
    return FlushKeyTokenAndHandle(key.token, key_data.key_handle);
  }

  if (key_data.reload_data.has_value()) {
    key_data.reload_data->client_count--;
    if (key_data.reload_data->client_count != 0) {
      // We still have the other client using this key.
      return OkStatus();
    }
  }

  if (key_data.reload_data.has_value() &&
      key_data.reload_data->lazy_expiration_time.is_positive() &&
      base::SequencedTaskRunner::HasCurrentDefault()) {
    base::OnceClosure flush_closure =
        base::BindOnce(&KeyManagementTpm2::FlushKeyTokenAndHandle,
                       base::Unretained(this), static_cast<KeyToken>(key.token),
                       static_cast<trunks::TPM_HANDLE>(key_data.key_handle))
            .Then(base::BindOnce([](Status result) {
              if (!result.ok()) {
                LOG(ERROR) << "Failed to flush key: " << result;
              }
            }));
    key_data.reload_data->flush_timer = std::make_unique<base::OneShotTimer>();
    key_data.reload_data->flush_timer->Start(
        FROM_HERE, key_data.reload_data->lazy_expiration_time,
        std::move(flush_closure));
    return OkStatus();
  }

  return FlushKeyTokenAndHandle(key.token, key_data.key_handle);
}

Status KeyManagementTpm2::FlushKeyTokenAndHandle(KeyToken token,
                                                 trunks::TPM_HANDLE handle) {
  RETURN_IF_ERROR(MakeStatus<TPM2Error>(
                      context_.GetTrunksFactory().GetTpm()->FlushContextSync(
                          handle, nullptr)))
      .WithStatus<TPMError>("Failed to flush key handle");

  key_map_.erase(token);
  return OkStatus();
}

StatusOr<std::reference_wrapper<KeyTpm2>> KeyManagementTpm2::GetKeyData(
    Key key) {
  auto it = key_map_.find(key.token);
  if (it == key_map_.end()) {
    return MakeStatus<TPMError>("Unknown key", TPMRetryAction::kNoRetry);
  }
  return it->second;
}

Status KeyManagementTpm2::ReloadIfPossible(Key key) {
  ASSIGN_OR_RETURN(KeyTpm2 & key_data, GetKeyData(key));

  if (key_data.type != KeyTpm2::Type::kReloadableTransientKey) {
    // We don't need to reload un-reloadable key.
    return OkStatus();
  }

  if (!key_data.reload_data.has_value()) {
    return MakeStatus<TPMError>("Empty reload data", TPMRetryAction::kNoRetry);
  }

  if (auto status = MakeStatus<TPM2Error>(
          context_.GetTrunksFactory().GetTpm()->FlushContextSync(
              key_data.key_handle, nullptr));
      !status.ok()) {
    LOG(WARNING) << "Failed to flush stale key handle: " << status;
  }

  uint32_t key_handle;
  std::unique_ptr<trunks::AuthorizationDelegate> delegate =
      context_.GetTrunksFactory().GetPasswordAuthorization("");
  RETURN_IF_ERROR(MakeStatus<TPM2Error>(context_.GetTpmUtility().LoadKey(
                      BlobToString(key_data.reload_data->key_blob),
                      delegate.get(), &key_handle)))
      .WithStatus<TPMError>("Failed to reload SRK wrapped key");

  key_data.key_handle = key_handle;
  return OkStatus();
}

StatusOr<ScopedKey> KeyManagementTpm2::LoadPublicKeyFromSpki(
    const brillo::Blob& public_key_spki_der,
    trunks::TPM_ALG_ID scheme,
    trunks::TPM_ALG_ID hash_alg) {
  ASSIGN_OR_RETURN(const RsaParameters& public_key,
                   ParseSpkiDer(public_key_spki_der));

  // Load the key into the TPM.
  trunks::TPM_HANDLE key_handle = 0;
  RETURN_IF_ERROR(
      MakeStatus<TPM2Error>(context_.GetTpmUtility().LoadRSAPublicKey(
          trunks::TpmUtility::AsymmetricKeyUsage::kSignKey, scheme, hash_alg,
          brillo::BlobToString(public_key.key_modulus), public_key.key_exponent,
          nullptr, &key_handle)))
      .WithStatus<TPMError>("Failed to load RSA public key");

  return LoadKeyInternal(OperationPolicy{}, KeyTpm2::Type::kTransientKey,
                         key_handle,
                         /*reload_data=*/std::nullopt);
}

}  // namespace hwsec
