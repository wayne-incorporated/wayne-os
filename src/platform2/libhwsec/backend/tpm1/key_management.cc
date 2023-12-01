// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "libhwsec/backend/tpm1/key_management.h"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include <base/functional/callback_helpers.h>
#include <brillo/secure_blob.h>
#include <crypto/scoped_openssl_types.h>
#include <libhwsec-foundation/crypto/rsa.h>
#include <libhwsec-foundation/crypto/secure_blob_util.h>
#include <libhwsec-foundation/crypto/sha.h>
#include <libhwsec-foundation/status/status_chain_macros.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

#include "libhwsec/error/tpm1_error.h"
#include "libhwsec/overalls/overalls.h"
#include "libhwsec/status.h"
#include "libhwsec/tss_utils/scoped_tss_type.h"

using brillo::BlobFromString;
using brillo::BlobToString;
using hwsec_foundation::CreateSecureRandomBlob;
using hwsec_foundation::kWellKnownExponent;
using hwsec_foundation::Sha1;
using hwsec_foundation::Sha256;
using hwsec_foundation::status::MakeStatus;

namespace hwsec {

namespace {

constexpr uint8_t kDefaultSrkAuth[] = {};
constexpr uint32_t kDefaultDiscardableWrapPasswordLength = 32;
constexpr uint32_t kDefaultTpmRsaKeyModulusBit = TSS_KEY_SIZEVAL_2048BIT;
constexpr uint8_t kDefaultTpmPublicExponentArray[] = {0x01, 0x00, 0x01};
constexpr uint32_t kSha1ModeAuthValueLength = 20;

// Min and max supported RSA modulus sizes (in bytes).
constexpr uint32_t kMinModulusSize = 64;
constexpr uint32_t kMaxModulusSize = 256;

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

TSS_FLAG GetKeySize(int modulus_bits) {
  switch (modulus_bits) {
    case TSS_KEY_SIZEVAL_512BIT:
      return TSS_KEY_SIZE_512;
    case TSS_KEY_SIZEVAL_1024BIT:
      return TSS_KEY_SIZE_1024;
    case TSS_KEY_SIZEVAL_2048BIT:
      return TSS_KEY_SIZE_2048;
    case TSS_KEY_SIZEVAL_4096BIT:
      return TSS_KEY_SIZE_4096;
    case TSS_KEY_SIZEVAL_8192BIT:
      return TSS_KEY_SIZE_8192;
    case TSS_KEY_SIZEVAL_16384BIT:
      return TSS_KEY_SIZE_16384;
    default:
      return TSS_KEY_SIZE_DEFAULT;
  }
}

StatusOr<ScopedTssPolicy> AddAuthPolicy(overalls::Overalls& overalls,
                                        TSS_HCONTEXT context,
                                        TSS_HKEY key,
                                        brillo::SecureBlob auth_value) {
  ScopedTssPolicy auth_policy(overalls, context);
  RETURN_IF_ERROR(MakeStatus<TPM1Error>(overalls.Ospi_Context_CreateObject(
                      context, TSS_OBJECT_TYPE_POLICY, TSS_POLICY_USAGE,
                      auth_policy.ptr())))
      .WithStatus<TPMError>("Failed to call Ospi_SetAttribUint32");

  if (auth_value.empty()) {
    RETURN_IF_ERROR(MakeStatus<TPM1Error>(overalls.Ospi_Policy_SetSecret(
                        auth_policy, TSS_SECRET_MODE_NONE, 0, nullptr)))
        .WithStatus<TPMError>("Failed to call Ospi_Policy_SetSecret");
  } else if (auth_value.size() == kSha1ModeAuthValueLength) {
    RETURN_IF_ERROR(MakeStatus<TPM1Error>(overalls.Ospi_Policy_SetSecret(
                        auth_policy, TSS_SECRET_MODE_SHA1, auth_value.size(),
                        auth_value.data())))
        .WithStatus<TPMError>("Failed to call Ospi_Policy_SetSecret");
  } else {
    RETURN_IF_ERROR(MakeStatus<TPM1Error>(overalls.Ospi_Policy_SetSecret(
                        auth_policy, TSS_SECRET_MODE_PLAIN, auth_value.size(),
                        auth_value.data())))
        .WithStatus<TPMError>("Failed to call Ospi_Policy_SetSecret");
  }

  RETURN_IF_ERROR(MakeStatus<TPM1Error>(
                      overalls.Ospi_Policy_AssignToObject(auth_policy, key)))
      .WithStatus<TPMError>("Failed to call Ospi_Policy_AssignToObject");

  return auth_policy;
}

}  // namespace

KeyManagementTpm1::~KeyManagementTpm1() {
  std::vector<Key> key_list;
  for (auto& [token, data] : key_map_) {
    key_list.push_back(Key{.token = token});
  }
  for (Key key : key_list) {
    if (Status status = Flush(key); !status.ok()) {
      LOG(WARNING) << "Failed to flush key: " << status;
    }
  }
}

StatusOr<absl::flat_hash_set<KeyAlgoType>>
KeyManagementTpm1::GetSupportedAlgo() {
  return absl::flat_hash_set<KeyAlgoType>({
      KeyAlgoType::kRsa,
  });
}

Status KeyManagementTpm1::IsSupported(KeyAlgoType key_algo,
                                      const CreateKeyOptions& options) {
  switch (key_algo) {
    case KeyAlgoType::kRsa:
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
    default:
      return MakeStatus<TPMError>("Unsupported key creation algorithm",
                                  TPMRetryAction::kNoRetry);
  }
}

StatusOr<KeyManagementTpm1::CreateKeyResult> KeyManagementTpm1::CreateKey(
    const OperationPolicySetting& policy,
    KeyAlgoType key_algo,
    const LoadKeyOptions& load_key_options,
    const CreateKeyOptions& options) {
  switch (key_algo) {
    case KeyAlgoType::kRsa:
      return CreateRsaKey(policy, options, load_key_options);
    default:
      return MakeStatus<TPMError>("Unsupported key creation algorithm",
                                  TPMRetryAction::kNoRetry);
  }
}

StatusOr<KeyManagementTpm1::CreateKeyResult> KeyManagementTpm1::CreateRsaKey(
    const OperationPolicySetting& policy,
    const CreateKeyOptions& options,
    const LoadKeyOptions& load_key_options) {
  ASSIGN_OR_RETURN(
      const ConfigTpm1::PcrMap& setting,
      config_.ToSettingsPcrMap(policy.device_config_settings),
      _.WithStatus<TPMError>("Failed to convert setting to PCR map"));

  if (options.allow_software_gen && setting.empty()) {
    return CreateSoftwareGenRsaKey(policy, options, load_key_options);
  }

  ASSIGN_OR_RETURN(ScopedKey srk,
                   GetPersistentKey(PersistentKeyType::kStorageRootKey));

  ASSIGN_OR_RETURN(const KeyTpm1& srk_data, GetKeyData(srk.GetKey()));

  ASSIGN_OR_RETURN(TSS_HCONTEXT context, tss_helper_.GetTssContext());

  // Create a PCRS object to hold pcr_index and pcr_value.
  ScopedTssPcrs pcrs(overalls_, context);
  if (!setting.empty()) {
    RETURN_IF_ERROR(
        MakeStatus<TPM1Error>(overalls_.Ospi_Context_CreateObject(
            context, TSS_OBJECT_TYPE_PCRS, TSS_PCRS_STRUCT_INFO, pcrs.ptr())))
        .WithStatus<TPMError>("Failed to call Ospi_Context_CreateObject");

    for (const auto& map_pair : setting) {
      uint32_t pcr_index = map_pair.first;
      brillo::Blob pcr_value = map_pair.second;
      RETURN_IF_ERROR(
          MakeStatus<TPM1Error>(overalls_.Ospi_PcrComposite_SetPcrValue(
              pcrs, pcr_index, pcr_value.size(), pcr_value.data())))
          .WithStatus<TPMError>("Failed to call Ospi_PcrComposite_SetPcrValue");
    }
  }

  // Create a non-migratable key restricted to |pcrs|.
  ScopedTssKey pcr_bound_key(overalls_, context);
  TSS_FLAG init_flags = TSS_KEY_VOLATILE | TSS_KEY_NOT_MIGRATABLE |
                        GetKeySize(options.rsa_modulus_bits.value_or(
                            kDefaultTpmRsaKeyModulusBit));
  if (policy.permission.auth_value.has_value()) {
    init_flags |= TSS_KEY_AUTHORIZATION;
  }

  // In this case, the key is not decrypt only. It can be used to sign the
  // data too. No easy way to make a decrypt only key here.
  if (options.allow_sign && !options.allow_decrypt) {
    init_flags |= TSS_KEY_TYPE_SIGNING;
  } else {
    init_flags |= TSS_KEY_TYPE_LEGACY;
  }

  brillo::Blob exponent = options.rsa_exponent.value_or(
      brillo::Blob(std::begin(kDefaultTpmPublicExponentArray),
                   std::end(kDefaultTpmPublicExponentArray)));

  RETURN_IF_ERROR(
      MakeStatus<TPM1Error>(overalls_.Ospi_Context_CreateObject(
          context, TSS_OBJECT_TYPE_RSAKEY, init_flags, pcr_bound_key.ptr())))
      .WithStatus<TPMError>("Failed to call Ospi_Context_CreateObject");

  if (options.allow_sign) {
    uint32_t sig_scheme = TSS_SS_RSASSAPKCS1V15_DER;
    RETURN_IF_ERROR(MakeStatus<TPM1Error>(overalls_.Ospi_SetAttribUint32(
                        pcr_bound_key, TSS_TSPATTRIB_KEY_INFO,
                        TSS_TSPATTRIB_KEYINFO_SIGSCHEME, sig_scheme)))
        .WithStatus<TPMError>("Failed to call Ospi_Context_CreateObject");
  }

  if (options.allow_decrypt) {
    uint32_t enc_scheme = TSS_ES_RSAESPKCSV15;
    RETURN_IF_ERROR(MakeStatus<TPM1Error>(overalls_.Ospi_SetAttribUint32(
                        pcr_bound_key, TSS_TSPATTRIB_KEY_INFO,
                        TSS_TSPATTRIB_KEYINFO_ENCSCHEME, enc_scheme)))
        .WithStatus<TPMError>("Failed to call Ospi_SetAttribUint32");
  }

  if (exponent != brillo::Blob(std::begin(kDefaultTpmPublicExponentArray),
                               std::end(kDefaultTpmPublicExponentArray))) {
    RETURN_IF_ERROR(MakeStatus<TPM1Error>(overalls_.Ospi_SetAttribData(
                        pcr_bound_key, TSS_TSPATTRIB_RSAKEY_INFO,
                        TSS_TSPATTRIB_KEYINFO_RSA_EXPONENT, exponent.size(),
                        exponent.data())))
        .WithStatus<TPMError>("Failed to call Ospi_SetAttribData");
  }

  ScopedTssPolicy auth_policy(overalls_, context);
  if (policy.permission.auth_value.has_value()) {
    ASSIGN_OR_RETURN(auth_policy,
                     AddAuthPolicy(overalls_, context, pcr_bound_key,
                                   policy.permission.auth_value.value()),
                     _.WithStatus<TPMError>("Failed to add auth policy"));
  }

  RETURN_IF_ERROR(MakeStatus<TPM1Error>(overalls_.Ospi_Key_CreateKey(
                      pcr_bound_key, srk_data.key_handle, pcrs)))
      .WithStatus<TPMError>("Failed to call Ospi_Key_CreateKey");

  RETURN_IF_ERROR(MakeStatus<TPM1Error>(overalls_.Ospi_Key_LoadKey(
                      pcr_bound_key, srk_data.key_handle)))
      .WithStatus<TPMError>("Failed to call Ospi_Key_LoadKey");

  // Get the key blob so we can load it later.
  uint32_t length = 0;
  ScopedTssMemory buf(overalls_, context);
  RETURN_IF_ERROR(MakeStatus<TPM1Error>(overalls_.Ospi_GetAttribData(
                      pcr_bound_key, TSS_TSPATTRIB_KEY_BLOB,
                      TSS_TSPATTRIB_KEYBLOB_BLOB, &length, buf.ptr())))
      .WithStatus<TPMError>("Failed to call Ospi_GetAttribData");

  brillo::Blob key_blob(buf.value(), buf.value() + length);

  ASSIGN_OR_RETURN(
      const OperationPolicy& op_policy, config_.ToOperationPolicy(policy),
      _.WithStatus<TPMError>("Failed to convert setting to policy"));

  uint32_t key_handle = pcr_bound_key.value();
  KeyTpm1::Type key_type = KeyTpm1::Type::kTransientKey;
  std::optional<KeyReloadDataTpm1> reload_data;

  if (load_key_options.auto_reload == true) {
    key_type = KeyTpm1::Type::kReloadableTransientKey;
    reload_data = KeyReloadDataTpm1{
        .policy = op_policy,
        .key_blob = key_blob,
    };
  }

  ASSIGN_OR_RETURN(ScopedKey key,
                   LoadKeyInternal(key_type, key_handle,
                                   KeyPolicyPair{
                                       .tss_key = std::move(pcr_bound_key),
                                       .tss_policy = std::move(auth_policy),
                                   },
                                   reload_data),
                   _.WithStatus<TPMError>("Failed to load created RSA key"));

  return CreateKeyResult{
      .key = std::move(key),
      .key_blob = std::move(key_blob),
  };
}

StatusOr<KeyManagementTpm1::CreateKeyResult>
KeyManagementTpm1::CreateSoftwareGenRsaKey(
    const OperationPolicySetting& policy,
    const CreateKeyOptions& options,
    const LoadKeyOptions& load_key_options) {
  brillo::SecureBlob public_modulus;
  brillo::SecureBlob prime_factor;
  if (!hwsec_foundation::CreateRsaKey(
          options.rsa_modulus_bits.value_or(kDefaultTpmRsaKeyModulusBit),
          &public_modulus, &prime_factor)) {
    return MakeStatus<TPMError>("Failed to creating software RSA key",
                                TPMRetryAction::kNoRetry);
  }

  return WrapRSAKey(
      policy,
      brillo::Blob(std::begin(public_modulus), std::end(public_modulus)),
      prime_factor, load_key_options, options);
}

StatusOr<KeyManagementTpm1::CreateKeyResult> KeyManagementTpm1::WrapRSAKey(
    const OperationPolicySetting& policy,
    const brillo::Blob& public_modulus,
    const brillo::SecureBlob& private_prime_factor,
    const LoadKeyOptions& load_key_options,
    const CreateKeyOptions& options) {
  brillo::Blob exponent = options.rsa_exponent.value_or(
      brillo::Blob(std::begin(kDefaultTpmPublicExponentArray),
                   std::end(kDefaultTpmPublicExponentArray)));
  brillo::Blob modulus = public_modulus;
  brillo::SecureBlob prime_factor = private_prime_factor;

  ASSIGN_OR_RETURN(ScopedKey srk,
                   GetPersistentKey(PersistentKeyType::kStorageRootKey));

  ASSIGN_OR_RETURN(const KeyTpm1& srk_data, GetKeyData(srk.GetKey()));

  ASSIGN_OR_RETURN(TSS_HCONTEXT context, tss_helper_.GetTssContext());

  // Create the key object
  TSS_FLAG init_flags = TSS_KEY_VOLATILE | TSS_KEY_MIGRATABLE |
                        GetKeySize(options.rsa_modulus_bits.value_or(
                            kDefaultTpmRsaKeyModulusBit));
  if (policy.permission.auth_value.has_value()) {
    init_flags |= TSS_KEY_AUTHORIZATION;
  }

  // In this case, the key is not decrypt only. It can be used to sign the
  // data too. No easy way to make a decrypt only key here.
  if (options.allow_sign && !options.allow_decrypt) {
    init_flags |= TSS_KEY_TYPE_SIGNING;
  } else {
    init_flags |= TSS_KEY_TYPE_LEGACY;
  }

  ScopedTssKey local_key_handle(overalls_, context);
  RETURN_IF_ERROR(
      MakeStatus<TPM1Error>(overalls_.Ospi_Context_CreateObject(
          context, TSS_OBJECT_TYPE_RSAKEY, init_flags, local_key_handle.ptr())))
      .WithStatus<TPMError>("Failed to call Ospi_Context_CreateObject");

  // Set the attributes
  if (options.allow_sign) {
    uint32_t sig_scheme = TSS_SS_RSASSAPKCS1V15_DER;
    RETURN_IF_ERROR(MakeStatus<TPM1Error>(overalls_.Ospi_SetAttribUint32(
                        local_key_handle, TSS_TSPATTRIB_KEY_INFO,
                        TSS_TSPATTRIB_KEYINFO_SIGSCHEME, sig_scheme)))
        .WithStatus<TPMError>("Failed to call Ospi_SetAttribUint32");
  }

  if (options.allow_decrypt) {
    uint32_t enc_scheme = TSS_ES_RSAESPKCSV15;
    RETURN_IF_ERROR(MakeStatus<TPM1Error>(overalls_.Ospi_SetAttribUint32(
                        local_key_handle, TSS_TSPATTRIB_KEY_INFO,
                        TSS_TSPATTRIB_KEYINFO_ENCSCHEME, enc_scheme)))
        .WithStatus<TPMError>("Failed to call Ospi_SetAttribUint32");
  }

  // Set a random migration policy password, and discard it.  The key will not
  // be migrated, but to create the key outside of the TPM, we have to do it
  // this way.
  ScopedTssPolicy policy_handle(overalls_, context);
  RETURN_IF_ERROR(MakeStatus<TPM1Error>(overalls_.Ospi_Context_CreateObject(
                      context, TSS_OBJECT_TYPE_POLICY, TSS_POLICY_MIGRATION,
                      policy_handle.ptr())))
      .WithStatus<TPMError>("Failed to call Ospi_SetAttribUint32");

  brillo::SecureBlob migration_password =
      CreateSecureRandomBlob(kDefaultDiscardableWrapPasswordLength);
  RETURN_IF_ERROR(MakeStatus<TPM1Error>(overalls_.Ospi_Policy_SetSecret(
                      policy_handle, TSS_SECRET_MODE_PLAIN,
                      migration_password.size(), migration_password.data())))
      .WithStatus<TPMError>("Failed to call Ospi_Policy_SetSecret");

  RETURN_IF_ERROR(MakeStatus<TPM1Error>(overalls_.Ospi_Policy_AssignToObject(
                      policy_handle, local_key_handle)))
      .WithStatus<TPMError>("Failed to call Ospi_Policy_AssignToObject");

  ScopedTssPolicy auth_policy(overalls_, context);
  if (policy.permission.auth_value.has_value()) {
    ASSIGN_OR_RETURN(auth_policy,
                     AddAuthPolicy(overalls_, context, local_key_handle,
                                   policy.permission.auth_value.value()),
                     _.WithStatus<TPMError>("Failed to add auth policy"));
  }

  if (exponent != brillo::Blob(std::begin(kDefaultTpmPublicExponentArray),
                               std::end(kDefaultTpmPublicExponentArray))) {
    RETURN_IF_ERROR(MakeStatus<TPM1Error>(overalls_.Ospi_SetAttribData(
                        local_key_handle, TSS_TSPATTRIB_RSAKEY_INFO,
                        TSS_TSPATTRIB_KEYINFO_RSA_EXPONENT, exponent.size(),
                        exponent.data())))
        .WithStatus<TPMError>("Failed to call Ospi_SetAttribData");
  }

  RETURN_IF_ERROR(
      MakeStatus<TPM1Error>(overalls_.Ospi_SetAttribData(
          local_key_handle, TSS_TSPATTRIB_RSAKEY_INFO,
          TSS_TSPATTRIB_KEYINFO_RSA_MODULUS, modulus.size(), modulus.data())))
      .WithStatus<TPMError>("Failed to call Ospi_SetAttribData");

  RETURN_IF_ERROR(MakeStatus<TPM1Error>(overalls_.Ospi_SetAttribData(
                      local_key_handle, TSS_TSPATTRIB_KEY_BLOB,
                      TSS_TSPATTRIB_KEYBLOB_PRIVATE_KEY, prime_factor.size(),
                      prime_factor.data())))
      .WithStatus<TPMError>("Failed to call Ospi_SetAttribData");

  RETURN_IF_ERROR(MakeStatus<TPM1Error>(overalls_.Ospi_Key_WrapKey(
                      local_key_handle, srk_data.key_handle, 0)))
      .WithStatus<TPMError>("Failed to call Ospi_Key_WrapKey");

  uint32_t length = 0;
  ScopedTssMemory buf(overalls_, context);
  RETURN_IF_ERROR(MakeStatus<TPM1Error>(overalls_.Ospi_GetAttribData(
                      local_key_handle, TSS_TSPATTRIB_KEY_BLOB,
                      TSS_TSPATTRIB_KEYBLOB_BLOB, &length, buf.ptr())))
      .WithStatus<TPMError>("Failed to call Ospi_GetAttribData");

  brillo::Blob key_blob(buf.value(), buf.value() + length);

  ASSIGN_OR_RETURN(
      const OperationPolicy& op_policy, config_.ToOperationPolicy(policy),
      _.WithStatus<TPMError>("Failed to convert setting to policy"));

  // TODO(b/257208272): We should reuse the auth_policy, so we don't need to
  // load it again.
  ASSIGN_OR_RETURN(
      ScopedKey key, LoadKey(op_policy, key_blob, load_key_options),
      _.WithStatus<TPMError>("Failed to load created software RSA key"));

  return CreateKeyResult{
      .key = std::move(key),
      .key_blob = std::move(key_blob),
  };
}

StatusOr<KeyManagementTpm1::CreateKeyResult> KeyManagementTpm1::WrapECCKey(
    const OperationPolicySetting& policy,
    const brillo::Blob& public_point_x,
    const brillo::Blob& public_point_y,
    const brillo::SecureBlob& private_value,
    const LoadKeyOptions& load_key_options,
    const CreateKeyOptions& options) {
  return MakeStatus<TPMError>("Unsupported", TPMRetryAction::kNoRetry);
}

StatusOr<ScopedKey> KeyManagementTpm1::LoadKey(
    const OperationPolicy& policy,
    const brillo::Blob& key_blob,
    const LoadKeyOptions& load_key_options) {
  ASSIGN_OR_RETURN(KeyPolicyPair result, LoadKeyBlob(policy, key_blob),
                   _.WithStatus<TPMError>("Failed to load key blob"));

  uint32_t key_handle = result.tss_key.value();

  KeyTpm1::Type key_type = KeyTpm1::Type::kTransientKey;
  std::optional<KeyReloadDataTpm1> reload_data;
  if (load_key_options.auto_reload == true) {
    key_type = KeyTpm1::Type::kReloadableTransientKey;
    reload_data = KeyReloadDataTpm1{
        .policy = policy,
        .key_blob = key_blob,
    };
  }

  return LoadKeyInternal(key_type, key_handle, std::move(result), reload_data);
}

StatusOr<KeyManagementTpm1::KeyPolicyPair> KeyManagementTpm1::LoadKeyBlob(
    const OperationPolicy& policy, const brillo::Blob& key_blob) {
  ASSIGN_OR_RETURN(ScopedKey srk,
                   GetPersistentKey(PersistentKeyType::kStorageRootKey));

  ASSIGN_OR_RETURN(const KeyTpm1& srk_data, GetKeyData(srk.GetKey()));

  ASSIGN_OR_RETURN(TSS_HCONTEXT context, tss_helper_.GetTssContext());

  ScopedTssKey local_key_handle(overalls_, context);
  brillo::Blob mutable_key_blob = key_blob;
  RETURN_IF_ERROR(MakeStatus<TPM1Error>(overalls_.Ospi_Context_LoadKeyByBlob(
                      context, srk_data.key_handle, mutable_key_blob.size(),
                      mutable_key_blob.data(), local_key_handle.ptr())))
      .WithStatus<TPMError>("Failed to call Ospi_Context_LoadKeyByBlob");

  ScopedTssPolicy auth_policy(overalls_, context);
  if (policy.permission.auth_value.has_value()) {
    ASSIGN_OR_RETURN(
        auth_policy,
        AddAuthPolicy(overalls_, context, local_key_handle,
                      policy.permission.auth_value.value()),
        _.WithStatus<TPMError>("Failed to add auth policy for load key"));
  }

  return KeyPolicyPair{
      .tss_key = std::move(local_key_handle),
      .tss_policy = std::move(auth_policy),
  };
}

StatusOr<ScopedKey> KeyManagementTpm1::GetPolicyEndorsementKey(
    const OperationPolicySetting& policy, KeyAlgoType key_algo) {
  return MakeStatus<TPMError>("Unsupported policy endorsement key",
                              TPMRetryAction::kNoRetry);
}

StatusOr<ScopedKey> KeyManagementTpm1::GetPersistentKey(
    PersistentKeyType key_type) {
  auto it = persistent_key_map_.find(key_type);
  if (it != persistent_key_map_.end()) {
    return ScopedKey(Key{.token = it->second}, middleware_derivative_);
  }

  uint32_t key_handle = 0;

  switch (key_type) {
    case PersistentKeyType::kStorageRootKey: {
      ASSIGN_OR_RETURN(key_handle, GetSrk(),
                       _.WithStatus<TPMError>("Failed to get SRK"));
    } break;
    default:
      return MakeStatus<TPMError>("Unknown persistent key type",
                                  TPMRetryAction::kNoRetry);
  }

  ASSIGN_OR_RETURN(
      ScopedKey key,
      LoadKeyInternal(KeyTpm1::Type::kPersistentKey, key_handle,
                      /*key_policy_pair=*/std::nullopt,
                      /*reload_data=*/std::nullopt),
      _.WithStatus<TPMError>("Failed to side load persistent key"));

  persistent_key_map_[key_type] = key.GetKey().token;
  return key;
}

StatusOr<brillo::Blob> KeyManagementTpm1::GetPubkeyHash(Key key) {
  ASSIGN_OR_RETURN(const KeyTpm1& key_data, GetKeyData(key));

  return Sha1(key_data.cache.pubkey_blob);
}

StatusOr<RSAPublicInfo> KeyManagementTpm1::GetRSAPublicInfo(Key key) {
  ASSIGN_OR_RETURN(const KeyTpm1& key_data, GetKeyData(key));

  ASSIGN_OR_RETURN(TSS_HCONTEXT context, tss_helper_.GetTssContext());

  uint32_t exponent_len = 0;
  ScopedTssMemory exponent(overalls_, context);
  RETURN_IF_ERROR(
      MakeStatus<TPM1Error>(overalls_.Ospi_GetAttribData(
          key_data.key_handle, TSS_TSPATTRIB_RSAKEY_INFO,
          TSS_TSPATTRIB_KEYINFO_RSA_EXPONENT, &exponent_len, exponent.ptr())))
      .WithStatus<TPMError>("Failed to call Ospi_GetAttribData");

  uint32_t modulus_len = 0;
  ScopedTssMemory modulus(overalls_, context);
  RETURN_IF_ERROR(
      MakeStatus<TPM1Error>(overalls_.Ospi_GetAttribData(
          key_data.key_handle, TSS_TSPATTRIB_RSAKEY_INFO,
          TSS_TSPATTRIB_KEYINFO_RSA_MODULUS, &modulus_len, modulus.ptr())))
      .WithStatus<TPMError>("Failed to call Ospi_GetAttribData");

  return RSAPublicInfo{
      .exponent =
          brillo::Blob(exponent.value(), exponent.value() + exponent_len),
      .modulus = brillo::Blob(modulus.value(), modulus.value() + modulus_len),
  };
}

StatusOr<ECCPublicInfo> KeyManagementTpm1::GetECCPublicInfo(Key key) {
  return MakeStatus<TPMError>("Unsupported", TPMRetryAction::kNoRetry);
}

StatusOr<ScopedKey> KeyManagementTpm1::SideLoadKey(uint32_t key_handle) {
  return LoadKeyInternal(KeyTpm1::Type::kPersistentKey, key_handle,
                         /*key_policy_pair=*/std::nullopt,
                         /*reload_data=*/std::nullopt);
}

StatusOr<uint32_t> KeyManagementTpm1::GetKeyHandle(Key key) {
  ASSIGN_OR_RETURN(const KeyTpm1& key_data, GetKeyData(key));

  return key_data.key_handle;
}

StatusOr<brillo::Blob> KeyManagementTpm1::GetPubkeyBlob(uint32_t key_handle) {
  ASSIGN_OR_RETURN(TSS_HCONTEXT context, tss_helper_.GetTssContext());

  uint32_t size;
  ScopedTssMemory public_blob(overalls_, context);
  RETURN_IF_ERROR(MakeStatus<TPM1Error>(overalls_.Ospi_Key_GetPubKey(
                      key_handle, &size, public_blob.ptr())))
      .WithStatus<TPMError>("Failed to call Ospi_Key_GetPubKey");

  return brillo::Blob(public_blob.value(), public_blob.value() + size);
}

StatusOr<ScopedKey> KeyManagementTpm1::LoadKeyInternal(
    KeyTpm1::Type key_type,
    uint32_t key_handle,
    std::optional<KeyPolicyPair> key_policy_pair,
    std::optional<KeyReloadDataTpm1> reload_data) {
  ASSIGN_OR_RETURN(brillo::Blob && pubkey_blob, GetPubkeyBlob(key_handle),
                   _.WithStatus<TPMError>("Failed to get pubkey blob"));

  std::optional<ScopedTssKey> scoped_key;
  std::optional<ScopedTssPolicy> scoped_policy;
  if (key_policy_pair.has_value()) {
    scoped_key = std::move(key_policy_pair->tss_key);
    scoped_policy = std::move(key_policy_pair->tss_policy);
  }

  KeyToken token = current_token_++;
  key_map_.emplace(token, KeyTpm1{
                              .type = key_type,
                              .key_handle = key_handle,
                              .cache =
                                  KeyTpm1::Cache{
                                      .pubkey_blob = std::move(pubkey_blob),
                                  },
                              .scoped_key = std::move(scoped_key),
                              .scoped_policy = std::move(scoped_policy),
                              .reload_data = std::move(reload_data),
                          });

  return ScopedKey(Key{.token = token}, middleware_derivative_);
}

Status KeyManagementTpm1::Flush(Key key) {
  ASSIGN_OR_RETURN(const KeyTpm1& key_data, GetKeyData(key));

  switch (key_data.type) {
    case KeyTpm1::Type::kPersistentKey:
      // We don't need to unload these kinds of key.
      return OkStatus();

    case KeyTpm1::Type::kTransientKey:
    case KeyTpm1::Type::kReloadableTransientKey:
      key_map_.erase(key.token);
      return OkStatus();

    default:
      return MakeStatus<TPMError>("Unknown key type", TPMRetryAction::kNoRetry);
  }
}

StatusOr<std::reference_wrapper<KeyTpm1>> KeyManagementTpm1::GetKeyData(
    Key key) {
  auto it = key_map_.find(key.token);
  if (it == key_map_.end()) {
    return MakeStatus<TPMError>("Unknown key", TPMRetryAction::kNoRetry);
  }
  return it->second;
}

Status KeyManagementTpm1::ReloadIfPossible(Key key) {
  ASSIGN_OR_RETURN(KeyTpm1 & key_data, GetKeyData(key));

  if (key_data.type != KeyTpm1::Type::kReloadableTransientKey) {
    // We don't need to reload un-reloadable key.
    return OkStatus();
  }

  if (!key_data.reload_data.has_value()) {
    return MakeStatus<TPMError>("Empty reload data", TPMRetryAction::kNoRetry);
  }

  ASSIGN_OR_RETURN(
      KeyPolicyPair result,
      LoadKeyBlob(key_data.reload_data->policy, key_data.reload_data->key_blob),
      _.WithStatus<TPMError>("Failed to load key blob"));

  key_data.key_handle = result.tss_key.value();
  key_data.scoped_key = std::move(result.tss_key);
  key_data.scoped_policy = std::move(result.tss_policy);

  return OkStatus();
}

StatusOr<uint32_t> KeyManagementTpm1::GetSrk() {
  if (srk_cache_.has_value()) {
    return srk_cache_->value();
  }

  ASSIGN_OR_RETURN(TSS_HCONTEXT context, tss_helper_.GetTssContext());

  // Load the Storage Root Key
  TSS_UUID SRK_UUID = TSS_UUID_SRK;
  ScopedTssKey local_srk_handle(overalls_, context);
  RETURN_IF_ERROR(
      MakeStatus<TPM1Error>(overalls_.Ospi_Context_LoadKeyByUUID(
          context, TSS_PS_TYPE_SYSTEM, SRK_UUID, local_srk_handle.ptr())))
      .WithStatus<TPMError>("Failed to call Ospi_Context_LoadKeyByUUID");

  // Check if the SRK wants a password
  uint32_t srk_authusage;
  RETURN_IF_ERROR(MakeStatus<TPM1Error>(overalls_.Ospi_GetAttribUint32(
                      local_srk_handle, TSS_TSPATTRIB_KEY_INFO,
                      TSS_TSPATTRIB_KEYINFO_AUTHUSAGE, &srk_authusage)))
      .WithStatus<TPMError>("Failed to call Ospi_GetAttribUint32");

  // Give it the password if needed
  if (srk_authusage) {
    TSS_HPOLICY srk_usage_policy;
    RETURN_IF_ERROR(MakeStatus<TPM1Error>(overalls_.Ospi_GetPolicyObject(
                        local_srk_handle, TSS_POLICY_USAGE, &srk_usage_policy)))
        .WithStatus<TPMError>("Failed to call Ospi_GetPolicyObject");

    brillo::Blob srk_auth(kDefaultSrkAuth,
                          kDefaultSrkAuth + sizeof(kDefaultSrkAuth));
    RETURN_IF_ERROR(MakeStatus<TPM1Error>(overalls_.Ospi_Policy_SetSecret(
                        srk_usage_policy, TSS_SECRET_MODE_PLAIN,
                        srk_auth.size(), srk_auth.data())))
        .WithStatus<TPMError>("Failed to call Ospi_Policy_SetSecret");
  }

  srk_cache_ = std::move(local_srk_handle);
  return srk_cache_->value();
}

StatusOr<ScopedKey> KeyManagementTpm1::CreateRsaPublicKeyObject(
    brillo::Blob key_modulus,
    uint32_t key_flags,
    uint32_t signature_scheme,
    uint32_t encryption_scheme) {
  ASSIGN_OR_RETURN(TSS_HCONTEXT context, tss_helper_.GetTssContext());

  ScopedTssKey local_key_handle(overalls_, context);
  RETURN_IF_ERROR(
      MakeStatus<TPM1Error>(overalls_.Ospi_Context_CreateObject(
          context, TSS_OBJECT_TYPE_RSAKEY, key_flags, local_key_handle.ptr())))
      .WithStatus<TPMError>("Failed to call Ospi_Context_CreateObject");

  RETURN_IF_ERROR(MakeStatus<TPM1Error>(overalls_.Ospi_SetAttribData(
                      local_key_handle, TSS_TSPATTRIB_RSAKEY_INFO,
                      TSS_TSPATTRIB_KEYINFO_RSA_MODULUS, key_modulus.size(),
                      key_modulus.data())))
      .WithStatus<TPMError>("Failed to call Ospi_SetAttribData");

  if (signature_scheme != TSS_SS_NONE) {
    RETURN_IF_ERROR(MakeStatus<TPM1Error>(overalls_.Ospi_SetAttribUint32(
                        local_key_handle, TSS_TSPATTRIB_KEY_INFO,
                        TSS_TSPATTRIB_KEYINFO_SIGSCHEME, signature_scheme)))
        .WithStatus<TPMError>("Failed to call Ospi_SetAttribUint32");
  }

  if (encryption_scheme != TSS_ES_NONE) {
    RETURN_IF_ERROR(MakeStatus<TPM1Error>(overalls_.Ospi_SetAttribUint32(
                        local_key_handle, TSS_TSPATTRIB_KEY_INFO,
                        TSS_TSPATTRIB_KEYINFO_ENCSCHEME, encryption_scheme)))
        .WithStatus<TPMError>("Failed to call Ospi_SetAttribUint32");
  }

  uint32_t key_handle = local_key_handle.value();

  KeyToken token = current_token_++;
  key_map_.emplace(
      token,
      KeyTpm1{
          .type = KeyTpm1::Type::kTransientKey,
          .key_handle = key_handle,
          .cache =
              KeyTpm1::Cache{
                  // RSA public key object would not have valid pubkey blob.
                  .pubkey_blob = brillo::Blob(),
              },
          .scoped_key = std::move(local_key_handle),
          .reload_data = std::nullopt,
      });

  return ScopedKey(Key{.token = token}, middleware_derivative_);
}

StatusOr<ScopedKey> KeyManagementTpm1::LoadPublicKeyFromSpki(
    const brillo::Blob& public_key_spki_der,
    uint32_t signature_scheme,
    uint32_t encryption_scheme) {
  ASSIGN_OR_RETURN(RsaParameters public_key, ParseSpkiDer(public_key_spki_der));

  if (public_key.key_exponent != kWellKnownExponent) {
    // Trousers only supports the well-known exponent, failing internally on
    // incorrect data serialization when other exponents are used.
    return MakeStatus<TPMError>("Unsupported key exponent",
                                TPMRetryAction::kNoRetry);
  }

  uint32_t key_size_flag = 0;
  const size_t key_size_bits =
      public_key.key_modulus.size() * /*bits per byte*/ 8;
  switch (key_size_bits) {
    case 1024:
      key_size_flag = TSS_KEY_SIZE_1024;
      break;
    case 2048:
      key_size_flag = TSS_KEY_SIZE_2048;
      break;
    default:
      return MakeStatus<TPMError>("Unsupported key size",
                                  TPMRetryAction::kNoRetry);
  }

  return CreateRsaPublicKeyObject(
      public_key.key_modulus,
      TSS_KEY_VOLATILE | TSS_KEY_TYPE_SIGNING | key_size_flag, signature_scheme,
      encryption_scheme);
}

}  // namespace hwsec
