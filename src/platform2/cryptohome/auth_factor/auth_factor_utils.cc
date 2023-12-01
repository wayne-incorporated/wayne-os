// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/auth_factor/auth_factor_utils.h"

#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <variant>
#include <vector>

#include <base/system/sys_info.h>
#include <cryptohome/proto_bindings/auth_factor.pb.h>

#include "cryptohome/auth_factor/auth_factor.h"
#include "cryptohome/auth_factor/auth_factor_label.h"
#include "cryptohome/auth_factor/auth_factor_label_arity.h"
#include "cryptohome/auth_factor/auth_factor_metadata.h"
#include "cryptohome/auth_factor/auth_factor_prepare_purpose.h"
#include "cryptohome/auth_factor/auth_factor_type.h"
#include "cryptohome/auth_session_protobuf.h"
#include "cryptohome/features.h"
#include "cryptohome/flatbuffer_schemas/auth_factor.h"

namespace cryptohome {
namespace {

// Set password metadata here, which happens to be empty. For other types of
// factors, there will be more computations involved.
void GetPasswordMetadata(const user_data_auth::AuthFactor& auth_factor,
                         AuthFactorMetadata& out_auth_factor_metadata) {
  out_auth_factor_metadata.metadata = auth_factor::PasswordMetadata();
}

// Set pin metadata here, which happens to be empty.
void GetPinMetadata(const user_data_auth::AuthFactor& auth_factor,
                    AuthFactorMetadata& out_auth_factor_metadata) {
  out_auth_factor_metadata.metadata = auth_factor::PinMetadata();
}

// Set cryptohome recovery metadata here, which happens to be empty.
void GetCryptohomeRecoveryMetadata(
    const user_data_auth::AuthFactor& auth_factor,
    AuthFactorMetadata& out_auth_factor_metadata) {
  out_auth_factor_metadata.metadata = auth_factor::CryptohomeRecoveryMetadata();
}

// Set kiosk metadata here.
void GetKioskMetadata(const user_data_auth::AuthFactor& auth_factor,
                      AuthFactorMetadata& out_auth_factor_metadata) {
  out_auth_factor_metadata.metadata = auth_factor::KioskMetadata();
}

// Set smart card metadata here, which includes public_key_spki_der.
void GetSmartCardMetadata(const user_data_auth::AuthFactor& auth_factor,
                          AuthFactorMetadata& out_auth_factor_metadata) {
  out_auth_factor_metadata.metadata = auth_factor::SmartCardMetadata{
      .public_key_spki_der = brillo::BlobFromString(
          auth_factor.smart_card_metadata().public_key_spki_der())};
}

void GetFingerprintMetadata(const user_data_auth::AuthFactor& auth_factor,
                            AuthFactorMetadata& out_auth_factor_metadata) {
  out_auth_factor_metadata.metadata = auth_factor::FingerprintMetadata();
}

auth_factor::LockoutPolicy LockoutPolicyFromAuthFactorProto(
    const user_data_auth::LockoutPolicy& policy) {
  switch (policy) {
    case user_data_auth::LOCKOUT_POLICY_ATTEMPT_LIMITED:
      return auth_factor::LockoutPolicy::ATTEMPT_LIMITED;
    case user_data_auth::LOCKOUT_POLICY_TIME_LIMITED:
      return auth_factor::LockoutPolicy::TIME_LIMITED;
    case user_data_auth::LOCKOUT_POLICY_NONE:
    // Usually, LOCKOUT_POLICY_UNKNOWN will will be an error for invalid
    // argument, but until chrome implements the change, we will continue to
    // keep it default to kNoLockout.
    case user_data_auth::LOCKOUT_POLICY_UNKNOWN:
    // Default covers for proto min and max.
    default:
      return auth_factor::LockoutPolicy::NO_LOCKOUT;
  }
}
}  // namespace

void PopulateAuthFactorProtoWithSysinfo(
    user_data_auth::AuthFactor& auth_factor) {
  // Populate the ChromeOS version. Note that reading GetLsbReleaseValue can
  // fail but in that case we still populate the metadata with an empty string.
  std::string chromeos_version;
  base::SysInfo::GetLsbReleaseValue("CHROMEOS_RELEASE_VERSION",
                                    &chromeos_version);
  auth_factor.mutable_common_metadata()->set_chromeos_version_last_updated(
      std::move(chromeos_version));
}

bool GetAuthFactorMetadata(const user_data_auth::AuthFactor& auth_factor,
                           const AsyncInitFeatures& features_lib,
                           AuthFactorMetadata& out_auth_factor_metadata,
                           AuthFactorType& out_auth_factor_type,
                           std::string& out_auth_factor_label) {
  // Extract the common metadata.
  out_auth_factor_metadata.common.chromeos_version_last_updated =
      auth_factor.common_metadata().chromeos_version_last_updated();
  out_auth_factor_metadata.common.chrome_version_last_updated =
      auth_factor.common_metadata().chrome_version_last_updated();
  out_auth_factor_metadata.common.lockout_policy =
      LockoutPolicyFromAuthFactorProto(
          auth_factor.common_metadata().lockout_policy());
  out_auth_factor_metadata.common.user_specified_name =
      auth_factor.common_metadata().user_specified_name();

  // Extract the factor type and use it to try and extract the factor-specific
  // metadata. Returns false if this fails.
  switch (auth_factor.type()) {
    case user_data_auth::AUTH_FACTOR_TYPE_PASSWORD:
      DCHECK(auth_factor.has_password_metadata());
      GetPasswordMetadata(auth_factor, out_auth_factor_metadata);
      out_auth_factor_type = AuthFactorType::kPassword;
      break;
    case user_data_auth::AUTH_FACTOR_TYPE_PIN:
      DCHECK(auth_factor.has_pin_metadata());
      GetPinMetadata(auth_factor, out_auth_factor_metadata);
      out_auth_factor_type = AuthFactorType::kPin;
      if (features_lib.IsFeatureEnabled(Features::kModernPin) &&
          out_auth_factor_metadata.common.lockout_policy !=
              auth_factor::LockoutPolicy::TIME_LIMITED) {
        LOG(ERROR) << "Lockout policy not set when modern pin is enabled "
                   << auth_factor.type();
        return false;
      }
      break;
    case user_data_auth::AUTH_FACTOR_TYPE_CRYPTOHOME_RECOVERY:
      DCHECK(auth_factor.has_cryptohome_recovery_metadata());
      GetCryptohomeRecoveryMetadata(auth_factor, out_auth_factor_metadata);
      out_auth_factor_type = AuthFactorType::kCryptohomeRecovery;
      break;
    case user_data_auth::AUTH_FACTOR_TYPE_KIOSK:
      DCHECK(auth_factor.has_kiosk_metadata());
      GetKioskMetadata(auth_factor, out_auth_factor_metadata);
      out_auth_factor_type = AuthFactorType::kKiosk;
      break;
    case user_data_auth::AUTH_FACTOR_TYPE_SMART_CARD:
      DCHECK(auth_factor.has_smart_card_metadata());
      GetSmartCardMetadata(auth_factor, out_auth_factor_metadata);
      out_auth_factor_type = AuthFactorType::kSmartCard;
      break;
    case user_data_auth::AUTH_FACTOR_TYPE_LEGACY_FINGERPRINT:
      DCHECK(auth_factor.has_legacy_fingerprint_metadata());
      // Legacy fingerprint factor has empty metadata, skip the metadata
      // extraction.
      out_auth_factor_type = AuthFactorType::kLegacyFingerprint;
      break;
    case user_data_auth::AUTH_FACTOR_TYPE_FINGERPRINT:
      DCHECK(auth_factor.has_fingerprint_metadata());
      GetFingerprintMetadata(auth_factor, out_auth_factor_metadata);
      out_auth_factor_type = AuthFactorType::kFingerprint;
      break;
    default:
      LOG(ERROR) << "Unknown auth factor type " << auth_factor.type();
      return false;
  }

  // Extract the label. Returns false if it isn't formatted correctly.
  out_auth_factor_label = auth_factor.label();
  if (!IsValidAuthFactorLabel(out_auth_factor_label)) {
    LOG(ERROR) << "Invalid auth factor label";
    return false;
  }

  return true;
}

bool LoadUserAuthFactorByLabel(AuthFactorDriverManager* driver_manager,
                               AuthFactorManager* manager,
                               const AuthBlockUtility& auth_block_utility,
                               const ObfuscatedUsername& obfuscated_username,
                               const std::string& factor_label,
                               user_data_auth::AuthFactor* out_auth_factor) {
  for (const auto& [label, auth_factor_type] :
       manager->ListAuthFactors(obfuscated_username)) {
    if (label == factor_label) {
      CryptohomeStatusOr<std::unique_ptr<AuthFactor>> owned_auth_factor =
          manager->LoadAuthFactor(obfuscated_username, auth_factor_type, label);
      if (!owned_auth_factor.ok() || *owned_auth_factor == nullptr) {
        return false;
      }

      AuthFactor& auth_factor = **owned_auth_factor;
      const AuthFactorDriver& factor_driver =
          driver_manager->GetDriver(auth_factor.type());

      auto auth_factor_proto = factor_driver.ConvertToProto(
          auth_factor.label(), auth_factor.metadata());
      if (!auth_factor_proto) {
        return false;
      }
      *out_auth_factor = std::move(*auth_factor_proto);
      return true;
    }
  }
  return false;
}

std::optional<AuthFactorPreparePurpose> AuthFactorPreparePurposeFromProto(
    user_data_auth::AuthFactorPreparePurpose purpose) {
  switch (purpose) {
    case user_data_auth::PURPOSE_AUTHENTICATE_AUTH_FACTOR:
      return AuthFactorPreparePurpose::kPrepareAuthenticateAuthFactor;
    case user_data_auth::PURPOSE_ADD_AUTH_FACTOR:
      return AuthFactorPreparePurpose::kPrepareAddAuthFactor;
    default:
      return std::nullopt;
  }
}

AuthFactorMap LoadAuthFactorMap(bool is_uss_migration_enabled,
                                const ObfuscatedUsername& obfuscated_username,
                                Platform& platform,
                                AuthFactorVaultKeysetConverter& converter,
                                AuthFactorManager& manager) {
  AuthFactorMap auth_factor_map;

  // Load all the VaultKeysets and backup VaultKeysets in disk and convert
  // them to AuthFactor format.
  std::map<std::string, std::unique_ptr<AuthFactor>> backup_factor_map;
  std::map<std::string, std::unique_ptr<AuthFactor>> vk_factor_map;
  std::vector<std::string> migrated_labels;

  converter.VaultKeysetsToAuthFactorsAndKeyLabelData(
      obfuscated_username, migrated_labels, vk_factor_map, backup_factor_map);
  // Load the USS AuthFactors.
  std::map<std::string, std::unique_ptr<AuthFactor>> uss_factor_map =
      manager.LoadAllAuthFactors(obfuscated_username);

  // UserSecretStash is enabled: merge VaultKeyset-AuthFactors with
  // USS-AuthFactors
  if (IsUserSecretStashExperimentEnabled(&platform)) {
    for (auto& [unused, factor] : uss_factor_map) {
      auth_factor_map.Add(std::move(factor),
                          AuthFactorStorageType::kUserSecretStash);
    }
    // If USS migration is disabled, but USS is still enabled only the migrated
    // AuthFactors should be rolled back. Override the AuthFactor with the
    // migrated VaultKeyset in this case.
    if (!is_uss_migration_enabled) {
      for (auto migrated_label : migrated_labels) {
        auto backup_factor_iter = backup_factor_map.find(migrated_label);
        if (backup_factor_iter != backup_factor_map.end()) {
          auth_factor_map.Add(std::move(backup_factor_iter->second),
                              AuthFactorStorageType::kVaultKeyset);
        }
      }
    }
  } else {
    // UserSecretStash is disabled: merge VaultKeyset-AuthFactors with
    // backup-VaultKeyset-AuthFactors.
    for (auto& [unused, factor] : backup_factor_map) {
      auth_factor_map.Add(std::move(factor),
                          AuthFactorStorageType::kVaultKeyset);
    }
  }

  // Duplicate labels are not expected on any use case. However in very rare
  // edge cases where an interrupted USS migration results in having both
  // regular VaultKeyset and USS factor in disk it is safer to use the original
  // VaultKeyset. In that case regular VaultKeyset overrides the existing
  // label in the map.
  for (auto& [unused, factor] : vk_factor_map) {
    if (auth_factor_map.Find(factor->label())) {
      LOG(WARNING) << "Unexpected duplication of label: " << factor->label()
                   << ". Regular VaultKeyset will override the AuthFactor.";
    }
    auth_factor_map.Add(std::move(factor), AuthFactorStorageType::kVaultKeyset);
  }

  return auth_factor_map;
}

}  // namespace cryptohome
