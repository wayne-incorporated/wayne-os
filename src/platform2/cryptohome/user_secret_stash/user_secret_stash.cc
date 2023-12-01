// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/user_secret_stash/user_secret_stash.h"

#include <base/check.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/memory/ptr_util.h>
#include <base/notreached.h>
#include <base/system/sys_info.h>
#include <brillo/secure_blob.h>
#include <libhwsec-foundation/crypto/aes.h>
#include <libhwsec-foundation/crypto/secure_blob_util.h>

#include <map>
#include <memory>
#include <optional>
#include <stdint.h>
#include <string>
#include <utility>
#include <vector>

#include "cryptohome/auth_factor/auth_factor_type.h"
#include "cryptohome/cryptohome_metrics.h"
#include "cryptohome/error/location_utils.h"
#include "cryptohome/filesystem_layout.h"
#include "cryptohome/flatbuffer_schemas/user_secret_stash_container.h"
#include "cryptohome/flatbuffer_schemas/user_secret_stash_payload.h"
#include "cryptohome/storage/encrypted_container/filesystem_key.h"
#include "cryptohome/storage/file_system_keyset.h"

using ::cryptohome::error::CryptohomeError;
using ::cryptohome::error::ErrorActionSet;
using ::cryptohome::error::PossibleAction;
using ::cryptohome::error::PrimaryAction;
using ::hwsec_foundation::AesGcmDecrypt;
using ::hwsec_foundation::AesGcmEncrypt;
using ::hwsec_foundation::CreateSecureRandomBlob;
using ::hwsec_foundation::kAesGcm256KeySize;
using ::hwsec_foundation::kAesGcmIVSize;
using ::hwsec_foundation::kAesGcmTagSize;
using ::hwsec_foundation::status::MakeStatus;
using ::hwsec_foundation::status::OkStatus;
using ::hwsec_foundation::status::StatusChain;

namespace cryptohome {
namespace {

constexpr char kEnableUssFeatureTestFlagName[] = "uss_enabled";
constexpr char kDisableUssFeatureTestFlagName[] = "uss_disabled";

std::optional<bool>& GetUserSecretStashExperimentOverride() {
  // The static variable holding the overridden state. The default state is
  // nullopt, which fallbacks to checking whether flag file exists.
  static std::optional<bool> uss_experiment_enabled;
  return uss_experiment_enabled;
}

bool EnableUssFeatureTestFlagFileExists(Platform* platform) {
  return DoesFlagFileExist(kEnableUssFeatureTestFlagName, platform);
}

bool DisableUssFeatureTestFlagFileExists(Platform* platform) {
  return DoesFlagFileExist(kDisableUssFeatureTestFlagName, platform);
}

// Loads the current OS version from the CHROMEOS_RELEASE_VERSION field in
// /etc/lsb-release. Returns an empty string on failure.
std::string GetCurrentOsVersion() {
  std::string version;
  if (!base::SysInfo::GetLsbReleaseValue("CHROMEOS_RELEASE_VERSION",
                                         &version)) {
    return std::string();
  }
  return version;
}

// Returns the UserSecretStash experiment flag value.
UssExperimentFlag UserSecretStashExperimentResult(Platform* platform) {
  // 1. If the state is overridden by unit tests, return this value.
  if (GetUserSecretStashExperimentOverride().has_value()) {
    return GetUserSecretStashExperimentOverride().value()
               ? UssExperimentFlag::kEnabled
               : UssExperimentFlag::kDisabled;
  }
  // 2. If no unittest override defer to checking the feature test file
  // existence. The disable file precedes the enable file.
  if (DisableUssFeatureTestFlagFileExists(platform)) {
    return UssExperimentFlag::kDisabled;
  }
  if (EnableUssFeatureTestFlagFileExists(platform)) {
    return UssExperimentFlag::kEnabled;
  }
  // 3. Without overrides, the behavior is to always enable UserSecretStash
  // experiment.
  return UssExperimentFlag::kEnabled;
}

// Extracts the file system keyset from the given USS payload. Returns nullopt
// on failure.
CryptohomeStatusOr<FileSystemKeyset> GetFileSystemKeyFromPayload(
    const UserSecretStashPayload& uss_payload) {
  if (uss_payload.fek.empty()) {
    LOG(ERROR) << "UserSecretStashPayload has no FEK";
    return MakeStatus<CryptohomeError>(
        CRYPTOHOME_ERR_LOC(kLocUSSNoFEKInGetFSKeyFromPayload),
        ErrorActionSet({PossibleAction::kDevCheckUnexpectedState}),
        user_data_auth::CRYPTOHOME_ERROR_BACKING_STORE_FAILURE);
  }
  if (uss_payload.fnek.empty()) {
    LOG(ERROR) << "UserSecretStashPayload has no FNEK";
    return MakeStatus<CryptohomeError>(
        CRYPTOHOME_ERR_LOC(kLocUSSNoFNEKInGetFSKeyFromPayload),
        ErrorActionSet({PossibleAction::kDevCheckUnexpectedState}),
        user_data_auth::CRYPTOHOME_ERROR_BACKING_STORE_FAILURE);
  }
  if (uss_payload.fek_salt.empty()) {
    LOG(ERROR) << "UserSecretStashPayload has no FEK salt";
    return MakeStatus<CryptohomeError>(
        CRYPTOHOME_ERR_LOC(kLocUSSNoFEKSaltInGetFSKeyFromPayload),
        ErrorActionSet({PossibleAction::kDevCheckUnexpectedState}),
        user_data_auth::CRYPTOHOME_ERROR_BACKING_STORE_FAILURE);
  }
  if (uss_payload.fnek_salt.empty()) {
    LOG(ERROR) << "UserSecretStashPayload has no FNEK salt";
    return MakeStatus<CryptohomeError>(
        CRYPTOHOME_ERR_LOC(kLocUSSNoFNEKSaltInGetFSKeyFromPayload),
        ErrorActionSet({PossibleAction::kDevCheckUnexpectedState}),
        user_data_auth::CRYPTOHOME_ERROR_BACKING_STORE_FAILURE);
  }
  if (uss_payload.fek_sig.empty()) {
    LOG(ERROR) << "UserSecretStashPayload has no FEK signature";
    return MakeStatus<CryptohomeError>(
        CRYPTOHOME_ERR_LOC(kLocUSSNoFEKSigInGetFSKeyFromPayload),
        ErrorActionSet({PossibleAction::kDevCheckUnexpectedState}),
        user_data_auth::CRYPTOHOME_ERROR_BACKING_STORE_FAILURE);
  }
  if (uss_payload.fnek_sig.empty()) {
    LOG(ERROR) << "UserSecretStashPayload has no FNEK signature";
    return MakeStatus<CryptohomeError>(
        CRYPTOHOME_ERR_LOC(kLocUSSNoFNEKSigInGetFSKeyFromPayload),
        ErrorActionSet({PossibleAction::kDevCheckUnexpectedState}),
        user_data_auth::CRYPTOHOME_ERROR_BACKING_STORE_FAILURE);
  }
  if (uss_payload.chaps_key.empty()) {
    LOG(ERROR) << "UserSecretStashPayload has no Chaps key";
    return MakeStatus<CryptohomeError>(
        CRYPTOHOME_ERR_LOC(kLocUSSNoChapsKeyInGetFSKeyFromPayload),
        ErrorActionSet({PossibleAction::kDevCheckUnexpectedState}),
        user_data_auth::CRYPTOHOME_ERROR_BACKING_STORE_FAILURE);
  }
  FileSystemKey file_system_key = {
      .fek = uss_payload.fek,
      .fnek = uss_payload.fnek,
      .fek_salt = uss_payload.fek_salt,
      .fnek_salt = uss_payload.fnek_salt,
  };
  FileSystemKeyReference file_system_key_reference = {
      .fek_sig = uss_payload.fek_sig,
      .fnek_sig = uss_payload.fnek_sig,
  };
  return FileSystemKeyset(std::move(file_system_key),
                          std::move(file_system_key_reference),
                          uss_payload.chaps_key);
}

// Converts the wrapped key block information from serializable structs
// (autogenerated by the Python script) into the mapping from wrapping_id to
// `UserSecretStash::WrappedKeyBlock`.
// Malformed and duplicate entries are logged and skipped.
std::map<std::string, UserSecretStash::WrappedKeyBlock>
GetKeyBlocksFromSerializableStructs(
    const std::vector<UserSecretStashWrappedKeyBlock>& serializable_blocks) {
  std::map<std::string, UserSecretStash::WrappedKeyBlock> key_blocks;

  for (const UserSecretStashWrappedKeyBlock& serializable_block :
       serializable_blocks) {
    if (serializable_block.wrapping_id.empty()) {
      LOG(WARNING)
          << "Ignoring UserSecretStash wrapped key block with an empty ID.";
      continue;
    }
    if (key_blocks.count(serializable_block.wrapping_id)) {
      LOG(WARNING)
          << "Ignoring UserSecretStash wrapped key block with duplicate ID "
          << serializable_block.wrapping_id << ".";
      continue;
    }

    if (!serializable_block.encryption_algorithm.has_value()) {
      LOG(WARNING) << "Ignoring UserSecretStash wrapped key block with an "
                      "unset algorithm";
      continue;
    }
    if (serializable_block.encryption_algorithm.value() !=
        UserSecretStashEncryptionAlgorithm::AES_GCM_256) {
      LOG(WARNING) << "Ignoring UserSecretStash wrapped key block with an "
                      "unknown algorithm: "
                   << static_cast<int>(
                          serializable_block.encryption_algorithm.value());
      continue;
    }

    if (serializable_block.encrypted_key.empty()) {
      LOG(WARNING) << "Ignoring UserSecretStash wrapped key block with an "
                      "empty encrypted key.";
      continue;
    }

    if (serializable_block.iv.empty()) {
      LOG(WARNING)
          << "Ignoring UserSecretStash wrapped key block with an empty IV.";
      continue;
    }

    if (serializable_block.gcm_tag.empty()) {
      LOG(WARNING) << "Ignoring UserSecretStash wrapped key block with an "
                      "empty AES-GCM tag.";
      continue;
    }

    UserSecretStash::WrappedKeyBlock key_block = {
        .encryption_algorithm = serializable_block.encryption_algorithm.value(),
        .encrypted_key = serializable_block.encrypted_key,
        .iv = serializable_block.iv,
        .gcm_tag = serializable_block.gcm_tag,
    };
    key_blocks.insert({serializable_block.wrapping_id, std::move(key_block)});
  }

  return key_blocks;
}

// Parses the USS container flatbuffer. On success, populates `ciphertext`,
// `iv`, `tag`, `wrapped_key_blocks`, `created_on_os_version`; on failure,
// returns false.
CryptohomeStatus GetContainerFromFlatbuffer(
    const brillo::Blob& flatbuffer,
    brillo::Blob* ciphertext,
    brillo::Blob* iv,
    brillo::Blob* tag,
    std::map<std::string, UserSecretStash::WrappedKeyBlock>* wrapped_key_blocks,
    std::string* created_on_os_version) {
  // This check is redundant to the flatbuffer parsing below, but we check it
  // here in order to distinguish "empty file" from "corrupted file" in metrics
  // and logs.
  if (flatbuffer.empty()) {
    return MakeStatus<CryptohomeError>(
        CRYPTOHOME_ERR_LOC(kLocUSSEmptySerializedInGetContainerFromFB),
        ErrorActionSet({PossibleAction::kDeleteVault, PossibleAction::kAuth,
                        PossibleAction::kDevCheckUnexpectedState}),
        user_data_auth::CRYPTOHOME_ERROR_BACKING_STORE_FAILURE);
  }

  std::optional<UserSecretStashContainer> deserialized =
      UserSecretStashContainer::Deserialize(flatbuffer);
  if (!deserialized.has_value()) {
    LOG(ERROR) << "Failed to deserialize UserSecretStashContainer";
    return MakeStatus<CryptohomeError>(
        CRYPTOHOME_ERR_LOC(kLocUSSDeserializeFailedInGetContainerFromFB),
        ErrorActionSet({PossibleAction::kDevCheckUnexpectedState}),
        user_data_auth::CRYPTOHOME_ERROR_BACKING_STORE_FAILURE);
  }

  if (!deserialized.value().encryption_algorithm.has_value()) {
    LOG(ERROR) << "UserSecretStashContainer has no algorithm set";
    return MakeStatus<CryptohomeError>(
        CRYPTOHOME_ERR_LOC(kLocUSSNoAlgInGetContainerFromFB),
        ErrorActionSet({PossibleAction::kDevCheckUnexpectedState}),
        user_data_auth::CRYPTOHOME_ERROR_BACKING_STORE_FAILURE);
  }
  if (deserialized.value().encryption_algorithm.value() !=
      UserSecretStashEncryptionAlgorithm::AES_GCM_256) {
    LOG(ERROR) << "UserSecretStashContainer uses unknown algorithm: "
               << static_cast<int>(deserialized->encryption_algorithm.value());
    return MakeStatus<CryptohomeError>(
        CRYPTOHOME_ERR_LOC(kLocUSSUnknownAlgInGetContainerFromFB),
        ErrorActionSet({PossibleAction::kDevCheckUnexpectedState}),
        user_data_auth::CRYPTOHOME_ERROR_BACKING_STORE_FAILURE);
  }

  if (deserialized.value().ciphertext.empty()) {
    LOG(ERROR) << "UserSecretStash has empty ciphertext";
    return MakeStatus<CryptohomeError>(
        CRYPTOHOME_ERR_LOC(kLocUSSNoCiphertextInGetContainerFromFB),
        ErrorActionSet({PossibleAction::kDevCheckUnexpectedState}),
        user_data_auth::CRYPTOHOME_ERROR_BACKING_STORE_FAILURE);
  }
  *ciphertext = deserialized.value().ciphertext;

  if (deserialized.value().iv.empty()) {
    LOG(ERROR) << "UserSecretStash has empty IV";
    return MakeStatus<CryptohomeError>(
        CRYPTOHOME_ERR_LOC(kLocUSSNoIVInGetContainerFromFB),
        ErrorActionSet({PossibleAction::kDevCheckUnexpectedState}),
        user_data_auth::CRYPTOHOME_ERROR_BACKING_STORE_FAILURE);
  }
  if (deserialized.value().iv.size() != kAesGcmIVSize) {
    LOG(ERROR) << "UserSecretStash has IV of wrong length: "
               << deserialized.value().iv.size()
               << ", expected: " << kAesGcmIVSize;
    return MakeStatus<CryptohomeError>(
        CRYPTOHOME_ERR_LOC(kLocUSSIVWrongSizeInGetContainerFromFB),
        ErrorActionSet({PossibleAction::kDevCheckUnexpectedState}),
        user_data_auth::CRYPTOHOME_ERROR_BACKING_STORE_FAILURE);
  }
  *iv = deserialized.value().iv;

  if (deserialized.value().gcm_tag.empty()) {
    LOG(ERROR) << "UserSecretStash has empty AES-GCM tag";
    return MakeStatus<CryptohomeError>(
        CRYPTOHOME_ERR_LOC(kLocUSSNoGCMTagInGetContainerFromFB),
        ErrorActionSet({PossibleAction::kDevCheckUnexpectedState}),
        user_data_auth::CRYPTOHOME_ERROR_BACKING_STORE_FAILURE);
  }
  if (deserialized.value().gcm_tag.size() != kAesGcmTagSize) {
    LOG(ERROR) << "UserSecretStash has AES-GCM tag of wrong length: "
               << deserialized.value().gcm_tag.size()
               << ", expected: " << kAesGcmTagSize;
    return MakeStatus<CryptohomeError>(
        CRYPTOHOME_ERR_LOC(kLocUSSTagWrongSizeInGetContainerFromFB),
        ErrorActionSet({PossibleAction::kDevCheckUnexpectedState}),
        user_data_auth::CRYPTOHOME_ERROR_BACKING_STORE_FAILURE);
  }
  *tag = deserialized.value().gcm_tag;

  *wrapped_key_blocks = GetKeyBlocksFromSerializableStructs(
      deserialized.value().wrapped_key_blocks);

  *created_on_os_version = deserialized.value().created_on_os_version;

  return OkStatus<CryptohomeError>();
}

CryptohomeStatusOr<brillo::SecureBlob> UnwrapMainKeyFromBlocks(
    const std::map<std::string, UserSecretStash::WrappedKeyBlock>&
        wrapped_key_blocks,
    const std::string& wrapping_id,
    const brillo::SecureBlob& wrapping_key) {
  // Verify preconditions.
  if (wrapping_id.empty()) {
    NOTREACHED() << "Empty wrapping ID is passed for UserSecretStash main key "
                    "unwrapping.";
    return MakeStatus<CryptohomeError>(
        CRYPTOHOME_ERR_LOC(kLocUSSEmptyWrappingIDInUnwrapMKFromBlocks),
        ErrorActionSet({PossibleAction::kDevCheckUnexpectedState}),
        user_data_auth::CRYPTOHOME_ERROR_BACKING_STORE_FAILURE);
  }
  if (wrapping_key.size() != kAesGcm256KeySize) {
    NOTREACHED() << "Wrong wrapping key size is passed for UserSecretStash "
                    "main key unwrapping. Received: "
                 << wrapping_key.size() << ", expected " << kAesGcm256KeySize
                 << ".";
    return MakeStatus<CryptohomeError>(
        CRYPTOHOME_ERR_LOC(kLocUSSWrongWKSizeInUnwrapMKFromBlocks),
        ErrorActionSet({PossibleAction::kDevCheckUnexpectedState}),
        user_data_auth::CRYPTOHOME_ERROR_BACKING_STORE_FAILURE);
  }

  // Find the wrapped key block.
  const auto wrapped_key_block_iter = wrapped_key_blocks.find(wrapping_id);
  if (wrapped_key_block_iter == wrapped_key_blocks.end()) {
    LOG(ERROR)
        << "UserSecretStash wrapped key block with the given ID not found.";
    return MakeStatus<CryptohomeError>(
        CRYPTOHOME_ERR_LOC(kLocUSSWrappedBlockNotFoundInUnwrapMKFromBlocks),
        ErrorActionSet({PossibleAction::kDevCheckUnexpectedState}),
        user_data_auth::CRYPTOHOME_ERROR_BACKING_STORE_FAILURE);
  }
  const UserSecretStash::WrappedKeyBlock& wrapped_key_block =
      wrapped_key_block_iter->second;

  // Verify the wrapped key block format. No NOTREACHED() checks here, since the
  // key block is a deserialization of the persisted blob.
  if (wrapped_key_block.encryption_algorithm !=
      UserSecretStashEncryptionAlgorithm::AES_GCM_256) {
    LOG(ERROR) << "UserSecretStash wrapped main key uses unknown algorithm: "
               << static_cast<int>(wrapped_key_block.encryption_algorithm)
               << ".";
    return MakeStatus<CryptohomeError>(
        CRYPTOHOME_ERR_LOC(kLocUSSUnknownAlgInUnwrapMKFromBlocks),
        ErrorActionSet({PossibleAction::kDevCheckUnexpectedState}),
        user_data_auth::CRYPTOHOME_ERROR_BACKING_STORE_FAILURE);
  }
  if (wrapped_key_block.encrypted_key.empty()) {
    LOG(ERROR) << "UserSecretStash wrapped main key has empty encrypted key.";
    return MakeStatus<CryptohomeError>(
        CRYPTOHOME_ERR_LOC(kLocUSSEmptyEncKeyInUnwrapMKFromBlocks),
        ErrorActionSet({PossibleAction::kDevCheckUnexpectedState}),
        user_data_auth::CRYPTOHOME_ERROR_BACKING_STORE_FAILURE);
  }
  if (wrapped_key_block.iv.size() != kAesGcmIVSize) {
    LOG(ERROR) << "UserSecretStash wrapped main key has IV of wrong length: "
               << wrapped_key_block.iv.size() << ", expected: " << kAesGcmIVSize
               << ".";
    return MakeStatus<CryptohomeError>(
        CRYPTOHOME_ERR_LOC(kLocUSSWrongIVSizeInUnwrapMKFromBlocks),
        ErrorActionSet({PossibleAction::kDevCheckUnexpectedState}),
        user_data_auth::CRYPTOHOME_ERROR_BACKING_STORE_FAILURE);
  }
  if (wrapped_key_block.gcm_tag.size() != kAesGcmTagSize) {
    LOG(ERROR)
        << "UserSecretStash wrapped main key has AES-GCM tag of wrong length: "
        << wrapped_key_block.gcm_tag.size() << ", expected: " << kAesGcmTagSize
        << ".";
    return MakeStatus<CryptohomeError>(
        CRYPTOHOME_ERR_LOC(kLocUSSWrongTagSizeInUnwrapMKFromBlocks),
        ErrorActionSet({PossibleAction::kDevCheckUnexpectedState}),
        user_data_auth::CRYPTOHOME_ERROR_BACKING_STORE_FAILURE);
  }

  // Attempt the unwrapping.
  brillo::SecureBlob main_key;
  if (!AesGcmDecrypt(
          brillo::SecureBlob(wrapped_key_block.encrypted_key),
          /*ad=*/std::nullopt, brillo::SecureBlob(wrapped_key_block.gcm_tag),
          wrapping_key, brillo::SecureBlob(wrapped_key_block.iv), &main_key)) {
    LOG(ERROR) << "Failed to unwrap UserSecretStash main key";
    return MakeStatus<CryptohomeError>(
        CRYPTOHOME_ERR_LOC(kLocUSSDecryptFailedInUnwrapMKFromBlocks),
        ErrorActionSet({PossibleAction::kDevCheckUnexpectedState}),
        user_data_auth::CRYPTOHOME_ERROR_BACKING_STORE_FAILURE);
  }
  return main_key;
}

}  // namespace

bool IsUserSecretStashExperimentEnabled(Platform* platform) {
  return UserSecretStashExperimentResult(platform) ==
         UssExperimentFlag::kEnabled;
}

void ResetUserSecretStashExperimentForTesting() {
  GetUserSecretStashExperimentOverride().reset();
}

std::optional<bool> SetUserSecretStashExperimentForTesting(
    std::optional<bool> enabled) {
  std::optional<bool> original = GetUserSecretStashExperimentOverride();
  GetUserSecretStashExperimentOverride() = enabled;
  return original;
}

// static
CryptohomeStatusOr<std::unique_ptr<UserSecretStash>>
UserSecretStash::CreateRandom(const FileSystemKeyset& file_system_keyset) {
  std::string current_os_version = GetCurrentOsVersion();

  // Note: make_unique() wouldn't work due to the constructor being private.
  std::unique_ptr<UserSecretStash> stash(
      new UserSecretStash(file_system_keyset));
  stash->created_on_os_version_ = std::move(current_os_version);
  return stash;
}

// static
CryptohomeStatusOr<std::unique_ptr<UserSecretStash>>
UserSecretStash::FromEncryptedContainer(const brillo::Blob& flatbuffer,
                                        const brillo::SecureBlob& main_key) {
  if (main_key.size() != kAesGcm256KeySize) {
    LOG(ERROR) << "The UserSecretStash main key is of wrong length: "
               << main_key.size() << ", expected: " << kAesGcm256KeySize;
    return MakeStatus<CryptohomeError>(
        CRYPTOHOME_ERR_LOC(kLocUSSInvalidKeySizeInFromEncContainer),
        ErrorActionSet({PossibleAction::kDevCheckUnexpectedState}),
        user_data_auth::CRYPTOHOME_ERROR_BACKING_STORE_FAILURE);
  }

  brillo::Blob ciphertext, iv, gcm_tag;
  std::map<std::string, WrappedKeyBlock> wrapped_key_blocks;
  std::string created_on_os_version;
  CryptohomeStatus status =
      GetContainerFromFlatbuffer(flatbuffer, &ciphertext, &iv, &gcm_tag,
                                 &wrapped_key_blocks, &created_on_os_version);
  if (!status.ok()) {
    // Note: the error is already logged.
    return MakeStatus<CryptohomeError>(
               CRYPTOHOME_ERR_LOC(kLocUSSGetFromFBFailedInFromEncContainer))
        .Wrap(std::move(status));
  }

  CryptohomeStatusOr<UserMetadata> user_metadata = GetUserMetadata(flatbuffer);
  if (!user_metadata.ok()) {
    return MakeStatus<CryptohomeError>(
               CRYPTOHOME_ERR_LOC(
                   kLocUSSGetUserMetadataFailedInFromEncContainer))
        .Wrap(std::move(user_metadata).err_status());
  }

  CryptohomeStatusOr<std::unique_ptr<UserSecretStash>> result =
      FromEncryptedPayload(ciphertext, iv, gcm_tag, wrapped_key_blocks,
                           created_on_os_version, user_metadata.value(),
                           main_key);
  if (!result.ok()) {
    return MakeStatus<CryptohomeError>(
               CRYPTOHOME_ERR_LOC(kLocUSSFromPayloadFailedInFromEncContainer))
        .Wrap(std::move(result).err_status());
  }
  return result;
}

// static
CryptohomeStatusOr<std::unique_ptr<UserSecretStash>>
UserSecretStash::FromEncryptedPayload(
    const brillo::Blob& ciphertext,
    const brillo::Blob& iv,
    const brillo::Blob& gcm_tag,
    const std::map<std::string, WrappedKeyBlock>& wrapped_key_blocks,
    const std::string& created_on_os_version,
    const UserMetadata& user_metadata,
    const brillo::SecureBlob& main_key) {
  brillo::SecureBlob serialized_uss_payload;
  if (!AesGcmDecrypt(brillo::SecureBlob(ciphertext), /*ad=*/std::nullopt,
                     brillo::SecureBlob(gcm_tag), main_key,
                     brillo::SecureBlob(iv), &serialized_uss_payload)) {
    LOG(ERROR) << "Failed to decrypt UserSecretStash payload";
    return MakeStatus<CryptohomeError>(
        CRYPTOHOME_ERR_LOC(kLocUSSAesGcmFailedInFromEncPayload),
        ErrorActionSet({PossibleAction::kDevCheckUnexpectedState}),
        user_data_auth::CRYPTOHOME_ERROR_BACKING_STORE_FAILURE);
  }

  std::optional<UserSecretStashPayload> uss_payload =
      UserSecretStashPayload::Deserialize(serialized_uss_payload);
  if (!uss_payload.has_value()) {
    LOG(ERROR) << "Failed to deserialize UserSecretStashPayload";
    return MakeStatus<CryptohomeError>(
        CRYPTOHOME_ERR_LOC(kLocUSSDeserializeFailedInFromEncPayload),
        ErrorActionSet({PossibleAction::kDevCheckUnexpectedState}),
        user_data_auth::CRYPTOHOME_ERROR_BACKING_STORE_FAILURE);
  }

  CryptohomeStatusOr<FileSystemKeyset> file_system_keyset_status =
      GetFileSystemKeyFromPayload(uss_payload.value());
  if (!file_system_keyset_status.ok()) {
    LOG(ERROR)
        << "UserSecretStashPayload has invalid file system keyset information";
    return MakeStatus<CryptohomeError>(
               CRYPTOHOME_ERR_LOC(kLocUSSGetFSKeyFailedInFromEncPayload))
        .Wrap(std::move(file_system_keyset_status).err_status());
  }

  std::map<std::string, brillo::SecureBlob> reset_secrets;
  for (const ResetSecretMapping& item : uss_payload.value().reset_secrets) {
    auto insertion_status =
        reset_secrets.insert({item.auth_factor_label, item.reset_secret});
    if (!insertion_status.second) {
      LOG(ERROR) << "UserSecretStashPayload contains multiple reset secrets "
                    "for label: "
                 << item.auth_factor_label;
    }
  }

  std::map<AuthFactorType, brillo::SecureBlob> rate_limiter_reset_secrets;
  for (const TypeToResetSecretMapping& item :
       uss_payload.value().rate_limiter_reset_secrets) {
    if (!item.auth_factor_type.has_value()) {
      LOG(ERROR)
          << "UserSecretStashPayload contains reset secret with missing type.";
      continue;
    }
    if (*item.auth_factor_type >=
        static_cast<unsigned int>(AuthFactorType::kUnspecified)) {
      LOG(ERROR)
          << "UserSecretStashPayload contains reset secret for invalid type: "
          << *item.auth_factor_type << ".";
      continue;
    }
    AuthFactorType auth_factor_type =
        static_cast<AuthFactorType>(*item.auth_factor_type);
    auto insertion_status = rate_limiter_reset_secrets.insert(
        {auth_factor_type, item.reset_secret});
    if (!insertion_status.second) {
      LOG(ERROR) << "UserSecretStashPayload contains multiple reset secrets "
                    "for type: "
                 << AuthFactorTypeToString(auth_factor_type) << ".";
    }
  }

  auto stash = base::WrapUnique(new UserSecretStash(
      std::move(file_system_keyset_status).value(), std::move(reset_secrets),
      std::move(rate_limiter_reset_secrets)));
  stash->wrapped_key_blocks_ = wrapped_key_blocks;
  stash->created_on_os_version_ = created_on_os_version;
  stash->user_metadata_ = user_metadata;
  return stash;
}

// static
CryptohomeStatusOr<std::unique_ptr<UserSecretStash>>
UserSecretStash::FromEncryptedContainerWithWrappingKey(
    const brillo::Blob& flatbuffer,
    const std::string& wrapping_id,
    const brillo::SecureBlob& wrapping_key,
    brillo::SecureBlob* main_key) {
  brillo::Blob ciphertext, iv, gcm_tag;
  std::map<std::string, WrappedKeyBlock> wrapped_key_blocks;
  std::string created_on_os_version;
  CryptohomeStatus status =
      GetContainerFromFlatbuffer(flatbuffer, &ciphertext, &iv, &gcm_tag,
                                 &wrapped_key_blocks, &created_on_os_version);
  if (!status.ok()) {
    // Note: the error is already logged.
    return MakeStatus<CryptohomeError>(
               CRYPTOHOME_ERR_LOC(
                   kLocUSSGetFromFBFailedInFromEncContainerWithWK))
        .Wrap(std::move(status));
  }

  CryptohomeStatusOr<UserMetadata> user_metadata = GetUserMetadata(flatbuffer);
  if (!user_metadata.ok()) {
    return MakeStatus<CryptohomeError>(
               CRYPTOHOME_ERR_LOC(
                   kLocUSSGetUserMetadataFailedInFromEncContainerWrappingKey))
        .Wrap(std::move(user_metadata).err_status());
  }

  CryptohomeStatusOr<brillo::SecureBlob> main_key_optional =
      UnwrapMainKeyFromBlocks(wrapped_key_blocks, wrapping_id, wrapping_key);
  if (!main_key_optional.ok()) {
    // Note: the error is already logged.
    return MakeStatus<CryptohomeError>(
               CRYPTOHOME_ERR_LOC(
                   kLocUSSUnwrapMKFailedInFromEncContainerWithWK))
        .Wrap(std::move(main_key_optional).err_status());
  }

  CryptohomeStatusOr<std::unique_ptr<UserSecretStash>> stash =
      FromEncryptedPayload(ciphertext, iv, gcm_tag, wrapped_key_blocks,
                           created_on_os_version, user_metadata.value(),
                           main_key_optional.value());
  if (!stash.ok()) {
    // Note: the error is already logged.
    return MakeStatus<CryptohomeError>(
               CRYPTOHOME_ERR_LOC(
                   kLocUSSFromPayloadFailedInFromEncContainerWithWK))
        .Wrap(std::move(stash).err_status());
  }

  *main_key = main_key_optional.value();
  return std::move(stash).value();
}

// static
brillo::SecureBlob UserSecretStash::CreateRandomMainKey() {
  return CreateSecureRandomBlob(kAesGcm256KeySize);
}

// static
CryptohomeStatusOr<UserMetadata> UserSecretStash::GetUserMetadata(
    const brillo::Blob& flatbuffer) {
  std::optional<UserSecretStashContainer> deserialized =
      UserSecretStashContainer::Deserialize(flatbuffer);
  if (!deserialized.has_value()) {
    LOG(ERROR) << "Failed to deserialize UserSecretStashContainer";
    return MakeStatus<CryptohomeError>(
        CRYPTOHOME_ERR_LOC(kLocUSSDeserializeFailedInGeUserMetadata),
        ErrorActionSet({PossibleAction::kDevCheckUnexpectedState}),
        user_data_auth::CRYPTOHOME_ERROR_BACKING_STORE_FAILURE);
  }
  return deserialized.value().user_metadata;
}

const FileSystemKeyset& UserSecretStash::GetFileSystemKeyset() const {
  return file_system_keyset_;
}

std::optional<brillo::SecureBlob> UserSecretStash::GetResetSecretForLabel(
    const std::string& label) const {
  const auto iter = reset_secrets_.find(label);
  if (iter == reset_secrets_.end()) {
    return std::nullopt;
  }
  return iter->second;
}

bool UserSecretStash::SetResetSecretForLabel(const std::string& label,
                                             const brillo::SecureBlob& secret) {
  const auto result = reset_secrets_.insert({label, secret});
  return result.second;
}

bool UserSecretStash::RemoveResetSecretForLabel(const std::string& label) {
  const auto iter = reset_secrets_.find(label);
  if (iter == reset_secrets_.end()) {
    return false;
  }
  reset_secrets_.erase(iter);
  return true;
}

std::optional<brillo::SecureBlob> UserSecretStash::GetRateLimiterResetSecret(
    AuthFactorType auth_factor_type) const {
  const auto iter = rate_limiter_reset_secrets_.find(auth_factor_type);
  if (iter == rate_limiter_reset_secrets_.end()) {
    return std::nullopt;
  }
  return iter->second;
}

bool UserSecretStash::SetRateLimiterResetSecret(
    AuthFactorType auth_factor_type, const brillo::SecureBlob& secret) {
  const auto result =
      rate_limiter_reset_secrets_.insert({auth_factor_type, secret});
  return result.second;
}

const std::string& UserSecretStash::GetCreatedOnOsVersion() const {
  return created_on_os_version_;
}

bool UserSecretStash::HasWrappedMainKey(const std::string& wrapping_id) const {
  return wrapped_key_blocks_.count(wrapping_id);
}

CryptohomeStatusOr<brillo::SecureBlob> UserSecretStash::UnwrapMainKey(
    const std::string& wrapping_id,
    const brillo::SecureBlob& wrapping_key) const {
  CryptohomeStatusOr<brillo::SecureBlob> result =
      UnwrapMainKeyFromBlocks(wrapped_key_blocks_, wrapping_id, wrapping_key);
  if (!result.ok()) {
    return MakeStatus<CryptohomeError>(
               CRYPTOHOME_ERR_LOC(kLocUSSUnwrapMKFailedInUnwrapMK))
        .Wrap(std::move(result).err_status());
  }
  return result.value();
}

CryptohomeStatus UserSecretStash::AddWrappedMainKey(
    const brillo::SecureBlob& main_key,
    const std::string& wrapping_id,
    const brillo::SecureBlob& wrapping_key,
    OverwriteExistingKeyBlock clobber) {
  // Verify preconditions.
  if (main_key.empty()) {
    NOTREACHED() << "Empty UserSecretStash main key is passed for wrapping.";
    return MakeStatus<CryptohomeError>(
        CRYPTOHOME_ERR_LOC(kLocUSSMainKeyEmptyInAddWrappedMainKey),
        ErrorActionSet({PossibleAction::kDevCheckUnexpectedState}),
        user_data_auth::CRYPTOHOME_ERROR_INVALID_ARGUMENT);
  }
  if (wrapping_id.empty()) {
    NOTREACHED()
        << "Empty wrapping ID is passed for UserSecretStash main key wrapping.";
    return MakeStatus<CryptohomeError>(
        CRYPTOHOME_ERR_LOC(kLocUSSWrappingIDEmptyInAddWrappedMainKey),
        ErrorActionSet({PossibleAction::kDevCheckUnexpectedState}),
        user_data_auth::CRYPTOHOME_ERROR_INVALID_ARGUMENT);
  }
  if (wrapping_key.size() != kAesGcm256KeySize) {
    NOTREACHED() << "Wrong wrapping key size is passed for UserSecretStash "
                    "main key wrapping. Received: "
                 << wrapping_key.size() << ", expected " << kAesGcm256KeySize
                 << ".";
    return MakeStatus<CryptohomeError>(
        CRYPTOHOME_ERR_LOC(kLocUSSWrappingWrongSizeInAddWrappedMainKey),
        ErrorActionSet({PossibleAction::kDevCheckUnexpectedState}),
        user_data_auth::CRYPTOHOME_ERROR_INVALID_ARGUMENT);
  }

  // Protect from duplicate wrapping IDs if clobbering is not enabled.
  if (wrapped_key_blocks_.count(wrapping_id) &&
      !(clobber == OverwriteExistingKeyBlock::kEnabled)) {
    LOG(ERROR) << "A UserSecretStash main key with the given wrapping_id "
                  "already exists.";
    return MakeStatus<CryptohomeError>(
        CRYPTOHOME_ERR_LOC(kLocUSSDuplicateWrappingInAddWrappedMainKey),
        ErrorActionSet({PossibleAction::kDevCheckUnexpectedState,
                        PossibleAction::kAuth, PossibleAction::kDeleteVault}),
        user_data_auth::CRYPTOHOME_ERROR_AUTHORIZATION_KEY_FAILED);
  }

  // Perform the wrapping.
  brillo::SecureBlob iv, gcm_tag, encrypted_key;
  if (!AesGcmEncrypt(main_key, /*ad=*/std::nullopt, wrapping_key, &iv, &gcm_tag,
                     &encrypted_key)) {
    LOG(ERROR) << "Failed to wrap UserSecretStash main key.";
    return MakeStatus<CryptohomeError>(
        CRYPTOHOME_ERR_LOC(kLocUSSEncryptFailedInAddWrappedMainKey),
        ErrorActionSet({PossibleAction::kDevCheckUnexpectedState}),
        user_data_auth::CRYPTOHOME_ERROR_AUTHORIZATION_KEY_FAILED);
  }

  wrapped_key_blocks_[wrapping_id] = WrappedKeyBlock{
      .encryption_algorithm = UserSecretStashEncryptionAlgorithm::AES_GCM_256,
      .encrypted_key = brillo::Blob(encrypted_key.begin(), encrypted_key.end()),
      .iv = brillo::Blob(iv.begin(), iv.end()),
      .gcm_tag = brillo::Blob(gcm_tag.begin(), gcm_tag.end()),
  };
  return OkStatus<CryptohomeError>();
}

bool UserSecretStash::RemoveWrappedMainKey(const std::string& wrapping_id) {
  auto iter = wrapped_key_blocks_.find(wrapping_id);
  if (iter == wrapped_key_blocks_.end()) {
    LOG(ERROR) << "No UserSecretStash wrapped key block is found with the "
                  "given wrapping ID.";
    return false;
  }
  wrapped_key_blocks_.erase(iter);
  return true;
}

CryptohomeStatusOr<brillo::Blob> UserSecretStash::GetEncryptedContainer(
    const brillo::SecureBlob& main_key) {
  UserSecretStashPayload payload = {
      .fek = file_system_keyset_.Key().fek,
      .fnek = file_system_keyset_.Key().fnek,
      .fek_salt = file_system_keyset_.Key().fek_salt,
      .fnek_salt = file_system_keyset_.Key().fnek_salt,
      .fek_sig = file_system_keyset_.KeyReference().fek_sig,
      .fnek_sig = file_system_keyset_.KeyReference().fnek_sig,
      .chaps_key = file_system_keyset_.chaps_key(),
  };

  // Note: It can happen that the USS container is created with empty
  // |reset_secrets_| if no PinWeaver credentials are present yet.
  for (const auto& item : reset_secrets_) {
    const std::string& auth_factor_label = item.first;
    const brillo::SecureBlob& reset_secret = item.second;
    payload.reset_secrets.push_back(ResetSecretMapping{
        .auth_factor_label = auth_factor_label,
        .reset_secret = reset_secret,
    });
  }

  // Note: It can happen that the USS container is created with empty
  // |rate_limiter_reset_secrets_| if no PinWeaver credentials are present yet.
  for (const auto& item : rate_limiter_reset_secrets_) {
    AuthFactorType auth_factor_type = item.first;
    const brillo::SecureBlob& reset_secret = item.second;
    payload.rate_limiter_reset_secrets.push_back(TypeToResetSecretMapping{
        .auth_factor_type = static_cast<unsigned int>(auth_factor_type),
        .reset_secret = reset_secret,
    });
  }

  std::optional<brillo::SecureBlob> serialized_payload = payload.Serialize();
  if (!serialized_payload.has_value()) {
    LOG(ERROR) << "Failed to serialize UserSecretStashPayload";
    return MakeStatus<CryptohomeError>(
        CRYPTOHOME_ERR_LOC(kLocUSSPayloadSerializeFailedInGetEncContainer),
        ErrorActionSet({PossibleAction::kDevCheckUnexpectedState,
                        PossibleAction::kAuth, PossibleAction::kDeleteVault}),
        user_data_auth::CRYPTOHOME_ERROR_BACKING_STORE_FAILURE);
  }

  brillo::SecureBlob tag, iv, ciphertext;
  if (!AesGcmEncrypt(serialized_payload.value(), /*ad=*/std::nullopt, main_key,
                     &iv, &tag, &ciphertext)) {
    LOG(ERROR) << "Failed to encrypt UserSecretStash";
    return MakeStatus<CryptohomeError>(
        CRYPTOHOME_ERR_LOC(kLocUSSPayloadEncryptFailedInGetEncContainer),
        ErrorActionSet({PossibleAction::kDevCheckUnexpectedState,
                        PossibleAction::kAuth, PossibleAction::kDeleteVault}),
        user_data_auth::CRYPTOHOME_ERROR_BACKING_STORE_FAILURE);
  }

  UserSecretStashContainer container = {
      .encryption_algorithm = UserSecretStashEncryptionAlgorithm::AES_GCM_256,
      .ciphertext = brillo::Blob(ciphertext.begin(), ciphertext.end()),
      .iv = brillo::Blob(iv.begin(), iv.end()),
      .gcm_tag = brillo::Blob(tag.begin(), tag.end()),
      .created_on_os_version = created_on_os_version_,
      .user_metadata = user_metadata_,
  };
  // Note: It can happen that the USS container is created with empty
  // |wrapped_key_blocks_| - they may be added later, when the user registers
  // the first credential with their cryptohome.
  for (const auto& item : wrapped_key_blocks_) {
    const std::string& wrapping_id = item.first;
    const UserSecretStash::WrappedKeyBlock& wrapped_key_block = item.second;
    container.wrapped_key_blocks.push_back(UserSecretStashWrappedKeyBlock{
        .wrapping_id = wrapping_id,
        .encryption_algorithm = wrapped_key_block.encryption_algorithm,
        .encrypted_key = wrapped_key_block.encrypted_key,
        .iv = wrapped_key_block.iv,
        .gcm_tag = wrapped_key_block.gcm_tag,
    });
  }

  std::optional<brillo::Blob> serialized_contaner = container.Serialize();
  if (!serialized_contaner.has_value()) {
    LOG(ERROR) << "Failed to serialize UserSecretStashContainer";
    return MakeStatus<CryptohomeError>(
        CRYPTOHOME_ERR_LOC(kLocUSSContainerSerializeFailedInGetEncContainer),
        ErrorActionSet({PossibleAction::kDevCheckUnexpectedState,
                        PossibleAction::kAuth, PossibleAction::kDeleteVault}),
        user_data_auth::CRYPTOHOME_ERROR_BACKING_STORE_FAILURE);
  }
  return serialized_contaner.value();
}

std::optional<uint64_t> UserSecretStash::GetFingerprintRateLimiterId() {
  return user_metadata_.fingerprint_rate_limiter_id;
}

bool UserSecretStash::InitializeFingerprintRateLimiterId(uint64_t id) {
  if (user_metadata_.fingerprint_rate_limiter_id.has_value()) {
    return false;
  }
  user_metadata_.fingerprint_rate_limiter_id = id;
  return true;
}

UserSecretStash::UserSecretStash(
    FileSystemKeyset file_system_keyset,
    std::map<std::string, brillo::SecureBlob> reset_secrets,
    std::map<AuthFactorType, brillo::SecureBlob> rate_limiter_reset_secrets)
    : file_system_keyset_(std::move(file_system_keyset)),
      reset_secrets_(std::move(reset_secrets)),
      rate_limiter_reset_secrets_(std::move(rate_limiter_reset_secrets)) {}

UserSecretStash::UserSecretStash(const FileSystemKeyset& file_system_keyset)
    : file_system_keyset_(file_system_keyset) {}

}  // namespace cryptohome
