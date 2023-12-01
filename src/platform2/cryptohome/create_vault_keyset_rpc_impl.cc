// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/create_vault_keyset_rpc_impl.h"

#include <memory>
#include <string>
#include <utility>

#include <libhwsec-foundation/status/status_chain_or.h>

#include "cryptohome/error/cryptohome_error.h"

using cryptohome::error::CryptohomeCryptoError;
using cryptohome::error::CryptohomeError;
using cryptohome::error::ErrorActionSet;
using cryptohome::error::PossibleAction;
using hwsec_foundation::status::MakeStatus;
using hwsec_foundation::status::OkStatus;

namespace cryptohome {

CreateVaultKeysetRpcImpl::CreateVaultKeysetRpcImpl(
    KeysetManagement* keyset_management,
    AuthBlockUtility* auth_block_utility,
    AuthFactorDriverManager* auth_factor_driver_manager,
    InUseAuthSession auth_session)
    : keyset_management_(keyset_management),
      auth_block_utility_(auth_block_utility),
      auth_factor_driver_manager_(auth_factor_driver_manager),
      auth_session_(std::move(auth_session)) {}

bool CreateVaultKeysetRpcImpl::ClearKeyDataFromInitialKeyset(
    bool disable_key_data) {
  // Remove KeyBlobs from the VaultKeyset and resave, as the
  // keyset_management flags need a valid KeyBlobs to operate.
  // Used only for the testing of legacy keysets which were created
  // KeyBlobs was not a concept.
  if (disable_key_data) {
    // Load the freshly created VaultKeyset.
    std::unique_ptr<VaultKeyset> created_vk =
        keyset_management_->GetVaultKeyset(auth_session_->obfuscated_username(),
                                           initial_vault_keyset_->GetLabel());
    if (created_vk) {
      created_vk->ClearKeyData();
      if (!created_vk->Save(created_vk->GetSourceFile())) {
        LOG(ERROR) << "Failed to clear key blobs from the vault_keyset.";
        return false;
      }
    }
  }

  return true;
}

void CreateVaultKeysetRpcImpl::CreateVaultKeyset(
    const user_data_auth::CreateVaultKeysetRequest& request,
    StatusCallback on_done) {
  // Preconditions:
  DCHECK_EQ(request.auth_session_id(), auth_session_->serialized_token());
  // At this point AuthSession should be authenticated as it needs
  // FileSystemKeys to wrap the new credentials.
  if (auth_session_->status() != AuthStatus::kAuthStatusAuthenticated) {
    std::move(on_done).Run(MakeStatus<CryptohomeError>(
        CRYPTOHOME_ERR_LOC(
            kLocCreateVaultKeysetRpcImplUnauthedInCreateVaultKeyset),
        ErrorActionSet({PossibleAction::kDevCheckUnexpectedState}),
        user_data_auth::CRYPTOHOME_ERROR_UNAUTHENTICATED_AUTH_SESSION));
    return;
  }

  AuthFactorType auth_factor_type = AuthFactorType::kPassword;
  std::string auth_factor_label = request.key_label();

  // Create and initialize AuthInput.
  AuthInput auth_input = {
      .user_input = brillo::SecureBlob(request.passkey()),
      .locked_to_single_user = auth_block_utility_->GetLockedToSingleUser(),
      .username = auth_session_->username(),
      .obfuscated_username = auth_session_->obfuscated_username()};

  // Determine the auth block type to use.
  const AuthFactorDriver& factor_driver =
      auth_factor_driver_manager_->GetDriver(auth_factor_type);
  CryptoStatusOr<AuthBlockType> auth_block_type =
      auth_block_utility_->SelectAuthBlockTypeForCreation(
          factor_driver.block_types());
  if (!auth_block_type.ok()) {
    std::move(on_done).Run(
        MakeStatus<CryptohomeError>(
            CRYPTOHOME_ERR_LOC(kLocCreateVaultKeysetRpcImplyInvalidBlockType),
            user_data_auth::CRYPTOHOME_ERROR_BACKING_STORE_FAILURE)
            .Wrap(std::move(auth_block_type).status()));
    return;
  }

  KeyData key_data;
  key_data.set_label(auth_factor_label);
  key_data.set_type(KeyData::KEY_TYPE_PASSWORD);

  auto create_callback = base::BindOnce(
      &CreateVaultKeysetRpcImpl::CreateAndPersistVaultKeyset,
      weak_factory_.GetWeakPtr(), key_data, request.disable_key_data(),
      auth_input, std::move(on_done));

  auth_block_utility_->CreateKeyBlobsWithAuthBlock(
      auth_block_type.value(), auth_input, std::move(create_callback));
}

void CreateVaultKeysetRpcImpl::CreateAndPersistVaultKeyset(
    const KeyData& key_data,
    const bool disable_key_data,
    AuthInput auth_input,
    StatusCallback on_done,
    CryptohomeStatus callback_error,
    std::unique_ptr<KeyBlobs> key_blobs,
    std::unique_ptr<AuthBlockState> auth_state) {
  // callback_error, key_blobs and auth_state are returned by
  // AuthBlock::CreateCallback.
  if (!callback_error.ok() || key_blobs == nullptr || auth_state == nullptr) {
    if (callback_error.ok()) {
      callback_error = MakeStatus<CryptohomeCryptoError>(
          CRYPTOHOME_ERR_LOC(
              kLocCreateVaultKeysetRpcImplNullParamInCallbackInAddKeyset),
          ErrorActionSet({PossibleAction::kDevCheckUnexpectedState}),
          CryptoError::CE_OTHER_CRYPTO,
          user_data_auth::CryptohomeErrorCode::
              CRYPTOHOME_ERROR_NOT_IMPLEMENTED);
    }
    LOG(ERROR) << "KeyBlobs derivation failed before adding keyset.";
    std::move(on_done).Run(
        MakeStatus<CryptohomeError>(
            CRYPTOHOME_ERR_LOC(
                kLocCreateVaultKeysetRpcImplCreateFailedInAddKeyset),
            user_data_auth::CRYPTOHOME_ADD_CREDENTIALS_FAILED)
            .Wrap(std::move(callback_error)));
    return;
  }

  CryptohomeStatus status =
      AddVaultKeyset(key_data.label(), key_data,
                     !auth_session_->auth_factor_map().HasFactorWithStorage(
                         AuthFactorStorageType::kVaultKeyset),
                     VaultKeysetIntent{.backup = false}, std::move(key_blobs),
                     std::move(auth_state));

  if (!status.ok()) {
    std::move(on_done).Run(
        MakeStatus<CryptohomeError>(
            CRYPTOHOME_ERR_LOC(
                kLocCreateVaultKeysetRpcImplAddVaultKeysetFailed),
            user_data_auth::CRYPTOHOME_ADD_CREDENTIALS_FAILED)
            .Wrap(std::move(status)));
    return;
  }

  if (!ClearKeyDataFromInitialKeyset(disable_key_data)) {
    std::move(on_done).Run(MakeStatus<CryptohomeError>(
        CRYPTOHOME_ERR_LOC(
            kLocCreateVaultKeysetRpcImplClearKeyDataFromInitialKeysetFailed),
        ErrorActionSet({PossibleAction::kDevCheckUnexpectedState}),
        user_data_auth::CRYPTOHOME_ADD_CREDENTIALS_FAILED));
    return;
  }

  std::move(on_done).Run(OkStatus<CryptohomeError>());
}

CryptohomeStatus CreateVaultKeysetRpcImpl::AddVaultKeyset(
    const std::string& key_label,
    const KeyData& key_data,
    bool is_initial_keyset,
    VaultKeysetIntent vk_backup_intent,
    std::unique_ptr<KeyBlobs> key_blobs,
    std::unique_ptr<AuthBlockState> auth_state) {
  DCHECK(key_blobs);
  DCHECK(auth_state);
  if (is_initial_keyset) {
    // TODO(b/229825202): Migrate KeysetManagement and wrap the returned error.
    CryptohomeStatusOr<std::unique_ptr<VaultKeyset>> vk_status =
        keyset_management_->AddInitialKeyset(
            vk_backup_intent, auth_session_->obfuscated_username(), key_data,
            /*challenge_credentials_keyset_info*/ std::nullopt,
            auth_session_->file_system_keyset(), std::move(*key_blobs.get()),
            std::move(auth_state));
    if (!vk_status.ok()) {
      initial_vault_keyset_ = nullptr;
      return MakeStatus<CryptohomeError>(
          CRYPTOHOME_ERR_LOC(
              kLocCreateVaultKeysetRpcImplAddInitialFailedInAddKeyset),
          ErrorActionSet({PossibleAction::kDevCheckUnexpectedState,
                          PossibleAction::kReboot}),
          user_data_auth::CRYPTOHOME_ADD_CREDENTIALS_FAILED);
    }
    LOG(INFO) << "CreateVaultKeysetRpcImpl: added initial keyset "
              << key_data.label() << ".";
    initial_vault_keyset_ = std::move(vk_status).value();
  } else {
    if (!initial_vault_keyset_) {
      // This shouldn't normally happen, but is possible if, e.g., the backup VK
      // is corrupted and the authentication completed via USS.
      return MakeStatus<CryptohomeError>(
          CRYPTOHOME_ERR_LOC(kLocCreateVaultKeysetRpcImplNoVkInAddKeyset),
          ErrorActionSet({PossibleAction::kDevCheckUnexpectedState}),
          user_data_auth::CRYPTOHOME_ADD_CREDENTIALS_FAILED);
    }
    CryptohomeStatus status = keyset_management_->AddKeyset(
        vk_backup_intent, auth_session_->obfuscated_username(), key_label,
        key_data, *initial_vault_keyset_.get(), std::move(*key_blobs.get()),
        std::move(auth_state), true /*clobber*/);
    if (!status.ok()) {
      return MakeStatus<CryptohomeError>(
                 CRYPTOHOME_ERR_LOC(
                     kLocCreateVaultKeysetRpcImplAddFailedInAddKeyset))
          .Wrap(std::move(status));
    }
    LOG(INFO) << "CreateVaultKeysetRpcImpl: added additional keyset "
              << key_label << ".";
  }

  return OkStatus<CryptohomeError>();
}

}  // namespace cryptohome
