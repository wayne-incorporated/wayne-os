// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <string>
#include <utility>
#include <vector>

#include <base/files/file_path.h>
#include <base/functional/bind.h>
#include <base/functional/callback.h>
#include <brillo/cryptohome.h>
#include <chromeos/constants/cryptohome.h>
#include <libhwsec-foundation/utility/task_dispatching_framework.h>

#include "cryptohome/service_userdataauth.h"
#include "cryptohome/userdataauth.h"

namespace cryptohome {

using ::hwsec_foundation::utility::ThreadSafeDBusMethodResponse;

void UserDataAuthAdaptor::IsMounted(
    std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
        user_data_auth::IsMountedReply>> response,
    const user_data_auth::IsMountedRequest& in_request) {
  service_->PostTaskToMountThread(
      FROM_HERE,
      base::BindOnce(
          &UserDataAuthAdaptor::DoIsMounted, base::Unretained(this),
          Username(in_request.username()),
          ThreadSafeDBusMethodResponse<user_data_auth::IsMountedReply>::
              MakeThreadSafe(std::move(response))));
}

void UserDataAuthAdaptor::DoIsMounted(
    const Username& username,
    std::unique_ptr<
        brillo::dbus_utils::DBusMethodResponse<user_data_auth::IsMountedReply>>
        response) {
  bool is_ephemeral = false;
  bool is_mounted = service_->IsMounted(username, &is_ephemeral);

  user_data_auth::IsMountedReply reply;
  reply.set_is_mounted(is_mounted);
  reply.set_is_ephemeral_mount(is_ephemeral);
  std::move(response)->Return(reply);
}

void UserDataAuthAdaptor::Unmount(
    std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
        user_data_auth::UnmountReply>> response,
    const user_data_auth::UnmountRequest& in_request) {
  // Unmount request doesn't have any parameters
  service_->PostTaskToMountThread(
      FROM_HERE,
      base::BindOnce(
          &UserDataAuthAdaptor::DoUnmount, base::Unretained(this),
          ThreadSafeDBusMethodResponse<user_data_auth::UnmountReply>::
              MakeThreadSafe(std::move(response))));
}

void UserDataAuthAdaptor::DoUnmount(
    std::unique_ptr<
        brillo::dbus_utils::DBusMethodResponse<user_data_auth::UnmountReply>>
        response) {
  user_data_auth::UnmountReply reply = service_->Unmount();
  response->Return(reply);
}

void UserDataAuthAdaptor::StartAuthSession(
    std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
        user_data_auth::StartAuthSessionReply>> response,
    const user_data_auth::StartAuthSessionRequest& in_request) {
  service_->PostTaskToMountThread(
      FROM_HERE,
      base::BindOnce(
          &UserDataAuthAdaptor::DoStartAuthSession, base::Unretained(this),
          ThreadSafeDBusMethodResponse<user_data_auth::StartAuthSessionReply>::
              MakeThreadSafe(std::move(response)),
          in_request));
}

void UserDataAuthAdaptor::DoStartAuthSession(
    std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
        user_data_auth::StartAuthSessionReply>> response,
    const user_data_auth::StartAuthSessionRequest& in_request) {
  service_->StartAuthSession(
      in_request,
      base::BindOnce(
          [](std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
                 user_data_auth::StartAuthSessionReply>> local_response,
             const user_data_auth::StartAuthSessionReply& reply) {
            local_response->Return(reply);
          },
          std::move(response)));
}

void UserDataAuthAdaptor::InvalidateAuthSession(
    std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
        user_data_auth::InvalidateAuthSessionReply>> response,
    const user_data_auth::InvalidateAuthSessionRequest& in_request) {
  service_->PostTaskToMountThread(
      FROM_HERE,
      base::BindOnce(&UserDataAuthAdaptor::DoInvalidateAuthSession,
                     base::Unretained(this),
                     ThreadSafeDBusMethodResponse<
                         user_data_auth::InvalidateAuthSessionReply>::
                         MakeThreadSafe(std::move(response)),
                     in_request));
}

void UserDataAuthAdaptor::DoInvalidateAuthSession(
    std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
        user_data_auth::InvalidateAuthSessionReply>> response,
    const user_data_auth::InvalidateAuthSessionRequest& in_request) {
  service_->InvalidateAuthSession(
      in_request,
      base::BindOnce(
          [](std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
                 user_data_auth::InvalidateAuthSessionReply>> local_response,
             const user_data_auth::InvalidateAuthSessionReply& reply) {
            local_response->Return(reply);
          },
          std::move(response)));
}

void UserDataAuthAdaptor::ExtendAuthSession(
    std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
        user_data_auth::ExtendAuthSessionReply>> response,
    const user_data_auth::ExtendAuthSessionRequest& in_request) {
  service_->PostTaskToMountThread(
      FROM_HERE,
      base::BindOnce(
          &UserDataAuthAdaptor::DoExtendAuthSession, base::Unretained(this),
          ThreadSafeDBusMethodResponse<user_data_auth::ExtendAuthSessionReply>::
              MakeThreadSafe(std::move(response)),
          in_request));
}

void UserDataAuthAdaptor::DoExtendAuthSession(
    std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
        user_data_auth::ExtendAuthSessionReply>> response,
    const user_data_auth::ExtendAuthSessionRequest& in_request) {
  service_->ExtendAuthSession(
      in_request,
      base::BindOnce(
          [](std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
                 user_data_auth::ExtendAuthSessionReply>> local_response,
             const user_data_auth::ExtendAuthSessionReply& reply) {
            local_response->Return(reply);
          },
          std::move(response)));
}

void UserDataAuthAdaptor::CreatePersistentUser(
    std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
        user_data_auth::CreatePersistentUserReply>> response,
    const user_data_auth::CreatePersistentUserRequest& in_request) {
  service_->PostTaskToMountThread(
      FROM_HERE, base::BindOnce(&UserDataAuthAdaptor::DoCreatePersistentUser,
                                base::Unretained(this),
                                ThreadSafeDBusMethodResponse<
                                    user_data_auth::CreatePersistentUserReply>::
                                    MakeThreadSafe(std::move(response)),
                                in_request));
}

void UserDataAuthAdaptor::DoCreatePersistentUser(
    std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
        user_data_auth::CreatePersistentUserReply>> response,
    const user_data_auth::CreatePersistentUserRequest& in_request) {
  service_->CreatePersistentUser(
      in_request,
      base::BindOnce(
          [](std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
                 user_data_auth::CreatePersistentUserReply>> local_response,
             const user_data_auth::CreatePersistentUserReply& reply) {
            local_response->Return(reply);
          },
          std::move(response)));
}

void UserDataAuthAdaptor::PrepareGuestVault(
    std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
        user_data_auth::PrepareGuestVaultReply>> response,
    const user_data_auth::PrepareGuestVaultRequest& in_request) {
  service_->PostTaskToMountThread(
      FROM_HERE,
      base::BindOnce(
          &UserDataAuthAdaptor::DoPrepareGuestVault, base::Unretained(this),
          ThreadSafeDBusMethodResponse<user_data_auth::PrepareGuestVaultReply>::
              MakeThreadSafe(std::move(response)),
          in_request));
}

void UserDataAuthAdaptor::DoPrepareGuestVault(
    std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
        user_data_auth::PrepareGuestVaultReply>> response,
    const user_data_auth::PrepareGuestVaultRequest& in_request) {
  service_->PrepareGuestVault(
      in_request,
      base::BindOnce(
          [](std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
                 user_data_auth::PrepareGuestVaultReply>> local_response,
             const user_data_auth::PrepareGuestVaultReply& reply) {
            local_response->Return(reply);
          },
          std::move(response)));
}

void UserDataAuthAdaptor::PrepareEphemeralVault(
    std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
        user_data_auth::PrepareEphemeralVaultReply>> response,
    const user_data_auth::PrepareEphemeralVaultRequest& in_request) {
  service_->PostTaskToMountThread(
      FROM_HERE,
      base::BindOnce(&UserDataAuthAdaptor::DoPrepareEphemeralVault,
                     base::Unretained(this),
                     ThreadSafeDBusMethodResponse<
                         user_data_auth::PrepareEphemeralVaultReply>::
                         MakeThreadSafe(std::move(response)),
                     in_request));
}

void UserDataAuthAdaptor::DoPrepareEphemeralVault(
    std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
        user_data_auth::PrepareEphemeralVaultReply>> response,
    const user_data_auth::PrepareEphemeralVaultRequest& in_request) {
  service_->PrepareEphemeralVault(
      in_request,
      base::BindOnce(
          [](std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
                 user_data_auth::PrepareEphemeralVaultReply>> local_response,
             const user_data_auth::PrepareEphemeralVaultReply& reply) {
            local_response->Return(reply);
          },
          std::move(response)));
}

void UserDataAuthAdaptor::PreparePersistentVault(
    std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
        user_data_auth::PreparePersistentVaultReply>> response,
    const user_data_auth::PreparePersistentVaultRequest& in_request) {
  service_->PostTaskToMountThread(
      FROM_HERE,
      base::BindOnce(&UserDataAuthAdaptor::DoPreparePersistentVault,
                     base::Unretained(this),
                     ThreadSafeDBusMethodResponse<
                         user_data_auth::PreparePersistentVaultReply>::
                         MakeThreadSafe(std::move(response)),
                     in_request));
}

void UserDataAuthAdaptor::DoPreparePersistentVault(
    std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
        user_data_auth::PreparePersistentVaultReply>> response,
    const user_data_auth::PreparePersistentVaultRequest& in_request) {
  service_->PreparePersistentVault(
      in_request,
      base::BindOnce(
          [](std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
                 user_data_auth::PreparePersistentVaultReply>> local_response,
             const user_data_auth::PreparePersistentVaultReply& reply) {
            local_response->Return(reply);
          },
          std::move(response)));
}

void UserDataAuthAdaptor::PrepareVaultForMigration(
    std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
        user_data_auth::PrepareVaultForMigrationReply>> response,
    const user_data_auth::PrepareVaultForMigrationRequest& in_request) {
  service_->PostTaskToMountThread(
      FROM_HERE,
      base::BindOnce(&UserDataAuthAdaptor::DoPrepareVaultForMigration,
                     base::Unretained(this),
                     ThreadSafeDBusMethodResponse<
                         user_data_auth::PrepareVaultForMigrationReply>::
                         MakeThreadSafe(std::move(response)),
                     in_request));
}

void UserDataAuthAdaptor::DoPrepareVaultForMigration(
    std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
        user_data_auth::PrepareVaultForMigrationReply>> response,
    const user_data_auth::PrepareVaultForMigrationRequest& in_request) {
  service_->PrepareVaultForMigration(
      in_request,
      base::BindOnce(
          [](std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
                 user_data_auth::PrepareVaultForMigrationReply>> local_response,
             const user_data_auth::PrepareVaultForMigrationReply& reply) {
            local_response->Return(reply);
          },
          std::move(response)));
}

void UserDataAuthAdaptor::AddAuthFactor(
    std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
        user_data_auth::AddAuthFactorReply>> response,
    const user_data_auth::AddAuthFactorRequest& in_request) {
  service_->PostTaskToMountThread(
      FROM_HERE,
      base::BindOnce(
          &UserDataAuthAdaptor::DoAddAuthFactor, base::Unretained(this),
          ThreadSafeDBusMethodResponse<user_data_auth::AddAuthFactorReply>::
              MakeThreadSafe(std::move(response)),
          in_request));
}

void UserDataAuthAdaptor::DoAddAuthFactor(
    std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
        user_data_auth::AddAuthFactorReply>> response,
    const user_data_auth::AddAuthFactorRequest& in_request) {
  service_->AddAuthFactor(
      in_request,
      base::BindOnce(
          [](std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
                 user_data_auth::AddAuthFactorReply>> local_response,
             const user_data_auth::AddAuthFactorReply& reply) {
            local_response->Return(reply);
          },
          std::move(response)));
}

void UserDataAuthAdaptor::AuthenticateAuthFactor(
    std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
        user_data_auth::AuthenticateAuthFactorReply>> response,
    const user_data_auth::AuthenticateAuthFactorRequest& in_request) {
  service_->PostTaskToMountThread(
      FROM_HERE,
      base::BindOnce(&UserDataAuthAdaptor::DoAuthenticateAuthFactor,
                     base::Unretained(this),
                     ThreadSafeDBusMethodResponse<
                         user_data_auth::AuthenticateAuthFactorReply>::
                         MakeThreadSafe(std::move(response)),
                     in_request));
}

void UserDataAuthAdaptor::DoAuthenticateAuthFactor(
    std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
        user_data_auth::AuthenticateAuthFactorReply>> response,
    const user_data_auth::AuthenticateAuthFactorRequest& in_request) {
  service_->AuthenticateAuthFactor(
      in_request,
      base::BindOnce(
          [](std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
                 user_data_auth::AuthenticateAuthFactorReply>> local_response,
             const user_data_auth::AuthenticateAuthFactorReply& reply) {
            local_response->Return(reply);
          },
          std::move(response)));
}

void UserDataAuthAdaptor::UpdateAuthFactor(
    std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
        user_data_auth::UpdateAuthFactorReply>> response,
    const user_data_auth::UpdateAuthFactorRequest& in_request) {
  service_->PostTaskToMountThread(
      FROM_HERE,
      base::BindOnce(
          &UserDataAuthAdaptor::DoUpdateAuthFactor, base::Unretained(this),
          ThreadSafeDBusMethodResponse<user_data_auth::UpdateAuthFactorReply>::
              MakeThreadSafe(std::move(response)),
          in_request));
}

void UserDataAuthAdaptor::DoUpdateAuthFactor(
    std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
        user_data_auth::UpdateAuthFactorReply>> response,
    const user_data_auth::UpdateAuthFactorRequest& in_request) {
  service_->UpdateAuthFactor(
      in_request,
      base::BindOnce(
          [](std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
                 user_data_auth::UpdateAuthFactorReply>> local_response,
             const user_data_auth::UpdateAuthFactorReply& reply) {
            local_response->Return(reply);
          },
          std::move(response)));
}

void UserDataAuthAdaptor::UpdateAuthFactorMetadata(
    std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
        user_data_auth::UpdateAuthFactorMetadataReply>> response,
    const user_data_auth::UpdateAuthFactorMetadataRequest& in_request) {
  service_->PostTaskToMountThread(
      FROM_HERE,
      base::BindOnce(&UserDataAuthAdaptor::DoUpdateAuthFactorMetadata,
                     base::Unretained(this),
                     ThreadSafeDBusMethodResponse<
                         user_data_auth::UpdateAuthFactorMetadataReply>::
                         MakeThreadSafe(std::move(response)),
                     in_request));
}

void UserDataAuthAdaptor::DoUpdateAuthFactorMetadata(
    std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
        user_data_auth::UpdateAuthFactorMetadataReply>> response,
    const user_data_auth::UpdateAuthFactorMetadataRequest& in_request) {
  service_->UpdateAuthFactorMetadata(
      in_request,
      base::BindOnce(
          [](std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
                 user_data_auth::UpdateAuthFactorMetadataReply>> local_response,
             const user_data_auth::UpdateAuthFactorMetadataReply& reply) {
            local_response->Return(reply);
          },
          std::move(response)));
}

void UserDataAuthAdaptor::RemoveAuthFactor(
    std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
        user_data_auth::RemoveAuthFactorReply>> response,
    const user_data_auth::RemoveAuthFactorRequest& in_request) {
  service_->PostTaskToMountThread(
      FROM_HERE,
      base::BindOnce(
          &UserDataAuthAdaptor::DoRemoveAuthFactor, base::Unretained(this),
          ThreadSafeDBusMethodResponse<user_data_auth::RemoveAuthFactorReply>::
              MakeThreadSafe(std::move(response)),
          in_request));
}

void UserDataAuthAdaptor::DoRemoveAuthFactor(
    std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
        user_data_auth::RemoveAuthFactorReply>> response,
    const user_data_auth::RemoveAuthFactorRequest& in_request) {
  service_->RemoveAuthFactor(
      in_request,
      base::BindOnce(
          [](std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
                 user_data_auth::RemoveAuthFactorReply>> local_response,
             const user_data_auth::RemoveAuthFactorReply& reply) {
            local_response->Return(reply);
          },
          std::move(response)));
}

void UserDataAuthAdaptor::ListAuthFactors(
    std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
        user_data_auth::ListAuthFactorsReply>> response,
    const user_data_auth::ListAuthFactorsRequest& in_request) {
  service_->PostTaskToMountThread(
      FROM_HERE,
      base::BindOnce(
          &UserDataAuthAdaptor::DoListAuthFactors, base::Unretained(this),
          ThreadSafeDBusMethodResponse<user_data_auth::ListAuthFactorsReply>::
              MakeThreadSafe(std::move(response)),
          in_request));
}

void UserDataAuthAdaptor::DoListAuthFactors(
    std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
        user_data_auth::ListAuthFactorsReply>> response,
    const user_data_auth::ListAuthFactorsRequest& in_request) {
  service_->ListAuthFactors(
      in_request,
      base::BindOnce(
          [](std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
                 user_data_auth::ListAuthFactorsReply>> local_response,
             const user_data_auth::ListAuthFactorsReply& reply) {
            local_response->Return(reply);
          },
          std::move(response)));
}

void UserDataAuthAdaptor::GetAuthFactorExtendedInfo(
    std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
        user_data_auth::GetAuthFactorExtendedInfoReply>> response,
    const user_data_auth::GetAuthFactorExtendedInfoRequest& in_request) {
  service_->PostTaskToMountThread(
      FROM_HERE,
      base::BindOnce(&UserDataAuthAdaptor::DoGetAuthFactorExtendedInfo,
                     base::Unretained(this),
                     ThreadSafeDBusMethodResponse<
                         user_data_auth::GetAuthFactorExtendedInfoReply>::
                         MakeThreadSafe(std::move(response)),
                     in_request));
}

void UserDataAuthAdaptor::DoGetAuthFactorExtendedInfo(
    std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
        user_data_auth::GetAuthFactorExtendedInfoReply>> response,
    const user_data_auth::GetAuthFactorExtendedInfoRequest& in_request) {
  service_->GetAuthFactorExtendedInfo(
      in_request,
      base::BindOnce(
          [](std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
                 user_data_auth::GetAuthFactorExtendedInfoReply>>
                 local_response,
             const user_data_auth::GetAuthFactorExtendedInfoReply& reply) {
            local_response->Return(reply);
          },
          std::move(response)));
}

void UserDataAuthAdaptor::PrepareAuthFactor(
    std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
        user_data_auth::PrepareAuthFactorReply>> response,
    const user_data_auth::PrepareAuthFactorRequest& in_request) {
  service_->PostTaskToMountThread(
      FROM_HERE,
      base::BindOnce(
          &UserDataAuthAdaptor::DoPrepareAuthFactor, base::Unretained(this),
          ThreadSafeDBusMethodResponse<user_data_auth::PrepareAuthFactorReply>::
              MakeThreadSafe(std::move(response)),
          in_request));
}

void UserDataAuthAdaptor::DoPrepareAuthFactor(
    std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
        user_data_auth::PrepareAuthFactorReply>> response,
    const user_data_auth::PrepareAuthFactorRequest& in_request) {
  service_->PrepareAuthFactor(
      in_request,
      base::BindOnce(
          [](std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
                 user_data_auth::PrepareAuthFactorReply>> local_response,
             const user_data_auth::PrepareAuthFactorReply& reply) {
            local_response->Return(reply);
          },
          std::move(response)));
}

void UserDataAuthAdaptor::TerminateAuthFactor(
    std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
        user_data_auth::TerminateAuthFactorReply>> response,
    const user_data_auth::TerminateAuthFactorRequest& in_request) {
  service_->PostTaskToMountThread(
      FROM_HERE, base::BindOnce(&UserDataAuthAdaptor::DoTerminateAuthFactor,
                                base::Unretained(this),
                                ThreadSafeDBusMethodResponse<
                                    user_data_auth::TerminateAuthFactorReply>::
                                    MakeThreadSafe(std::move(response)),
                                in_request));
}

void UserDataAuthAdaptor::DoTerminateAuthFactor(
    std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
        user_data_auth::TerminateAuthFactorReply>> response,
    const user_data_auth::TerminateAuthFactorRequest& in_request) {
  service_->TerminateAuthFactor(
      in_request,
      base::BindOnce(
          [](std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
                 user_data_auth::TerminateAuthFactorReply>> local_response,
             const user_data_auth::TerminateAuthFactorReply& reply) {
            local_response->Return(reply);
          },
          std::move(response)));
}

void UserDataAuthAdaptor::GetRecoveryRequest(
    std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
        user_data_auth::GetRecoveryRequestReply>> response,
    const user_data_auth::GetRecoveryRequestRequest& in_request) {
  service_->PostTaskToMountThread(
      FROM_HERE, base::BindOnce(&UserDataAuthAdaptor::DoGetRecoveryRequest,
                                base::Unretained(this),
                                ThreadSafeDBusMethodResponse<
                                    user_data_auth::GetRecoveryRequestReply>::
                                    MakeThreadSafe(std::move(response)),
                                in_request));
}

void UserDataAuthAdaptor::DoGetRecoveryRequest(
    std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
        user_data_auth::GetRecoveryRequestReply>> response,
    const user_data_auth::GetRecoveryRequestRequest& in_request) {
  service_->GetRecoveryRequest(
      in_request,
      base::BindOnce(
          [](std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
                 user_data_auth::GetRecoveryRequestReply>> local_response,
             const user_data_auth::GetRecoveryRequestReply& reply) {
            local_response->Return(reply);
          },
          std::move(response)));
}

void UserDataAuthAdaptor::CreateVaultKeyset(
    std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
        user_data_auth::CreateVaultKeysetReply>> response,
    const user_data_auth::CreateVaultKeysetRequest& in_request) {
  service_->PostTaskToMountThread(
      FROM_HERE,
      base::BindOnce(
          &UserDataAuthAdaptor::DoCreateVaultKeyset, base::Unretained(this),
          ThreadSafeDBusMethodResponse<user_data_auth::CreateVaultKeysetReply>::
              MakeThreadSafe(std::move(response)),
          in_request));
}

void UserDataAuthAdaptor::DoCreateVaultKeyset(
    std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
        user_data_auth::CreateVaultKeysetReply>> response,
    const user_data_auth::CreateVaultKeysetRequest& in_request) {
  service_->CreateVaultKeyset(
      in_request,
      base::BindOnce(
          [](std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
                 user_data_auth::CreateVaultKeysetReply>> local_response,
             const user_data_auth::CreateVaultKeysetReply& reply) {
            local_response->Return(reply);
          },
          std::move(response)));
}

void UserDataAuthAdaptor::Remove(
    std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
        user_data_auth::RemoveReply>> response,
    const user_data_auth::RemoveRequest& in_request) {
  service_->PostTaskToMountThread(
      FROM_HERE,
      base::BindOnce(
          &UserDataAuthAdaptor::DoRemove, base::Unretained(this),
          ThreadSafeDBusMethodResponse<
              user_data_auth::RemoveReply>::MakeThreadSafe(std::move(response)),
          in_request));
}

void UserDataAuthAdaptor::DoRemove(
    std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
        user_data_auth::RemoveReply>> response,
    const user_data_auth::RemoveRequest& in_request) {
  user_data_auth::RemoveReply reply = service_->Remove(in_request);
  response->Return(reply);
}

void UserDataAuthAdaptor::ListKeys(
    std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
        user_data_auth::ListKeysReply>> response,
    const user_data_auth::ListKeysRequest& in_request) {
  service_->PostTaskToMountThread(
      FROM_HERE,
      base::BindOnce(
          &UserDataAuthAdaptor::DoListKeys, base::Unretained(this),
          ThreadSafeDBusMethodResponse<user_data_auth::ListKeysReply>::
              MakeThreadSafe(std::move(response)),
          in_request));
}

void UserDataAuthAdaptor::DoListKeys(
    std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
        user_data_auth::ListKeysReply>> response,
    const user_data_auth::ListKeysRequest& in_request) {
  // TODO(b/136152258): Add unit test for this method.
  user_data_auth::ListKeysReply reply = service_->ListKeys(in_request);
  response->Return(reply);
}

void UserDataAuthAdaptor::GetWebAuthnSecret(
    std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
        user_data_auth::GetWebAuthnSecretReply>> response,
    const user_data_auth::GetWebAuthnSecretRequest& in_request) {
  service_->PostTaskToMountThread(
      FROM_HERE,
      base::BindOnce(
          &UserDataAuthAdaptor::DoGetWebAuthnSecret, base::Unretained(this),
          ThreadSafeDBusMethodResponse<user_data_auth::GetWebAuthnSecretReply>::
              MakeThreadSafe(std::move(response)),
          in_request));
}

void UserDataAuthAdaptor::DoGetWebAuthnSecret(
    std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
        user_data_auth::GetWebAuthnSecretReply>> response,
    const user_data_auth::GetWebAuthnSecretRequest& in_request) {
  response->Return(service_->GetWebAuthnSecret(in_request));
}

void UserDataAuthAdaptor::GetWebAuthnSecretHash(
    std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
        user_data_auth::GetWebAuthnSecretHashReply>> response,
    const user_data_auth::GetWebAuthnSecretHashRequest& in_request) {
  service_->PostTaskToMountThread(
      FROM_HERE,
      base::BindOnce(&UserDataAuthAdaptor::DoGetWebAuthnSecretHash,
                     base::Unretained(this),
                     ThreadSafeDBusMethodResponse<
                         user_data_auth::GetWebAuthnSecretHashReply>::
                         MakeThreadSafe(std::move(response)),
                     in_request));
}

void UserDataAuthAdaptor::DoGetWebAuthnSecretHash(
    std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
        user_data_auth::GetWebAuthnSecretHashReply>> response,
    const user_data_auth::GetWebAuthnSecretHashRequest& in_request) {
  response->Return(service_->GetWebAuthnSecretHash(in_request));
}

void UserDataAuthAdaptor::GetHibernateSecret(
    std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
        user_data_auth::GetHibernateSecretReply>> response,
    const user_data_auth::GetHibernateSecretRequest& in_request) {
  service_->PostTaskToMountThread(
      FROM_HERE, base::BindOnce(&UserDataAuthAdaptor::DoGetHibernateSecret,
                                base::Unretained(this),
                                ThreadSafeDBusMethodResponse<
                                    user_data_auth::GetHibernateSecretReply>::
                                    MakeThreadSafe(std::move(response)),
                                in_request));
}

void UserDataAuthAdaptor::DoGetHibernateSecret(
    std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
        user_data_auth::GetHibernateSecretReply>> response,
    const user_data_auth::GetHibernateSecretRequest& in_request) {
  response->Return(service_->GetHibernateSecret(in_request));
}

void UserDataAuthAdaptor::GetEncryptionInfo(
    std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
        user_data_auth::GetEncryptionInfoReply>> response,
    const user_data_auth::GetEncryptionInfoRequest& in_request) {
  service_->PostTaskToMountThread(
      FROM_HERE,
      base::BindOnce(
          &UserDataAuthAdaptor::DoGetEncryptionInfo, base::Unretained(this),
          ThreadSafeDBusMethodResponse<user_data_auth::GetEncryptionInfoReply>::
              MakeThreadSafe(std::move(response)),
          in_request));
}

void UserDataAuthAdaptor::DoGetEncryptionInfo(
    std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
        user_data_auth::GetEncryptionInfoReply>> response,
    const user_data_auth::GetEncryptionInfoRequest& in_request) {
  response->Return(service_->GetEncryptionInfo(in_request));
}

void UserDataAuthAdaptor::StartMigrateToDircrypto(
    std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
        user_data_auth::StartMigrateToDircryptoReply>> response,
    const user_data_auth::StartMigrateToDircryptoRequest& in_request) {
  // This will be called whenever there's a status update from the migration.
  auto status_callback = base::BindRepeating(
      [](UserDataAuthAdaptor* adaptor,
         const user_data_auth::DircryptoMigrationProgress& progress) {
        adaptor->SendDircryptoMigrationProgressSignal(progress);
      },
      base::Unretained(this));

  // Kick start the migration process.
  service_->PostTaskToMountThread(
      FROM_HERE,
      base::BindOnce(&UserDataAuth::StartMigrateToDircrypto,
                     base::Unretained(service_), in_request, status_callback));

  // This function returns immediately after starting the migration process.
  // Also, this is always successful. Failure will be notified through the
  // signal.
  user_data_auth::StartMigrateToDircryptoReply reply;
  response->Return(reply);
}

void UserDataAuthAdaptor::NeedsDircryptoMigration(
    std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
        user_data_auth::NeedsDircryptoMigrationReply>> response,
    const user_data_auth::NeedsDircryptoMigrationRequest& in_request) {
  service_->PostTaskToMountThread(
      FROM_HERE,
      base::BindOnce(&UserDataAuthAdaptor::DoNeedsDircryptoMigration,
                     base::Unretained(this),
                     ThreadSafeDBusMethodResponse<
                         user_data_auth::NeedsDircryptoMigrationReply>::
                         MakeThreadSafe(std::move(response)),
                     in_request));
}

void UserDataAuthAdaptor::DoNeedsDircryptoMigration(
    std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
        user_data_auth::NeedsDircryptoMigrationReply>> response,
    const user_data_auth::NeedsDircryptoMigrationRequest& in_request) {
  user_data_auth::NeedsDircryptoMigrationReply reply;
  bool result = false;
  auto status =
      service_->NeedsDircryptoMigration(in_request.account_id(), &result);
  // Note, if there's no error, then |status| is set to CRYPTOHOME_ERROR_NOT_SET
  // to indicate that.
  reply.set_error(status);
  reply.set_needs_dircrypto_migration(result);
  response->Return(reply);
}

void UserDataAuthAdaptor::GetSupportedKeyPolicies(
    std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
        user_data_auth::GetSupportedKeyPoliciesReply>> response,
    const user_data_auth::GetSupportedKeyPoliciesRequest& in_request) {
  user_data_auth::GetSupportedKeyPoliciesReply reply;
  reply.set_low_entropy_credentials_supported(
      service_->IsLowEntropyCredentialSupported());
  response->Return(reply);
}

void UserDataAuthAdaptor::GetAccountDiskUsage(
    std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
        user_data_auth::GetAccountDiskUsageReply>> response,
    const user_data_auth::GetAccountDiskUsageRequest& in_request) {
  // Note that this is a long running call, so we're posting it to mount thread.
  service_->PostTaskToMountThread(
      FROM_HERE, base::BindOnce(&UserDataAuthAdaptor::DoGetAccountDiskUsage,
                                base::Unretained(this),
                                ThreadSafeDBusMethodResponse<
                                    user_data_auth::GetAccountDiskUsageReply>::
                                    MakeThreadSafe(std::move(response)),
                                in_request));
}

void UserDataAuthAdaptor::DoGetAccountDiskUsage(
    std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
        user_data_auth::GetAccountDiskUsageReply>> response,
    const user_data_auth::GetAccountDiskUsageRequest& in_request) {
  user_data_auth::GetAccountDiskUsageReply reply;
  // Note that for now, this call always succeeds, so |reply.error| is unset.
  reply.set_size(service_->GetAccountDiskUsage(in_request.identifier()));
  response->Return(reply);
}

void UserDataAuthAdaptor::AuthFactorStatusUpdateCallback(
    user_data_auth::AuthFactorWithStatus auth_factor_with_status,
    const std::string& broadcast_id) {
  user_data_auth::AuthFactorStatusUpdate status_update;
  *status_update.mutable_auth_factor_with_status() = auth_factor_with_status;
  status_update.set_broadcast_id(broadcast_id);
  SendAuthFactorStatusUpdateSignal(status_update);
}

void UserDataAuthAdaptor::LowDiskSpaceCallback(uint64_t free_disk_space) {
  user_data_auth::LowDiskSpace signal_payload;
  signal_payload.set_disk_free_bytes(free_disk_space);
  SendLowDiskSpaceSignal(signal_payload);
}

void UserDataAuthAdaptor::FingerprintScanResultCallback(
    user_data_auth::FingerprintScanResult result) {
  user_data_auth::AuthScanResult signal_payload;
  signal_payload.set_fingerprint_result(result);
  SendAuthScanResultSignal(signal_payload);
}

void UserDataAuthAdaptor::PrepareAuthFactorProgressCallback(
    user_data_auth::PrepareAuthFactorProgress signal) {
  SendPrepareAuthFactorProgressSignal(signal);
}

void ArcQuotaAdaptor::GetArcDiskFeatures(
    std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
        user_data_auth::GetArcDiskFeaturesReply>> response,
    const user_data_auth::GetArcDiskFeaturesRequest& in_request) {
  user_data_auth::GetArcDiskFeaturesReply reply;
  reply.set_quota_supported(service_->IsArcQuotaSupported());
  response->Return(reply);
}

void ArcQuotaAdaptor::GetCurrentSpaceForArcUid(
    std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
        user_data_auth::GetCurrentSpaceForArcUidReply>> response,
    const user_data_auth::GetCurrentSpaceForArcUidRequest& in_request) {
  user_data_auth::GetCurrentSpaceForArcUidReply reply;
  reply.set_cur_space(service_->GetCurrentSpaceForArcUid(in_request.uid()));
  response->Return(reply);
}

void ArcQuotaAdaptor::GetCurrentSpaceForArcGid(
    std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
        user_data_auth::GetCurrentSpaceForArcGidReply>> response,
    const user_data_auth::GetCurrentSpaceForArcGidRequest& in_request) {
  user_data_auth::GetCurrentSpaceForArcGidReply reply;
  reply.set_cur_space(service_->GetCurrentSpaceForArcGid(in_request.gid()));
  response->Return(reply);
}

void ArcQuotaAdaptor::GetCurrentSpaceForArcProjectId(
    std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
        user_data_auth::GetCurrentSpaceForArcProjectIdReply>> response,
    const user_data_auth::GetCurrentSpaceForArcProjectIdRequest& in_request) {
  user_data_auth::GetCurrentSpaceForArcProjectIdReply reply;
  reply.set_cur_space(
      service_->GetCurrentSpaceForArcProjectId(in_request.project_id()));
  response->Return(reply);
}

void ArcQuotaAdaptor::SetMediaRWDataFileProjectId(
    std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
        user_data_auth::SetMediaRWDataFileProjectIdReply>> response,
    const base::ScopedFD& in_fd,
    const user_data_auth::SetMediaRWDataFileProjectIdRequest& in_request) {
  int error = 0;
  const bool success = service_->SetMediaRWDataFileProjectId(
      in_request.project_id(), in_fd.get(), &error);
  user_data_auth::SetMediaRWDataFileProjectIdReply reply;
  reply.set_success(success);
  if (!success)
    reply.set_error(error);
  response->Return(reply);
}

void ArcQuotaAdaptor::SetMediaRWDataFileProjectInheritanceFlag(
    std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
        user_data_auth::SetMediaRWDataFileProjectInheritanceFlagReply>>
        response,
    const base::ScopedFD& in_fd,
    const user_data_auth::SetMediaRWDataFileProjectInheritanceFlagRequest&
        in_request) {
  int error = 0;
  const bool success = service_->SetMediaRWDataFileProjectInheritanceFlag(
      in_request.enable(), in_fd.get(), &error);
  user_data_auth::SetMediaRWDataFileProjectInheritanceFlagReply reply;
  reply.set_success(success);
  if (!success)
    reply.set_error(error);
  response->Return(reply);
}

void Pkcs11Adaptor::Pkcs11IsTpmTokenReady(
    std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
        user_data_auth::Pkcs11IsTpmTokenReadyReply>> response,
    const user_data_auth::Pkcs11IsTpmTokenReadyRequest& in_request) {
  service_->PostTaskToMountThread(
      FROM_HERE,
      base::BindOnce(&Pkcs11Adaptor::DoPkcs11IsTpmTokenReady,
                     base::Unretained(this),
                     ThreadSafeDBusMethodResponse<
                         user_data_auth::Pkcs11IsTpmTokenReadyReply>::
                         MakeThreadSafe(std::move(response)),
                     in_request));
}

void Pkcs11Adaptor::DoPkcs11IsTpmTokenReady(
    std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
        user_data_auth::Pkcs11IsTpmTokenReadyReply>> response,
    const user_data_auth::Pkcs11IsTpmTokenReadyRequest& in_request) {
  user_data_auth::Pkcs11IsTpmTokenReadyReply reply;
  reply.set_ready(service_->Pkcs11IsTpmTokenReady());
  response->Return(reply);
}

void Pkcs11Adaptor::Pkcs11GetTpmTokenInfo(
    std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
        user_data_auth::Pkcs11GetTpmTokenInfoReply>> response,
    const user_data_auth::Pkcs11GetTpmTokenInfoRequest& in_request) {
  user_data_auth::Pkcs11GetTpmTokenInfoReply reply;
  *reply.mutable_token_info() =
      service_->Pkcs11GetTpmTokenInfo(Username(in_request.username()));
  response->Return(reply);
}

void Pkcs11Adaptor::Pkcs11Terminate(
    std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
        user_data_auth::Pkcs11TerminateReply>> response,
    const user_data_auth::Pkcs11TerminateRequest& in_request) {
  service_->PostTaskToMountThread(
      FROM_HERE,
      base::BindOnce(
          &Pkcs11Adaptor::DoPkcs11Terminate, base::Unretained(this),
          ThreadSafeDBusMethodResponse<user_data_auth::Pkcs11TerminateReply>::
              MakeThreadSafe(std::move(response)),
          in_request));
}

void Pkcs11Adaptor::DoPkcs11Terminate(
    std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
        user_data_auth::Pkcs11TerminateReply>> response,
    const user_data_auth::Pkcs11TerminateRequest& in_request) {
  user_data_auth::Pkcs11TerminateReply reply;
  service_->Pkcs11Terminate();
  response->Return(reply);
}

void Pkcs11Adaptor::Pkcs11RestoreTpmTokens(
    std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
        user_data_auth::Pkcs11RestoreTpmTokensReply>> response,
    const user_data_auth::Pkcs11RestoreTpmTokensRequest& in_request) {
  service_->PostTaskToMountThread(
      FROM_HERE,
      base::BindOnce(&Pkcs11Adaptor::DoPkcs11RestoreTpmTokens,
                     base::Unretained(this),
                     ThreadSafeDBusMethodResponse<
                         user_data_auth::Pkcs11RestoreTpmTokensReply>::
                         MakeThreadSafe(std::move(response)),
                     in_request));
}

void Pkcs11Adaptor::DoPkcs11RestoreTpmTokens(
    std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
        user_data_auth::Pkcs11RestoreTpmTokensReply>> response,
    const user_data_auth::Pkcs11RestoreTpmTokensRequest& in_request) {
  user_data_auth::Pkcs11RestoreTpmTokensReply reply;
  service_->Pkcs11RestoreTpmTokens();
  response->Return(reply);
}

void InstallAttributesAdaptor::InstallAttributesGet(
    std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
        user_data_auth::InstallAttributesGetReply>> response,
    const user_data_auth::InstallAttributesGetRequest& in_request) {
  service_->PostTaskToMountThread(
      FROM_HERE,
      base::BindOnce(&InstallAttributesAdaptor::DoInstallAttributesGet,
                     base::Unretained(this),
                     ThreadSafeDBusMethodResponse<
                         user_data_auth::InstallAttributesGetReply>::
                         MakeThreadSafe(std::move(response)),
                     in_request));
}

void InstallAttributesAdaptor::DoInstallAttributesGet(
    std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
        user_data_auth::InstallAttributesGetReply>> response,
    const user_data_auth::InstallAttributesGetRequest& in_request) {
  user_data_auth::InstallAttributesGetReply reply;
  std::vector<uint8_t> data;
  bool result = service_->InstallAttributesGet(in_request.name(), &data);
  if (result) {
    *reply.mutable_value() = {data.begin(), data.end()};
  } else {
    reply.set_error(
        user_data_auth::CRYPTOHOME_ERROR_INSTALL_ATTRIBUTES_GET_FAILED);
  }
  response->Return(reply);
}

void InstallAttributesAdaptor::InstallAttributesSet(
    std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
        user_data_auth::InstallAttributesSetReply>> response,
    const user_data_auth::InstallAttributesSetRequest& in_request) {
  service_->PostTaskToMountThread(
      FROM_HERE,
      base::BindOnce(&InstallAttributesAdaptor::DoInstallAttributesSet,
                     base::Unretained(this),
                     ThreadSafeDBusMethodResponse<
                         user_data_auth::InstallAttributesSetReply>::
                         MakeThreadSafe(std::move(response)),
                     in_request));
}

void InstallAttributesAdaptor::DoInstallAttributesSet(
    std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
        user_data_auth::InstallAttributesSetReply>> response,
    const user_data_auth::InstallAttributesSetRequest& in_request) {
  user_data_auth::InstallAttributesSetReply reply;
  std::vector<uint8_t> data(in_request.value().begin(),
                            in_request.value().end());
  bool result = service_->InstallAttributesSet(in_request.name(), data);
  if (!result) {
    reply.set_error(
        user_data_auth::CRYPTOHOME_ERROR_INSTALL_ATTRIBUTES_SET_FAILED);
  }
  response->Return(reply);
}

void InstallAttributesAdaptor::InstallAttributesFinalize(
    std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
        user_data_auth::InstallAttributesFinalizeReply>> response,
    const user_data_auth::InstallAttributesFinalizeRequest& in_request) {
  service_->PostTaskToMountThread(
      FROM_HERE,
      base::BindOnce(&InstallAttributesAdaptor::DoInstallAttributesFinalize,
                     base::Unretained(this),
                     ThreadSafeDBusMethodResponse<
                         user_data_auth::InstallAttributesFinalizeReply>::
                         MakeThreadSafe(std::move(response)),
                     in_request));
}

void InstallAttributesAdaptor::DoInstallAttributesFinalize(
    std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
        user_data_auth::InstallAttributesFinalizeReply>> response,
    const user_data_auth::InstallAttributesFinalizeRequest& in_request) {
  user_data_auth::InstallAttributesFinalizeReply reply;
  if (!service_->InstallAttributesFinalize()) {
    reply.set_error(
        user_data_auth::CRYPTOHOME_ERROR_INSTALL_ATTRIBUTES_FINALIZE_FAILED);
  }
  response->Return(reply);
}

void InstallAttributesAdaptor::InstallAttributesGetStatus(
    std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
        user_data_auth::InstallAttributesGetStatusReply>> response,
    const user_data_auth::InstallAttributesGetStatusRequest& in_request) {
  service_->PostTaskToMountThread(
      FROM_HERE,
      base::BindOnce(&InstallAttributesAdaptor::DoInstallAttributesGetStatus,
                     base::Unretained(this),
                     ThreadSafeDBusMethodResponse<
                         user_data_auth::InstallAttributesGetStatusReply>::
                         MakeThreadSafe(std::move(response)),
                     in_request));
}

void InstallAttributesAdaptor::DoInstallAttributesGetStatus(
    std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
        user_data_auth::InstallAttributesGetStatusReply>> response,
    const user_data_auth::InstallAttributesGetStatusRequest& in_request) {
  user_data_auth::InstallAttributesGetStatusReply reply;
  reply.set_count(service_->InstallAttributesCount());
  reply.set_is_secure(service_->InstallAttributesIsSecure());
  reply.set_state(UserDataAuth::InstallAttributesStatusToProtoEnum(
      service_->InstallAttributesGetStatus()));
  response->Return(reply);
}

void InstallAttributesAdaptor::GetFirmwareManagementParameters(
    std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
        user_data_auth::GetFirmwareManagementParametersReply>> response,
    const user_data_auth::GetFirmwareManagementParametersRequest& in_request) {
  user_data_auth::GetFirmwareManagementParametersReply reply;
  user_data_auth::FirmwareManagementParameters fwmp;
  auto status = service_->GetFirmwareManagementParameters(&fwmp);
  // Note, if there's no error, then |status| is set to CRYPTOHOME_ERROR_NOT_SET
  // to indicate that.
  reply.set_error(status);

  if (status == user_data_auth::CRYPTOHOME_ERROR_NOT_SET) {
    *reply.mutable_fwmp() = fwmp;
  }
  response->Return(reply);
}

void InstallAttributesAdaptor::RemoveFirmwareManagementParameters(
    std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
        user_data_auth::RemoveFirmwareManagementParametersReply>> response,
    const user_data_auth::RemoveFirmwareManagementParametersRequest&
        in_request) {
  user_data_auth::RemoveFirmwareManagementParametersReply reply;
  if (!service_->RemoveFirmwareManagementParameters()) {
    reply.set_error(
        user_data_auth::
            CRYPTOHOME_ERROR_FIRMWARE_MANAGEMENT_PARAMETERS_CANNOT_REMOVE);
  }
  response->Return(reply);
}

void InstallAttributesAdaptor::SetFirmwareManagementParameters(
    std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
        user_data_auth::SetFirmwareManagementParametersReply>> response,
    const user_data_auth::SetFirmwareManagementParametersRequest& in_request) {
  user_data_auth::SetFirmwareManagementParametersReply reply;
  auto status = service_->SetFirmwareManagementParameters(in_request.fwmp());
  // Note, if there's no error, then |status| is set to CRYPTOHOME_ERROR_NOT_SET
  // to indicate that.
  reply.set_error(status);
  response->Return(reply);
}

void CryptohomeMiscAdaptor::GetSystemSalt(
    std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
        user_data_auth::GetSystemSaltReply>> response,
    const user_data_auth::GetSystemSaltRequest& in_request) {
  user_data_auth::GetSystemSaltReply reply;
  const brillo::SecureBlob& salt = service_->GetSystemSalt();
  reply.set_salt(salt.char_data(), salt.size());
  response->Return(reply);
}

void CryptohomeMiscAdaptor::UpdateCurrentUserActivityTimestamp(
    std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
        user_data_auth::UpdateCurrentUserActivityTimestampReply>> response,
    const user_data_auth::UpdateCurrentUserActivityTimestampRequest&
        in_request) {
  service_->PostTaskToMountThread(
      FROM_HERE,
      base::BindOnce(
          &CryptohomeMiscAdaptor::DoUpdateCurrentUserActivityTimestamp,
          base::Unretained(this),
          ThreadSafeDBusMethodResponse<
              user_data_auth::UpdateCurrentUserActivityTimestampReply>::
              MakeThreadSafe(std::move(response)),
          in_request));
}

void CryptohomeMiscAdaptor::DoUpdateCurrentUserActivityTimestamp(
    std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
        user_data_auth::UpdateCurrentUserActivityTimestampReply>> response,
    const user_data_auth::UpdateCurrentUserActivityTimestampRequest&
        in_request) {
  user_data_auth::UpdateCurrentUserActivityTimestampReply reply;
  bool success =
      service_->UpdateCurrentUserActivityTimestamp(in_request.time_shift_sec());
  if (!success) {
    reply.set_error(
        user_data_auth::CRYPTOHOME_ERROR_UPDATE_USER_ACTIVITY_TIMESTAMP_FAILED);
  }
  response->Return(reply);
}

void CryptohomeMiscAdaptor::GetSanitizedUsername(
    std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
        user_data_auth::GetSanitizedUsernameReply>> response,
    const user_data_auth::GetSanitizedUsernameRequest& in_request) {
  user_data_auth::GetSanitizedUsernameReply reply;
  reply.set_sanitized_username(*brillo::cryptohome::home::SanitizeUserName(
      Username(in_request.username())));
  response->Return(reply);
}

void CryptohomeMiscAdaptor::GetLoginStatus(
    std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
        user_data_auth::GetLoginStatusReply>> response,
    const user_data_auth::GetLoginStatusRequest& in_request) {
  user_data_auth::GetLoginStatusReply reply;
  reply.set_owner_user_exists(service_->OwnerUserExists());
  reply.set_is_locked_to_single_user(
      base::PathExists(base::FilePath(kLockedToSingleUserFile)));
  response->Return(reply);
}

void CryptohomeMiscAdaptor::LockToSingleUserMountUntilReboot(
    std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
        user_data_auth::LockToSingleUserMountUntilRebootReply>> response,
    const user_data_auth::LockToSingleUserMountUntilRebootRequest& in_request) {
  user_data_auth::LockToSingleUserMountUntilRebootReply reply;
  auto status =
      service_->LockToSingleUserMountUntilReboot(in_request.account_id());
  reply.set_error(status);
  response->Return(reply);
}

void CryptohomeMiscAdaptor::GetRsuDeviceId(
    std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
        user_data_auth::GetRsuDeviceIdReply>> response,
    const user_data_auth::GetRsuDeviceIdRequest& in_request) {
  user_data_auth::GetRsuDeviceIdReply reply;
  std::string rsu_device_id;
  if (!service_->GetRsuDeviceId(&rsu_device_id)) {
    response->ReplyWithError(FROM_HERE, brillo::errors::dbus::kDomain,
                             DBUS_ERROR_FAILED,
                             "Unable to retrieve lookup key!");
    return;
  }
  *reply.mutable_rsu_device_id() = rsu_device_id;
  response->Return(reply);
}

void UserDataAuthAdaptor::GetAuthSessionStatus(
    std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
        user_data_auth::GetAuthSessionStatusReply>> response,
    const user_data_auth::GetAuthSessionStatusRequest& in_request) {
  service_->PostTaskToMountThread(
      FROM_HERE, base::BindOnce(&UserDataAuthAdaptor::DoGetAuthSessionStatus,
                                base::Unretained(this),
                                ThreadSafeDBusMethodResponse<
                                    user_data_auth::GetAuthSessionStatusReply>::
                                    MakeThreadSafe(std::move(response)),
                                in_request));
}

void UserDataAuthAdaptor::DoGetAuthSessionStatus(
    std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
        user_data_auth::GetAuthSessionStatusReply>> response,
    const user_data_auth::GetAuthSessionStatusRequest& in_request) {
  service_->GetAuthSessionStatus(
      in_request,
      base::BindOnce(
          [](std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
                 user_data_auth::GetAuthSessionStatusReply>> local_response,
             const user_data_auth::GetAuthSessionStatusReply& reply) {
            local_response->Return(reply);
          },
          std::move(response)));
}

void UserDataAuthAdaptor::ResetApplicationContainer(
    std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
        user_data_auth::ResetApplicationContainerReply>> response,
    const user_data_auth::ResetApplicationContainerRequest& in_request) {
  service_->PostTaskToMountThread(
      FROM_HERE,
      base::BindOnce(&UserDataAuthAdaptor::DoResetApplicationContainer,
                     base::Unretained(this),
                     ThreadSafeDBusMethodResponse<
                         user_data_auth::ResetApplicationContainerReply>::
                         MakeThreadSafe(std::move(response)),
                     in_request));
}

void UserDataAuthAdaptor::DoResetApplicationContainer(
    std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
        user_data_auth::ResetApplicationContainerReply>> response,
    const user_data_auth::ResetApplicationContainerRequest& in_request) {
  user_data_auth::ResetApplicationContainerReply reply =
      service_->ResetApplicationContainer(in_request);
  response->Return(reply);
}

}  // namespace cryptohome
