// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// Provides the implementation of StatefulRecovery.

#include "cryptohome/stateful_recovery/stateful_recovery.h"

#include <brillo/secure_blob.h>
#include <unistd.h>

#include <string>

#include <base/files/file_path.h>
#include <base/json/json_writer.h>
#include <base/logging.h>
#include <base/strings/string_util.h>
#include <base/values.h>
#include <brillo/syslog_logging.h>
#include <brillo/cryptohome.h>
#include <cryptohome/proto_bindings/auth_factor.pb.h>
#include <policy/device_policy.h>
#include <policy/libpolicy.h>

#include "cryptohome/auth_session.h"
#include "cryptohome/filesystem_layout.h"
#include "cryptohome/platform.h"
#include "cryptohome/username.h"

using base::FilePath;

namespace cryptohome {

const char StatefulRecovery::kRecoverSource[] =
    "/mnt/stateful_partition/encrypted";
const char StatefulRecovery::kRecoverDestination[] =
    "/mnt/stateful_partition/decrypted";
const char StatefulRecovery::kRecoverBlockUsage[] =
    "/mnt/stateful_partition/decrypted/block-usage.txt";
const char StatefulRecovery::kRecoverFilesystemDetails[] =
    "/mnt/stateful_partition/decrypted/filesystem-details.txt";
const char StatefulRecovery::kFlagFile[] =
    "/mnt/stateful_partition/decrypt_stateful";
const int kDefaultTimeoutMs = 30000;

StatefulRecovery::StatefulRecovery(
    Platform* platform,
    org::chromium::UserDataAuthInterfaceProxyInterface* userdataauth_proxy,
    policy::PolicyProvider* policy_provider,
    std::string flag_file)
    : requested_(false),
      platform_(platform),
      userdataauth_proxy_(userdataauth_proxy),
      policy_provider_(policy_provider),
      flag_file_(FilePath(flag_file)),
      timeout_ms_(kDefaultTimeoutMs) {}

bool StatefulRecovery::Requested() {
  requested_ = ParseFlagFile();
  return requested_;
}

bool StatefulRecovery::CopyPartitionInfo() {
  struct statvfs vfs;

  if (!platform_->StatVFS(FilePath(kRecoverSource), &vfs))
    return false;

  base::Value::Dict dv =
      base::Value::Dict()
          .Set("filesystem", FilePath(kRecoverSource).value())
          .Set("blocks-total", static_cast<int>(vfs.f_blocks))
          .Set("blocks-free", static_cast<int>(vfs.f_bfree))
          .Set("blocks-avail", static_cast<int>(vfs.f_bavail))
          .Set("inodes-total", static_cast<int>(vfs.f_files))
          .Set("inodes-free", static_cast<int>(vfs.f_ffree))
          .Set("inodes-avail", static_cast<int>(vfs.f_favail));

  std::string output;
  base::JSONWriter::WriteWithOptions(dv, base::JSONWriter::OPTIONS_PRETTY_PRINT,
                                     &output);

  if (!platform_->WriteStringToFile(FilePath(kRecoverBlockUsage), output))
    return false;

  if (!platform_->ReportFilesystemDetails(FilePath(kRecoverSource),
                                          FilePath(kRecoverFilesystemDetails)))
    return false;

  return true;
}

bool StatefulRecovery::CopyUserContents() {
  int rc;
  FilePath path;

  if (!Mount(user_, passkey_, &path)) {
    // mountfn_ logged the error already.
    return false;
  }

  rc = platform_->Copy(path, FilePath(kRecoverDestination));

  Unmount();
  // If it failed, unmountfn_ would log the error.

  if (rc)
    return true;
  LOG(ERROR) << "Failed to copy " << path.value();
  return false;
}

bool StatefulRecovery::CopyPartitionContents() {
  int rc;

  rc = platform_->Copy(FilePath(kRecoverSource), FilePath(kRecoverDestination));
  if (rc)
    return true;
  LOG(ERROR) << "Failed to copy " << FilePath(kRecoverSource).value();
  return false;
}

bool StatefulRecovery::RecoverV1() {
  // Version 1 requires write protect be disabled.
  if (platform_->FirmwareWriteProtected()) {
    LOG(ERROR) << "Refusing v1 recovery request: firmware is write protected.";
    return false;
  }

  if (!CopyPartitionContents())
    return false;
  if (!CopyPartitionInfo())
    return false;

  return true;
}

bool StatefulRecovery::RecoverV2() {
  bool wrote_data = false;
  bool is_authenticated_owner = false;

  // If possible, copy user contents.
  if (CopyUserContents()) {
    wrote_data = true;
    // If user authenticated, check if they are the owner.
    if (IsOwner(*user_)) {
      is_authenticated_owner = true;
    }
  }

  // Version 2 requires either write protect disabled or system owner.
  if (!platform_->FirmwareWriteProtected() || is_authenticated_owner) {
    if (!CopyPartitionContents() || !CopyPartitionInfo()) {
      // Even if we wrote out user data, claim failure here if the
      // encrypted-stateful partition couldn't be extracted.
      return false;
    }

    wrote_data = true;
  }

  return wrote_data;
}

bool StatefulRecovery::Recover() {
  if (!requested_)
    return false;

  // Start with a clean slate. Note that there is a window of opportunity for
  // another process to create the directory with funky permissions after the
  // delete takes place but before we manage to recreate. Since the parent
  // directory is root-owned though, this isn't a problem in practice.
  const FilePath kDestinationPath(kRecoverDestination);
  if (!platform_->DeletePathRecursively(kDestinationPath) ||
      !platform_->CreateDirectory(kDestinationPath)) {
    PLOG(ERROR) << "Failed to create fresh " << kDestinationPath.value();
    return false;
  }

  if (version_ == "2") {
    return RecoverV2();
  } else if (version_ == "1") {
    return RecoverV1();
  } else {
    LOG(ERROR) << "Unknown recovery version: " << version_;
    return false;
  }
}

bool StatefulRecovery::ParseFlagFile() {
  std::string contents;
  size_t delim, pos;
  if (!platform_->ReadFileToString(flag_file_, &contents))
    return false;

  // Make sure there is a trailing newline.
  contents += "\n";

  do {
    pos = 0;
    delim = contents.find("\n", pos);
    if (delim == std::string::npos)
      break;
    version_ = contents.substr(pos, delim);

    if (version_ == "1")
      return true;

    if (version_ != "2")
      break;

    pos = delim + 1;
    delim = contents.find("\n", pos);
    if (delim == std::string::npos)
      break;
    user_ = Username(contents.substr(pos, delim - pos));

    pos = delim + 1;
    delim = contents.find("\n", pos);
    if (delim == std::string::npos)
      break;
    passkey_ = contents.substr(pos, delim - pos);

    return true;
  } while (0);

  // TODO(ellyjones): UMA stat?
  LOG(ERROR) << "Bogus stateful recovery request file:" << contents;
  return false;
}

void StatefulRecovery::InvalidateAuthSession(
    const std::string& auth_session_id) {
  user_data_auth::InvalidateAuthSessionRequest invalidate_session_req;
  invalidate_session_req.set_auth_session_id(auth_session_id);
  user_data_auth::InvalidateAuthSessionReply invalidate_session_reply;
  brillo::ErrorPtr error;

  if (!userdataauth_proxy_->InvalidateAuthSession(invalidate_session_req,
                                                  &invalidate_session_reply,
                                                  &error, timeout_ms_) ||
      error) {
    LOG(WARNING) << "Failed to invalidate auth session for stateful recovery: "
                 << error->GetMessage();
  }
  if (invalidate_session_reply.error() !=
      user_data_auth::CryptohomeErrorCode::CRYPTOHOME_ERROR_NOT_SET) {
    LOG(ERROR) << "InvalidateAuthSession failed during stateful recovery: "
               << invalidate_session_reply.error();
  }
}

bool StatefulRecovery::Mount(const Username& username,
                             const std::string& password,
                             FilePath* out_home_path) {
  // Start an AuthSession first to authenticate the user and mount the user
  // vault.

  brillo::ErrorPtr error;
  user_data_auth::StartAuthSessionRequest auth_session_req;
  auth_session_req.mutable_account_id()->set_account_id(*username);
  auth_session_req.set_intent(user_data_auth::AUTH_INTENT_DECRYPT);
  auth_session_req.set_flags(
      user_data_auth::AuthSessionFlags::AUTH_SESSION_FLAGS_NONE);
  user_data_auth::StartAuthSessionReply auth_session_reply;
  if (!userdataauth_proxy_->StartAuthSession(
          auth_session_req, &auth_session_reply, &error, timeout_ms_) ||
      error) {
    LOG(ERROR) << "Failed to start auth session for stateful recovery: "
               << error->GetMessage();
    return false;
  }
  if (auth_session_reply.error() !=
      user_data_auth::CryptohomeErrorCode::CRYPTOHOME_ERROR_NOT_SET) {
    LOG(ERROR) << "StartAuthSession failed during stateful recovery: "
               << auth_session_reply.error();
    return false;
  }
  if (!auth_session_reply.user_exists()) {
    LOG(ERROR) << "User for stateful recovery doesn't exist.";
    return false;
  }
  LOG(INFO) << "AuthSession started for stateful recovery.";

  // Parse the available factors to find the password label
  std::string auth_factor_label;
  for (auto auth_factor : auth_session_reply.auth_factors()) {
    if (auth_factor.type() ==
        user_data_auth::AuthFactorType::AUTH_FACTOR_TYPE_PASSWORD) {
      auth_factor_label = auth_factor.label();
    }
  }

  // Authenticate the user with the created AuthSession

  // Obtain salted passkey from raw password.
  brillo::SecureBlob salt;
  if (!GetSystemSalt(platform_, &salt)) {
    LOG(ERROR) << "Failed to get system salt for stateful recovery.";
    return false;
  }
  brillo::SecureBlob passkey_blob;
  Crypto::PasswordToPasskey(password.c_str(), salt, &passkey_blob);
  std::string passkey = passkey_blob.to_string();

  // Authenticate.
  user_data_auth::AuthenticateAuthFactorRequest authenticate_req;
  authenticate_req.set_auth_session_id(auth_session_reply.auth_session_id());
  authenticate_req.set_auth_factor_label(auth_factor_label);
  authenticate_req.mutable_auth_input()->mutable_password_input()->set_secret(
      passkey);
  user_data_auth::AuthenticateAuthFactorReply authenticate_reply;
  if (!userdataauth_proxy_->AuthenticateAuthFactor(
          authenticate_req, &authenticate_reply, &error, timeout_ms_) ||
      error) {
    LOG(ERROR) << "Failed to authenticate auth session for stateful recovery: "
               << error->GetMessage();
    InvalidateAuthSession(auth_session_reply.auth_session_id());
    return false;
  }
  if (authenticate_reply.error() !=
      user_data_auth::CryptohomeErrorCode::CRYPTOHOME_ERROR_NOT_SET) {
    LOG(ERROR) << "AuthenticateAuthFactor failed during stateful recovery: "
               << auth_session_reply.error();
    InvalidateAuthSession(auth_session_reply.auth_session_id());
    return false;
  }

  if (std::find(authenticate_reply.authorized_for().begin(),
                authenticate_reply.authorized_for().end(),
                user_data_auth::AUTH_INTENT_DECRYPT) ==
      authenticate_reply.authorized_for().end()) {
    LOG(ERROR) << "AuthenticateAuthFactor returned success but failed to "
                  "authenticate.";
    InvalidateAuthSession(auth_session_reply.auth_session_id());
    return false;
  }
  LOG(INFO) << "AuthSession authenticated for stateful recovery.";

  // Now the user is authenticated and we can attempt mounting user vault.

  user_data_auth::PreparePersistentVaultRequest prepare_vault_req;
  prepare_vault_req.set_auth_session_id(auth_session_reply.auth_session_id());

  user_data_auth::PreparePersistentVaultReply prepare_vault_reply;
  if (!userdataauth_proxy_->PreparePersistentVault(
          prepare_vault_req, &prepare_vault_reply, &error, timeout_ms_) ||
      error) {
    LOG(ERROR) << "Failed to prepare persistent vault for stateful recovery: "
               << error->GetMessage();
    InvalidateAuthSession(auth_session_reply.auth_session_id());
    return false;
  }
  if (prepare_vault_reply.error() !=
      user_data_auth::CryptohomeErrorCode::CRYPTOHOME_ERROR_NOT_SET) {
    LOG(ERROR) << "PreparePersistentVault failed during stateful recovery: "
               << prepare_vault_reply.error();
    InvalidateAuthSession(auth_session_reply.auth_session_id());
    return false;
  }
  LOG(INFO) << "Prepared persistent vault for stateful recovery.";

  // Cleanup AuthSession.

  *out_home_path = GetUserMountDirectory(
      brillo::cryptohome::home::SanitizeUserName(username));

  InvalidateAuthSession(auth_session_reply.auth_session_id());
  return true;
}

bool StatefulRecovery::Unmount() {
  user_data_auth::UnmountRequest req;

  user_data_auth::UnmountReply reply;
  brillo::ErrorPtr error;
  if (!userdataauth_proxy_->Unmount(req, &reply, &error, timeout_ms_) ||
      error) {
    LOG(ERROR) << "Unmount call failed: " << error->GetMessage();
    return false;
  }
  if (reply.error() !=
      user_data_auth::CryptohomeErrorCode::CRYPTOHOME_ERROR_NOT_SET) {
    LOG(ERROR) << "Unmount failed: " << reply.error();
    printf("Unmount failed.\n");
    return false;
  }
  LOG(INFO) << "Unmount succeeded.";
  return true;
}

bool StatefulRecovery::IsOwner(const std::string& username) {
  std::string owner;
  policy_provider_->Reload();
  if (!policy_provider_->device_policy_is_loaded())
    return false;
  policy_provider_->GetDevicePolicy().GetOwner(&owner);
  if (username.empty() || owner.empty())
    return false;

  return username == owner;
}

}  // namespace cryptohome
