// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "tpm_softclear_utils/tpm2_impl.h"

#include <memory>
#include <optional>
#include <string>

#include <base/logging.h>
#include <tpm_manager/proto_bindings/tpm_manager.pb.h>
#include <trunks/authorization_delegate.h>
#include <trunks/error_codes.h>
#include <trunks/tpm_generated.h>
#include <trunks/tpm_state.h>

namespace tpm_softclear_utils {

bool Tpm2Impl::Initialize() {
  if (!default_trunks_factory_.Initialize()) {
    LOG(ERROR) << __func__ << ": failed to initialize trunks factory.";
    return false;
  }

  trunks_factory_ = &default_trunks_factory_;
  return true;
}

std::optional<std::string> Tpm2Impl::GetAuthForOwnerReset() {
  if (!trunks_factory_) {
    LOG(ERROR) << __func__ << ": trunks factory is uninitialized.";
    return {};
  }

  std::unique_ptr<trunks::TpmState> trunks_tpm_state =
      trunks_factory_->GetTpmState();
  trunks::TPM_RC result = trunks_tpm_state->Initialize();
  if (result) {
    LOG(ERROR) << __func__ << ": failed to initialize trunks tpm state: "
               << trunks::GetErrorString(result);
    return {};
  }

  if (!trunks_tpm_state->IsLockoutPasswordSet()) {
    // If the lockout password is not set in the TPM, we should not trust the
    // local data but use the default password instead.
    LOG(INFO) << "Lockout password hasn't been set. Using the default lockout "
                 "password.";
    return std::string(kDefaultLockoutPassword);
  }

  std::string raw_data;
  if (!ReadFileToString(local_data_path_, &raw_data)) {
    // This covers both the cases of local data file not existing and failing to
    // read that file. The local data file should exist if the lockout password
    // is set.
    LOG(ERROR) << __func__ << " : failed to read file "
               << local_data_path_.value();
    return {};
  }

  tpm_manager::LocalData local_data;
  if (!local_data.ParseFromString(raw_data)) {
    LOG(ERROR) << __func__
               << ": failed to parse local data file into protobuf.";
    return {};
  }

  const std::string& lockout_password = local_data.lockout_password();
  const size_t password_length = lockout_password.length();
  if (password_length != kLockoutPasswordSize) {
    LOG(ERROR) << __func__
               << ": bad lockout password, length = " << password_length;
    return {};
  }

  LOG(INFO) << "Using the lockout password in tpm_manager local data.";
  return lockout_password;
}

bool Tpm2Impl::SoftClearOwner(const std::string& auth_for_owner_reset) {
  if (!trunks_factory_) {
    LOG(ERROR) << __func__ << ": trunks factory is uninitialized.";
    return {};
  }
  LOG(INFO) << "Start soft-clearing TPM 2.0";

  std::unique_ptr<trunks::AuthorizationDelegate> lockout_password_delegate(
      trunks_factory_->GetPasswordAuthorization(auth_for_owner_reset));

  std::string lockout_handle_name;
  trunks::TPM_RC result = trunks::Serialize_TPM_HANDLE(trunks::TPM_RH_LOCKOUT,
                                                       &lockout_handle_name);
  if (result != trunks::TPM_RC_SUCCESS) {
    LOG(ERROR) << __func__ << ": failed to serialize TPM lockout handle: "
               << trunks::GetErrorString(result);
    return false;
  }

  result = trunks_factory_->GetTpm()->ClearSync(
      trunks::TPM_RH_LOCKOUT, lockout_handle_name,
      lockout_password_delegate.get());
  if (result != trunks::TPM_RC_SUCCESS) {
    LOG(ERROR) << __func__ << ": failed to clear the TPM: "
               << trunks::GetErrorString(result);
    return false;
  }

  return true;
}

}  // namespace tpm_softclear_utils
