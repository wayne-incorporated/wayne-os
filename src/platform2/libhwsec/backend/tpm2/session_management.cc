// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "libhwsec/backend/tpm2/session_management.h"

#include <functional>
#include <memory>
#include <utility>

#include <absl/container/flat_hash_map.h>
#include <libhwsec-foundation/status/status_chain_macros.h>
#include <trunks/hmac_session.h>
#include <trunks/tpm_utility.h>
#include <trunks/trunks_factory.h>

#include "libhwsec/error/tpm2_error.h"
#include "libhwsec/status.h"

using brillo::BlobFromString;
using brillo::BlobToString;
using hwsec_foundation::status::MakeStatus;

namespace hwsec {

Status SessionManagementTpm2::FlushInvalidSessions() {
  if (hmac_sessions_.empty()) {
    return MakeStatus<TPMError>("Nothing to flush", TPMRetryAction::kNoRetry);
  }
  // Clear all HMAC sessions.
  hmac_sessions_.clear();
  return OkStatus();
}

StatusOr<std::reference_wrapper<trunks::HmacSession>>
SessionManagementTpm2::GetOrCreateHmacSession(SessionSecuritySetting setting) {
  auto [iter, new_insert] = hmac_sessions_.insert({setting, nullptr});
  if (!new_insert && iter->second != nullptr) {
    // The session already exists.
    // Reset the entity authorization value.
    iter->second->SetEntityAuthorizationValue("");
    return *iter->second;
  }

  std::unique_ptr<trunks::HmacSession>& hmac_session = iter->second;

  hmac_session = context_.GetTrunksFactory().GetHmacSession();

  SessionSecurityDetail detail = ToSessionSecurityDetail(setting);

  RETURN_IF_ERROR(MakeStatus<TPM2Error>(hmac_session->StartUnboundSession(
                      detail.salted, detail.enable_encryption)))
      .WithStatus<TPMError>("Failed to start hmac session");

  hmac_session->SetEntityAuthorizationValue("");

  return *hmac_session;
}

}  // namespace hwsec
