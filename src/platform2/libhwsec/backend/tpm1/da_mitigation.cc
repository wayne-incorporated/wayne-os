// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "libhwsec/backend/tpm1/da_mitigation.h"

#include <utility>

#include <base/time/time.h>
#include <libhwsec-foundation/status/status_chain_macros.h>
#include <tpm_manager/proto_bindings/tpm_manager.pb.h>
#include <tpm_manager-client/tpm_manager/dbus-proxies.h>

#include "libhwsec/error/tpm_manager_error.h"

using hwsec_foundation::status::MakeStatus;

namespace hwsec {

StatusOr<bool> DAMitigationTpm1::IsReady() {
  tpm_manager::GetTpmNonsensitiveStatusRequest request;
  tpm_manager::GetTpmNonsensitiveStatusReply reply;

  if (brillo::ErrorPtr err; !tpm_manager_.GetTpmNonsensitiveStatus(
          request, &reply, &err, Proxy::kDefaultDBusTimeoutMs)) {
    return MakeStatus<TPMError>(TPMRetryAction::kCommunication)
        .Wrap(std::move(err));
  }

  RETURN_IF_ERROR(MakeStatus<TPMManagerError>(reply.status()));

  return reply.has_reset_lock_permissions();
}

StatusOr<DAMitigationTpm1::DAMitigationStatus> DAMitigationTpm1::GetStatus() {
  tpm_manager::GetDictionaryAttackInfoRequest request;
  tpm_manager::GetDictionaryAttackInfoReply reply;

  if (brillo::ErrorPtr err; !tpm_manager_.GetDictionaryAttackInfo(
          request, &reply, &err, Proxy::kDefaultDBusTimeoutMs)) {
    return MakeStatus<TPMError>(TPMRetryAction::kCommunication)
        .Wrap(std::move(err));
  }

  RETURN_IF_ERROR(MakeStatus<TPMManagerError>(reply.status()));

  return DAMitigationStatus{
      .lockout = reply.dictionary_attack_lockout_in_effect(),
      .remaining =
          base::Seconds(reply.dictionary_attack_lockout_seconds_remaining()),
  };
}

Status DAMitigationTpm1::Mitigate() {
  tpm_manager::ResetDictionaryAttackLockRequest request;
  tpm_manager::ResetDictionaryAttackLockReply reply;

  if (brillo::ErrorPtr err; !tpm_manager_.ResetDictionaryAttackLock(
          request, &reply, &err, Proxy::kDefaultDBusTimeoutMs)) {
    return MakeStatus<TPMError>(TPMRetryAction::kCommunication)
        .Wrap(std::move(err));
  }

  return MakeStatus<TPMManagerError>(reply.status());
}

}  // namespace hwsec
