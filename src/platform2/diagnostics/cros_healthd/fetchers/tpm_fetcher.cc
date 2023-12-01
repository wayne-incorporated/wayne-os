// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/cros_healthd/fetchers/tpm_fetcher.h"

#include <optional>
#include <string>
#include <utility>

#include <attestation-client/attestation/dbus-proxies.h>
#include <base/check.h>
#include <base/functional/callback.h>
#include <base/strings/string_number_conversions.h>
#include <base/time/time.h>
#include <brillo/errors/error.h>
#include <dbus/object_proxy.h>
#include <tpm_manager-client/tpm_manager/dbus-proxies.h>

#include "diagnostics/base/file_utils.h"
#include "diagnostics/cros_healthd/utils/dbus_utils.h"
#include "diagnostics/cros_healthd/utils/error_utils.h"

namespace diagnostics {

namespace {

namespace mojom = ::ash::cros_healthd::mojom;

// Tpm manager and attestation require a long timeout.
const int64_t DBUS_TIMEOUT_MS = base::Minutes(2).InMilliseconds();

mojom::TpmGSCVersion GetGscVersion(
    const tpm_manager::GetVersionInfoReply& reply) {
  switch (reply.gsc_version()) {
    case tpm_manager::GSC_VERSION_NOT_GSC:
      return mojom::TpmGSCVersion::kNotGSC;
    case tpm_manager::GSC_VERSION_CR50:
      return mojom::TpmGSCVersion::kCr50;
    case tpm_manager::GSC_VERSION_TI50:
      return mojom::TpmGSCVersion::kTi50;
  }
}

}  // namespace

void TpmFetcher::FetchVersion() {
  tpm_manager::GetVersionInfoRequest request;
  auto [on_success, on_error] = SplitDbusCallback(
      base::BindOnce(&TpmFetcher::HandleVersion, weak_factory_.GetWeakPtr()));
  context_->tpm_manager_proxy()->GetVersionInfoAsync(
      request, std::move(on_success), std::move(on_error), DBUS_TIMEOUT_MS);
}

void TpmFetcher::HandleVersion(brillo::Error* err,
                               const tpm_manager::GetVersionInfoReply& reply) {
  DCHECK(info_);
  if (err) {
    SendError("Failed to call TpmManager::GetVersionInfo(): " +
              err->GetMessage());
    return;
  }
  if (reply.status() != tpm_manager::STATUS_SUCCESS) {
    SendError("TpmManager::GetVersionInfo() returned error status: " +
              base::NumberToString(reply.status()));
    return;
  }
  auto version = mojom::TpmVersion::New();
  version->gsc_version = GetGscVersion(reply);
  version->family = reply.family();
  version->spec_level = reply.spec_level();
  version->manufacturer = reply.manufacturer();
  version->tpm_model = reply.tpm_model();
  version->firmware_version = reply.firmware_version();
  version->vendor_specific = reply.vendor_specific().empty()
                                 ? std::nullopt
                                 : std::make_optional(reply.vendor_specific());
  info_->version = std::move(version);
  CheckAndSendInfo();
}

void TpmFetcher::FetchStatus() {
  tpm_manager::GetTpmNonsensitiveStatusRequest request;
  auto [on_success, on_error] = SplitDbusCallback(
      base::BindOnce(&TpmFetcher::HandleStatus, weak_factory_.GetWeakPtr()));
  context_->tpm_manager_proxy()->GetTpmNonsensitiveStatusAsync(
      request, std::move(on_success), std::move(on_error), DBUS_TIMEOUT_MS);
}

void TpmFetcher::HandleStatus(
    brillo::Error* err,
    const tpm_manager::GetTpmNonsensitiveStatusReply& reply) {
  DCHECK(info_);
  if (err) {
    SendError("Failed to call TpmManager::GetTpmNonsensitiveStatus(): " +
              err->GetMessage());
    return;
  }
  if (reply.status() != tpm_manager::STATUS_SUCCESS) {
    SendError("TpmManager::GetTpmNonsensitiveStatus() returned error status: " +
              base::NumberToString(reply.status()));
    return;
  }
  auto status = mojom::TpmStatus::New();
  status->enabled = reply.is_enabled();
  status->owned = reply.is_owned();
  status->owner_password_is_present = reply.is_owner_password_present();
  info_->status = std::move(status);
  CheckAndSendInfo();
}

void TpmFetcher::FetchDictionaryAttack() {
  tpm_manager::GetDictionaryAttackInfoRequest request;
  auto [on_success, on_error] = SplitDbusCallback(base::BindOnce(
      &TpmFetcher::HandleDictionaryAttack, weak_factory_.GetWeakPtr()));
  context_->tpm_manager_proxy()->GetDictionaryAttackInfoAsync(
      request, std::move(on_success), std::move(on_error), DBUS_TIMEOUT_MS);
}

void TpmFetcher::HandleDictionaryAttack(
    brillo::Error* err,
    const tpm_manager::GetDictionaryAttackInfoReply& reply) {
  DCHECK(info_);
  if (err) {
    SendError("Failed to call TpmManager::GetDictionaryAttackInfo(): " +
              err->GetMessage());
    return;
  }
  if (reply.status() != tpm_manager::STATUS_SUCCESS) {
    SendError("TpmManager::GetDictionaryAttackInfo() returned error status: " +
              base::NumberToString(reply.status()));
    return;
  }

  auto da = mojom::TpmDictionaryAttack::New();
  da->counter = reply.dictionary_attack_counter();
  da->threshold = reply.dictionary_attack_threshold();
  da->lockout_in_effect = reply.dictionary_attack_lockout_in_effect();
  da->lockout_seconds_remaining =
      reply.dictionary_attack_lockout_seconds_remaining();
  info_->dictionary_attack = std::move(da);
  CheckAndSendInfo();
}

void TpmFetcher::FetchAttestation() {
  attestation::GetStatusRequest request;
  auto [on_success, on_error] = SplitDbusCallback(base::BindOnce(
      &TpmFetcher::HandleAttestation, weak_factory_.GetWeakPtr()));
  context_->attestation_proxy()->GetStatusAsync(
      request, std::move(on_success), std::move(on_error), DBUS_TIMEOUT_MS);
}

void TpmFetcher::HandleAttestation(brillo::Error* err,
                                   const attestation::GetStatusReply& reply) {
  DCHECK(info_);
  if (err) {
    SendError("Failed to call Attestation::GetStatus(): " + err->GetMessage());
    return;
  }
  if (reply.status() != attestation::STATUS_SUCCESS) {
    SendError("TpmManager::GetDictionaryAttackInfo() returned error status: " +
              base::NumberToString(reply.status()));
    return;
  }

  auto data = mojom::TpmAttestation::New();
  data->prepared_for_enrollment = reply.prepared_for_enrollment();
  data->enrolled = reply.enrolled();
  info_->attestation = std::move(data);
  CheckAndSendInfo();
}

void TpmFetcher::FetchSupportedFeatures() {
  tpm_manager::GetSupportedFeaturesRequest request;
  auto [on_success, on_error] = SplitDbusCallback(base::BindOnce(
      &TpmFetcher::HandleSupportedFeatures, weak_factory_.GetWeakPtr()));
  context_->tpm_manager_proxy()->GetSupportedFeaturesAsync(
      request, std::move(on_success), std::move(on_error), DBUS_TIMEOUT_MS);
}

void TpmFetcher::HandleSupportedFeatures(
    brillo::Error* err, const tpm_manager::GetSupportedFeaturesReply& reply) {
  DCHECK(info_);
  if (err) {
    SendError("Failed to call TpmManager::GetSupportedFeatures(): " +
              err->GetMessage());
    return;
  }
  if (reply.status() != tpm_manager::STATUS_SUCCESS) {
    SendError("TpmManager::GetSupportedFeatures() returned error status: " +
              base::NumberToString(reply.status()));
    return;
  }

  auto data = mojom::TpmSupportedFeatures::New();
  data->support_u2f = reply.support_u2f();
  data->support_pinweaver = reply.support_pinweaver();
  data->support_runtime_selection = reply.support_runtime_selection();
  data->is_allowed = reply.is_allowed();
  info_->supported_features = std::move(data);
  CheckAndSendInfo();
}

void TpmFetcher::CheckAndSendInfo() {
  DCHECK(info_);
  if (!info_->version || !info_->status || !info_->dictionary_attack ||
      !info_->attestation || !info_->supported_features) {
    return;
  }
  SendResult(mojom::TpmResult::NewTpmInfo(std::move(info_)));
}

void TpmFetcher::SendError(const std::string& message) {
  SendResult(mojom::TpmResult::NewError(
      CreateAndLogProbeError(mojom::ErrorType::kServiceUnavailable, message)));
}

void TpmFetcher::SendResult(mojom::TpmResultPtr result) {
  // Invalid all weak ptrs to prevent other callbacks to be run.
  weak_factory_.InvalidateWeakPtrs();
  if (pending_callbacks_.empty())
    return;
  for (size_t i = 1; i < pending_callbacks_.size(); ++i) {
    std::move(pending_callbacks_[i]).Run(result.Clone());
  }
  std::move(pending_callbacks_[0]).Run(std::move(result));
  pending_callbacks_.clear();
}

void TpmFetcher::FetchTpmInfo(TpmFetcher::FetchTpmInfoCallback&& callback) {
  pending_callbacks_.push_back(std::move(callback));
  // Returns if there is already a pending callback. The second callback will be
  // fulfilled when the first one is fulfilled.
  if (pending_callbacks_.size() > 1)
    return;

  info_ = mojom::TpmInfo::New();
  FetchVersion();
  FetchStatus();
  FetchDictionaryAttack();
  FetchAttestation();
  FetchSupportedFeatures();

  ReadAndTrimString(context_->root_dir().Append(kFileTpmDidVid),
                    &info_->did_vid);
}

}  // namespace diagnostics
