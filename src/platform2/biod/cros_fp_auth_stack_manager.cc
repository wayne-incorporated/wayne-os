// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "biod/cros_fp_auth_stack_manager.h"

#include <memory>
#include <string>
#include <utility>

#include <base/check.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/notreached.h>

#include "biod/cros_fp_device.h"
#include "biod/cros_fp_record_manager.h"
#include "biod/power_button_filter_interface.h"
#include "biod/proto_bindings/constants.pb.h"
#include "biod/proto_bindings/messages.pb.h"

namespace biod {

// There is already a Session class in the biod namespace.
using BioSession = CrosFpAuthStackManager::Session;
using Mode = ec::FpMode::Mode;

CrosFpAuthStackManager::CrosFpAuthStackManager(
    std::unique_ptr<PowerButtonFilterInterface> power_button_filter,
    std::unique_ptr<ec::CrosFpDeviceInterface> cros_fp_device,
    BiodMetricsInterface* biod_metrics,
    std::unique_ptr<CrosFpRecordManagerInterface> record_manager)
    : biod_metrics_(biod_metrics),
      cros_dev_(std::move(cros_fp_device)),
      power_button_filter_(std::move(power_button_filter)),
      record_manager_(std::move(record_manager)),
      session_weak_factory_(this) {
  CHECK(power_button_filter_);
  CHECK(cros_dev_);
  CHECK(biod_metrics_);
  CHECK(record_manager_);

  cros_dev_->SetMkbpEventCallback(base::BindRepeating(
      &CrosFpAuthStackManager::OnMkbpEvent, base::Unretained(this)));
}

BiometricType CrosFpAuthStackManager::GetType() {
  return BIOMETRIC_TYPE_FINGERPRINT;
}

BioSession CrosFpAuthStackManager::StartEnrollSession() {
  NOTREACHED();
  return BioSession(base::NullCallback());
}

CreateCredentialReply CrosFpAuthStackManager::CreateCredential(
    const CreateCredentialRequest& request) {
  NOTREACHED();
  CreateCredentialReply reply;
  return reply;
}

BioSession CrosFpAuthStackManager::StartAuthSession() {
  NOTREACHED();
  return BioSession(base::NullCallback());
}

AuthenticateCredentialReply CrosFpAuthStackManager::AuthenticateCredential(
    const AuthenticateCredentialRequest& request) {
  NOTREACHED();
  AuthenticateCredentialReply reply;
  return reply;
}

void CrosFpAuthStackManager::RemoveRecordsFromMemory() {
  NOTREACHED();
}

bool CrosFpAuthStackManager::ReadRecordsForSingleUser(
    const std::string& user_id) {
  NOTREACHED();
  return false;
}

void CrosFpAuthStackManager::SetEnrollScanDoneHandler(
    const AuthStackManager::EnrollScanDoneCallback& on_enroll_scan_done) {
  NOTREACHED();
}

void CrosFpAuthStackManager::SetAuthScanDoneHandler(
    const AuthStackManager::AuthScanDoneCallback& on_auth_scan_done) {
  NOTREACHED();
}

void CrosFpAuthStackManager::SetSessionFailedHandler(
    const AuthStackManager::SessionFailedCallback& on_session_failed) {
  NOTREACHED();
}

void CrosFpAuthStackManager::EndEnrollSession() {
  KillMcuSession();
}

void CrosFpAuthStackManager::EndAuthSession() {
  KillMcuSession();
}

void CrosFpAuthStackManager::KillMcuSession() {
  // TODO(b/274509408): test cros_dev_->FpMode(FP_MODE_DEEPSLEEP);
  cros_dev_->SetFpMode(ec::FpMode(Mode::kNone));
  session_weak_factory_.InvalidateWeakPtrs();
  OnTaskComplete();
}

void CrosFpAuthStackManager::OnMkbpEvent(uint32_t event) {
  if (!next_session_action_.is_null())
    next_session_action_.Run(event);
}

void CrosFpAuthStackManager::OnTaskComplete() {
  next_session_action_ = SessionAction();
}

}  // namespace biod
