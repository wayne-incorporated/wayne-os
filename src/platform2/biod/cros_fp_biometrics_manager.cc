// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "biod/cros_fp_biometrics_manager.h"

#include <optional>
#include <utility>

#include <errno.h>
#include <poll.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <base/base64.h>
#include <base/check.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_piece.h>
#include <base/threading/platform_thread.h>
#include <base/time/time.h>
#include <base/timer/timer.h>
#include <crypto/random.h>
#include <dbus/bus.h>
#include <metrics/metrics_library.h>

#include "biod/biod_crypto.h"
#include "biod/biod_metrics.h"
#include "biod/power_button_filter.h"
#include "biod/utils.h"
#include "libec/fingerprint/cros_fp_device_interface.h"
#include "libec/fingerprint/fp_mode.h"
#include "libec/fingerprint/fp_sensor_errors.h"

namespace {

std::string MatchResultToString(int result) {
  switch (result) {
    case EC_MKBP_FP_ERR_MATCH_NO:
      return "No match";
    case EC_MKBP_FP_ERR_MATCH_NO_INTERNAL:
      return "Internal error";
    case EC_MKBP_FP_ERR_MATCH_NO_TEMPLATES:
      return "No templates";
    case EC_MKBP_FP_ERR_MATCH_NO_LOW_QUALITY:
      return "Low quality";
    case EC_MKBP_FP_ERR_MATCH_NO_LOW_COVERAGE:
      return "Low coverage";
    case EC_MKBP_FP_ERR_MATCH_YES:
      return "Finger matched";
    case EC_MKBP_FP_ERR_MATCH_YES_UPDATED:
      return "Finger matched, template updated";
    case EC_MKBP_FP_ERR_MATCH_YES_UPDATE_FAILED:
      return "Finger matched, template updated failed";
    default:
      return "Unknown matcher result";
  }
}

std::string EnrollResultToString(int result) {
  switch (result) {
    case EC_MKBP_FP_ERR_ENROLL_OK:
      return "Success";
    case EC_MKBP_FP_ERR_ENROLL_LOW_QUALITY:
      return "Low quality";
    case EC_MKBP_FP_ERR_ENROLL_IMMOBILE:
      return "Same area";
    case EC_MKBP_FP_ERR_ENROLL_LOW_COVERAGE:
      return "Low coverage";
    case EC_MKBP_FP_ERR_ENROLL_INTERNAL:
      return "Internal error";
    default:
      return "Unknown enrollment result";
  }
}

};  // namespace

namespace biod {

using Mode = ec::FpMode::Mode;

const std::string& CrosFpBiometricsManager::Record::GetId() const {
  return record_id_;
}

std::string CrosFpBiometricsManager::Record::GetUserId() const {
  CHECK(biometrics_manager_);
  const auto record_metadata =
      biometrics_manager_->GetRecordMetadata(record_id_);
  CHECK(record_metadata);

  return record_metadata->user_id;
}

std::string CrosFpBiometricsManager::Record::GetLabel() const {
  CHECK(biometrics_manager_);
  const auto record_metadata =
      biometrics_manager_->GetRecordMetadata(record_id_);
  CHECK(record_metadata);

  return record_metadata->label;
}

std::vector<uint8_t> CrosFpBiometricsManager::Record::GetValidationVal() const {
  CHECK(biometrics_manager_);
  const auto record_metadata =
      biometrics_manager_->GetRecordMetadata(record_id_);
  CHECK(record_metadata);

  return record_metadata->validation_val;
}

bool CrosFpBiometricsManager::Record::SetLabel(std::string label) {
  CHECK(biometrics_manager_);

  auto record_metadata = biometrics_manager_->GetRecordMetadata(record_id_);
  CHECK(record_metadata);

  record_metadata->label = std::move(label);

  return biometrics_manager_->UpdateRecordMetadata(*record_metadata);
}

bool CrosFpBiometricsManager::Record::Remove() {
  if (!biometrics_manager_)
    return false;

  return biometrics_manager_->RemoveRecord(record_id_);
}

bool CrosFpBiometricsManager::ReloadAllRecords(std::string user_id) {
  // Here we need a copy of user_id because the user_id could be part of
  // loaded_records_ which is cleared in this method.
  loaded_records_.clear();
  suspicious_templates_.clear();

  return ReadRecordsForSingleUser(user_id);
}

BiometricType CrosFpBiometricsManager::GetType() {
  return BIOMETRIC_TYPE_FINGERPRINT;
}

BiometricsManager::EnrollSession CrosFpBiometricsManager::StartEnrollSession(
    std::string user_id, std::string label) {
  LOG(INFO) << __func__;
  // Another session is on-going, fail early ...
  if (!next_session_action_.is_null()) {
    LOG(ERROR) << kEnrollSessionExists;
    BiometricsManager::EnrollSession enroll_session;
    enroll_session.set_error(kEnrollSessionExists);
    return enroll_session;
  }

  if (loaded_records_.size() >= cros_dev_->MaxTemplateCount()) {
    LOG(ERROR) << kTemplatesFull;
    BiometricsManager::EnrollSession enroll_session;
    enroll_session.set_error(kTemplatesFull);
    return enroll_session;
  }

  std::vector<uint8_t> validation_val;
  if (!RequestEnrollImage(BiodStorageInterface::RecordMetadata{
          kRecordFormatVersion, BiodStorage::GenerateNewRecordId(),
          std::move(user_id), std::move(label), std::move(validation_val)})) {
    LOG(ERROR) << kEnrollImageNotRequested;
    BiometricsManager::EnrollSession enroll_session;
    enroll_session.set_error(kEnrollImageNotRequested);
    return enroll_session;
  }

  if (cros_dev_->GetHwErrors() != ec::FpSensorErrors::kNone) {
    LOG(ERROR) << kFpHwUnavailable;
    BiometricsManager::EnrollSession enroll_session;
    enroll_session.set_error(kFpHwUnavailable);
    return enroll_session;
  }

  num_enrollment_captures_ = 0;
  return BiometricsManager::EnrollSession(session_weak_factory_.GetWeakPtr());
}

BiometricsManager::AuthSession CrosFpBiometricsManager::StartAuthSession() {
  LOG(INFO) << __func__;
  // Another session is on-going, fail early ...
  if (!next_session_action_.is_null()) {
    LOG(ERROR) << kAuthSessionExists;
    BiometricsManager::AuthSession auth_session;
    auth_session.set_error(kAuthSessionExists);
    return auth_session;
  }

  if (!RequestMatch()) {
    LOG(ERROR) << kMatchNotRequested;
    BiometricsManager::AuthSession auth_session;
    auth_session.set_error(kMatchNotRequested);
    return auth_session;
  }

  if (cros_dev_->GetHwErrors() != ec::FpSensorErrors::kNone) {
    LOG(ERROR) << kFpHwUnavailable;
    BiometricsManager::AuthSession auth_session;
    auth_session.set_error(kFpHwUnavailable);
    return auth_session;
  }

  return BiometricsManager::AuthSession(session_weak_factory_.GetWeakPtr());
}

std::vector<std::unique_ptr<BiometricsManagerRecord>>
CrosFpBiometricsManager::GetLoadedRecords() {
  std::vector<std::unique_ptr<BiometricsManagerRecord>> records;

  for (const auto& record_id : loaded_records_) {
    records.emplace_back(
        std::make_unique<Record>(weak_factory_.GetWeakPtr(), record_id));
  }

  return records;
}

std::optional<BiodStorageInterface::RecordMetadata>
CrosFpBiometricsManager::GetRecordMetadata(const std::string& record_id) const {
  return record_manager_->GetRecordMetadata(record_id);
}

std::optional<std::string> CrosFpBiometricsManager::GetLoadedRecordId(int id) {
  if (id < 0 || id >= loaded_records_.size()) {
    return std::nullopt;
  }
  return loaded_records_[id];
}

bool CrosFpBiometricsManager::DestroyAllRecords() {
  return record_manager_->DeleteAllRecords();
}

void CrosFpBiometricsManager::RemoveRecordsFromMemory() {
  record_manager_->RemoveRecordsFromMemory();
  loaded_records_.clear();
  suspicious_templates_.clear();
  cros_dev_->ResetContext();
}

bool CrosFpBiometricsManager::RemoveRecord(const std::string& record_id) {
  const auto record = record_manager_->GetRecordMetadata(record_id);
  if (!record) {
    LOG(ERROR) << "Can't find metadata for record " << LogSafeID(record_id);
    return false;
  }

  std::string user_id = record->user_id;

  // TODO(b/115399954): only delete record if user_id is primary user.
  if (!record_manager_->DeleteRecord(record_id))
    return false;

  // We cannot remove only one record if we want to stay in sync with the MCU,
  // Clear and reload everything.
  return ReloadAllRecords(user_id);
}

bool CrosFpBiometricsManager::UpdateRecordMetadata(
    const BiodStorageInterface::RecordMetadata& record_metadata) {
  return record_manager_->UpdateRecordMetadata(record_metadata);
}

bool CrosFpBiometricsManager::ReadRecordsForSingleUser(
    const std::string& user_id) {
  cros_dev_->SetContext(user_id);
  auto valid_records = record_manager_->GetRecordsForUser(user_id);
  for (const auto& record : valid_records) {
    LoadRecord(std::move(record));
  }

  if (record_manager_->UserHasInvalidRecords(user_id)) {
    record_manager_->DeleteInvalidRecords();
    return false;
  }

  return true;
}

void CrosFpBiometricsManager::SetEnrollScanDoneHandler(
    const BiometricsManager::EnrollScanDoneCallback& on_enroll_scan_done) {
  on_enroll_scan_done_ = on_enroll_scan_done;
}

void CrosFpBiometricsManager::SetAuthScanDoneHandler(
    const BiometricsManager::AuthScanDoneCallback& on_auth_scan_done) {
  on_auth_scan_done_ = on_auth_scan_done;
}

void CrosFpBiometricsManager::SetSessionFailedHandler(
    const BiometricsManager::SessionFailedCallback& on_session_failed) {
  on_session_failed_ = on_session_failed;
}

bool CrosFpBiometricsManager::SendStatsOnLogin() {
  bool rc = true;
  rc = biod_metrics_->SendEnrolledFingerCount(loaded_records_.size()) && rc;
  // Even though it looks a bit redundant with the finger count, it's easier to
  // discover and interpret.
  rc = biod_metrics_->SendFpUnlockEnabled(!loaded_records_.empty()) && rc;
  return rc;
}

void CrosFpBiometricsManager::SetDiskAccesses(bool allow) {
  record_manager_->SetAllowAccess(allow);
}

bool CrosFpBiometricsManager::ResetSensor() {
  if (!cros_dev_->SetFpMode(ec::FpMode(Mode::kResetSensor))) {
    LOG(ERROR) << "Failed to send reset_sensor command to FPMCU.";
    return false;
  }

  int retries = 50;
  bool reset_complete = false;
  while (retries--) {
    ec::FpMode cur_mode = cros_dev_->GetFpMode();
    if (cur_mode == ec::FpMode(Mode::kModeInvalid)) {
      LOG(ERROR) << "Failed to query sensor state during reset.";
      return false;
    }

    if (cur_mode != ec::FpMode(Mode::kResetSensor)) {
      reset_complete = true;
      break;
    }
    base::PlatformThread::Sleep(base::Milliseconds(100));
  }

  if (!reset_complete) {
    LOG(ERROR) << "Reset on FPMCU failed to complete.";
    return false;
  }

  return true;
}

bool CrosFpBiometricsManager::ResetEntropy(bool factory_init) {
  bool success = cros_dev_->InitEntropy(!factory_init);
  if (!success) {
    LOG(INFO) << "Entropy source reset failed.";
    return false;
  }
  LOG(INFO) << "Entropy source has been successfully reset.";
  return true;
}

void CrosFpBiometricsManager::EndEnrollSession() {
  LOG(INFO) << __func__;
  KillMcuSession();
}

void CrosFpBiometricsManager::EndAuthSession() {
  LOG(INFO) << __func__;
  KillMcuSession();
}

void CrosFpBiometricsManager::KillMcuSession() {
  // TODO(vpalatin): test cros_dev_->FpMode(FP_MODE_DEEPSLEEP);
  cros_dev_->SetFpMode(ec::FpMode(Mode::kNone));
  session_weak_factory_.InvalidateWeakPtrs();
  OnTaskComplete();
}

CrosFpBiometricsManager::CrosFpBiometricsManager(
    std::unique_ptr<PowerButtonFilterInterface> power_button_filter,
    std::unique_ptr<ec::CrosFpDeviceInterface> cros_fp_device,
    BiodMetricsInterface* biod_metrics,
    std::unique_ptr<CrosFpRecordManagerInterface> record_manager)
    : biod_metrics_(biod_metrics),
      cros_dev_(std::move(cros_fp_device)),
      session_weak_factory_(this),
      weak_factory_(this),
      power_button_filter_(std::move(power_button_filter)),
      record_manager_(std::move(record_manager)),
      maintenance_timer_(std::make_unique<base::OneShotTimer>()) {
  CHECK(power_button_filter_);
  CHECK(cros_dev_);
  CHECK(biod_metrics_);
  CHECK(maintenance_timer_);
  CHECK(record_manager_);

  cros_dev_->SetMkbpEventCallback(base::BindRepeating(
      &CrosFpBiometricsManager::OnMkbpEvent, base::Unretained(this)));

  CHECK(cros_dev_->SupportsPositiveMatchSecret());

  ScheduleMaintenance(base::Days(1));
}

void CrosFpBiometricsManager::ScheduleMaintenance(
    const base::TimeDelta& delta) {
  maintenance_timer_->Start(
      FROM_HERE, delta,
      base::BindOnce(&CrosFpBiometricsManager::OnMaintenanceTimerFired,
                     base::Unretained(this)));
}

CrosFpBiometricsManager::~CrosFpBiometricsManager() {}

void CrosFpBiometricsManager::OnEnrollScanDone(
    ScanResult result, const BiometricsManager::EnrollStatus& enroll_status) {
  if (!on_enroll_scan_done_.is_null())
    on_enroll_scan_done_.Run(result, enroll_status);
}

void CrosFpBiometricsManager::OnAuthScanDone(
    FingerprintMessage result,
    const BiometricsManager::AttemptMatches& matches) {
  if (!on_auth_scan_done_.is_null())
    on_auth_scan_done_.Run(result, matches);
}

void CrosFpBiometricsManager::OnSessionFailed() {
  LOG(INFO) << __func__;

  if (!on_session_failed_.is_null())
    on_session_failed_.Run();
}

void CrosFpBiometricsManager::OnMkbpEvent(uint32_t event) {
  if (!next_session_action_.is_null())
    next_session_action_.Run(event);
}

bool CrosFpBiometricsManager::RequestEnrollImage(
    BiodStorageInterface::RecordMetadata record) {
  next_session_action_ =
      base::BindRepeating(&CrosFpBiometricsManager::DoEnrollImageEvent,
                          base::Unretained(this), std::move(record));
  if (!cros_dev_->SetFpMode(ec::FpMode(Mode::kEnrollSessionEnrollImage))) {
    next_session_action_ = SessionAction();
    LOG(ERROR) << "Failed to start enrolling mode";
    return false;
  }
  return true;
}

bool CrosFpBiometricsManager::RequestEnrollFingerUp(
    BiodStorageInterface::RecordMetadata record) {
  next_session_action_ =
      base::BindRepeating(&CrosFpBiometricsManager::DoEnrollFingerUpEvent,
                          base::Unretained(this), std::move(record));
  if (!cros_dev_->SetFpMode(ec::FpMode(Mode::kEnrollSessionFingerUp))) {
    next_session_action_ = SessionAction();
    LOG(ERROR) << "Failed to wait for finger up";
    return false;
  }
  return true;
}

bool CrosFpBiometricsManager::RequestMatch(int attempt) {
  next_session_action_ = base::BindRepeating(
      &CrosFpBiometricsManager::DoMatchEvent, base::Unretained(this), attempt);
  if (!cros_dev_->SetFpMode(ec::FpMode(Mode::kMatch))) {
    next_session_action_ = SessionAction();
    LOG(ERROR) << "Failed to start matching mode";
    return false;
  }
  return true;
}

bool CrosFpBiometricsManager::RequestMatchFingerUp() {
  next_session_action_ = base::BindRepeating(
      &CrosFpBiometricsManager::DoMatchFingerUpEvent, base::Unretained(this));
  if (!cros_dev_->SetFpMode(ec::FpMode(Mode::kFingerUp))) {
    next_session_action_ = SessionAction();
    LOG(ERROR) << "Failed to request finger up event";
    return false;
  }
  return true;
}

void CrosFpBiometricsManager::DoEnrollImageEvent(
    BiodStorageInterface::RecordMetadata record, uint32_t event) {
  if (!(event & EC_MKBP_FP_ENROLL)) {
    LOG(WARNING) << "Unexpected MKBP event: 0x" << std::hex << event;
    // Continue waiting for the proper event, do not abort session.
    return;
  }

  int image_result = EC_MKBP_FP_ERRCODE(event);
  LOG(INFO) << __func__ << " result: '" << EnrollResultToString(image_result)
            << "'";
  ScanResult scan_result;
  switch (image_result) {
    case EC_MKBP_FP_ERR_ENROLL_OK:
      scan_result = ScanResult::SCAN_RESULT_SUCCESS;
      break;
    case EC_MKBP_FP_ERR_ENROLL_IMMOBILE:
      scan_result = ScanResult::SCAN_RESULT_IMMOBILE;
      break;
    case EC_MKBP_FP_ERR_ENROLL_LOW_COVERAGE:
      scan_result = ScanResult::SCAN_RESULT_PARTIAL;
      break;
    case EC_MKBP_FP_ERR_ENROLL_LOW_QUALITY:
      scan_result = ScanResult::SCAN_RESULT_INSUFFICIENT;
      break;
    case EC_MKBP_FP_ERR_ENROLL_INTERNAL:
    default:
      LOG(ERROR) << "Unexpected result from capture: " << std::hex << event;
      OnSessionFailed();
      return;
  }

  int percent = EC_MKBP_FP_ENROLL_PROGRESS(event);
  ++num_enrollment_captures_;

  if (percent < 100) {
    BiometricsManager::EnrollStatus enroll_status = {false, percent};

    OnEnrollScanDone(scan_result, enroll_status);

    // The user needs to remove the finger before the next enrollment image.
    if (!RequestEnrollFingerUp(std::move(record)))
      OnSessionFailed();

    return;
  }

  // we are done with captures, send metrics and save the template.
  OnTaskComplete();
  biod_metrics_->SendEnrollmentCapturesCount(num_enrollment_captures_);

  std::unique_ptr<VendorTemplate> tmpl =
      cros_dev_->GetTemplate(CrosFpDevice::kLastTemplate);
  if (!tmpl) {
    LOG(ERROR) << "Failed to retrieve enrolled finger";
    OnSessionFailed();
    return;
  }

  std::optional<brillo::SecureVector> secret =
      cros_dev_->GetPositiveMatchSecret(CrosFpDevice::kLastTemplate);
  if (!secret) {
    LOG(ERROR) << "Failed to get positive match secret.";
    OnSessionFailed();
    return;
  }

  std::vector<uint8_t> validation_val;
  if (!BiodCrypto::ComputeValidationValue(*secret, record.user_id,
                                          &validation_val)) {
    LOG(ERROR) << "Failed to compute validation value.";
    OnSessionFailed();
    return;
  }
  record.validation_val = std::move(validation_val);
  LOG(INFO) << "Computed validation value for enrolled finger.";

  std::string record_id = record.record_id;

  if (!record_manager_->CreateRecord(record, std::move(tmpl))) {
    OnSessionFailed();
    return;
  }

  // This record is now loaded in FPMCU, so add it to the list.
  loaded_records_.emplace_back(record_id);

  BiometricsManager::EnrollStatus enroll_status = {true, 100};
  OnEnrollScanDone(ScanResult::SCAN_RESULT_SUCCESS, enroll_status);
}

void CrosFpBiometricsManager::DoEnrollFingerUpEvent(
    BiodStorageInterface::RecordMetadata record, uint32_t event) {
  if (!(event & EC_MKBP_FP_FINGER_UP)) {
    LOG(WARNING) << "Unexpected MKBP event: 0x" << std::hex << event;
    // Continue waiting for the proper event, do not abort session.
    return;
  }

  if (!RequestEnrollImage(std::move(record)))
    OnSessionFailed();
}

void CrosFpBiometricsManager::DoMatchFingerUpEvent(uint32_t event) {
  if (!(event & EC_MKBP_FP_FINGER_UP)) {
    LOG(WARNING) << "Unexpected MKBP event: 0x" << std::hex << event;
    // Continue waiting for the proper event, do not abort session.
    return;
  }
  // The user has lifted their finger, try to match the next touch.
  if (!RequestMatch())
    OnSessionFailed();
}

bool CrosFpBiometricsManager::CheckPositiveMatchSecret(
    const std::string& record_id, int match_idx) {
  std::optional<brillo::SecureVector> secret =
      cros_dev_->GetPositiveMatchSecret(match_idx);
  biod_metrics_->SendReadPositiveMatchSecretSuccess(secret.has_value());

  if (!secret) {
    LOG(ERROR) << "Failed to read positive match secret on match for finger "
               << match_idx << ".";
    return false;
  }

  const auto record_metadata = record_manager_->GetRecordMetadata(record_id);
  if (!record_metadata) {
    LOG(ERROR) << "Can't find metadata for record " << LogSafeID(record_id);
    return false;
  }

  std::vector<uint8_t> validation_value;
  if (!BiodCrypto::ComputeValidationValue(*secret, record_metadata->user_id,
                                          &validation_value)) {
    LOG(ERROR) << "Failed to compute validation value for finger " << match_idx
               << ".";
    return false;
  }

  if (validation_value != record_metadata->validation_val) {
    LOG(ERROR) << "Validation value does not match for finger " << match_idx;
    biod_metrics_->SendPositiveMatchSecretCorrect(false);
    suspicious_templates_.emplace(match_idx);
    return false;
  }

  LOG(INFO) << "Verified validation value for finger " << match_idx;
  biod_metrics_->SendPositiveMatchSecretCorrect(true);
  suspicious_templates_.erase(match_idx);
  return true;
}

void CrosFpBiometricsManager::DoMatchEvent(int attempt, uint32_t event) {
  if (!(event & EC_MKBP_FP_MATCH)) {
    LOG(WARNING) << "Unexpected MKBP event: 0x" << std::hex << event;
    // Continue waiting for the proper event, do not abort session.
    return;
  }

  // The user intention might be to press the power button. If so, ignore the
  // current match.
  if (power_button_filter_->ShouldFilterFingerprintMatch()) {
    LOG(INFO)
        << "Power button event seen along with fp match. Ignoring fp match.";

    // Try to match the next touch once the user lifts the finger as the client
    // is still waiting for an auth. Wait for finger up event here is to prevent
    // the following scenario.
    // 1. Display is on. Now user presses power button with an enrolled finger.
    // 3. Display goes off. biod starts auth session.
    // 4. Fp match happens and is filtered by biod. biod immediately restarts
    //    a new auth session (if we do not wait for finger up).
    // 5. fp sensor immediately sends a match event before user gets a chance to
    //    lift the finger.
    // 6. biod sees a match again and this time notifies chrome without
    //    filtering it as it has filtered one already.

    if (!RequestMatchFingerUp())
      OnSessionFailed();

    biod_metrics_->SendIgnoreMatchEventOnPowerButtonPress(true);
    return;
  }

  biod_metrics_->SendIgnoreMatchEventOnPowerButtonPress(false);
  int match_result = EC_MKBP_FP_ERRCODE(event);

  // If the finger is positioned slightly off the sensor, retry a few times
  // before failing. Typically the user has put their finger down and is now
  // moving their finger to the correct position on the sensor. Instead of
  // immediately failing, retry until we get a good image.
  // Retry 20 times, which takes about 5 to 15s, before giving up and sending
  // an error back to the user. Assume ~1s for user noticing that no matching
  // happened, some time to move the finger on the sensor to allow a full
  // capture and another 1s for the second matching attempt. 5s gives a bit of
  // margin to avoid interrupting the user while they're moving the finger on
  // the sensor.
  const int kMaxPartialAttempts = 20;

  if (match_result == EC_MKBP_FP_ERR_MATCH_NO_LOW_COVERAGE &&
      attempt < kMaxPartialAttempts) {
    /* retry a match */
    if (!RequestMatch(attempt + 1))
      OnSessionFailed();
    return;
  }

  // Don't try to match again until the user has lifted their finger from the
  // sensor. Request the FingerUp event as soon as the HW signaled a match so it
  // doesn't attempt a new match while the host is processing the first
  // match event.
  if (!RequestMatchFingerUp()) {
    OnSessionFailed();
    return;
  }

  std::vector<int> dirty_list;
  if (match_result == EC_MKBP_FP_ERR_MATCH_YES_UPDATED) {
    dirty_list = GetDirtyList();
  }

  FingerprintMessage result;
  std::optional<std::string> matched_record_id;
  std::optional<RecordMetadata> matched_record_meta;

  uint32_t match_idx = EC_MKBP_FP_MATCH_IDX(event);
  LOG(INFO) << __func__ << " result: '" << MatchResultToString(match_result)
            << "' (finger: " << match_idx << ")";
  switch (match_result) {
    case EC_MKBP_FP_ERR_MATCH_NO_TEMPLATES:
      LOG(ERROR) << "No templates to match: " << std::hex << event;
      result.set_error(FingerprintError::ERROR_NO_TEMPLATES);
      break;
    case EC_MKBP_FP_ERR_MATCH_NO_INTERNAL:
      LOG(ERROR) << "Internal error when matching templates: " << std::hex
                 << event;
      result.set_error(FingerprintError::ERROR_UNABLE_TO_PROCESS);
      break;
    case EC_MKBP_FP_ERR_MATCH_NO:
      result.set_scan_result(ScanResult::SCAN_RESULT_NO_MATCH);
      break;
    case EC_MKBP_FP_ERR_MATCH_YES:
    case EC_MKBP_FP_ERR_MATCH_YES_UPDATED:
    case EC_MKBP_FP_ERR_MATCH_YES_UPDATE_FAILED:
      // We are on a good path to successfully authenticate user, but
      // we still need to confirm that positive match secret is correct.
      // Set UNABLE_TO_PROCESS error for now, it will be changed to
      // SUCCESS scan result when positive match secret is validated.
      result.set_error(FingerprintError::ERROR_UNABLE_TO_PROCESS);
      matched_record_id = GetLoadedRecordId(match_idx);
      if (matched_record_id) {
        matched_record_meta =
            record_manager_->GetRecordMetadata(*matched_record_id);
        if (!matched_record_meta) {
          LOG(ERROR) << "Can't find metadata for record "
                     << LogSafeID(*matched_record_id);
        }
      } else {
        LOG(ERROR) << "Invalid finger index " << match_idx;
      }
      break;
    case EC_MKBP_FP_ERR_MATCH_NO_LOW_QUALITY:
      result.set_scan_result(ScanResult::SCAN_RESULT_INSUFFICIENT);
      break;
    case EC_MKBP_FP_ERR_MATCH_NO_LOW_COVERAGE:
      result.set_scan_result(ScanResult::SCAN_RESULT_PARTIAL);
      break;
    default:
      LOG(ERROR) << "Unexpected result from matching templates: " << std::hex
                 << event;
      OnSessionFailed();
      return;
  }

  BiometricsManager::AttemptMatches matches;

  if (matched_record_meta) {
    // CrosFp says that match was successful, let's check if this is true
    if (CheckPositiveMatchSecret(matched_record_meta->record_id, match_idx)) {
      matches.emplace(
          matched_record_meta->user_id,
          std::vector<std::string>({matched_record_meta->record_id}));
      result.set_scan_result(ScanResult::SCAN_RESULT_SUCCESS);
      biod_metrics_->SendPartialAttemptsBeforeSuccess(attempt);
    } else {
      LOG(ERROR) << "Failed to check Secure Secret for " << match_idx;
      matched_record_meta = std::nullopt;
    }
  }

  // Send back the result directly (as we are running on the main thread).
  OnAuthScanDone(std::move(result), std::move(matches));

  std::optional<ec::CrosFpDeviceInterface::FpStats> stats =
      cros_dev_->GetFpStats();
  if (stats) {
    biod_metrics_->SendFpLatencyStats(matched_record_meta.has_value(), *stats);
  }

  // Record updated templates
  // TODO(vpalatin): this is slow, move to end of session ?
  UpdateTemplatesOnDisk(dirty_list, suspicious_templates_);
}

void CrosFpBiometricsManager::OnTaskComplete() {
  next_session_action_ = SessionAction();
}

bool CrosFpBiometricsManager::LoadRecord(
    const BiodStorageInterface::Record record) {
  std::string tmpl_data_str;
  base::Base64Decode(record.data, &tmpl_data_str);

  if (loaded_records_.size() >= cros_dev_->MaxTemplateCount()) {
    LOG(ERROR) << "No space to upload template from "
               << LogSafeID(record.metadata.record_id) << ".";
    return false;
  }

  biod_metrics_->SendRecordFormatVersion(record.metadata.record_format_version);
  LOG(INFO) << "Upload record " << LogSafeID(record.metadata.record_id) << ".";
  VendorTemplate tmpl(tmpl_data_str.begin(), tmpl_data_str.end());
  auto* metadata =
      reinterpret_cast<const ec_fp_template_encryption_metadata*>(tmpl.data());
  if (metadata->struct_version != cros_dev_->TemplateVersion()) {
    LOG(ERROR) << "Version mismatch between template ("
               << metadata->struct_version << ") and hardware ("
               << cros_dev_->TemplateVersion() << ")";
    record_manager_->DeleteRecord(record.metadata.record_id);
    return false;
  }
  if (!cros_dev_->UploadTemplate(tmpl)) {
    LOG(ERROR) << "Cannot send template to the MCU from "
               << LogSafeID(record.metadata.record_id) << ".";
    return false;
  }

  loaded_records_.emplace_back(record.metadata.record_id);
  return true;
}

void CrosFpBiometricsManager::OnMaintenanceTimerFired() {
  auto fp_sensor_mode = cros_dev_->GetFpMode();
  if (fp_sensor_mode != ec::FpMode(Mode::kNone)) {
    LOG(INFO) << "Rescheduling maintenance due to fp_sensor_mode: "
              << fp_sensor_mode;
    ScheduleMaintenance(base::Minutes(10));
    return;
  }
  LOG(INFO) << "Maintenance timer fired";

  // Report the number of dead pixels
  cros_dev_->UpdateFpInfo();
  biod_metrics_->SendDeadPixelCount(cros_dev_->DeadPixelCount());

  // The maintenance operation can take a couple hundred milliseconds, so it's
  // an asynchronous mode (the state is cleared by the FPMCU after it is
  // finished with the operation).
  cros_dev_->SetFpMode(ec::FpMode(Mode::kSensorMaintenance));
  ScheduleMaintenance(base::Days(1));
}

std::vector<int> CrosFpBiometricsManager::GetDirtyList() {
  std::vector<int> dirty_list;

  // Retrieve which templates have been updated.
  std::optional<std::bitset<32>> dirty_bitmap = cros_dev_->GetDirtyMap();
  if (!dirty_bitmap) {
    LOG(ERROR) << "Failed to get updated templates map";
    return dirty_list;
  }

  // Create a list of modified template indexes from the bitmap.
  dirty_list.reserve(dirty_bitmap->count());
  for (int i = 0; dirty_bitmap->any() && i < dirty_bitmap->size(); i++) {
    if ((*dirty_bitmap)[i]) {
      dirty_list.emplace_back(i);
      dirty_bitmap->reset(i);
    }
  }

  return dirty_list;
}

bool CrosFpBiometricsManager::UpdateTemplatesOnDisk(
    const std::vector<int>& dirty_list,
    const std::unordered_set<uint32_t>& suspicious_templates) {
  bool ret = true;
  for (int i : dirty_list) {
    if (!GetLoadedRecordId(i)) {
      LOG(ERROR)
          << "Index " << i
          << " is on dirty list, but corresponding record doesn't exist.";
      continue;
    }
    // If the template previously came with wrong validation value, do not
    // accept it until it comes with correct validation value.
    if (suspicious_templates.find(i) != suspicious_templates.end()) {
      continue;
    }

    std::unique_ptr<VendorTemplate> templ = cros_dev_->GetTemplate(i);
    LOG(INFO) << "Retrieve updated template " << i << " -> " << std::boolalpha
              << templ.get();
    if (!templ) {
      continue;
    }

    const auto record_metadata =
        record_manager_->GetRecordMetadata(*GetLoadedRecordId(i));
    if (!record_metadata) {
      LOG(ERROR) << "Can't find metadata for record "
                 << LogSafeID(*GetLoadedRecordId(i));
      ret = false;
    }

    if (!record_manager_->UpdateRecord(*record_metadata, std::move(templ))) {
      LOG(ERROR) << "Cannot update record "
                 << LogSafeID(GetLoadedRecordId(i).value())
                 << " in storage during AuthSession because writing failed.";
      ret = false;
    }
  }

  return ret;
}

}  // namespace biod
