// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "hps/daemon/dbus_adaptor.h"

#include <utility>
#include <vector>

#include <base/location.h>
#include <base/logging.h>
#include <brillo/errors/error.h>
#include <brillo/errors/error_codes.h>
#include <chromeos/dbus/service_constants.h>
#include <hps/daemon/filters/filter_factory.h>

namespace hps {

constexpr char kErrorPath[] = "org.chromium.Hps.GetFeatureResultError";

namespace {

std::vector<uint8_t> HpsResultToSerializedBytes(HpsResult result) {
  HpsResultProto result_proto;
  result_proto.set_value(result);

  std::vector<uint8_t> serialized;
  serialized.resize(result_proto.ByteSizeLong());
  result_proto.SerializeToArray(serialized.data(),
                                static_cast<int>(serialized.size()));
  return serialized;
}

}  // namespace

void DBusAdaptor::FeatureState::Enable(const FeatureConfig& config,
                                       FeatureCallback callback) {
  DCHECK(!enabled_);
  DCHECK(!enabled_in_hps_);
  DCHECK(!callback.is_null());
  enabled_ = true;
  config_ = config;
  callback_ = std::move(callback);
  raw_result_ = {};
}

void DBusAdaptor::FeatureState::Disable() {
  DCHECK(enabled_);
  DCHECK(enabled_in_hps_);
  enabled_ = false;
  config_ = {};
  callback_ = FeatureCallback{};
  raw_result_ = {};
}

void DBusAdaptor::FeatureState::DidCommit() {
  enabled_in_hps_ = enabled_;
  if (enabled_) {
    DCHECK(!callback_.is_null());
    auto callback = base::BindRepeating(
        &DBusAdaptor::FeatureState::OnFilteredResult, base::Unretained(this));
    filter_ = CreateFilter(config_, std::move(callback));
  } else {
    DCHECK(callback_.is_null());
    filter_.reset();
  }
}

void DBusAdaptor::FeatureState::OnFilteredResult(HpsResult result) {
  DCHECK(callback_);
  HpsResultProto result_proto;
  SerializeInternal(result_proto, result);
  std::vector<uint8_t> serialized;
  serialized.resize(result_proto.ByteSizeLong());
  result_proto.SerializeToArray(serialized.data(),
                                static_cast<int>(serialized.size()));
  callback_.Run(std::move(serialized));
}

void DBusAdaptor::FeatureState::DidShutDown() {
  enabled_in_hps_ = false;
  filter_.reset();
}

HpsResult DBusAdaptor::FeatureState::ProcessResult(FeatureResult result) {
  DCHECK(enabled_);
  raw_result_ = result;
  return filter_->ProcessResult(result.inference_result, result.valid);
}

void DBusAdaptor::FeatureState::Serialize(HpsResultProto& result_proto) {
  DCHECK(filter_);
  SerializeInternal(result_proto, filter_->GetCurrentResult());
}

void DBusAdaptor::FeatureState::SerializeInternal(HpsResultProto& result_proto,
                                                  HpsResult value) {
  DCHECK(enabled_);
  result_proto.set_value(value);
  if (config_.report_raw_results()) {
    result_proto.set_inference_result(raw_result_.inference_result);
    result_proto.set_inference_result_valid(raw_result_.valid);
  }
}

DBusAdaptor::DBusAdaptor(scoped_refptr<dbus::Bus> bus,
                         std::unique_ptr<HPS> hps,
                         uint32_t poll_time_ms)
    : org::chromium::HpsAdaptor(this),
      dbus_object_(nullptr, bus, dbus::ObjectPath(::hps::kHpsServicePath)),
      hps_(std::move(hps)),
      poll_time_ms_(poll_time_ms) {
  ShutDown();
}

void DBusAdaptor::RegisterAsync(
    brillo::dbus_utils::AsyncEventSequencer::CompletionAction cb) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  RegisterWithDBusObject(&dbus_object_);
  dbus_object_.RegisterAsync(std::move(cb));
}

void DBusAdaptor::PollTask() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  // Make sure the HPS module is powered on again if we are resuming from a
  // system suspend state.
  CommitState();

  for (uint8_t i = 0; i < kFeatures; ++i) {
    auto& feature = features_[i];
    if (feature.enabled()) {
      FeatureResult result = this->hps_->Result(i);
      DCHECK(feature.filter());
      DCHECK(!feature.needs_commit());
      const auto res = feature.ProcessResult(result);
      VLOG(2) << "Poll: Feature: " << static_cast<int>(i)
              << " Valid: " << result.valid
              << " Result: " << static_cast<int>(result.inference_result)
              << " Filter: " << static_cast<int>(res);
    }
  }
}

void DBusAdaptor::BootIfNeeded() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  if (hps_booted_) {
    return;
  }
  hps_->Boot();
  hps_booted_ = true;
}

void DBusAdaptor::ShutDown() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  poll_timer_.Stop();
  if (!hps_->ShutDown()) {
    LOG(FATAL) << "Failed to shutdown";
  }
  hps_booted_ = false;
  for (auto& feature : features_) {
    feature.DidShutDown();
  }
}

// Synchronizes the desired feature enable/disable state with the HPS module. If
// no features are enabled, HPS is also powered off. If HPS has been reset
// because of a system suspend, this method will also restore any enabled
// feature settings.
bool DBusAdaptor::CommitState() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  bool result = true;
  if (hps_booted_ && !hps_->IsRunning()) {
    // If the HPS module is not running even though we haven't shut it down, the
    // system was probably suspended and resumed, resetting HPS as a side
    // effect. Reboot the module and restore the enabled features so we can
    // continue polling.
    //
    // Note that it's possible for a system suspend and resume to happen at any
    // point, including while we're polling for features. That means we'll
    // either report unknown feature results or in the worst case abort with a
    // fault if HPS is in an unexpected state. This means DBUS clients need to
    // handle hpsd restarting at arbitrary times.
    LOG(INFO) << "HPS reset detected";
    ShutDown();

    // Post condition: all features are disabled in HPS after shutting down.
    for (const auto& feature : features_) {
      DCHECK(!feature.enabled_in_hps());
    }
  }

  for (uint8_t i = 0; i < kFeatures; i++) {
    auto& feature = features_[i];
    if (!feature.needs_commit())
      continue;

    if (feature.enabled()) {
      // If we want to enable any features, HPS needs to be running.
      BootIfNeeded();
      LOG_IF(FATAL, !hps_->Enable(i)) << "Failed to enable feature " << i;
    } else {
      // If any features need to be disabled, HPS must be running. If HPS is not
      // running, all features are already disabled and we won't end up in this
      // branch.
      DCHECK(hps_booted_);
      LOG_IF(FATAL, !hps_->Disable(i)) << "Failed to disable feature " << i;
    }
    feature.DidCommit();
  }

  // Post condition: all feature states have been committed to HPS.
  for (const auto& feature : features_) {
    DCHECK(!feature.needs_commit());
  }

  size_t active_features =
      std::count_if(features_.begin(), features_.end(),
                    [](const auto& f) { return f.enabled_in_hps(); });

  if (!active_features && hps_booted_) {
    ShutDown();
  } else if (active_features && !poll_timer_.IsRunning()) {
    poll_timer_.Start(
        FROM_HERE, base::Milliseconds(poll_time_ms_),
        base::BindRepeating(&DBusAdaptor::PollTask, base::Unretained(this)));
  }
  return result;
}

bool DBusAdaptor::EnableFeature(brillo::ErrorPtr* error,
                                const hps::FeatureConfig& config,
                                uint8_t feature,
                                FeatureCallback callback) {
  CHECK_LT(feature, kFeatures);
  if (features_[feature].enabled()) {
    brillo::Error::AddTo(error, FROM_HERE, brillo::errors::dbus::kDomain,
                         kErrorPath, "hpsd: Feature already enabled.");

    return false;
  }
  features_[feature].Enable(config, std::move(callback));
  CommitState();
  return true;
}

bool DBusAdaptor::DisableFeature(brillo::ErrorPtr* error, uint8_t feature) {
  CHECK_LT(feature, kFeatures);
  if (!features_[feature].enabled()) {
    brillo::Error::AddTo(error, FROM_HERE, brillo::errors::dbus::kDomain,
                         kErrorPath, "hpsd: Feature not enabled.");

    return false;
  }
  features_[feature].Disable();
  CommitState();
  return true;
}

bool DBusAdaptor::GetFeatureResult(brillo::ErrorPtr* error,
                                   HpsResultProto* result,
                                   uint8_t feature) {
  CHECK_LT(feature, kFeatures);
  if (!features_[feature].enabled()) {
    brillo::Error::AddTo(error, FROM_HERE, brillo::errors::dbus::kDomain,
                         kErrorPath, "hpsd: Feature not enabled.");

    return false;
  }
  features_[feature].Serialize(*result);
  return true;
}

bool DBusAdaptor::EnableHpsSense(brillo::ErrorPtr* error,
                                 const hps::FeatureConfig& config) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  LOG(INFO) << "DBusAdaptor::EnableHpsSense with config type "
            << static_cast<int>(config.filter_config_case());
  return EnableFeature(
      error, config, 0,
      base::BindRepeating(&DBusAdaptor::SendHpsSenseChangedSignal,
                          base::Unretained(this)));
}

bool DBusAdaptor::DisableHpsSense(brillo::ErrorPtr* error) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  LOG(INFO) << "DBusAdaptor::DisableHpsSense";
  if (DisableFeature(error, 0)) {
    DBusAdaptor::SendHpsSenseChangedSignal(
        HpsResultToSerializedBytes(HpsResult::UNKNOWN));
    return true;
  }
  return false;
}

bool DBusAdaptor::GetResultHpsSense(brillo::ErrorPtr* error,
                                    HpsResultProto* result) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  return GetFeatureResult(error, result, 0);
}

bool DBusAdaptor::EnableHpsNotify(brillo::ErrorPtr* error,
                                  const hps::FeatureConfig& config) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  LOG(INFO) << "DBusAdaptor::EnableHpsNotify with config type "
            << static_cast<int>(config.filter_config_case());
  return EnableFeature(
      error, config, 1,
      base::BindRepeating(&DBusAdaptor::SendHpsNotifyChangedSignal,
                          base::Unretained(this)));
}

bool DBusAdaptor::DisableHpsNotify(brillo::ErrorPtr* error) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  LOG(INFO) << "DBusAdaptor::DisableHpsNotify";
  if (DisableFeature(error, 1)) {
    DBusAdaptor::SendHpsNotifyChangedSignal(
        HpsResultToSerializedBytes(HpsResult::UNKNOWN));
    return true;
  }
  return false;
}

bool DBusAdaptor::GetResultHpsNotify(brillo::ErrorPtr* error,
                                     HpsResultProto* result) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  return GetFeatureResult(error, result, 1);
}

}  // namespace hps
