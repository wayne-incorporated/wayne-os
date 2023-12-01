// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "secagentd/policies_features_broker.h"

#include <array>
#include <memory>
#include <string>
#include <utility>

#include "base/functional/bind.h"
#include "base/functional/callback_forward.h"
#include "base/logging.h"
#include "base/synchronization/lock.h"
#include "base/time/time.h"
#include "base/timer/timer.h"
#include "featured/c_feature_library.h"
#include "featured/feature_library.h"
#include "policy/device_policy.h"
#include "policy/libpolicy.h"

namespace secagentd {

using feature::PlatformFeaturesInterface;

PoliciesFeaturesBroker::PoliciesFeaturesBroker(
    std::unique_ptr<policy::PolicyProvider> policy_provider,
    feature::PlatformFeaturesInterface* features,
    base::RepeatingClosure poll_done_cb)
    : weak_ptr_factory_(this),
      policy_provider_(std::move(policy_provider)),
      features_(features),
      poll_done_cb_(std::move(poll_done_cb)),
      feature_values_{{Feature::kCrOSLateBootSecagentdXDRReporting,
                       {{.name = "CrOSLateBootSecagentdXDRReporting",
                         .default_state = FEATURE_ENABLED_BY_DEFAULT},
                        false}},
                      {Feature::kCrOSLateBootSecagentdCoalesceTerminates,
                       {{.name = "CrOSLateBootSecagentdCoalesceTerminates",
                         .default_state = FEATURE_DISABLED_BY_DEFAULT},
                        false}},
                      {Feature::kCrOSLateBootSecagentdXDRNetworkEvents,
                       {{.name = "CrOSLateBootSecagentdXDRNetworkEvents",
                         .default_state = FEATURE_DISABLED_BY_DEFAULT},
                        false}}} {
  for (const auto& [k, v] : feature_values_) {
    variations_to_query_.push_back(&v.variation);
  }
}

void PoliciesFeaturesBroker::StartAndBlockForSync(
    base::TimeDelta poll_duration) {
  Poll(true);
  poll_timer_.Start(FROM_HERE, poll_duration,
                    base::BindRepeating(&PoliciesFeaturesBroker::Poll,
                                        weak_ptr_factory_.GetWeakPtr(), false));
}

bool PoliciesFeaturesBroker::GetFeature(Feature key) const {
  base::AutoLock lock(values_lock_);
  auto it = feature_values_.find(key);
  CHECK(it != feature_values_.end());
  return it->second.value;
}

bool PoliciesFeaturesBroker::GetDeviceReportXDREventsPolicy() const {
  base::AutoLock lock(values_lock_);
  return device_report_xdr_events_policy_value_;
}

void PoliciesFeaturesBroker::Poll(bool blocking) {
  UpdateDeviceReportXDREventsPolicy();
  if (blocking) {
    UpdateFeaturesResults(
        features_->GetParamsAndEnabledBlocking(variations_to_query_));
  } else {
    // Start a timer just in case features never runs the async callback for
    // some reason. Probably not required in practice but being paranoid here
    // because either the Policy or the Feature could be used to make the daemon
    // stop emitting events in an emergency. So it's best for them to be as
    // independent as possible.
    poll_done_fallback_timer_.Start(
        FROM_HERE, (poll_timer_.GetCurrentDelay() / 2),
        base::BindOnce(&PoliciesFeaturesBroker::RunPollDoneCb,
                       weak_ptr_factory_.GetWeakPtr()));
    features_->GetParamsAndEnabled(
        variations_to_query_,
        base::BindOnce(&PoliciesFeaturesBroker::UpdateFeaturesResults,
                       weak_ptr_factory_.GetWeakPtr()));
  }
}

void PoliciesFeaturesBroker::UpdateFeaturesResults(
    PlatformFeaturesInterface::ParamsResult result) {
  VLOG(1) << "Updating Feature values.";
  base::AutoLock lock(values_lock_);
  for (auto& [k, v] : feature_values_) {
    auto it = result.find(v.variation.name);
    if (it != result.end()) {
      if (v.value != it->second.enabled) {
        v.value = it->second.enabled;
        LOG(INFO) << "Feature " << v.variation.name << "changed to "
                  << std::to_string(v.value);
      }
    } else {
      LOG(INFO) << "Feature " << v.variation.name << "not in results";
    }
  }
  if (poll_done_fallback_timer_.IsRunning()) {
    poll_done_fallback_timer_.Stop();
  }
  base::SequencedTaskRunner::GetCurrentDefault()->PostTask(
      FROM_HERE, base::BindOnce(&PoliciesFeaturesBroker::RunPollDoneCb,
                                weak_ptr_factory_.GetWeakPtr()));
}

void PoliciesFeaturesBroker::UpdateDeviceReportXDREventsPolicy() {
  VLOG(1) << "Updating DeviceReportXDREvents Policy.";
  base::AutoLock lock(values_lock_);
  // Default value is do not report.
  bool new_policy = false;
  policy_provider_->Reload();
  if (policy_provider_->device_policy_is_loaded()) {
    new_policy =
        policy_provider_->GetDevicePolicy().GetDeviceReportXDREvents().value_or(
            false);
  }
  if (new_policy != device_report_xdr_events_policy_value_) {
    LOG(INFO) << "DeviceReportXDREvents policy changed to "
              << std::to_string(new_policy);
    device_report_xdr_events_policy_value_ = new_policy;
  }
}

void PoliciesFeaturesBroker::RunPollDoneCb() {
  VLOG(1) << "Running poll_done_cb_";
  poll_done_cb_.Run();
}

}  // namespace secagentd
