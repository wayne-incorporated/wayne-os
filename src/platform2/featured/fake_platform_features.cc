// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
#include "featured/fake_platform_features.h"

#include <string>
#include <utility>

#include <base/functional/bind.h>

namespace feature {

void FakePlatformFeatures::IsEnabled(const VariationsFeature& feature,
                                     IsEnabledCallback callback) {
  base::AutoLock auto_lock(enabled_lock_);
  bus_->AssertOnOriginThread();
  auto it = enabled_.find(feature.name);
  bool enabled = feature.default_state == FEATURE_ENABLED_BY_DEFAULT;
  if (it != enabled_.end()) {
    enabled = it->second;
  }
  bus_->GetOriginTaskRunner()->PostTask(
      FROM_HERE, base::BindOnce(std::move(callback), enabled));
}

bool FakePlatformFeatures::IsEnabledBlockingWithTimeout(
    const VariationsFeature& feature, int timeout_ms) {
  base::AutoLock auto_lock(enabled_lock_);
  auto it = enabled_.find(feature.name);
  if (it != enabled_.end()) {
    return it->second;
  }
  return feature.default_state == FEATURE_ENABLED_BY_DEFAULT;
}

void FakePlatformFeatures::GetParamsAndEnabled(
    const std::vector<const VariationsFeature*>& features,
    GetParamsCallback callback) {
  bus_->AssertOnOriginThread();

  bus_->GetOriginTaskRunner()->PostTask(
      FROM_HERE, base::BindOnce(std::move(callback),
                                GetParamsAndEnabledBlocking(features)));
}

PlatformFeaturesInterface::ParamsResult
FakePlatformFeatures::GetParamsAndEnabledBlocking(
    const std::vector<const VariationsFeature*>& features) {
  base::AutoLock auto_lock(enabled_lock_);
  std::map<std::string, ParamsResultEntry> out;
  for (const auto* feature : features) {
    ParamsResultEntry cur;

    auto enabled_it = enabled_.find(feature->name);
    cur.enabled = enabled_it != enabled_.end() && enabled_it->second;
    if (cur.enabled) {
      // only enabled features have params.
      auto params_it = params_.find(feature->name);
      if (params_it != params_.end()) {
        cur.params = params_it->second;
      }
    } else if (enabled_it == enabled_.end()) {
      cur.enabled = (feature->default_state == FEATURE_ENABLED_BY_DEFAULT);
    }

    out[feature->name] = cur;
  }

  return out;
}

void FakePlatformFeatures::SetEnabled(const std::string& feature,
                                      bool enabled) {
  base::AutoLock auto_lock(enabled_lock_);
  enabled_[feature] = enabled;
}

void FakePlatformFeatures::ClearEnabled(const std::string& feature) {
  base::AutoLock auto_lock(enabled_lock_);
  enabled_.erase(feature);
}

void FakePlatformFeatures::SetParam(const std::string& feature,
                                    const std::string& key,
                                    const std::string& value) {
  base::AutoLock auto_lock(enabled_lock_);
  params_[feature][key] = value;
}

void FakePlatformFeatures::ClearParams(const std::string& feature) {
  base::AutoLock auto_lock(enabled_lock_);
  params_.erase(feature);
}

void FakePlatformFeatures::ShutdownBus() {
  bus_->ShutdownAndBlock();
}

void FakePlatformFeatures::ListenForRefetchNeeded(
    base::RepeatingCallback<void(void)> signal_callback,
    base::OnceCallback<void(bool)> attached_callback) {
  base::AutoLock auto_lock(enabled_lock_);
  signal_callbacks_.push_back(signal_callback);
  bus_->GetOriginTaskRunner()->PostTask(
      FROM_HERE, base::BindOnce(std::move(attached_callback), true));
}

void FakePlatformFeatures::TriggerRefetchSignal() {
  std::vector<base::RepeatingCallback<void(void)>> callbacks;
  {
    base::AutoLock auto_lock(enabled_lock_);
    callbacks = signal_callbacks_;
  }
  for (const auto& cb : callbacks) {
    bus_->GetOriginTaskRunner()->PostTask(FROM_HERE, cb);
  }
}

}  // namespace feature
