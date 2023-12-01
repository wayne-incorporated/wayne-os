// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
#ifndef FEATURED_FAKE_PLATFORM_FEATURES_H_
#define FEATURED_FAKE_PLATFORM_FEATURES_H_

#include <map>
#include <string>
#include <vector>

#include <base/memory/scoped_refptr.h>
#include <base/synchronization/lock.h>
#include <base/task/task_runner.h>
#include <dbus/bus.h>

#include "featured/c_feature_library.h"  // for enums
#include "featured/feature_export.h"
#include "featured/feature_library.h"

namespace feature {

// Fake class for testing, which returns a specified value for each feature.
class FEATURE_EXPORT FakePlatformFeatures : public PlatformFeaturesInterface {
 public:
  explicit FakePlatformFeatures(scoped_refptr<dbus::Bus> bus) : bus_(bus) {}

  FakePlatformFeatures(const FakePlatformFeatures&) = delete;
  FakePlatformFeatures& operator=(const FakePlatformFeatures&) = delete;

  void IsEnabled(const VariationsFeature& feature,
                 IsEnabledCallback callback) override;

  bool IsEnabledBlockingWithTimeout(const VariationsFeature& feature,
                                    int timeout_ms) override;

  void GetParamsAndEnabled(
      const std::vector<const VariationsFeature*>& features,
      GetParamsCallback callback) override;

  ParamsResult GetParamsAndEnabledBlocking(
      const std::vector<const VariationsFeature*>& features) override;

  void SetEnabled(const std::string& feature, bool enabled);

  void ClearEnabled(const std::string& feature);

  void SetParam(const std::string& feature,
                const std::string& key,
                const std::string& value);
  void ClearParams(const std::string& feature);

  void ShutdownBus();

  void ListenForRefetchNeeded(
      base::RepeatingCallback<void(void)> signal_callback,
      base::OnceCallback<void(bool)> attached_callback) override;

  void TriggerRefetchSignal();

 private:
  scoped_refptr<dbus::Bus> bus_;

  base::Lock enabled_lock_;
  std::map<std::string, bool> enabled_;
  std::map<std::string, std::map<std::string, std::string>> params_;
  std::vector<base::RepeatingCallback<void(void)>> signal_callbacks_;
};
}  // namespace feature

#endif  // FEATURED_FAKE_PLATFORM_FEATURES_H_
