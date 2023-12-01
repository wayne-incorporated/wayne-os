// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SECAGENTD_POLICIES_FEATURES_BROKER_H_
#define SECAGENTD_POLICIES_FEATURES_BROKER_H_

#include <map>
#include <memory>
#include <vector>

#include "base/functional/callback_forward.h"
#include "base/memory/ref_counted.h"
#include "base/memory/weak_ptr.h"
#include "base/time/time.h"
#include "base/timer/timer.h"
#include "featured/c_feature_library.h"
#include "featured/feature_library.h"
#include "policy/libpolicy.h"

namespace secagentd {

namespace testing {
class PoliciesFeaturesBrokerTestFixture;
}  // namespace testing

class PoliciesFeaturesBrokerInterface
    : public base::RefCounted<PoliciesFeaturesBrokerInterface> {
 public:
  enum class Feature {
    kCrOSLateBootSecagentdXDRReporting,
    kCrOSLateBootSecagentdCoalesceTerminates,
    kCrOSLateBootSecagentdXDRNetworkEvents,
  };

  // Starts polling the watched features and policies. Runs the first watch
  // immediately and blocks for the result. Posts a task to run poll_done_cb_
  // ASAP.
  virtual void StartAndBlockForSync(base::TimeDelta poll_duration) = 0;
  // Returns the latest cached value of the requested secagentd feature.
  virtual bool GetFeature(Feature key) const = 0;
  // Returns the latest cached value of the DeviceReportXDREvents device policy.
  virtual bool GetDeviceReportXDREventsPolicy() const = 0;

  virtual ~PoliciesFeaturesBrokerInterface() = default;
};

// Polls and caches secagentd policies and features. Async runs an owner
// provided callback after every polling interval.
class PoliciesFeaturesBroker : public PoliciesFeaturesBrokerInterface {
  friend class testing::PoliciesFeaturesBrokerTestFixture;

 public:
  PoliciesFeaturesBroker(
      std::unique_ptr<policy::PolicyProvider> policy_provider,
      feature::PlatformFeaturesInterface* features,
      base::RepeatingClosure poll_done_cb);

  void StartAndBlockForSync(base::TimeDelta poll_duration =
                                base::Seconds(kDefaultPollDurationS)) override;
  bool GetFeature(Feature key) const override;
  bool GetDeviceReportXDREventsPolicy() const override;

  PoliciesFeaturesBroker(const PoliciesFeaturesBroker&) = delete;
  PoliciesFeaturesBroker(PoliciesFeaturesBroker&&) = delete;
  PoliciesFeaturesBroker& operator=(const PoliciesFeaturesBroker&) = delete;
  PoliciesFeaturesBroker& operator=(PoliciesFeaturesBroker&&) = delete;

  // Default poll duration. Must be larger than poll_done_fallback_timer_
  static constexpr uint32_t kDefaultPollDurationS = 10 * 60;

 private:
  struct VariationAndValue {
    VariationsFeature variation;
    bool value;
  };

  void Poll(bool blocking);
  void UpdateFeaturesResults(
      feature::PlatformFeaturesInterface::ParamsResult result);
  void UpdateDeviceReportXDREventsPolicy();
  void RunPollDoneCb();

  base::WeakPtrFactory<PoliciesFeaturesBroker> weak_ptr_factory_;
  std::unique_ptr<policy::PolicyProvider> policy_provider_;
  feature::PlatformFeaturesInterface* features_;
  base::RepeatingClosure poll_done_cb_;
  mutable base::Lock values_lock_;
  std::map<Feature, VariationAndValue> feature_values_;
  bool device_report_xdr_events_policy_value_ = false;
  std::vector<const VariationsFeature*> variations_to_query_;

  base::RepeatingTimer poll_timer_;
  base::OneShotTimer poll_done_fallback_timer_;
};

}  // namespace secagentd

#endif  // SECAGENTD_POLICIES_FEATURES_BROKER_H_
