// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef HPS_DAEMON_DBUS_ADAPTOR_H_
#define HPS_DAEMON_DBUS_ADAPTOR_H_

#include <array>
#include <memory>
#include <vector>

#include <base/sequence_checker.h>
#include <base/timer/timer.h>
#include <hps/hps.h>
#include <hps/daemon/filters/filter.h>
#include <hps/daemon/filters/status_callback.h>
#include <hps/proto_bindings/hps_service.pb.h>
#include <dbus_adaptors/org.chromium.Hps.h>

namespace hps {

using FeatureCallback =
    base::RepeatingCallback<void(const std::vector<uint8_t>&)>;

class DBusAdaptor : public org::chromium::HpsAdaptor,
                    public org::chromium::HpsInterface {
 public:
  DBusAdaptor(scoped_refptr<dbus::Bus> bus,
              std::unique_ptr<HPS>,
              uint32_t poll_time_ms);

  DBusAdaptor(const DBusAdaptor&) = delete;
  DBusAdaptor& operator=(const DBusAdaptor&) = delete;

  void RegisterAsync(
      brillo::dbus_utils::AsyncEventSequencer::CompletionAction cb);

  // Timer Callback used to poll hps hardware and debounce results.
  void PollTask();

  // Methods for HpsInterface
  bool EnableHpsSense(brillo::ErrorPtr* error,
                      const hps::FeatureConfig& config) override;
  bool DisableHpsSense(brillo::ErrorPtr* error) override;
  bool GetResultHpsSense(brillo::ErrorPtr* error,
                         HpsResultProto* result) override;

  bool EnableHpsNotify(brillo::ErrorPtr* error,
                       const hps::FeatureConfig& config) override;
  bool DisableHpsNotify(brillo::ErrorPtr* error) override;
  bool GetResultHpsNotify(brillo::ErrorPtr* error,
                          HpsResultProto* result) override;

 private:
  void BootIfNeeded();
  void ShutDown();
  bool CommitState();
  bool EnableFeature(brillo::ErrorPtr* error,
                     const hps::FeatureConfig& config,
                     uint8_t feature,
                     FeatureCallback callback);
  bool DisableFeature(brillo::ErrorPtr* error, uint8_t feature);
  bool GetFeatureResult(brillo::ErrorPtr* error,
                        HpsResultProto* result,
                        uint8_t feature);

  class FeatureState {
   public:
    void Enable(const FeatureConfig&, FeatureCallback);
    void Disable();
    void DidCommit();
    void DidShutDown();
    HpsResult ProcessResult(FeatureResult);
    void Serialize(HpsResultProto&);

    bool enabled() const { return enabled_; }
    bool enabled_in_hps() const { return enabled_in_hps_; }
    bool needs_commit() const { return enabled_ != enabled_in_hps_; }
    const Filter* filter() const {
      DCHECK(enabled_);
      return filter_.get();
    }

   private:
    void OnFilteredResult(HpsResult);
    void SerializeInternal(HpsResultProto&, HpsResult);

    bool enabled_ = false;  // Whether the user wants the feature on or off.
    bool enabled_in_hps_ = false;  // Whether the feature is on or off in HPS.

    FeatureConfig config_;
    std::unique_ptr<Filter> filter_;
    FeatureCallback callback_;
    FeatureResult raw_result_{};  // Most recent (unfiltered) inference result.
  };

  brillo::dbus_utils::DBusObject dbus_object_;
  std::unique_ptr<HPS> hps_;
  bool hps_booted_ = true;
  const uint32_t poll_time_ms_;
  base::RepeatingTimer poll_timer_;
  std::array<FeatureState, kFeatures> features_;

  SEQUENCE_CHECKER(sequence_checker_);
};

}  // namespace hps

#endif  // HPS_DAEMON_DBUS_ADAPTOR_H_
