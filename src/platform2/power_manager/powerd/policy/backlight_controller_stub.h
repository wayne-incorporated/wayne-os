// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef POWER_MANAGER_POWERD_POLICY_BACKLIGHT_CONTROLLER_STUB_H_
#define POWER_MANAGER_POWERD_POLICY_BACKLIGHT_CONTROLLER_STUB_H_

#include <vector>

#include <base/observer_list.h>

#include "power_manager/powerd/policy/backlight_controller.h"
#include "power_manager/powerd/policy/backlight_controller_observer.h"
#include "power_manager/proto_bindings/backlight.pb.h"
#include "power_manager/proto_bindings/policy.pb.h"

namespace power_manager::policy {

// policy::BacklightController implementation that returns dummy values.
class BacklightControllerStub : public policy::BacklightController {
 public:
  BacklightControllerStub() = default;
  BacklightControllerStub(const BacklightControllerStub&) = delete;
  BacklightControllerStub& operator=(const BacklightControllerStub&) = delete;

  ~BacklightControllerStub() override = default;

  const std::vector<PowerSource>& power_source_changes() const {
    return power_source_changes_;
  }
  const std::vector<DisplayMode>& display_mode_changes() const {
    return display_mode_changes_;
  }
  const std::vector<SessionState>& session_state_changes() const {
    return session_state_changes_;
  }
  int power_button_presses() const { return power_button_presses_; }
  const std::vector<LidState>& lid_state_changes() const {
    return lid_state_changes_;
  }
  const std::vector<UserActivityType>& user_activity_reports() const {
    return user_activity_reports_;
  }
  const std::vector<bool>& video_activity_reports() const {
    return video_activity_reports_;
  }
  const std::vector<bool>& hover_state_changes() const {
    return hover_state_changes_;
  }
  const std::vector<TabletMode>& tablet_mode_changes() const {
    return tablet_mode_changes_;
  }
  const std::vector<PowerManagementPolicy>& policy_changes() const {
    return policy_changes_;
  }
  int display_service_starts() const { return display_service_starts_; }
  int wake_notification_reports() const { return wake_notification_reports_; }
  bool dimmed() const { return dimmed_; }
  bool off() const { return off_; }
  bool suspended() const { return suspended_; }
  bool shutting_down() const { return shutting_down_; }
  bool forced_off() const { return forced_off_; }
  bool ambient_light_metrics_callback_registered() const {
    return ambient_light_metrics_callback_registered_;
  }

  void set_percent(double percent) { percent_ = percent; }
  void set_num_als_adjustments(int num) { num_als_adjustments_ = num; }
  void set_num_user_adjustments(int num) { num_user_adjustments_ = num; }

  void ResetStats();

  // Notify |observers_| that the brightness has changed to |percent| due
  // to |cause|. Also updates |percent_|.
  void NotifyObservers(double percent, BacklightBrightnessChange_Cause cause);

  // policy::BacklightController implementation:
  void AddObserver(policy::BacklightControllerObserver* observer) override;
  void RemoveObserver(policy::BacklightControllerObserver* observer) override;
  void HandlePowerSourceChange(PowerSource source) override;
  void HandleDisplayModeChange(DisplayMode mode) override;
  void HandleSessionStateChange(SessionState state) override;
  void HandlePowerButtonPress() override;
  void HandleLidStateChange(LidState state) override;
  void HandleUserActivity(UserActivityType type) override;
  void HandleVideoActivity(bool is_fullscreen) override;
  void HandleWakeNotification() override;
  void HandleHoverStateChange(bool hovering) override;
  void HandleTabletModeChange(TabletMode mode) override;
  void HandlePolicyChange(const PowerManagementPolicy& policy) override;
  void HandleDisplayServiceStart() override;
  void HandleBatterySaverModeChange(
      const BatterySaverModeState& state) override;
  void SetDimmedForInactivity(bool dimmed) override;
  void SetOffForInactivity(bool off) override;
  void SetSuspended(bool suspended) override;
  void SetShuttingDown(bool shutting_down) override;
  void SetForcedOff(bool forced_off) override;
  bool GetForcedOff() override;
  bool GetBrightnessPercent(double* percent) override;
  int GetNumAmbientLightSensorAdjustments() const override {
    return num_als_adjustments_;
  }
  int GetNumUserAdjustments() const override { return num_user_adjustments_; }
  double LevelToPercent(int64_t level) const override;
  int64_t PercentToLevel(double percent) const override;

  void RegisterAmbientLightResumeMetricsHandler(
      AmbientLightOnResumeMetricsCallback callback) override;

 private:
  base::ObserverList<BacklightControllerObserver> observers_;

  // Percent to be returned by GetBrightnessPercent().
  double percent_ = 100.0;

  std::vector<PowerSource> power_source_changes_;
  std::vector<DisplayMode> display_mode_changes_;
  std::vector<SessionState> session_state_changes_;
  int power_button_presses_ = 0;
  std::vector<LidState> lid_state_changes_;
  std::vector<UserActivityType> user_activity_reports_;
  std::vector<bool> video_activity_reports_;
  std::vector<bool> hover_state_changes_;
  std::vector<TabletMode> tablet_mode_changes_;
  std::vector<PowerManagementPolicy> policy_changes_;
  int display_service_starts_ = 0;
  int wake_notification_reports_ = 0;
  int battery_saver_changes_ = 0;

  bool dimmed_ = false;
  bool off_ = false;
  bool suspended_ = false;
  bool shutting_down_ = false;
  bool forced_off_ = false;
  bool ambient_light_metrics_callback_registered_ = false;

  // Counts to be returned by GetNum*Adjustments().
  int num_als_adjustments_ = 0;
  int num_user_adjustments_ = 0;
};

}  // namespace power_manager::policy

#endif  // POWER_MANAGER_POWERD_POLICY_BACKLIGHT_CONTROLLER_STUB_H_
