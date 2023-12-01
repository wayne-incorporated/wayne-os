// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BIOD_POWER_BUTTON_FILTER_H_
#define BIOD_POWER_BUTTON_FILTER_H_

#include <memory>
#include <string>

#include <base/time/tick_clock.h>
#include <base/time/time.h>
#include <base/system/sys_info.h>
#include <cros_config/cros_config_interface.h>

#include <dbus/bus.h>

#include "biod/power_button_filter_interface.h"
#include "biod/power_manager_client.h"

namespace biod {

inline constexpr char kFingerprintSensorTypePrefName[] =
    "fingerprint-sensor-type";
inline constexpr char kFingerprintSensorTypeOverlapped[] = "on-power-button";
inline constexpr char kFingerprintSensorTypeStandAlone[] = "stand-alone";

// Number of msecs to ignore fp match after seeing a power button down event on
// devices with fp overlapped on power button. This is picked based on max
// time taken to match/nomatch fp during an auth session
// (http://shortn/_O6PdXwhIqy ). Note that |kAuthIgnoreTimeoutmsecs| is padded
// above the current maximum time (600msecs) FP sensor takes to process a touch
// to accommodate minor regressions in the future.
// TODO(ravisadineni): Add autotest to verify that the time taken to fp match is
// less than 1000 msecs..
inline constexpr int64_t kAuthIgnoreTimeoutmsecs = 1000;

class PowerButtonFilter : public PowerButtonFilterInterface,
                          public PowerEventObserver {
 public:
  static std::unique_ptr<PowerButtonFilterInterface> Create(
      const scoped_refptr<dbus::Bus>& bus);
  static std::unique_ptr<PowerButtonFilterInterface>
  create_power_button_filter_for_test(
      std::unique_ptr<PowerManagerClientInterface> power_manager_client,
      std::unique_ptr<brillo::CrosConfigInterface> cros_config_prefs,
      std::unique_ptr<base::TickClock> tick_clock);
  ~PowerButtonFilter() override = default;

  void Init(std::unique_ptr<PowerManagerClientInterface> power_manager_client,
            std::unique_ptr<brillo::CrosConfigInterface> cros_config_prefs,
            std::unique_ptr<base::TickClock> tick_clock);

  // PowerButtonFilterInterface implementation.
  bool ShouldFilterFingerprintMatch() override;

  // Implements PowerEventObserver.
  void PowerButtonEventReceived(bool down,
                                const base::TimeTicks& timestamp) override;

 private:
  PowerButtonFilter() = default;
  PowerButtonFilter(const PowerButtonFilter&) = delete;
  PowerButtonFilter& operator=(const PowerButtonFilter&) = delete;

  // Timestamp of last power button event.
  base::TimeTicks last_power_button_event_;
  // Is fp touch already filtered for the latest power button event? This helps
  // us from filtering multiple fingerprint touch events for the same power
  // button event. This is added to prevent powerbutton events before suspend
  // from filtering fingerprint events after (responsible for) resume as
  // DefaultTick clock and powerbutton event timestamp (sent by powerd) use
  // CLOCK_MONOTONIC which stands still in suspend (on linux). Defaulted to true
  // to prevent filtering before any power button press.
  bool is_already_filtered_ = true;
  std::unique_ptr<PowerManagerClientInterface> power_manager_client_;
  std::unique_ptr<brillo::CrosConfigInterface> cros_config_prefs_;
  std::unique_ptr<base::TickClock> tick_clock_;

  bool fp_on_power_button_ = false;
};

}  // namespace biod

#endif  // BIOD_POWER_BUTTON_FILTER_H_
