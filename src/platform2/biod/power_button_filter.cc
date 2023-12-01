// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "biod/power_button_filter.h"

#include <memory>
#include <utility>

#include <base/logging.h>
#include <base/memory/ptr_util.h>
#include <base/time/default_tick_clock.h>
#include <cros_config/cros_config.h>

#include "biod/biod_config.h"
#include "biod/power_manager_client.h"

namespace biod {

std::unique_ptr<PowerButtonFilterInterface> PowerButtonFilter::Create(
    const scoped_refptr<dbus::Bus>& bus) {
  auto power_button_filter = base::WrapUnique(new PowerButtonFilter());
  // DefaultTickClock uses TimeTicks with clock of type CLOCK_MONOTONIC in the
  // background. CLOCK_MONOTONIC advances monotonically while the system is in
  // S0. Note that CLOCK_MONOTONIC stands still when the system is suspended.
  // But that should not cause any problems in this use case.
  power_button_filter->Init(PowerManagerClient::Create(bus),
                            std::make_unique<brillo::CrosConfig>(),
                            std::make_unique<base::DefaultTickClock>());
  return power_button_filter;
}

std::unique_ptr<PowerButtonFilterInterface>
PowerButtonFilter::create_power_button_filter_for_test(
    std::unique_ptr<PowerManagerClientInterface> power_manager_client,
    std::unique_ptr<brillo::CrosConfigInterface> cros_config_prefs,
    std::unique_ptr<base::TickClock> tick_clock) {
  auto power_button_filter = base::WrapUnique(new PowerButtonFilter());
  power_button_filter->Init(std::move(power_manager_client),
                            std::move(cros_config_prefs),
                            std::move(tick_clock));
  return power_button_filter;
}

bool PowerButtonFilter::ShouldFilterFingerprintMatch() {
  if (!fp_on_power_button_)
    return false;

  // If we have already suppressed a fp touch for the latest power button event,
  // let us not suppress anymore fp touch events.
  if (is_already_filtered_ == true)
    return false;

  if ((tick_clock_->NowTicks() - base::Milliseconds(kAuthIgnoreTimeoutmsecs)) <
      last_power_button_event_) {
    is_already_filtered_ = true;
    return true;
  }

  return false;
}

void PowerButtonFilter::PowerButtonEventReceived(
    bool down, const base::TimeTicks& timestamp) {
  if (down) {
    last_power_button_event_ = timestamp;
    is_already_filtered_ = false;
  }
}

void PowerButtonFilter::Init(
    std::unique_ptr<PowerManagerClientInterface> power_manager_client,
    std::unique_ptr<brillo::CrosConfigInterface> cros_config_prefs,
    std::unique_ptr<base::TickClock> tick_clock) {
  power_manager_client_ = std::move(power_manager_client);
  cros_config_prefs_ = std::move(cros_config_prefs);
  tick_clock_ = std::move(tick_clock);

  std::string sensor_type_out;

  // If unibuild is supported, check if |kFingerprintSensorTypePrefName| is set.
  if (cros_config_prefs_ &&
      cros_config_prefs_->GetString(kCrosConfigFPPath,
                                    kFingerprintSensorTypePrefName,
                                    &sensor_type_out)) {
    fp_on_power_button_ = (sensor_type_out == kFingerprintSensorTypeOverlapped);
  } else {
    // If unibuild is not supported or if |kFingerprintSensorTypePrefName| is
    // not set, check if FP_ON_POWER_BUTTON is defined.
#if defined(FP_ON_POWER_BUTTON)
    fp_on_power_button_ = true;
#else
    fp_on_power_button_ = false;
#endif  // FP_ON_POWER_BUTTON
  }

  LOG(INFO) << "Fp is " << (fp_on_power_button_ ? "" : "not ")
            << "overlapped on powerbutton.";
  if (fp_on_power_button_ && !power_manager_client_->HasObserver(this))
    power_manager_client_->AddObserver(this);
}

}  // namespace biod
