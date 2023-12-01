// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_EVENT_AGGREGATOR_H_
#define DIAGNOSTICS_CROS_HEALTHD_EVENT_AGGREGATOR_H_

#include <memory>

#include <mojo/public/cpp/bindings/pending_remote.h>

#include "diagnostics/cros_healthd/events/audio_events.h"
#include "diagnostics/cros_healthd/events/audio_jack_events.h"
#include "diagnostics/cros_healthd/events/bluetooth_events.h"
#include "diagnostics/cros_healthd/events/crash_events.h"
#include "diagnostics/cros_healthd/events/event_reporter.h"
#include "diagnostics/cros_healthd/events/lid_events.h"
#include "diagnostics/cros_healthd/events/power_events.h"
#include "diagnostics/cros_healthd/events/stylus_events.h"
#include "diagnostics/cros_healthd/events/stylus_garage_events.h"
#include "diagnostics/cros_healthd/events/touchpad_events.h"
#include "diagnostics/cros_healthd/events/touchscreen_events.h"
#include "diagnostics/cros_healthd/events/udev_events.h"
#include "diagnostics/cros_healthd/system/context.h"
#include "diagnostics/cros_healthd/system/ground_truth.h"
#include "diagnostics/mojom/public/cros_healthd.mojom.h"
#include "diagnostics/mojom/public/cros_healthd_events.mojom.h"

namespace diagnostics {

// This class is responsible for aggregating event instances.
class EventAggregator final {
 public:
  explicit EventAggregator(Context* context);
  EventAggregator(const EventAggregator&) = delete;
  EventAggregator& operator=(const EventAggregator&) = delete;
  ~EventAggregator();

  void AddObserver(
      ash::cros_healthd::mojom::EventCategoryEnum category,
      mojo::PendingRemote<ash::cros_healthd::mojom::EventObserver> observer);

  void IsEventSupported(ash::cros_healthd::mojom::EventCategoryEnum category,
                        ash::cros_healthd::mojom::CrosHealthdEventService::
                            IsEventSupportedCallback callback);

  // Deprecated interface. Only for backward compatibility.
  void AddObserver(
      mojo::PendingRemote<ash::cros_healthd::mojom::CrosHealthdUsbObserver>
          observer);

  // Deprecated interface. Only for backward compatibility.
  void AddObserver(
      mojo::PendingRemote<
          ash::cros_healthd::mojom::CrosHealthdThunderboltObserver> observer);

  // Deprecated interface. Only for backward compatibility.
  void AddObserver(
      mojo::PendingRemote<ash::cros_healthd::mojom::CrosHealthdPowerObserver>
          observer);

  // Deprecated interface. Only for backward compatibility.
  void AddObserver(
      mojo::PendingRemote<ash::cros_healthd::mojom::CrosHealthdAudioObserver>
          observer);

 private:
  // The pointer to the Context object for accessing system utilities.
  Context* const context_;

  std::unique_ptr<UdevEvents> udev_events_;
  std::unique_ptr<LidEvents> lid_events_;
  std::unique_ptr<AudioJackEvents> audio_jack_events_;
  std::unique_ptr<PowerEvents> power_events_;
  std::unique_ptr<AudioEvents> audio_events_;
  std::unique_ptr<BluetoothEvents> bluetooth_events_;
  std::unique_ptr<TouchpadEvents> touchpad_events_;
  std::unique_ptr<TouchscreenEvents> touchscreen_events_;
  std::unique_ptr<StylusGarageEvents> stylus_garage_events_;
  std::unique_ptr<StylusEvents> stylus_events_;
  std::unique_ptr<CrashEvents> crash_events_;
  EventReporter event_reporter_{context_};
  GroundTruth ground_truth_{context_};
};

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_EVENT_AGGREGATOR_H_
