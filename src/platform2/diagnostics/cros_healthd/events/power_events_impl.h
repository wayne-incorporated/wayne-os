// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_EVENTS_POWER_EVENTS_IMPL_H_
#define DIAGNOSTICS_CROS_HEALTHD_EVENTS_POWER_EVENTS_IMPL_H_

#include <optional>
#include <vector>

#include <mojo/public/cpp/bindings/pending_remote.h>
#include <mojo/public/cpp/bindings/remote_set.h>
#include <power_manager/proto_bindings/power_supply_properties.pb.h>

#include "diagnostics/cros_healthd/events/power_events.h"
#include "diagnostics/cros_healthd/system/context.h"
#include "diagnostics/mojom/public/cros_healthd_events.mojom.h"

namespace diagnostics {

// Production implementation of the PowerEvents interface.
class PowerEventsImpl final : public PowerEvents {
 public:
  explicit PowerEventsImpl(Context* context);
  PowerEventsImpl(const PowerEventsImpl&) = delete;
  PowerEventsImpl& operator=(const PowerEventsImpl&) = delete;
  ~PowerEventsImpl() = default;

  // PowerEvents overrides:
  void AddObserver(mojo::PendingRemote<ash::cros_healthd::mojom::EventObserver>
                       observer) override;

  // Deprecated interface. Only for backward compatibility.
  void AddObserver(
      mojo::PendingRemote<ash::cros_healthd::mojom::CrosHealthdPowerObserver>
          observer) override;

 private:
  // Mapping between powerd's PowerSupplyProperties and events that PowerEvents
  // cares about.
  enum class PowerEventType {
    // Energy consumption from an external power source has started.
    kAcInserted,
    // Energy consumption from an external power source has stopped.
    kAcRemoved,
  };

  void OnPowerSupplyPollSignal(const std::vector<uint8_t>& signal);
  void OnSuspendImminentSignal(const std::vector<uint8_t>& signal);
  void OnDarkSuspendImminentSignal(const std::vector<uint8_t>& signal);
  void OnSuspendDoneSignal(const std::vector<uint8_t>& signal);

  // Common response to either a SuspendImminentSignal or
  // DarkSuspendImminentSignal.
  void OnAnySuspendImminentSignal();

  // Most recent external power AC event, from powerd's last
  // PowerSupplyPollSignal (updates every 30 seconds or when something changes
  // in the power supply).
  std::optional<PowerEventType> external_power_ac_event_;

  // Each observer in |observers_| will be notified of any power event in the
  // ash::cros_healthd::mojom::CrosHealthdPowerObserver interface. The
  // InterfacePtrSet manages the lifetime of the endpoints, which are
  // automatically destroyed and removed when the pipe they are bound to is
  // destroyed.
  mojo::RemoteSet<ash::cros_healthd::mojom::EventObserver> observers_;
  mojo::RemoteSet<ash::cros_healthd::mojom::CrosHealthdPowerObserver>
      deprecated_observers_;

  // Unowned pointer. Should outlive this instance.
  Context* const context_ = nullptr;

  base::WeakPtrFactory<PowerEventsImpl> weak_ptr_factory_;
};

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_EVENTS_POWER_EVENTS_IMPL_H_
