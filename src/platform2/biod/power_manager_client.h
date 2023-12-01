// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BIOD_POWER_MANAGER_CLIENT_H_
#define BIOD_POWER_MANAGER_CLIENT_H_

#include <stdint.h>

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <base/observer_list.h>
#include <power_manager/dbus-proxies.h>

#include "biod/power_event_observer.h"
#include "biod/power_manager_client_interface.h"

namespace biod {

// Connects to the system D-Bus and listens for signals from the power manager.
class PowerManagerClient : public PowerManagerClientInterface {
 public:
  static std::unique_ptr<PowerManagerClientInterface> Create(
      const scoped_refptr<dbus::Bus>& bus);
  ~PowerManagerClient() override = default;

  // PowerManagerClientInterface Implementation.
  void AddObserver(PowerEventObserver* observer) override;
  bool HasObserver(PowerEventObserver* observer) override;
  void RemoveObserver(PowerEventObserver* observer) override;

 private:
  // Constructs a PowerManager dbus client with signals dispatched to
  // |observers|.
  explicit PowerManagerClient(const scoped_refptr<dbus::Bus>& bus);
  PowerManagerClient(const PowerManagerClient&) = delete;
  PowerManagerClient& operator=(const PowerManagerClient&) = delete;

  // InputEvent handler.
  void InputEvent(const std::vector<uint8_t>& serialized_proto);

  // Called when signal is connected to the ObjectProxy.
  void OnSignalConnected(const std::string& interface_name,
                         const std::string& signal_name,
                         bool success);

  std::unique_ptr<org::chromium::PowerManagerProxy> proxy_;
  base::ObserverList<PowerEventObserver> observers_;
  base::WeakPtrFactory<PowerManagerClient> weak_factory_{this};
};

}  // namespace biod

#endif  // BIOD_POWER_MANAGER_CLIENT_H_
