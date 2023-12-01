// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_DBUS_POWER_MANAGER_PROXY_H_
#define SHILL_DBUS_POWER_MANAGER_PROXY_H_

// An implementation of PowerManagerProxyInterface.  It connects to the dbus and
// listens for events from the power manager.  When they occur, the delegate's
// member functions are called.

#include <stdint.h>

#include <memory>
#include <string>
#include <vector>

#include <base/compiler_specific.h>
#include <chromeos/dbus/service_constants.h>
#include <power_manager/dbus-proxies.h>

#include "shill/power_manager_proxy_interface.h"

namespace shill {

class EventDispatcher;

class PowerManagerProxy : public PowerManagerProxyInterface {
 public:
  // Constructs a PowerManager DBus object proxy with signals dispatched to
  // |delegate|.
  PowerManagerProxy(EventDispatcher* dispatcher,
                    const scoped_refptr<dbus::Bus>& bus,
                    PowerManagerProxyDelegate* delegate,
                    const base::RepeatingClosure& service_appeared_callback,
                    const base::RepeatingClosure& service_vanished_callback);
  PowerManagerProxy(const PowerManagerProxy&) = delete;
  PowerManagerProxy& operator=(const PowerManagerProxy&) = delete;

  ~PowerManagerProxy() override;

  // Inherited from PowerManagerProxyInterface.
  bool RegisterSuspendDelay(base::TimeDelta timeout,
                            const std::string& description,
                            int* delay_id_out) override;
  bool UnregisterSuspendDelay(int delay_id) override;
  bool ReportSuspendReadiness(int delay_id, int suspend_id) override;
  bool RegisterDarkSuspendDelay(base::TimeDelta timeout,
                                const std::string& description,
                                int* delay_id_out) override;
  bool UnregisterDarkSuspendDelay(int delay_id) override;
  bool ReportDarkSuspendReadiness(int delay_id, int suspend_id) override;
  bool RecordDarkResumeWakeReason(const std::string& wake_reason) override;
  void ChangeRegDomain(power_manager::WifiRegDomainDbus domain) override;

 private:
  // Signal handlers.
  void SuspendImminent(const std::vector<uint8_t>& serialized_proto);
  void SuspendDone(const std::vector<uint8_t>& serialized_proto);
  void DarkSuspendImminent(const std::vector<uint8_t>& serialized_proto);

  bool RegisterSuspendDelayInternal(bool is_dark,
                                    base::TimeDelta timeout,
                                    const std::string& description,
                                    int* delay_id_out);
  bool UnregisterSuspendDelayInternal(bool is_dark, int delay_id);
  bool ReportSuspendReadinessInternal(bool is_dark,
                                      int delay_id,
                                      int suspend_id);

  // Called when service appeared or vanished.
  void OnServiceAvailable(bool available);

  // Service name owner changed handler.
  void OnServiceOwnerChanged(const std::string& old_owner,
                             const std::string& new_owner);

  // Called when signal is connected to the ObjectProxy.
  void OnSignalConnected(const std::string& interface_name,
                         const std::string& signal_name,
                         bool success);

  // Invoke |service_appeared_callback_| if it is set.
  void OnServiceAppeared();

  // Invoke |service_vanished_callback_| if it is set.
  void OnServiceVanished();

  std::unique_ptr<org::chromium::PowerManagerProxy> proxy_;
  EventDispatcher* dispatcher_;
  PowerManagerProxyDelegate* delegate_;
  base::RepeatingClosure service_appeared_callback_;
  base::RepeatingClosure service_vanished_callback_;
  bool service_available_;

  base::WeakPtrFactory<PowerManagerProxy> weak_factory_{this};
};

}  // namespace shill

#endif  // SHILL_DBUS_POWER_MANAGER_PROXY_H_
