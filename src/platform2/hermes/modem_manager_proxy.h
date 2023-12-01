// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef HERMES_MODEM_MANAGER_PROXY_H_
#define HERMES_MODEM_MANAGER_PROXY_H_

#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <chromeos/dbus/service_constants.h>
#include <dbus/bus.h>
#include <base/cancelable_callback.h>

#include "hermes/dbus_bindings/mm-proxies.h"
#include "hermes/executor.h"
#include "hermes/hermes_common.h"
#include "hermes/modem_manager_proxy_interface.h"

namespace hermes {

class ModemManagerProxy : public ModemManagerProxyInterface {
 public:
  using DBusInterfaceToProperties =
      std::map<std::string, brillo::VariantDictionary>;
  using DBusObjectsWithProperties =
      std::map<dbus::ObjectPath, DBusInterfaceToProperties>;
  explicit ModemManagerProxy(const scoped_refptr<dbus::Bus>& bus);

  // cb is executed when a new modem appears on DBus. Executed only once.
  void RegisterModemAppearedCallback(base::OnceClosure cb) override;
  // If MM has exported a DBus object, executes cb immediately. If not,
  // waits for MM to export a DBus object.
  void WaitForModem(base::OnceClosure cb) override;

  std::string GetMbimPort() const override;

  void ScheduleUninhibit(base::TimeDelta timeout) override;
  void WaitForModemAndInhibit(ResultCallback cb) override;

 protected:
  // To be used by mocks only
  ModemManagerProxy();

 private:
  void WaitForModemStepGetObjects(base::OnceClosure cb, bool /*is_available*/);
  void OnInterfaceAdded(const dbus::ObjectPath& object_path,
                        const DBusInterfaceToProperties& properties);
  void OnInterfaceRemoved(const dbus::ObjectPath& object_path,
                          const std::vector<std::string>& iface);
  void WaitForModemStepLast(
      base::OnceClosure cb,
      const DBusObjectsWithProperties& dbus_objects_with_properties);
  void OnNewModemDetected(dbus::ObjectPath object_path);
  void OnPropertiesChanged(
      org::freedesktop::ModemManager1::ModemProxyInterface* /*unused*/,
      const std::string& prop);

  void Uninhibit();
  bool IsModemSafeToInhibit();
  void InhibitDevice(bool inhibit, ResultCallback cb);
  void OnInhibitSuccess(bool inhibit,
                        std::basic_string<char> uid,
                        ResultCallback cb);
  void InhibitTimeout(ResultCallback cb);

  scoped_refptr<dbus::Bus> bus_;
  std::unique_ptr<org::freedesktop::DBus::ObjectManagerProxy>
      object_manager_proxy_;
  std::unique_ptr<org::freedesktop::ModemManager1Proxy> mm_proxy_;
  std::optional<std::string> cached_mbim_port_;
  std::unique_ptr<org::freedesktop::ModemManager1::ModemProxy> modem_proxy_;

  std::optional<std::basic_string<char>> device_identifier_;
  bool modem_appeared_;
  base::OnceClosure on_modem_appeared_cb_;

  std::optional<std::basic_string<char>> inhibited_uid_;
  base::CancelableOnceClosure uninhibit_cb_;
  base::OnceClosure pending_inhibit_cb_;

  base::WeakPtrFactory<ModemManagerProxy> weak_factory_;
};
}  // namespace hermes

#endif  // HERMES_MODEM_MANAGER_PROXY_H_
