// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_DBUS_MM1_MODEM_LOCATION_PROXY_H_
#define SHILL_DBUS_MM1_MODEM_LOCATION_PROXY_H_

#include <map>
#include <memory>
#include <string>

#include "cellular/dbus-proxies.h"
#include "shill/cellular/mm1_modem_location_proxy_interface.h"

namespace shill {
namespace mm1 {

// A proxy to org.freedesktop.ModemManager1.Modem.Location.
class ModemLocationProxy : public ModemLocationProxyInterface {
 public:
  // Constructs an org.freedesktop.ModemManager1.Modem.Location DBus
  // object proxy at |path| owned by |service|.
  ModemLocationProxy(const scoped_refptr<dbus::Bus>& bus,
                     const RpcIdentifier& path,
                     const std::string& service);
  ModemLocationProxy(const ModemLocationProxy&) = delete;
  ModemLocationProxy& operator=(const ModemLocationProxy&) = delete;

  ~ModemLocationProxy() override;
  // Inherited methods from ModemLocationProxyInterface.
  void Setup(uint32_t sources,
             bool signal_location,
             Error* error,
             ResultCallback callback,
             int timeout) override;

  void GetLocation(Error* error,
                   BrilloAnyCallback callback,
                   int timeout) override;

 private:
  // Callbacks for Setup async call.
  void OnSetupSuccess(ResultCallback callback);
  void OnSetupFailure(ResultCallback callback, brillo::Error* dbus_error);

  // Callbacks for GetLocation async call.
  void OnGetLocationSuccess(BrilloAnyCallback callback,
                            const std::map<uint32_t, brillo::Any>& results);
  void OnGetLocationFailure(BrilloAnyCallback callback,
                            brillo::Error* dbus_error);

  std::unique_ptr<org::freedesktop::ModemManager1::Modem::LocationProxy> proxy_;

  base::WeakPtrFactory<ModemLocationProxy> weak_factory_{this};
};

}  // namespace mm1
}  // namespace shill

#endif  // SHILL_DBUS_MM1_MODEM_LOCATION_PROXY_H_
