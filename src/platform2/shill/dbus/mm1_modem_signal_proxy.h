// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_DBUS_MM1_MODEM_SIGNAL_PROXY_H_
#define SHILL_DBUS_MM1_MODEM_SIGNAL_PROXY_H_

#include <memory>
#include <string>
#include <vector>

#include "cellular/dbus-proxies.h"
#include "shill/cellular/mm1_modem_signal_proxy_interface.h"
#include "shill/store/key_value_store.h"

namespace shill {
namespace mm1 {

// A proxy to org.freedesktop.ModemManager1.Modem.Signal.
class ModemSignalProxy : public ModemSignalProxyInterface {
 public:
  // Constructs an org.freedesktop.ModemManager1.Modem.Signal DBus
  // object proxy at |path| owned by |service|.
  ModemSignalProxy(const scoped_refptr<dbus::Bus>& bus,
                   const RpcIdentifier& path,
                   const std::string& service);
  ModemSignalProxy(const ModemSignalProxy&) = delete;
  ModemSignalProxy& operator=(const ModemSignalProxy&) = delete;

  ~ModemSignalProxy() override;

  // Inherited methods from ModemSignalProxyInterface.
  void Setup(const int rate,
             Error* /*error*/,
             ResultCallback callback,
             int timeout) override;

  void SetupThresholds(const KeyValueStore& settings,
                       Error* /*error*/,
                       ResultCallback callback,
                       int timeout) override;

 private:
  // Callbacks for Setup async call.
  void OnSetupSuccess(ResultCallback callback);
  void OnSetupFailure(ResultCallback callback, brillo::Error* dbus_error);

  // Callbacks for SetupThresholds async call.
  void OnSetupThresholdsSuccess(ResultCallback callback);
  void OnSetupThresholdsFailure(ResultCallback callback,
                                brillo::Error* dbus_error);

  std::unique_ptr<org::freedesktop::ModemManager1::Modem::SignalProxy> proxy_;

  base::WeakPtrFactory<ModemSignalProxy> weak_factory_{this};
};

}  // namespace mm1
}  // namespace shill

#endif  // SHILL_DBUS_MM1_MODEM_SIGNAL_PROXY_H_
