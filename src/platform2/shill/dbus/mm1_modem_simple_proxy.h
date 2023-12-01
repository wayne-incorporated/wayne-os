// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_DBUS_MM1_MODEM_SIMPLE_PROXY_H_
#define SHILL_DBUS_MM1_MODEM_SIMPLE_PROXY_H_

#include <memory>
#include <string>

#include "cellular/dbus-proxies.h"
#include "shill/cellular/mm1_modem_simple_proxy_interface.h"

namespace shill {
namespace mm1 {

// A proxy to org.freedesktop.ModemManager1.Modem.Simple.
class ModemSimpleProxy : public ModemSimpleProxyInterface {
 public:
  // Constructs a org.freedesktop.ModemManager1.Modem.Simple DBus
  // object proxy at |path| owned by |service|.
  ModemSimpleProxy(const scoped_refptr<dbus::Bus>& bus,
                   const RpcIdentifier& path,
                   const std::string& service);
  ModemSimpleProxy(const ModemSimpleProxy&) = delete;
  ModemSimpleProxy& operator=(const ModemSimpleProxy&) = delete;

  ~ModemSimpleProxy() override;

  // Inherited methods from SimpleProxyInterface.
  void Connect(const KeyValueStore& properties,
               RpcIdentifierCallback callback,
               int timeout) override;
  void Disconnect(const RpcIdentifier& bearer,
                  ResultCallback callback,
                  int timeout) override;

 private:
  // Callbacks for Connect async call.
  void OnConnectSuccess(RpcIdentifierCallback callback,
                        const dbus::ObjectPath& path);
  void OnConnectFailure(RpcIdentifierCallback callback, brillo::Error* error);

  // Callbacks for Disconnect async call.
  void OnDisconnectSuccess(ResultCallback callback);
  void OnDisconnectFailure(ResultCallback callback, brillo::Error* dbus_error);

  std::unique_ptr<org::freedesktop::ModemManager1::Modem::SimpleProxy> proxy_;

  base::WeakPtrFactory<ModemSimpleProxy> weak_factory_{this};
};

}  // namespace mm1
}  // namespace shill

#endif  // SHILL_DBUS_MM1_MODEM_SIMPLE_PROXY_H_
