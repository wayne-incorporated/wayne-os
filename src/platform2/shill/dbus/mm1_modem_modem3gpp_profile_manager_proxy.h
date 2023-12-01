// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_DBUS_MM1_MODEM_MODEM3GPP_PROFILE_MANAGER_PROXY_H_
#define SHILL_DBUS_MM1_MODEM_MODEM3GPP_PROFILE_MANAGER_PROXY_H_

#include <memory>
#include <string>
#include <vector>

#include "cellular/dbus-proxies.h"
#include "shill/cellular/mm1_modem_modem3gpp_profile_manager_proxy_interface.h"
#include "shill/store/key_value_store.h"

namespace shill {
namespace mm1 {

// A proxy to org.freedesktop.ModemManager1.Modem.Modem3gpp.ProfileManager.
class ModemModem3gppProfileManagerProxy
    : public ModemModem3gppProfileManagerProxyInterface {
 public:
  // Constructs an org.freedesktop.ModemManager1.Modem.Modem3gpp.ProfileManager
  // DBus object proxy at |path| owned by |service|.
  ModemModem3gppProfileManagerProxy(const scoped_refptr<dbus::Bus>& bus,
                                    const RpcIdentifier& path,
                                    const std::string& service);
  ModemModem3gppProfileManagerProxy(const ModemModem3gppProfileManagerProxy&) =
      delete;
  ModemModem3gppProfileManagerProxy& operator=(
      const ModemModem3gppProfileManagerProxy&) = delete;

  ~ModemModem3gppProfileManagerProxy() override;
  // Inherited methods from ModemModem3gppProfileManagerProxyInterface.
  void List(ResultVariantDictionariesOnceCallback callback,
            int timeout) override;

  // Non inherited methods.
  // Sets the callback to be used when the |Updated| signal is triggered.
  void SetUpdatedCallback(
      const base::RepeatingCallback<void()>& callback) override;

 private:
  // Signal handler.
  void OnUpdated();

  // Callbacks for List async call.
  void OnListSuccess(ResultVariantDictionariesOnceCallback callback,
                     const std::vector<brillo::VariantDictionary>& profiles);
  void OnListFailure(ResultVariantDictionariesOnceCallback callback,
                     brillo::Error* dbus_error);

  // Called when signal is connected to the ObjectProxy.
  void OnSignalConnected(const std::string& interface_name,
                         const std::string& signal_name,
                         bool success);

  Modem3gppProfileManagerUpdatedSignalCallback updated_callback_;

  std::unique_ptr<
      org::freedesktop::ModemManager1::Modem::Modem3gpp::ProfileManagerProxy>
      proxy_;

  base::WeakPtrFactory<ModemModem3gppProfileManagerProxy> weak_factory_{this};
};

}  // namespace mm1
}  // namespace shill

#endif  // SHILL_DBUS_MM1_MODEM_MODEM3GPP_PROFILE_MANAGER_PROXY_H_
