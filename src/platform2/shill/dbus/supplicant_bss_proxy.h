// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_DBUS_SUPPLICANT_BSS_PROXY_H_
#define SHILL_DBUS_SUPPLICANT_BSS_PROXY_H_

#include <memory>
#include <string>

#include "shill/data_types.h"
#include "shill/refptr_types.h"
#include "shill/supplicant/supplicant_bss_proxy_interface.h"
#include "supplicant/dbus-proxies.h"

namespace shill {

class WiFiEndpoint;

class SupplicantBSSProxy : public SupplicantBSSProxyInterface {
 public:
  SupplicantBSSProxy(const scoped_refptr<dbus::Bus>& bus,
                     const RpcIdentifier& object_path,
                     WiFiEndpoint* wifi_endpoint);
  SupplicantBSSProxy(const SupplicantBSSProxy&) = delete;
  SupplicantBSSProxy& operator=(const SupplicantBSSProxy&) = delete;

  ~SupplicantBSSProxy() override;

 private:
  // Signal handlers.
  void PropertiesChanged(const brillo::VariantDictionary& properties);

  // Called when signal is connected to the ObjectProxy.
  void OnSignalConnected(const std::string& interface_name,
                         const std::string& signal_name,
                         bool success);

  std::unique_ptr<fi::w1::wpa_supplicant1::BSSProxy> bss_proxy_;
  // We use a bare pointer, because each SupplcantBSSProxy is
  // owned (using a unique_ptr) by a WiFiEndpoint. This means that if
  // |wifi_endpoint_| is invalid, then so is |this|.
  WiFiEndpoint* wifi_endpoint_;

  base::WeakPtrFactory<SupplicantBSSProxy> weak_factory_{this};
};

}  // namespace shill

#endif  // SHILL_DBUS_SUPPLICANT_BSS_PROXY_H_
