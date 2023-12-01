// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_DBUS_DHCPCD_PROXY_H_
#define SHILL_DBUS_DHCPCD_PROXY_H_

#include <memory>
#include <string>

#include "dhcpcd/dbus-proxies.h"
#include "shill/network/dhcp_proxy_interface.h"

namespace shill {

// There's a single DHCPCD proxy per DHCP client identified by its process id.
class DHCPCDProxy : public DHCPProxyInterface {
 public:
  DHCPCDProxy(const scoped_refptr<dbus::Bus>& bus,
              const std::string& service_name);
  DHCPCDProxy(const DHCPCDProxy&) = delete;
  DHCPCDProxy& operator=(const DHCPCDProxy&) = delete;

  ~DHCPCDProxy() override;

  // Inherited from DHCPProxyInterface.
  void Rebind(const std::string& interface) override;
  void Release(const std::string& interface) override;

 private:
  void LogDBusError(const brillo::ErrorPtr& error,
                    const std::string& method,
                    const std::string& interface);

  std::unique_ptr<org::chromium::dhcpcdProxy> dhcpcd_proxy_;
};

}  // namespace shill

#endif  // SHILL_DBUS_DHCPCD_PROXY_H_
