// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_NETWORK_DHCP_PROXY_INTERFACE_H_
#define SHILL_NETWORK_DHCP_PROXY_INTERFACE_H_

#include <string>

namespace shill {

// These are the methods that a DHCP proxy must support. The interface is
// provided so that it can be mocked in tests.
class DHCPProxyInterface {
 public:
  virtual ~DHCPProxyInterface() = default;

  virtual void Rebind(const std::string& interface) = 0;
  virtual void Release(const std::string& interface) = 0;
};

}  // namespace shill

#endif  // SHILL_NETWORK_DHCP_PROXY_INTERFACE_H_
