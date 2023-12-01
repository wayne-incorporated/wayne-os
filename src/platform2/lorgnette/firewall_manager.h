// Copyright 2015 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LORGNETTE_FIREWALL_MANAGER_H_
#define LORGNETTE_FIREWALL_MANAGER_H_

#include <memory>
#include <set>
#include <string>

#include <base/files/scoped_file.h>
#include <base/memory/weak_ptr.h>

#include "permission_broker/dbus-proxies.h"

namespace lorgnette {

class FirewallManager;

// Class representing access to an open port. When it goes out of scope,
// it will release the port.
class PortToken {
 public:
  PortToken(base::WeakPtr<FirewallManager> firewall_manager, uint16_t port);
  PortToken(const PortToken&) = delete;
  PortToken& operator=(const PortToken&) = delete;
  PortToken(PortToken&&);
  ~PortToken();

 private:
  base::WeakPtr<FirewallManager> firewall_manager_;
  uint16_t port_;
};

// Class for managing required firewall rules for lorgnette.
class FirewallManager final {
 public:
  explicit FirewallManager(const std::string& interface);
  FirewallManager(const FirewallManager&) = delete;
  FirewallManager& operator=(const FirewallManager&) = delete;
  ~FirewallManager() = default;

  void Init(std::unique_ptr<org::chromium::PermissionBrokerProxyInterface>
                permission_broker_proxy);

  // Request port access for all well-known Canon scanner port.
  PortToken RequestPixmaPortAccess();

  // Request UDP port access for the specified port.
  PortToken RequestUdpPortAccess(uint16_t port);

 private:
  // ReleaseUdpPortAccess() should be private so that users don't free ports
  // they didn't request, but PortToken's destructor needs access to it.
  friend PortToken::~PortToken();

  // Setup lifeline pipe to allow the remote firewall server
  // (permission_broker) to monitor this process, so it can remove the firewall
  // rules in case this process crashes.
  bool SetupLifelinePipe();

  void OnServiceAvailable(bool service_available);
  void OnServiceNameChanged(const std::string& old_owner,
                            const std::string& new_owner);

  void SendPortAccessRequest(uint16_t port);

  // This is called when a new instance of permission_broker is detected. Since
  // the new instance doesn't have any knowledge of previously port access
  // requests, re-issue those requests to permission_broker to get in sync.
  void RequestAllPortsAccess();

  void ReleaseUdpPortAccess(uint16_t port);

  // DBus proxy for permission_broker.
  std::unique_ptr<org::chromium::PermissionBrokerProxyInterface>
      permission_broker_proxy_;
  // File descriptors for the two end of the pipe use for communicating with
  // remote firewall server (permission_broker), where the remote firewall
  // server will use the read end of the pipe to detect when this process exits.
  base::ScopedFD lifeline_read_;
  base::ScopedFD lifeline_write_;

  // The interface on which to request network access.
  std::string interface_;

  // The set of ports for which access has been requested.
  std::set<uint16_t> requested_ports_;

  // Keep as the last member variable.
  base::WeakPtrFactory<FirewallManager> weak_factory_{this};
};

}  // namespace lorgnette

#endif  // LORGNETTE_FIREWALL_MANAGER_H_
