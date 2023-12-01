// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_NETWORK_DHCP_PROVIDER_H_
#define SHILL_NETWORK_DHCP_PROVIDER_H_

#include <map>
#include <memory>
#include <set>
#include <string>

#include <base/files/file_path.h>
#include <base/lazy_instance.h>
#include <base/memory/weak_ptr.h>
#include <gtest/gtest_prod.h>  // for FRIEND_TEST

#include "shill/network/dhcp_controller.h"
#include "shill/refptr_types.h"
#include "shill/technology.h"

namespace shill {

class ControlInterface;
class DHCPCDListenerInterface;
class EventDispatcher;
class Metrics;

// DHCPProvider is a singleton providing the main DHCP configuration entrypoint.
// Once the provider is initialized through its Init method, DHCP configurations
// for devices can be obtained through its CreateController() method. For
// example, a single DHCP configuration request can be initiated as:
//
// DHCPProvider::GetInstance()->CreateController(device_name,
//                                               lease_file_suffix,
//                                               arp_gateway,
//                                               dhcp_props)->Request();
class DHCPProvider {
 public:
  // Options to create a DHCP controller.
  struct Options {
    // If true, the DHCP client will ARP for the gateway IP address as an
    // additional safeguard against the issued IP address being in-use by
    // another station.
    bool use_arp_gateway = false;
    // If true, the DHCP client will request option 108 to prefer IPv6-only on a
    // capable network.
    bool use_rfc_8925 = false;
    // The DHCP lease file will contain the suffix supplied in |lease_name| if
    // non-empty, otherwise the interface name will be used.
    std::string lease_name;
    // Hostname to be used in DHCP request. If it is not empty, it is placed in
    // the DHCP request to allow the server to map the request to a specific
    // user-named origin.
    std::string hostname;
  };

  static constexpr char kDHCPCDPathFormatLease[] = "var/lib/dhcpcd/%s.lease";

  virtual ~DHCPProvider();

  // This is a singleton -- use DHCPProvider::GetInstance()->Foo().
  static DHCPProvider* GetInstance();

  // Initializes the provider singleton. This method hooks up a D-Bus signal
  // listener that catches signals from spawned DHCP clients and dispatches them
  // to the appropriate DHCP configuration instance.
  virtual void Init(ControlInterface* control_interface,
                    EventDispatcher* dispatcher,
                    Metrics* metrics);

  // Called on shutdown to release |listener_|.
  void Stop();

  // Creates a new DHCPController for |device_name|. The DHCP configuration for
  // the device can then be initiated through DHCPController::Request and
  // DHCPController::Renew.
  virtual std::unique_ptr<DHCPController> CreateController(
      const std::string& device_name,
      const Options& opts,
      Technology technology);

  // Returns the DHCP configuration associated with DHCP client |pid|. Returns
  // nullptr if |pid| is not bound to a configuration. Caller should not hold
  // this pointer.
  DHCPController* GetController(int pid);

  // Binds a |pid| to a DHCP |controller|. When a DHCPController spawns a new
  // DHCP client, it binds itself to that client's |pid|.
  virtual void BindPID(int pid, base::WeakPtr<DHCPController> controller);

  // Unbinds a |pid|. This method is used by a DHCPController to signal the
  // provider that the DHCP client has been terminated.
  virtual void UnbindPID(int pid);

  // Destroy lease file associated with this |name|.
  virtual void DestroyLease(const std::string& name);

  // Returns true if |pid| was recently unbound from the provider.
  bool IsRecentlyUnbound(int pid);

 protected:
  DHCPProvider();
  DHCPProvider(const DHCPProvider&) = delete;
  DHCPProvider& operator=(const DHCPProvider&) = delete;

 private:
  friend base::LazyInstanceTraitsBase<DHCPProvider>;
  friend class CellularTest;
  friend class DHCPProviderTest;
  friend class DeviceInfoTest;
  friend class DeviceTest;
  FRIEND_TEST(DHCPProviderTest, CreateController);
  FRIEND_TEST(DHCPProviderTest, DestroyLease);

  using PIDControllerMap = std::map<int, base::WeakPtr<DHCPController>>;

  // Retire |pid| from the set of recently retired PIDs.
  void RetireUnboundPID(int pid);

  // A single listener is used to catch signals from all DHCP clients and
  // dispatch them to the appropriate DHCPController instance.
  std::unique_ptr<DHCPCDListenerInterface> listener_;

  // A map that binds PIDs to DHCPController instances.
  PIDControllerMap controllers_;

  base::FilePath root_;
  ControlInterface* control_interface_;
  EventDispatcher* dispatcher_;
  Metrics* metrics_;

  // Track the set of PIDs recently unbound from the provider in case messages
  // arrive addressed from them.
  std::set<int> recently_unbound_pids_;
};

}  // namespace shill

#endif  // SHILL_NETWORK_DHCP_PROVIDER_H_
