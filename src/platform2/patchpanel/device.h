// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef PATCHPANEL_DEVICE_H_
#define PATCHPANEL_DEVICE_H_

#include <linux/in6.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <map>
#include <memory>
#include <optional>
#include <ostream>
#include <string>

#include <base/functional/bind.h>
#include <base/memory/weak_ptr.h>
#include <gtest/gtest_prod.h>  // for FRIEND_TEST
#include <net-base/ipv4_address.h>

#include "patchpanel/mac_address_generator.h"
#include "patchpanel/shill_client.h"
#include "patchpanel/subnet.h"

namespace patchpanel {

// Represents a virtual network interface created and managed by patchpanel with
// its configuration. A Device can be associated with:
//  - ARC container: a pair of virtual ethernet interfaces setup across the
//  host / ARC namespace boundary, plus a software bridge to which the host-side
//  veth interface is attached.
//  - ARCVM: a TAP device plus a software bridge to which the TAP device is
//  attached.
//  - Termina VMs, Parallels VMs, other crosvm guests: a TAP device, with no
// software bridge.
// The main interface interacting with other parts of the network layer is:
//  - ARC, ARCVM: the software bridge.
//  - other crosvm guests: the TAP device.
// A Device always is always associated with a unique IPv4 subnet statically
// assigned by AddressManager based on the type of guest. Connected namespaces
// have currently no Device representation.
class Device {
 public:
  enum class Type {
    // ARC container or ARCVM legacy management interface used for adb
    // connections and VPN forwarding.
    kARC0,
    // Virtual ethernet interface and bridge setup used by ARC container.
    kARCContainer,
    // TAP device and bridge setup used by ARCVM.
    kARCVM,
    // TAP device used by concierge for the Termina VM and its user LXD
    // containers.
    kTerminaVM,
    // TAP device used by concierge for the Parallels VM.
    kParallelsVM,
  };

  enum class ChangeEvent {
    kAdded,
    kRemoved,
  };

  using ChangeEventHandler =
      base::RepeatingCallback<void(const Device&, ChangeEvent)>;

  class Config {
   public:
    Config(const MacAddress& mac_addr,
           std::unique_ptr<Subnet> ipv4_subnet,
           std::unique_ptr<SubnetAddress> host_ipv4_addr,
           std::unique_ptr<SubnetAddress> guest_ipv4_addr,
           std::unique_ptr<Subnet> lxd_ipv4_subnet = nullptr);
    Config(const Config&) = delete;
    Config& operator=(const Config&) = delete;

    ~Config() = default;

    MacAddress mac_addr() const { return mac_addr_; }
    void set_mac_addr(const MacAddress& mac) { mac_addr_ = mac; }

    net_base::IPv4Address host_ipv4_addr() const;
    net_base::IPv4Address guest_ipv4_addr() const;

    const SubnetAddress* const host_ipv4_subnet_addr() const {
      return host_ipv4_addr_.get();
    }
    const SubnetAddress* const guest_ipv4_subnet_addr() const {
      return guest_ipv4_addr_.get();
    }

    const Subnet* const ipv4_subnet() const { return ipv4_subnet_.get(); }

    const Subnet* const lxd_ipv4_subnet() const {
      return lxd_ipv4_subnet_.get();
    }

    void set_tap_ifname(const std::string& tap);
    const std::string& tap_ifname() const;

   private:
    // A random MAC address assigned to the Device for the guest facing
    // interface.
    MacAddress mac_addr_;
    // The static IPv4 subnet allocated for this Device for the host and guest
    // facing interfaces.
    std::unique_ptr<Subnet> ipv4_subnet_;
    // The address allocated from |ipv4_subnet| for use by the host-side
    // interface associated with this Device. This is also used as the next hop
    // for the guest default route on the virtual network associated with that
    // Device.
    std::unique_ptr<SubnetAddress> host_ipv4_addr_;
    // The address allocated from |ipv4_subnet| for use by the guest-side
    // interface associated with this Device, if applicable.
    std::unique_ptr<SubnetAddress> guest_ipv4_addr_;
    // If applicable, an additional IPv4 subnet allocated for this Device for
    // guests like Crostini to use for assigning addresses to containers running
    // within the VM.
    std::unique_ptr<Subnet> lxd_ipv4_subnet_;
    // For VM guest, the interface name of the TAP device currently associated
    // with the configuration.
    std::string tap_;
  };

  // |type| the type of guest associated with this virtual device created by
  // patchpanel.
  // |shill_device| corresponds to the shill Device tracked by this virtual
  // Device. Only defined for ARC or ARCVM devices tracking physical devices.
  // Even when a host VPN is connected, |shill_device| is not defined for the
  // legacy "arc0" Device. |host_ifname| identifies the name of the virtual
  // (bridge) interface (all ARC virtual interfaces) or of the tap device (all
  // non-ARC virtual interfaces). |guest_ifname|, if specified, identifies the
  // name of the interface used inside the guest.
  Device(Type type,
         std::optional<ShillClient::Device> shill_device,
         const std::string& host_ifname,
         const std::string& guest_ifname,
         std::unique_ptr<Config> config);
  Device(const Device&) = delete;
  Device& operator=(const Device&) = delete;

  ~Device() = default;

  Type type() const { return type_; }
  const std::optional<ShillClient::Device>& shill_device() const {
    return shill_device_;
  }
  const std::string& host_ifname() const { return host_ifname_; }
  const std::string& guest_ifname() const { return guest_ifname_; }
  Config& config() const;
  std::unique_ptr<Config> release_config();

 private:
  // The type of virtual device setup and guest.
  Type type_;
  // The physical shill Device that this virtual device is attached to. Only
  // defined for ARC and ARCVM. This member variable is set at creation time and
  // is not updated after that. The owner of instances of this class must ensure
  // that instances are regenarated when the IP configurations of the shill
  // Devices change if accurate properties are needed.
  std::optional<ShillClient::Device> shill_device_;
  // The name of the main virtual interface created by patchpanel for carrying
  // packets out of the guest environment and onto the host routing setup. For
  // all ARC virtual devices, |host_ifname_| corresponds to the virtual bridge
  // created with Datapath::AddBridge(). For other crosvm guests (Termina VM,
  // Parallels VM, etc) this corresponds to the TAP device created with
  // Datapath::AddTAP().
  std::string host_ifname_;
  // The name of the virtual interface used inside the guest environment. Only
  // available for ARC virtual devices, otherwise empty for other crosvm guests.
  std::string guest_ifname_;
  // The MAC address and IPv4 configuration for this virtual device.
  std::unique_ptr<Config> config_;

  FRIEND_TEST(DeviceTest, DisableLegacyAndroidDeviceSendsTwoMessages);

  base::WeakPtrFactory<Device> weak_factory_{this};
};

std::ostream& operator<<(std::ostream& stream, const Device& device);
std::ostream& operator<<(std::ostream& stream, const Device::Type type);

}  // namespace patchpanel

#endif  // PATCHPANEL_DEVICE_H_
