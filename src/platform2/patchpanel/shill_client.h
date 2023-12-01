// Copyright 2016 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef PATCHPANEL_SHILL_CLIENT_H_
#define PATCHPANEL_SHILL_CLIENT_H_

#include <map>
#include <memory>
#include <optional>
#include <ostream>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include <base/memory/weak_ptr.h>
#include <dbus/object_path.h>
#include <shill/dbus-proxies.h>

#include "patchpanel/system.h"

namespace patchpanel {

// Listens for shill signals over dbus in order to:
// - Find which network interface are currently managed by shill and to which
//   shill Device they are associated.
// - Figure out which network interface (if any) is being used as the default
//   logical service.
// - Invoke callbacks when the IPConfigs of a shill Device has changed.
class ShillClient {
 public:
  // IPConfig for a shill Device. If the shill Device does not have a valid
  // ipv4/ipv6 config, the corresponding fields will be empty or 0.
  // TODO(jiejiang): add the following fields into this struct:
  // - IPv4 search domains
  // - IPv6 search domains
  // - MTU (one only per network)
  struct IPConfig {
    int ipv4_prefix_length{0};
    std::string ipv4_address;
    std::string ipv4_gateway;
    std::vector<std::string> ipv4_dns_addresses;

    int ipv6_prefix_length{0};
    // Note due to the limitation of shill, we will only get one IPv6 address
    // from it. This address should be the privacy address for device with type
    // of ethernet or wifi.
    std::string ipv6_address;
    std::string ipv6_gateway;
    std::vector<std::string> ipv6_dns_addresses;
    bool operator==(const IPConfig& b) const {
      return ipv4_prefix_length == b.ipv4_prefix_length &&
             ipv4_address == b.ipv4_address && ipv4_gateway == b.ipv4_gateway &&
             std::set<std::string>(ipv4_dns_addresses.begin(),
                                   ipv4_dns_addresses.end()) ==
                 std::set<std::string>(b.ipv4_dns_addresses.begin(),
                                       b.ipv4_dns_addresses.end()) &&
             ipv6_prefix_length == b.ipv6_prefix_length &&
             ipv6_address == b.ipv6_address && ipv6_gateway == b.ipv6_gateway &&
             std::set<std::string>(ipv6_dns_addresses.begin(),
                                   ipv6_dns_addresses.end()) ==
                 std::set<std::string>(b.ipv6_dns_addresses.begin(),
                                       b.ipv6_dns_addresses.end());
    }
  };

  // Represents the properties of an object of org.chromium.flimflam.Device.
  // Only contains the properties we care about.
  // TODO(jiejiang): add the following fields into this struct:
  // - the connection state of the Service, if possible by translating back to
  //   the enum shill::Service::ConnectState
  struct Device {
    // A subset of shill::Technology::Type.
    enum class Type {
      kUnknown,
      kCellular,
      kEthernet,
      kEthernetEap,
      kGuestInterface,
      kLoopback,
      kPPP,
      kTunnel,
      kVPN,
      kWifi,
    };

    Type type;
    int ifindex;
    std::string ifname;
    std::string service_path;
    IPConfig ipconfig;
  };

  // Client callback for learning when shill default logical network changes.
  using DefaultDeviceChangeHandler = base::RepeatingCallback<void(
      const Device& new_device, const Device& prev_device)>;
  // Client callback for learning which shill Devices were created or removed by
  // shill.
  using DevicesChangeHandler = base::RepeatingCallback<void(
      const std::vector<Device>& added, const std::vector<Device>& removed)>;
  // Client callback for listening to IPConfig changes on any shill Device with
  // interface name |ifname|. Changes to the IP configuration of a VPN
  // connection are not taken into account.
  using IPConfigsChangeHandler =
      base::RepeatingCallback<void(const Device& device)>;

  // Client callback for listening to IPv6 network changes on any shill physical
  // Device. The changes are identified by IPv6 prefix change. Note that any
  // IPv6 prefix change also triggers all IPConfigsChangeHandler registered
  // callbacks. Changes to the IPv6 network of a VPN connection are not taken
  // into account.
  using IPv6NetworkChangeHandler =
      base::RepeatingCallback<void(const Device& device)>;

  explicit ShillClient(const scoped_refptr<dbus::Bus>& bus, System* system);
  ShillClient(const ShillClient&) = delete;
  ShillClient& operator=(const ShillClient&) = delete;

  virtual ~ShillClient() = default;

  // Registers the provided handler for changes in shill default logical or
  // physical network.
  // The handler will be called once immediately at registration
  // with the current default logical or physical network as |new_device| and
  // an empty Device as |prev_device|.
  void RegisterDefaultLogicalDeviceChangedHandler(
      const DefaultDeviceChangeHandler& handler);
  void RegisterDefaultPhysicalDeviceChangedHandler(
      const DefaultDeviceChangeHandler& handler);

  void RegisterDevicesChangedHandler(const DevicesChangeHandler& handler);

  void RegisterIPConfigsChangedHandler(const IPConfigsChangeHandler& handler);

  void RegisterIPv6NetworkChangedHandler(
      const IPv6NetworkChangeHandler& handler);

  void ScanDevices();

  // Finds the shill physical or VPN Device whose "Interface" property matches
  // |shill_device_ifname|. This function is meant for associating a shill
  // Device to an interface name argument passed directly to patchpanel DBus
  // RPCs for DownstreamNetwork and ConnectNamespace.
  // TODO(b/273744897): Migrate callers to use the future Network primitive
  // directly.
  virtual const Device* GetDevice(const std::string& shill_device_ifname) const;
  // Returns the cached default logical shill Device; does not initiate a
  // property fetch.
  virtual const Device& default_logical_device() const;
  // Returns the cached default physical shill Device; does not initiate a
  // property fetch.
  virtual const Device& default_physical_device() const;
  // Returns interface names of all known shill physical Devices.
  const std::vector<Device> GetDevices() const;

 protected:
  void OnManagerPropertyChangeRegistration(const std::string& interface,
                                           const std::string& signal_name,
                                           bool success);
  void OnManagerPropertyChange(const std::string& property_name,
                               const brillo::Any& property_value);

  void OnDevicePropertyChangeRegistration(
      const std::string& dbus_interface_name,
      const std::string& signal_name,
      bool success);
  void OnDevicePropertyChange(const dbus::ObjectPath& device_path,
                              const std::string& property_name,
                              const brillo::Any& property_value);

  // Fetches Device dbus properties via dbus for the shill Device identified
  // by |device_path|. Returns false if an error occurs. Notes that this method
  // will block the current thread.
  virtual bool GetDeviceProperties(const dbus::ObjectPath& device_path,
                                   Device* output);

  // Returns the current default logical and physical shill Device for the
  // system, or an empty pair of shill Device result when the system has no
  // default network.
  virtual std::pair<Device, Device> GetDefaultDevices();

 private:
  // Updates the list of currently known shill Devices, adding or removing
  // Device tracking entries accordingly. Listeners that have registered a
  // DevicesChangeHandler callback gets notified about any new or old Device
  // change.
  void UpdateDevices(const brillo::Any& property_value);

  // Sets the internal variable tracking the system default logical network and
  // default physical network. Calls the registered client handlers if the
  // default logical network or the default physical network changed. The
  // arguments is a pair of default logical network and default physical
  // network. If a VPN is connected, the logical Device pertains to the
  // VPN connection.
  void SetDefaultDevices(const std::pair<Device, Device>& devices);

  // Parses the |ipconfig_properties| as the IPConfigs property of the shill
  // Device identified by |device_path|, which should be a list of object paths
  // of IPConfigs.
  IPConfig ParseIPConfigsProperty(const dbus::ObjectPath& device_path,
                                  const brillo::Any& ipconfig_paths);

  // Tracks the system default physical network chosen by shill.
  Device default_physical_device_;
  // Tracks the system default logical network chosen by shill. This corresponds
  // to the physical or VPN shill Device associated with the default logical
  // network service.
  Device default_logical_device_;
  // Maps of all current shill physical Devices, indexed by shill Device
  // identifier. VPN Devices are ignored.
  std::map<dbus::ObjectPath, Device> devices_;
  // Sets of shill Device Dbus object path for all the shill physical Devices
  // seen so far. Unlike |devices_|, entries in this set will never be
  // removed during the lifetime of this class. We maintain this set mainly for
  // keeping track of the shill Device object proxies we have created, to avoid
  // registering the handler on the same object twice.
  std::set<dbus::ObjectPath> known_device_paths_;
  // A map used for remembering the interface index of an interface. This
  // information is necessary when cleaning up the state of various subsystems
  // in patchpanel that directly references the interface index. However after
  // receiving the interface removal event (RTM_DELLINK event or shill DBus
  // event), the interface index cannot be retrieved anymore. A new entry is
  // only added when a new upstream network interface appears, and entries are
  // not removed.
  std::map<std::string, int> if_nametoindex_;

  // Called when the shill Device used as the default logical network changes.
  std::vector<DefaultDeviceChangeHandler> default_logical_device_handlers_;
  // Called when the shill Device used as the default physical network changes.
  std::vector<DefaultDeviceChangeHandler> default_physical_device_handlers_;
  // Called when the list of network interfaces managed by shill changes.
  std::vector<DevicesChangeHandler> device_handlers_;
  // Called when the IPConfigs of any shill Device changes.
  std::vector<IPConfigsChangeHandler> ipconfigs_handlers_;
  // Called when the IPv6 network of any shill Device changes.
  std::vector<IPv6NetworkChangeHandler> ipv6_network_handlers_;

  scoped_refptr<dbus::Bus> bus_;
  std::unique_ptr<org::chromium::flimflam::ManagerProxy> manager_proxy_;
  // Owned by Manager
  System* system_;

  base::WeakPtrFactory<ShillClient> weak_factory_{this};
};

std::ostream& operator<<(std::ostream& stream, const ShillClient::Device& dev);
std::ostream& operator<<(std::ostream& stream,
                         const ShillClient::Device::Type type);
std::ostream& operator<<(std::ostream& stream,
                         const ShillClient::IPConfig& ipconfig);

}  // namespace patchpanel

#endif  // PATCHPANEL_SHILL_CLIENT_H_
