// Copyright 2016 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "patchpanel/shill_client.h"

#include <algorithm>

#include <base/check.h>
#include <base/containers/contains.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/strings/string_util.h>
#include <brillo/variant_dictionary.h>
#include <chromeos/dbus/service_constants.h>
#include <dbus/object_path.h>
#include <net-base/ipv6_address.h>

#include "patchpanel/net_util.h"

namespace patchpanel {

namespace {

ShillClient::Device::Type ParseDeviceType(const std::string& type_str) {
  static const std::map<std::string, ShillClient::Device::Type> str2enum{
      {shill::kTypeCellular, ShillClient::Device::Type::kCellular},
      {shill::kTypeEthernet, ShillClient::Device::Type::kEthernet},
      {shill::kTypeEthernetEap, ShillClient::Device::Type::kEthernetEap},
      {shill::kTypeGuestInterface, ShillClient::Device::Type::kGuestInterface},
      {shill::kTypeLoopback, ShillClient::Device::Type::kLoopback},
      {shill::kTypePPP, ShillClient::Device::Type::kPPP},
      {shill::kTypeTunnel, ShillClient::Device::Type::kTunnel},
      {shill::kTypeWifi, ShillClient::Device::Type::kWifi},
      {shill::kTypeVPN, ShillClient::Device::Type::kVPN},
  };

  const auto it = str2enum.find(type_str);
  return it != str2enum.end() ? it->second
                              : ShillClient::Device::Type::kUnknown;
}

const std::string DeviceTypeName(ShillClient::Device::Type type) {
  static const std::map<ShillClient::Device::Type, std::string> enum2str{
      {ShillClient::Device::Type::kUnknown, "Unknown"},
      {ShillClient::Device::Type::kCellular, "Cellular"},
      {ShillClient::Device::Type::kEthernet, "Ethernet"},
      {ShillClient::Device::Type::kEthernetEap, "EthernetEap"},
      {ShillClient::Device::Type::kGuestInterface, "GuestInterface"},
      {ShillClient::Device::Type::kLoopback, "Loopback"},
      {ShillClient::Device::Type::kPPP, "PPP"},
      {ShillClient::Device::Type::kTunnel, "Tunnel"},
      {ShillClient::Device::Type::kVPN, "VPN"},
      {ShillClient::Device::Type::kWifi, "Wifi"},
  };

  const auto it = enum2str.find(type);
  return it != enum2str.end() ? it->second : "Unknown";
}

// Returns |s| if it is not empty, otherwise returns |fallback|.
// Useful for handling empty IP address literals when logging.
const std::string& OrDefault(const std::string& s,
                             const std::string& fallback) {
  return !s.empty() ? s : fallback;
}
}  // namespace

ShillClient::ShillClient(const scoped_refptr<dbus::Bus>& bus, System* system)
    : bus_(bus), system_(system) {
  manager_proxy_.reset(new org::chromium::flimflam::ManagerProxy(bus_));
  manager_proxy_->RegisterPropertyChangedSignalHandler(
      base::BindRepeating(&ShillClient::OnManagerPropertyChange,
                          weak_factory_.GetWeakPtr()),
      base::BindOnce(&ShillClient::OnManagerPropertyChangeRegistration,
                     weak_factory_.GetWeakPtr()));
  // Shill client needs to know about the current default devices in case the
  // default devices are available prior to the client.
  SetDefaultDevices(GetDefaultDevices());
}

const ShillClient::Device& ShillClient::default_logical_device() const {
  return default_logical_device_;
}

const ShillClient::Device& ShillClient::default_physical_device() const {
  return default_physical_device_;
}

const std::vector<ShillClient::Device> ShillClient::GetDevices() const {
  std::vector<Device> devices;
  devices.reserve(devices_.size());
  for (const auto& [_, device] : devices_) {
    devices.push_back(device);
  }
  return devices;
}

void ShillClient::ScanDevices() {
  brillo::VariantDictionary props;
  if (!manager_proxy_->GetProperties(&props, nullptr)) {
    LOG(ERROR) << "Unable to get Manager properties";
    return;
  }
  const auto it = props.find(shill::kDevicesProperty);
  if (it == props.end()) {
    LOG(WARNING) << "Manager properties is missing " << shill::kDevicesProperty;
    return;
  }
  UpdateDevices(it->second);
}

std::pair<ShillClient::Device, ShillClient::Device>
ShillClient::GetDefaultDevices() {
  brillo::VariantDictionary manager_properties;
  if (!manager_proxy_->GetProperties(&manager_properties, nullptr)) {
    LOG(ERROR) << "Unable to get Manager properties";
    return {};
  }
  auto services =
      brillo::GetVariantValueOrDefault<std::vector<dbus::ObjectPath>>(
          manager_properties, shill::kServicesProperty);

  Device default_logical_device = {};
  Device default_physical_device = {};
  // Iterate through Services listed as the shill Manager "Services" properties.
  // This Service DBus path list is built in shill with the Manager function
  // EnumerateAvailableServices() which uses the vector of Services with the
  // Service::Compare() function. This guarantees that connected Services are at
  // the front of the list. If a VPN Service is connected, it is always at the
  // front of the list, however this relies on the following implementation
  // details:
  //   - portal detection is not run on VPN, therefore a connected VPN should
  //     always be in the "online" state.
  //   - the shill Manager Technology order property has VPN in front
  //     (Manager.GetServiceOrder).
  for (const auto& service_path : services) {
    brillo::VariantDictionary service_properties;
    org::chromium::flimflam::ServiceProxy service_proxy(bus_, service_path);
    if (!service_proxy.GetProperties(&service_properties, nullptr)) {
      LOG(ERROR) << "Unable to get Service properties for "
                 << service_path.value();
      return {};
    }

    // Check if there is any connected Service at the moment.
    if (const auto it = service_properties.find(shill::kIsConnectedProperty);
        it == service_properties.end()) {
      LOG(ERROR) << "Service " << service_path.value() << " missing property "
                 << shill::kIsConnectedProperty;
      return {};
    } else if (!it->second.TryGet<bool>()) {
      return {};
    }

    std::string service_type = brillo::GetVariantValueOrDefault<std::string>(
        service_properties, shill::kTypeProperty);
    if (service_type.empty()) {
      LOG(ERROR) << "Service " << service_path.value() << " missing property "
                 << shill::kTypeProperty;
      return {};
    }

    auto device_path = brillo::GetVariantValueOrDefault<dbus::ObjectPath>(
        service_properties, shill::kDeviceProperty);
    if (!device_path.IsValid()) {
      LOG(WARNING) << "Service " << service_path.value() << " missing property "
                   << shill::kDeviceProperty;
      return {};
    }

    if (ParseDeviceType(service_type) == ShillClient::Device::Type::kVPN) {
      GetDeviceProperties(device_path, &default_logical_device);
    } else {
      GetDeviceProperties(device_path, &default_physical_device);
      // When there is no VPN connected, the default logical device corresponds
      // to the default physical device.
      if (default_logical_device.type == ShillClient::Device::Type::kUnknown) {
        default_logical_device = default_physical_device;
      }
      // Stops once the first default physical Device has been found.
      break;
    }
  }
  return std::make_pair(default_logical_device, default_physical_device);
}

void ShillClient::OnManagerPropertyChangeRegistration(
    const std::string& interface,
    const std::string& signal_name,
    bool success) {
  if (!success)
    LOG(FATAL) << "Unable to register for interface change events";
}

void ShillClient::OnManagerPropertyChange(const std::string& property_name,
                                          const brillo::Any& property_value) {
  if (property_name == shill::kDevicesProperty) {
    UpdateDevices(property_value);
  } else if (property_name != shill::kDefaultServiceProperty &&
             property_name != shill::kServicesProperty &&
             property_name != shill::kConnectionStateProperty) {
    return;
  }

  // All registered DefaultDeviceChangeHandler objects should be called if
  // the default network has changed or if shill::kDevicesProperty has changed.
  SetDefaultDevices(GetDefaultDevices());
}

void ShillClient::SetDefaultDevices(const std::pair<Device, Device>& devices) {
  auto default_logical_device = devices.first;
  auto default_physical_device = devices.second;
  if (default_logical_device_.ifname != default_logical_device.ifname) {
    LOG(INFO) << "Default network changed from " << default_logical_device_
              << " to " << default_logical_device;

    for (const auto& h : default_logical_device_handlers_) {
      if (!h.is_null())
        h.Run(default_logical_device, default_logical_device_);
    }
    default_logical_device_ = default_logical_device;
  }

  if (default_physical_device_.ifname != default_physical_device.ifname) {
    LOG(INFO) << "Default physical device changed from "
              << default_physical_device_ << " to " << default_physical_device;

    for (const auto& h : default_physical_device_handlers_) {
      if (!h.is_null())
        h.Run(default_physical_device, default_physical_device_);
    }
    default_physical_device_ = default_physical_device;
  }
}

void ShillClient::RegisterDefaultLogicalDeviceChangedHandler(
    const DefaultDeviceChangeHandler& handler) {
  default_logical_device_handlers_.emplace_back(handler);
  // Explicitly trigger the callback once to let it know of the the current
  // default interface. The previous interface is left empty.
  handler.Run(default_logical_device_, {});
}

void ShillClient::RegisterDefaultPhysicalDeviceChangedHandler(
    const DefaultDeviceChangeHandler& handler) {
  default_physical_device_handlers_.emplace_back(handler);
  // Explicitly trigger the callback once to let it know of the the current
  // default interface. The previous interface is left empty.
  handler.Run(default_physical_device_, {});
}

void ShillClient::RegisterDevicesChangedHandler(
    const DevicesChangeHandler& handler) {
  device_handlers_.emplace_back(handler);
}

void ShillClient::RegisterIPConfigsChangedHandler(
    const IPConfigsChangeHandler& handler) {
  ipconfigs_handlers_.emplace_back(handler);
}

void ShillClient::RegisterIPv6NetworkChangedHandler(
    const IPv6NetworkChangeHandler& handler) {
  ipv6_network_handlers_.emplace_back(handler);
}

void ShillClient::UpdateDevices(const brillo::Any& property_value) {
  std::set<dbus::ObjectPath> current, added, removed;

  // Find all new Devices.
  for (const auto& device_path :
       property_value.TryGet<std::vector<dbus::ObjectPath>>()) {
    current.insert(device_path);
    if (!base::Contains(devices_, device_path)) {
      added.insert(device_path);
    }
    // Registers handler if we see this shill Device for the first time.
    if (known_device_paths_.insert(device_path).second) {
      org::chromium::flimflam::DeviceProxy proxy(bus_, device_path);
      proxy.RegisterPropertyChangedSignalHandler(
          base::BindRepeating(&ShillClient::OnDevicePropertyChange,
                              weak_factory_.GetWeakPtr(), device_path),
          base::BindOnce(&ShillClient::OnDevicePropertyChangeRegistration,
                         weak_factory_.GetWeakPtr()));
    }
  }

  // Find all removed Devices.
  for (const auto& [device_path, _] : devices_) {
    if (!base::Contains(current, device_path)) {
      removed.insert(device_path);
    }
  }

  // This can happen if the default network switched from one device to another.
  if (added.empty() && removed.empty()) {
    return;
  }

  // Remove Devices removed by shill.
  std::vector<Device> removed_devices;
  for (const auto& device_path : removed) {
    const auto it = devices_.find(device_path);
    if (it == devices_.end()) {
      LOG(WARNING) << "Unknown removed Device " << device_path.value();
      continue;
    }
    LOG(INFO) << "Removed shill Device " << it->second;
    removed_devices.push_back(it->second);
    devices_.erase(it);
  }

  // Populate ShillClient::Device properties for any new shill Device.
  std::vector<Device> added_devices;
  for (const auto& device_path : added) {
    auto* new_device = &devices_[device_path];
    if (!GetDeviceProperties(device_path, new_device)) {
      LOG(WARNING) << "Failed to add properties of new Device "
                   << device_path.value();
      devices_.erase(device_path);
      continue;
    }
    LOG(INFO) << "New shill Device " << *new_device;
    added_devices.push_back(*new_device);
  }

  // Update DevicesChangeHandler listeners.
  for (const auto& h : device_handlers_) {
    h.Run(added_devices, removed_devices);
  }
}

ShillClient::IPConfig ShillClient::ParseIPConfigsProperty(
    const dbus::ObjectPath& device, const brillo::Any& ipconfig_paths) {
  IPConfig ipconfig;
  for (const auto& path :
       ipconfig_paths.TryGet<std::vector<dbus::ObjectPath>>()) {
    std::unique_ptr<org::chromium::flimflam::IPConfigProxy> ipconfig_proxy(
        new org::chromium::flimflam::IPConfigProxy(bus_, path));
    brillo::VariantDictionary ipconfig_props;

    if (!ipconfig_proxy->GetProperties(&ipconfig_props, nullptr)) {
      // It is possible that an IPConfig object is removed after we know its
      // path, especially when the interface is going down.
      LOG(WARNING) << "[" << device.value() << "]: "
                   << "Unable to get properties for " << path.value();
      continue;
    }

    // Gets the value of address, prefix_length, gateway, and dns_servers.
    auto it = ipconfig_props.find(shill::kAddressProperty);
    if (it == ipconfig_props.end()) {
      LOG(WARNING) << "[" << device.value()
                   << "]: IPConfig properties is missing Address";
      continue;
    }
    const std::string& address = it->second.TryGet<std::string>();
    if (address.empty()) {
      // On IPv6 only networks, dhcp is expected to fail, nevertheless shill
      // will still expose a mostly empty IPConfig object. On dual stack
      // networks, the IPv6 configuration may be available before dhcp has
      // finished. Avoid logging spurious WARNING messages in these two cases.
      continue;
    }
    auto ip_family = GetIpFamily(address);
    if (ip_family != AF_INET && ip_family != AF_INET6) {
      LOG(WARNING) << "[" << device.value()
                   << "]: IPConfig Address property was invalid: " << address;
      continue;
    }
    const bool is_ipv4 = ip_family == AF_INET;
    const std::string method = is_ipv4 ? "IPv4" : "IPv6";
    if ((is_ipv4 && !ipconfig.ipv4_address.empty()) ||
        (!is_ipv4 && !ipconfig.ipv6_address.empty())) {
      LOG(WARNING) << "[" << device.value() << "]: "
                   << "Duplicated IPconfig for " << method;
      continue;
    }

    it = ipconfig_props.find(shill::kPrefixlenProperty);
    if (it == ipconfig_props.end()) {
      LOG(WARNING) << "[" << device.value() << "]: " << method
                   << " IPConfig properties is missing Prefixlen";
      continue;
    }
    int prefix_length = it->second.TryGet<int>();
    if (prefix_length < 0 || (is_ipv4 && prefix_length > 32) ||
        prefix_length > 128) {
      LOG(WARNING) << "[" << device.value() << "]: " << method
                   << " IPConfig Prefixlen property was invalid: "
                   << prefix_length;
      continue;
    }
    if (prefix_length == 0) {
      LOG(WARNING)
          << "[" << device.value() << "]: " << method
          << " IPConfig Prefixlen property is 0, may be an invalid setup";
    }

    it = ipconfig_props.find(shill::kGatewayProperty);
    if (it == ipconfig_props.end()) {
      LOG(WARNING) << "[" << device.value() << "]: " << method
                   << " IPConfig properties is missing Gateway";
      continue;
    }
    const std::string& gateway = it->second.TryGet<std::string>();
    if (gateway.empty()) {
      LOG(WARNING) << "[" << device.value() << "]: " << method
                   << " IPConfig Gateway property was empty.";
      continue;
    }

    it = ipconfig_props.find(shill::kNameServersProperty);
    if (it == ipconfig_props.end()) {
      LOG(WARNING) << "[" << device.value() << "]: " << method
                   << " IPConfig properties is missing NameServers";
      // Shill will emit this property with empty value if it has no dns for
      // this device, so missing this property indicates an error.
      continue;
    }
    const std::vector<std::string>& dns_addresses =
        it->second.TryGet<std::vector<std::string>>();

    // Fills the IPConfig struct according to the type.
    if (is_ipv4) {
      ipconfig.ipv4_prefix_length = prefix_length;
      ipconfig.ipv4_address = address;
      ipconfig.ipv4_gateway = gateway;
      ipconfig.ipv4_dns_addresses = dns_addresses;
    } else {  // AF_INET6
      ipconfig.ipv6_prefix_length = prefix_length;
      ipconfig.ipv6_address = address;
      ipconfig.ipv6_gateway = gateway;
      ipconfig.ipv6_dns_addresses = dns_addresses;
    }
  }

  return ipconfig;
}

bool ShillClient::GetDeviceProperties(const dbus::ObjectPath& device_path,
                                      Device* output) {
  DCHECK(output);

  org::chromium::flimflam::DeviceProxy proxy(bus_, device_path);
  brillo::VariantDictionary props;
  if (!proxy.GetProperties(&props, nullptr)) {
    LOG(WARNING) << "Unable to get shill Device properties for "
                 << device_path.value();
    return false;
  }

  const auto& type_it = props.find(shill::kTypeProperty);
  if (type_it == props.end()) {
    LOG(WARNING) << "shill Device properties is missing Type for "
                 << device_path.value();
    return false;
  }
  const std::string& type_str = type_it->second.TryGet<std::string>();
  output->type = ParseDeviceType(type_str);
  if (output->type == Device::Type::kUnknown)
    LOG(WARNING) << "Unknown shill Device type " << type_str << " for "
                 << device_path.value();

  const auto& interface_it = props.find(shill::kInterfaceProperty);
  if (interface_it == props.end()) {
    LOG(WARNING) << "shill Device properties is missing Interface for "
                 << device_path.value();
    return false;
  }
  output->ifname = interface_it->second.TryGet<std::string>();

  output->ifindex = system_->IfNametoindex(output->ifname);
  if (output->ifindex > 0) {
    if_nametoindex_[output->ifname] = output->ifindex;
  } else {
    const auto it = if_nametoindex_.find(output->ifname);
    if (it == if_nametoindex_.end()) {
      LOG(WARNING) << "Could not obtain the interface index of "
                   << output->ifname;
      return false;
    }
    output->ifindex = it->second;
  }

  const auto& ipconfigs_it = props.find(shill::kIPConfigsProperty);
  if (ipconfigs_it == props.end()) {
    LOG(WARNING) << "shill Device properties is missing IPConfigs for "
                 << device_path.value();
    return false;
  }
  output->ipconfig = ParseIPConfigsProperty(device_path, ipconfigs_it->second);

  // Optional property: a Device does not necessarily have a selected Service at
  // all time.
  const auto& selected_service_it = props.find(shill::kSelectedServiceProperty);
  if (selected_service_it != props.end()) {
    output->service_path =
        selected_service_it->second.TryGet<dbus::ObjectPath>().value();
  }

  return true;
}

const ShillClient::Device* ShillClient::GetDevice(
    const std::string& shill_device_ifname) const {
  // To find the VPN Device, the default logical Device must be checked
  // separately.
  if (default_logical_device_.ifname == shill_device_ifname) {
    return &default_logical_device_;
  }
  for (const auto& [_, device] : devices_) {
    if (device.ifname == shill_device_ifname) {
      return &device;
    }
  }
  return nullptr;
}

void ShillClient::OnDevicePropertyChangeRegistration(
    const std::string& dbus_interface_name,
    const std::string& signal_name,
    bool success) {
  if (!success)
    LOG(ERROR) << "Unable to register Device property listener for "
               << signal_name;
}

void ShillClient::OnDevicePropertyChange(const dbus::ObjectPath& device_path,
                                         const std::string& property_name,
                                         const brillo::Any& property_value) {
  // TODO(b/273741099) If kPrimaryMultiplexedInterfaceProperty changed, update
  // the Cellular Device and advertise it as a new Device.

  if (property_name != shill::kIPConfigsProperty)
    return;

  const auto& device_it = devices_.find(device_path);
  if (device_it == devices_.end()) {
    LOG(WARNING) << "Cannot update " << property_name
                 << " property for unknown Device " << device_path.value();
    return;
  }

  IPConfig old_ip_config = device_it->second.ipconfig;

  // Refresh all properties at once.
  if (!GetDeviceProperties(device_path, &device_it->second)) {
    LOG(ERROR) << "Failed to update properties of Device "
               << device_path.value();
    return;
  }

  // Do not run the IPConfigsChangeHandler and IPv6NetworkChangeHandler
  // callbacks if there is no IPConfig change.
  const IPConfig& new_ip_config = device_it->second.ipconfig;
  if (old_ip_config == new_ip_config) {
    return;
  }

  // Ensure that the cached states of the default physical Device and default
  // logical Device are refreshed as well.
  // TODO(b/273741099): Handle the VPN Device. Since the VPN Device is not
  // exposed in kDevicesProperty, ShillClient never registers a signal handler
  // for Device property changes on the VPN Device.
  if (default_physical_device_.ifname == device_it->second.ifname) {
    default_physical_device_ = device_it->second;
  }
  if (default_logical_device_.ifname == device_it->second.ifname) {
    default_logical_device_ = device_it->second;
  }

  LOG(INFO) << "[" << device_path.value()
            << "]: IPConfig changed: " << new_ip_config;
  for (const auto& handler : ipconfigs_handlers_) {
    handler.Run(device_it->second);
  }

  // Compares if the new IPv6 network is the same as the old one by checking
  // its prefix.
  const auto old_cidr = net_base::IPv6CIDR::CreateFromStringAndPrefix(
      old_ip_config.ipv6_address, old_ip_config.ipv6_prefix_length);
  const auto new_cidr = net_base::IPv6CIDR::CreateFromStringAndPrefix(
      new_ip_config.ipv6_address, new_ip_config.ipv6_prefix_length);
  if (!old_cidr && !new_cidr) {
    return;
  }
  if (old_cidr && new_cidr &&
      old_cidr->prefix_length() == new_cidr->prefix_length() &&
      old_cidr->GetPrefixAddress() == new_cidr->GetPrefixAddress()) {
    return;
  }
  for (const auto& handler : ipv6_network_handlers_) {
    handler.Run(device_it->second);
  }
}

std::ostream& operator<<(std::ostream& stream, const ShillClient::Device& dev) {
  return stream << "{ifname: " << dev.ifname << ", ifindex: " << dev.ifindex
                << ", type: " << DeviceTypeName(dev.type)
                << ", service: " << dev.service_path << "}";
}

std::ostream& operator<<(std::ostream& stream,
                         const ShillClient::Device::Type type) {
  return stream << DeviceTypeName(type);
}

std::ostream& operator<<(std::ostream& stream,
                         const ShillClient::IPConfig& ipconfig) {
  return stream << "{ ipv4_addr: "
                << OrDefault(ipconfig.ipv4_address, "0.0.0.0") << "/"
                << ipconfig.ipv4_prefix_length << ", ipv4_gateway: "
                << OrDefault(ipconfig.ipv4_gateway, "0.0.0.0")
                << ", ipv4_dns: ["
                << base::JoinString(ipconfig.ipv4_dns_addresses, ",")
                << "], ipv6_addr: " << OrDefault(ipconfig.ipv6_address, "::")
                << "/" << ipconfig.ipv6_prefix_length
                << ", ipv6_gateway: " << OrDefault(ipconfig.ipv6_gateway, "::")
                << ", ipv6_dns: ["
                << base::JoinString(ipconfig.ipv6_dns_addresses, ",") << "]}";
}
}  // namespace patchpanel
