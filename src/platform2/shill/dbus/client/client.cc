// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/dbus/client/client.h"

#include <set>

#include <base/functional/bind.h>
#include <base/logging.h>
#include <brillo/variant_dictionary.h>
#include <shill/net/ip_address.h>

using org::chromium::flimflam::DeviceProxy;
using org::chromium::flimflam::DeviceProxyInterface;
using org::chromium::flimflam::IPConfigProxy;
using org::chromium::flimflam::IPConfigProxyInterface;
using org::chromium::flimflam::ManagerProxy;
using org::chromium::flimflam::ManagerProxyInterface;
using org::chromium::flimflam::ServiceProxy;
using org::chromium::flimflam::ServiceProxyInterface;

namespace shill {
namespace {

Client::Device::Type ParseDeviceType(const std::string& type_str) {
  static const std::map<std::string, Client::Device::Type> str2enum{
      {shill::kTypeCellular, Client::Device::Type::kCellular},
      {shill::kTypeEthernet, Client::Device::Type::kEthernet},
      {shill::kTypeEthernetEap, Client::Device::Type::kEthernetEap},
      {shill::kTypeGuestInterface, Client::Device::Type::kGuestInterface},
      {shill::kTypeLoopback, Client::Device::Type::kLoopback},
      {shill::kTypePPP, Client::Device::Type::kPPP},
      {shill::kTypeTunnel, Client::Device::Type::kTunnel},
      {shill::kTypeWifi, Client::Device::Type::kWifi},
      {shill::kTypeVPN, Client::Device::Type::kVPN},
  };

  const auto it = str2enum.find(type_str);
  return it != str2enum.end() ? it->second : Client::Device::Type::kUnknown;
}

Client::Device::ConnectionState ParseConnectionState(const std::string& s) {
  static const std::map<std::string, Client::Device::ConnectionState> m{
      {shill::kStateIdle, Client::Device::ConnectionState::kIdle},
      {shill::kStateAssociation, Client::Device::ConnectionState::kAssociation},
      {shill::kStateConfiguration,
       Client::Device::ConnectionState::kConfiguration},
      {shill::kStateReady, Client::Device::ConnectionState::kReady},
      {shill::kStateNoConnectivity,
       Client::Device::ConnectionState::kNoConnectivity},
      {shill::kStateRedirectFound,
       Client::Device::ConnectionState::kRedirectFound},
      {shill::kStatePortalSuspected,
       Client::Device::ConnectionState::kPortalSuspected},
      {shill::kStateOnline, Client::Device::ConnectionState::kOnline},
      {shill::kStateOffline, Client::Device::ConnectionState::kOffline},
      {shill::kStateFailure, Client::Device::ConnectionState::kFailure},
      {shill::kStateDisconnect, Client::Device::ConnectionState::kDisconnect},
  };
  const auto it = m.find(s);
  return it != m.end() ? it->second : Client::Device::ConnectionState::kUnknown;
}

const char* ToString(Client::Device::ConnectionState state) {
  static const std::map<Client::Device::ConnectionState, const char*> m{
      {Client::Device::ConnectionState::kIdle, shill::kStateIdle},
      {Client::Device::ConnectionState::kAssociation, shill::kStateAssociation},
      {Client::Device::ConnectionState::kConfiguration,
       shill::kStateConfiguration},
      {Client::Device::ConnectionState::kReady, shill::kStateReady},
      {Client::Device::ConnectionState::kNoConnectivity,
       shill::kStateNoConnectivity},
      {Client::Device::ConnectionState::kRedirectFound,
       shill::kStateRedirectFound},
      {Client::Device::ConnectionState::kPortalSuspected,
       shill::kStatePortalSuspected},
      {Client::Device::ConnectionState::kOnline, shill::kStateOnline},
      {Client::Device::ConnectionState::kOffline, shill::kStateOffline},
      {Client::Device::ConnectionState::kFailure, shill::kStateFailure},
      {Client::Device::ConnectionState::kDisconnect, shill::kStateDisconnect},
  };
  const auto it = m.find(state);
  return it != m.end() ? it->second : "unknown";
}

bool IsConnectedState(Client::Device::ConnectionState state) {
  switch (state) {
    case Client::Device::ConnectionState::kUnknown:
    case Client::Device::ConnectionState::kIdle:
    case Client::Device::ConnectionState::kAssociation:
    case Client::Device::ConnectionState::kConfiguration:
    case Client::Device::ConnectionState::kOffline:
    case Client::Device::ConnectionState::kFailure:
    case Client::Device::ConnectionState::kDisconnect:
      return false;
    case Client::Device::ConnectionState::kReady:
    case Client::Device::ConnectionState::kNoConnectivity:
    case Client::Device::ConnectionState::kRedirectFound:
    case Client::Device::ConnectionState::kPortalSuspected:
    case Client::Device::ConnectionState::kOnline:
      return true;
  }
}

std::string GetCellularProviderCountryCode(
    const brillo::VariantDictionary& device_properties) {
  auto operator_info =
      brillo::GetVariantValueOrDefault<std::map<std::string, std::string>>(
          device_properties, kHomeProviderProperty);
  return operator_info[shill::kOperatorCountryKey];
}

}  // namespace

Client::Client(scoped_refptr<dbus::Bus> bus) : bus_(bus) {
  bus_->GetObjectProxy(kFlimflamServiceName, dbus::ObjectPath{"/"})
      ->SetNameOwnerChangedCallback(base::BindRepeating(
          &Client::OnOwnerChange, weak_factory_.GetWeakPtr()));
  manager_proxy_ = std::make_unique<ManagerProxy>(bus_);
  manager_proxy_->RegisterPropertyChangedSignalHandler(
      base::BindRepeating(&Client::OnManagerPropertyChange,
                          weak_factory_.GetWeakPtr()),
      base::BindOnce(&Client::OnManagerPropertyChangeRegistration,
                     weak_factory_.GetWeakPtr()));
}

void Client::NewDefaultServiceProxy(const dbus::ObjectPath& service_path) {
  default_service_proxy_ = std::make_unique<ServiceProxy>(bus_, service_path);
}

void Client::SetupDefaultServiceProxy(const dbus::ObjectPath& service_path) {
  NewDefaultServiceProxy(service_path);
  default_service_proxy_->RegisterPropertyChangedSignalHandler(
      base::BindRepeating(&Client::OnDefaultServicePropertyChange,
                          weak_factory_.GetWeakPtr()),
      base::BindOnce(&Client::OnDefaultServicePropertyChangeRegistration,
                     weak_factory_.GetWeakPtr()));
}

void Client::ReleaseDefaultServiceProxy() {
  default_device_path_.clear();

  if (default_service_proxy_) {
    bus_->RemoveObjectProxy(kFlimflamServiceName,
                            default_service_proxy_->GetObjectPath(),
                            base::DoNothing());
    default_service_proxy_.reset();
  }
}

std::unique_ptr<DeviceProxyInterface> Client::NewDeviceProxy(
    const dbus::ObjectPath& device_path) {
  return std::make_unique<DeviceProxy>(bus_, device_path);
}

void Client::SetupDeviceProxy(const dbus::ObjectPath& device_path) {
  auto proxy = NewDeviceProxy(device_path);
  auto* ptr = proxy.get();
  devices_.emplace(device_path.value(),
                   std::make_unique<DeviceWrapper>(bus_, std::move(proxy)));
  ptr->RegisterPropertyChangedSignalHandler(
      base::BindRepeating(&Client::OnDevicePropertyChange,
                          weak_factory_.GetWeakPtr(), false /*device_added*/,
                          device_path.value()),
      base::BindOnce(&Client::OnDevicePropertyChangeRegistration,
                     weak_factory_.GetWeakPtr(), device_path.value()));
}

std::unique_ptr<ServiceProxyInterface> Client::NewServiceProxy(
    const dbus::ObjectPath& service_path) {
  return std::make_unique<ServiceProxy>(bus_, service_path);
}

void Client::SetupSelectedServiceProxy(const dbus::ObjectPath& service_path,
                                       const dbus::ObjectPath& device_path) {
  const auto it = devices_.find(device_path.value());
  if (it == devices_.end()) {
    LOG(DFATAL) << "Cannot find device [" << device_path.value() << "]";
    return;
  }

  auto proxy = NewServiceProxy(service_path);
  auto* ptr = proxy.get();
  it->second->set_service_proxy(std::move(proxy));
  ptr->RegisterPropertyChangedSignalHandler(
      base::BindRepeating(&Client::OnServicePropertyChange,
                          weak_factory_.GetWeakPtr(), device_path.value()),
      base::BindOnce(&Client::OnServicePropertyChangeRegistration,
                     weak_factory_.GetWeakPtr(), device_path.value()));
}

void Client::RegisterOnAvailableCallback(
    base::OnceCallback<void(bool)> handler) {
  bus_->GetObjectProxy(kFlimflamServiceName,
                       dbus::ObjectPath(kFlimflamServicePath))
      ->WaitForServiceToBeAvailable(std::move(handler));
}

void Client::RegisterProcessChangedHandler(
    const base::RepeatingCallback<void(bool)>& handler) {
  process_handler_ = handler;
}

void Client::RegisterDefaultServiceChangedHandler(
    const DefaultServiceChangedHandler& handler) {
  default_service_handlers_.emplace_back(handler);
}

void Client::RegisterDefaultDeviceChangedHandler(
    const DeviceChangedHandler& handler) {
  // Provide the current default device to the new handler.
  Device* device = nullptr;
  const auto it = devices_.find(default_device_path_);
  if (it != devices_.end())
    device = it->second->device();

  handler.Run(device);

  default_device_handlers_.emplace_back(handler);
}

void Client::RegisterDeviceChangedHandler(const DeviceChangedHandler& handler) {
  device_handlers_.emplace_back(handler);
}

void Client::RegisterDeviceAddedHandler(const DeviceChangedHandler& handler) {
  // Provide the current list of devices.
  for (const auto& kv : devices_) {
    handler.Run(kv.second->device());
  }

  device_added_handlers_.emplace_back(handler);
}

void Client::RegisterDeviceRemovedHandler(const DeviceChangedHandler& handler) {
  device_removed_handlers_.emplace_back(handler);
}

void Client::OnOwnerChange(const std::string& old_owner,
                           const std::string& new_owner) {
  ReleaseDefaultServiceProxy();
  for (const auto& device : devices_) {
    device.second->release_object_proxy();
  }
  devices_.clear();

  bool reset = !new_owner.empty();
  if (reset)
    VLOG(2) << "Shill reset";
  else
    VLOG(2) << "Shill lost";

  if (!process_handler_.is_null())
    process_handler_.Run(reset);
}

void Client::OnManagerPropertyChangeRegistration(const std::string& interface,
                                                 const std::string& signal_name,
                                                 bool success) {
  if (!success) {
    LOG(ERROR) << "Unable to register for Manager change events "
               << " for " << signal_name << " on " << interface;
    return;
  }
  brillo::VariantDictionary properties;
  if (!manager_proxy_ || !manager_proxy_->GetProperties(&properties, nullptr)) {
    LOG(WARNING) << "Unable to get shill Manager properties, likely because "
                    "shill is unavailable";
    return;
  }

  for (const auto& prop : {kDevicesProperty, kDefaultServiceProperty}) {
    auto it = properties.find(prop);
    if (it != properties.end()) {
      OnManagerPropertyChange(prop, it->second);
    } else {
      LOG(ERROR) << "Cannot find Manager property [" << prop << "]";
    }
  }
}

void Client::OnManagerPropertyChange(const std::string& property_name,
                                     const brillo::Any& property_value) {
  if (property_name == kDefaultServiceProperty) {
    HandleDefaultServiceChanged(property_value);
    return;
  }

  if (property_name == kDevicesProperty) {
    HandleDevicesChanged(property_value);
    return;
  }
}

void Client::HandleDefaultServiceChanged(const brillo::Any& property_value) {
  dbus::ObjectPath cur_path,
      service_path = property_value.TryGet<dbus::ObjectPath>();
  if (default_service_proxy_)
    cur_path = default_service_proxy_->GetObjectPath();

  if (service_path != cur_path) {
    LOG(INFO) << "Default service changed from [" << cur_path.value()
              << "] to [" << service_path.value() << "]";
  }
  ReleaseDefaultServiceProxy();

  // If the service is disconnected, run the handlers here since the normal flow
  // of doing so on property callback registration won't run.
  if (!service_path.IsValid() || service_path.value() == "/") {
    for (auto& handler : default_service_handlers_) {
      handler.Run("");
    }
    VLOG(2) << "Default service device is removed";
    for (auto& handler : default_device_handlers_) {
      handler.Run(nullptr);
    }
    return;
  }

  SetupDefaultServiceProxy(service_path);
}

void Client::AddDevice(const dbus::ObjectPath& device_path) {
  const std::string& path = device_path.value();
  if (devices_.find(path) != devices_.end())
    return;

  VLOG(2) << "Device [" << path << "] added";
  SetupDeviceProxy(device_path);
}

void Client::HandleDevicesChanged(const brillo::Any& property_value) {
  std::set<std::string> latest;
  for (const auto& path :
       property_value.TryGet<std::vector<dbus::ObjectPath>>()) {
    latest.emplace(path.value());
    AddDevice(path);
  }

  for (auto it = devices_.begin(); it != devices_.end();) {
    if (latest.find(it->first) == latest.end()) {
      VLOG(2) << "Device [" << it->first << "] removed";
      for (auto& handler : device_removed_handlers_) {
        handler.Run(it->second->device());
      }
      it->second->release_object_proxy();
      it = devices_.erase(it);
    } else {
      ++it;
    }
  }
}

void Client::OnDefaultServicePropertyChangeRegistration(
    const std::string& interface,
    const std::string& signal_name,
    bool success) {
  if (!success) {
    std::string path;
    if (default_service_proxy_)
      path = default_service_proxy_->GetObjectPath().value();

    LOG(ERROR) << "Unable to register for Service [" << path
               << "] change events "
               << " for " << signal_name << " on " << interface;
    return;
  }

  if (!default_service_proxy_) {
    LOG(ERROR) << "No default service";
    return;
  }
  const std::string service_path =
      default_service_proxy_->GetObjectPath().value();
  brillo::VariantDictionary properties;
  if (!default_service_proxy_->GetProperties(&properties, nullptr)) {
    LOG(ERROR) << "Unable to get properties for the default service ["
               << service_path << "]";
    return;
  }

  // Notify that the default service has changed.
  const auto type =
      brillo::GetVariantValueOrDefault<std::string>(properties, kTypeProperty);
  for (auto& handler : default_service_handlers_) {
    handler.Run(type);
  }

  OnDefaultServicePropertyChange(
      kIsConnectedProperty,
      brillo::GetVariantValueOrDefault<bool>(properties, kIsConnectedProperty));
  OnDefaultServicePropertyChange(
      kDeviceProperty, brillo::GetVariantValueOrDefault<dbus::ObjectPath>(
                           properties, kDeviceProperty));
}

void Client::OnDefaultServicePropertyChange(const std::string& property_name,
                                            const brillo::Any& property_value) {
  if (property_name != kDeviceProperty) {
    return;
  }

  std::string path = property_value.TryGet<dbus::ObjectPath>().value();
  if (path == default_device_path_) {
    return;
  }

  VLOG(2) << "Default service device changed to [" << path << "]";
  default_device_path_ = path;

  // When there is no service, run the handlers with a nullptr to indicate this
  // condition.
  if (default_device_path_ == "" || default_device_path_ == "/") {
    for (auto& handler : default_device_handlers_) {
      handler.Run(nullptr);
    }
    return;
  }

  // We generally expect to already be aware of the default device unless it
  // happens to be a VPN. In the case of the latter, add and track it (this will
  // ultimately fire the same handler after reading all the properties.
  const auto& it = devices_.find(default_device_path_);
  if (it != devices_.end()) {
    for (auto& handler : default_device_handlers_) {
      handler.Run(it->second->device());
    }
  } else {
    AddDevice(dbus::ObjectPath(default_device_path_));
  }
}

void Client::OnDevicePropertyChangeRegistration(const std::string& device_path,
                                                const std::string& interface,
                                                const std::string& signal_name,
                                                bool success) {
  if (!success) {
    LOG(ERROR) << "Unable to register for Device [" << device_path
               << "] change events "
               << " for " << signal_name << " on " << interface;
    return;
  }

  auto it = devices_.find(device_path);
  if (it == devices_.end()) {
    LOG(ERROR) << "Device [" << device_path << "] not found";
    return;
  }

  brillo::VariantDictionary properties;
  if (!it->second->proxy()->GetProperties(&properties, nullptr)) {
    LOG(ERROR) << "Unable to get properties for device [" << device_path << "]";
    return;
  }

  auto* device = it->second->device();
  device->type = ParseDeviceType(
      brillo::GetVariantValueOrDefault<std::string>(properties, kTypeProperty));
  if (device->type == Device::Type::kUnknown)
    LOG(ERROR) << "Device [" << device_path << "] type is unknown";

  device->ifname = brillo::GetVariantValueOrDefault<std::string>(
      properties, kInterfaceProperty);
  if (device->ifname.empty()) {
    LOG(ERROR) << "Device [" << device_path << "] has no interface";
    return;
  }

  if (device->type == Client::Device::Type::kCellular) {
    device->cellular_country_code = GetCellularProviderCountryCode(properties);
  }
  // Obtain and monitor properties on this device's selected service and treat
  // them as if they are instrinsically characteristic of the device itself.
  const auto service_path = brillo::GetVariantValueOrDefault<dbus::ObjectPath>(
      properties, kSelectedServiceProperty);
  HandleSelectedServiceChanged(device_path, service_path);

  // Set |device_added| to true here so it invokes the corresponding handler, if
  // applicable - this will occur only once (per device).
  OnDevicePropertyChange(
      true /*device_added*/, device_path, kIPConfigsProperty,
      brillo::GetVariantValueOrDefault<std::vector<dbus::ObjectPath>>(
          properties, kIPConfigsProperty));
}

void Client::OnDevicePropertyChange(bool device_added,
                                    const std::string& device_path,
                                    const std::string& property_name,
                                    const brillo::Any& property_value) {
  Device* device = nullptr;
  if (property_name == kIPConfigsProperty) {
    auto it = devices_.find(device_path);
    if (it == devices_.end()) {
      LOG(ERROR) << "Device [" << device_path << "] not found";
      return;
    }
    device = it->second->device();
    auto paths = property_value.TryGet<std::vector<dbus::ObjectPath>>();
    if (paths.empty() && IsConnectedState(device->state)) {
      LOG(WARNING) << "Device [" << device_path << "] has no IPConfigs";
    } else {
      device->ipconfig = ParseIPConfigsProperty(device_path, paths);
    }
  } else if (property_name == kSelectedServiceProperty) {
    device = HandleSelectedServiceChanged(device_path, property_value);
    if (!device)
      return;
  } else if (property_name == kHomeProviderProperty) {
    auto it = devices_.find(device_path);
    if (it == devices_.end()) {
      LOG(ERROR) << "Device [" << device_path << "] not found";
      return;
    }
    device = it->second->device();
    device->cellular_country_code = property_value.TryGet<
        std::map<std::string, std::string>>()[shill::kOperatorCountryKey];
  } else {
    return;
  }

  // |device_added| will only be true if this method is called from the
  // registration callback, which in turn will only ever be called once per
  // device when it is first discovered. Deferring this callback until now
  // allows us to provide a Device struct populated with all the properties
  // available at the time.
  if (device_added) {
    for (auto& handler : device_added_handlers_)
      handler.Run(device);
  }

  // If this is the default device then notify the handlers.
  if (device_path == default_device_path_) {
    for (auto& handler : default_device_handlers_)
      handler.Run(device);
  }

  // Notify the handlers interested in all device changes.
  for (auto& handler : device_handlers_) {
    handler.Run(device);
  }
}

Client::Device* Client::HandleSelectedServiceChanged(
    const std::string& device_path, const brillo::Any& property_value) {
  auto it = devices_.find(device_path);
  if (it == devices_.end()) {
    LOG(ERROR) << "Device [" << device_path << "] not found";
    return nullptr;
  }
  auto* device = it->second->device();

  auto service_path = property_value.TryGet<dbus::ObjectPath>();
  if (!service_path.IsValid() || service_path.value() == "/") {
    device->state = Device::ConnectionState::kUnknown;
    VLOG(2) << "Device [" << device_path << "] has no service";
    return device;
  }

  SetupSelectedServiceProxy(service_path, dbus::ObjectPath(device_path));
  brillo::VariantDictionary properties;
  if (auto* proxy = it->second->service_proxy()) {
    if (!proxy->GetProperties(&properties, nullptr))
      LOG(ERROR) << "Unable to get properties for device service ["
                 << service_path.value() << "]";
  } else {
    LOG(DFATAL) << "Device [" << device_path
                << "] has no selected service proxy";
  }

  device->state =
      ParseConnectionState(brillo::GetVariantValueOrDefault<std::string>(
          properties, kStateProperty));
  if (device->state == Device::ConnectionState::kUnknown)
    LOG(ERROR) << "Device [" << device_path << "] connection state for ["
               << service_path.value() << "] is unknown";

  return device;
}

Client::IPConfig Client::ParseIPConfigsProperty(
    const std::string& device_path,
    const std::vector<dbus::ObjectPath>& ipconfig_paths) const {
  std::unique_ptr<IPConfigProxy> proxy;
  auto reset_proxy = [&](const dbus::ObjectPath& path) {
    if (proxy)
      proxy->ReleaseObjectProxy(base::DoNothing());

    if (path.IsValid())
      proxy.reset(new IPConfigProxy(bus_, path));
  };

  IPConfig ipconfig;
  for (const auto& path : ipconfig_paths) {
    reset_proxy(path);
    brillo::VariantDictionary properties;
    if (!proxy->GetProperties(&properties, nullptr)) {
      // It is possible that an IPConfig object is removed after we know its
      // path, especially when the interface is going down.
      LOG(WARNING) << "Unable to get properties for IPConfig [" << path.value()
                   << "] on device [" << device_path << "]";
      continue;
    }

    std::string addr = brillo::GetVariantValueOrDefault<std::string>(
        properties, kAddressProperty);
    if (addr.empty()) {
      // On IPv6 only network, dhcp is expected to fail, nevertheless shill
      // will still expose a mostly empty IPConfig object, On dual stack
      // networks, the IPv6 configuration may be available before dhcp has
      // finished. Avoid logging spurious WARNING messages in these two cases.
      continue;
    }

    const auto ip_addr = IPAddress::CreateFromString(addr);
    if (!ip_addr.has_value()) {
      LOG(WARNING) << "Invalid address [" << addr << "] in IPConfig ["
                   << path.value() << "] on device [" << device_path << "]";
      continue;
    }

    std::string gw = brillo::GetVariantValueOrDefault<std::string>(
        properties, kGatewayProperty);
    if (gw.empty()) {
      LOG(WARNING) << "Empty property [" << kGatewayProperty
                   << "] in IPConfig [" << path.value() << "] on device ["
                   << device_path << "]";
      continue;
    }

    int len =
        brillo::GetVariantValueOrDefault<int>(properties, kPrefixlenProperty);
    if (len < 0 || (ip_addr->family() == IPAddress::kFamilyIPv4 && len > 32) ||
        len > 128) {
      LOG(WARNING) << "Invalid property [" << kPrefixlenProperty
                   << "] in IPConfig [" << path.value() << "] on device ["
                   << device_path << "] with value " << len;
      continue;
    }
    if (len == 0) {
      LOG(WARNING) << "Property [" << kPrefixlenProperty << "] in IPConfig ["
                   << path.value() << "] on device [" << device_path
                   << "] has a value of 0. May indicate an invalid setup.";
    }

    // While multiple IPv6 addresses are valid, we expect shill to provide at
    // most one for now.
    // TODO(garrick): Support multiple IPv6 configurations.
    if ((ip_addr->family() == IPAddress::kFamilyIPv4 &&
         !ipconfig.ipv4_address.empty()) ||
        (ip_addr->family() == IPAddress::kFamilyIPv6 &&
         !ipconfig.ipv6_address.empty())) {
      LOG(WARNING) << "Duplicate [" << ip_addr->family() << "] IPConfig found"
                   << " on device [" << device_path << "]";
      continue;
    }

    // Note that empty name server list may indicates the network does not have
    // Internet connectivity.
    auto ns = brillo::GetVariantValueOrDefault<std::vector<std::string>>(
        properties, kNameServersProperty);
    auto search_domains =
        brillo::GetVariantValueOrDefault<std::vector<std::string>>(
            properties, kSearchDomainsProperty);

    if (ip_addr->family() == IPAddress::kFamilyIPv4) {
      ipconfig.ipv4_prefix_length = len;
      ipconfig.ipv4_address = addr;
      ipconfig.ipv4_gateway = gw;
      ipconfig.ipv4_dns_addresses = ns;
      ipconfig.ipv4_search_domains = search_domains;
    } else {  // is_ipv6_type
      ipconfig.ipv6_prefix_length = len;
      ipconfig.ipv6_address = addr;
      ipconfig.ipv6_gateway = gw;
      ipconfig.ipv6_dns_addresses = ns;
      ipconfig.ipv6_search_domains = search_domains;
    }
  }
  reset_proxy(dbus::ObjectPath());

  return ipconfig;
}
void Client::OnServicePropertyChangeRegistration(const std::string& device_path,
                                                 const std::string& interface,
                                                 const std::string& signal_name,
                                                 bool success) {
  if (!success) {
    LOG(ERROR) << "Unable to register for Device [" << device_path
               << "] connected service change events "
               << " for " << signal_name << " on " << interface;
    return;
  }

  // This is OK for now since this signal handler is only used for device
  // connected services. If this changes in the future, then we need to
  // accommodate device_path being empty.
  const auto it = devices_.find(device_path);
  if (it == devices_.end()) {
    LOG(ERROR) << "Cannot find device [" << device_path << "]";
    return;
  }

  // This should really exist at this point...
  auto* service_proxy = it->second->service_proxy();
  if (!service_proxy) {
    LOG(DFATAL) << "Missing service proxy for device [" << device_path << "]";
    return;
  }

  brillo::VariantDictionary properties;
  if (!service_proxy->GetProperties(&properties, nullptr)) {
    LOG(ERROR) << "Unable to get connected service properties for device ["
               << device_path << "]";
    return;
  }

  OnServicePropertyChange(device_path, kStateProperty,
                          brillo::GetVariantValueOrDefault<std::string>(
                              properties, kStateProperty));
}

void Client::OnServicePropertyChange(const std::string& device_path,
                                     const std::string& property_name,
                                     const brillo::Any& property_value) {
  if (property_name != kStateProperty)
    return;

  const auto it = devices_.find(device_path);
  if (it == devices_.end()) {
    LOG(ERROR) << "Cannot find device [" << device_path << "]";
    return;
  }

  auto* device = it->second->device();
  const auto state = ParseConnectionState(property_value.TryGet<std::string>());
  if (device->state == state)
    return;

  if (IsConnectedState(device->state) || IsConnectedState(state)) {
    LOG(INFO) << "Device [" << device_path
              << "] connection state changed from [" << ToString(device->state)
              << "] to [" << ToString(state) << "]";
  }
  device->state = state;

  for (auto& handler : device_handlers_)
    handler.Run(device);

  if (device_path == default_device_path_)
    for (auto& handler : default_device_handlers_)
      handler.Run(device);
}

std::vector<std::unique_ptr<Client::Device>> Client::GetDevices() const {
  std::vector<std::unique_ptr<Client::Device>> devices;
  // Provide the current list of devices.
  for (const auto& [_, dev] : devices_) {
    auto device = std::make_unique<Device>();
    device->type = dev->device()->type;
    device->ifname = dev->device()->ifname;
    device->state = dev->device()->state;
    device->ipconfig = dev->device()->ipconfig;
    device->cellular_country_code = dev->device()->cellular_country_code;
    devices.emplace_back(std::move(device));
  }
  return devices;
}

std::unique_ptr<Client::ManagerPropertyAccessor> Client::ManagerProperties(
    const base::TimeDelta& timeout) const {
  return std::make_unique<PropertyAccessor<ManagerProxyInterface>>(
      manager_proxy_.get(), timeout);
}

std::unique_ptr<Client::ServicePropertyAccessor>
Client::DefaultServicePropertyAccessor(const base::TimeDelta& timeout) const {
  if (default_service_proxy_.get() == nullptr) {
    return nullptr;
  }
  return std::make_unique<PropertyAccessor<ServiceProxyInterface>>(
      default_service_proxy_.get(), timeout);
}

std::unique_ptr<brillo::VariantDictionary> Client::GetDefaultServiceProperties(
    const base::TimeDelta& timeout) const {
  brillo::ErrorPtr error;
  brillo::VariantDictionary properties;
  if (!DefaultServicePropertyAccessor(timeout)->Get(&properties, &error)) {
    LOG(ERROR) << "Failed to obtain default service properties: "
               << error->GetMessage();
    return nullptr;
  }

  return std::make_unique<brillo::VariantDictionary>(std::move(properties));
}

std::unique_ptr<Client::Device> Client::DefaultDevice(bool exclude_vpn) {
  brillo::ErrorPtr error;
  brillo::VariantDictionary properties;
  if (!manager_proxy_->GetProperties(&properties, &error)) {
    LOG(ERROR) << "Failed to obtain manager properties";
    return nullptr;
  }
  auto services =
      brillo::GetVariantValueOrDefault<std::vector<dbus::ObjectPath>>(
          properties, shill::kServicesProperty);

  dbus::ObjectPath device_path;
  shill::Client::Device::ConnectionState conn_state;
  for (const auto& s : services) {
    properties.clear();
    if (!NewServiceProxy(s)->GetProperties(&properties, &error)) {
      LOG(ERROR) << "Failed to obtain service [" << s.value()
                 << "] properties: " << error->GetMessage();
      return nullptr;
    }
    if (exclude_vpn) {
      auto type = brillo::GetVariantValueOrDefault<std::string>(properties,
                                                                kTypeProperty);
      if (type.empty()) {
        LOG(ERROR) << "Failed to obtain property [" << shill::kTypeProperty
                   << "] on service [" << s.value() << "]";
        return nullptr;
      }
      if (type == kTypeVPN)
        continue;
    }

    conn_state =
        ParseConnectionState(brillo::GetVariantValueOrDefault<std::string>(
            properties, kStateProperty));
    device_path = brillo::GetVariantValueOrDefault<dbus::ObjectPath>(
        properties, kDeviceProperty);
    if (device_path.IsValid())
      break;

    LOG(WARNING) << "Failed to obtain device for service [" << s.value() << "]";
    continue;
  }
  if (!device_path.IsValid()) {
    LOG(ERROR) << "No devices found";
    return nullptr;
  }

  auto proxy = NewDeviceProxy(device_path);
  properties.clear();
  if (!proxy->GetProperties(&properties, &error)) {
    LOG(ERROR) << "Failed to obtain properties for device ["
               << device_path.value() << "]: " << error->GetMessage();
    return nullptr;
  }
  auto device = std::make_unique<Device>();
  device->type = ParseDeviceType(
      brillo::GetVariantValueOrDefault<std::string>(properties, kTypeProperty));
  device->ifname = brillo::GetVariantValueOrDefault<std::string>(
      properties, kInterfaceProperty);
  device->state = conn_state;
  device->ipconfig = ParseIPConfigsProperty(
      device_path.value(),
      brillo::GetVariantValueOrDefault<std::vector<dbus::ObjectPath>>(
          properties, kIPConfigsProperty));
  if (device->type == Client::Device::Type::kCellular) {
    device->cellular_country_code = GetCellularProviderCountryCode(properties);
  }
  return device;
}

org::chromium::flimflam::ManagerProxyInterface* Client::GetManagerProxy()
    const {
  return manager_proxy_.get();
}

}  // namespace shill
