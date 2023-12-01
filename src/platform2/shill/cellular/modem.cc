// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/cellular/modem.h"

#include <limits>
#include <optional>
#include <tuple>

#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/strings/stringprintf.h>

#include <ModemManager/ModemManager.h>

#include "shill/cellular/cellular.h"
#include "shill/control_interface.h"
#include "shill/device_info.h"
#include "shill/logging.h"
#include "shill/manager.h"

namespace shill {

namespace Logging {
static auto kModuleLogScope = ScopeLogger::kModem;
static std::string ObjectID(const Modem* m) {
  return m->path().value().c_str();
}
}  // namespace Logging

namespace {
// TODO(b/175305412): Remove kRmnetIpa0 and kRmnetData0.
constexpr char kRmnetIpa0[] = "rmnet_ipa0";
constexpr char kRmnetData0[] = "rmnet_data0";
}  // namespace

// statics
constexpr char Modem::kFakeDevNameFormat[];
const char Modem::kFakeDevAddress[] = "000000000000";
const int Modem::kFakeDevInterfaceIndex = -1;
size_t Modem::fake_dev_serial_ = 0;

Modem::Modem(const std::string& service,
             const RpcIdentifier& path,
             DeviceInfo* device_info)
    : service_(service), path_(path), device_info_(device_info) {
  SLOG(this, 1) << "Modem() Path: " << path.value();
}

Modem::~Modem() {
  SLOG(this, 1) << "~Modem() Path: " << path_.value();
  if (!interface_index_.has_value())
    return;

  // Note: The Cellular Device |device_| is owned by DeviceInfo. It will not
  // be destroyed here, instead it will be kept around until/unless an RTNL
  // link delete message is received. If/when a new Modem instance is
  // constructed (e.g. after modemmanager restarts), the call to
  // GetOrCreateCellularDevice will return the existing device for the
  // interface.
  CellularRefPtr cellular = GetExistingCellularDevice(interface_index_.value());
  if (cellular)
    cellular->OnModemDestroyed();
}

void Modem::CreateDevice(const InterfaceToProperties& properties) {
  SLOG(this, 1) << __func__;

  uint32_t capabilities = MM_MODEM_CAPABILITY_NONE;
  const auto iter = properties.find(MM_DBUS_INTERFACE_MODEM);
  if (iter == properties.end()) {
    LOG(ERROR) << "Cellular device with no modem properties";
    return;
  }
  const KeyValueStore& modem_props = iter->second;
  if (modem_props.Contains<uint32_t>(MM_MODEM_PROPERTY_CURRENTCAPABILITIES)) {
    capabilities =
        modem_props.Get<uint32_t>(MM_MODEM_PROPERTY_CURRENTCAPABILITIES);
  }

  if (!(capabilities & (MM_MODEM_CAPABILITY_GSM_UMTS | MM_MODEM_CAPABILITY_LTE |
                        MM_MODEM_CAPABILITY_5GNR))) {
    LOG(ERROR) << "Unsupported capabilities: " << capabilities;
    return;
  }

  // We cannot check the IP method to make sure it's not PPP. The IP
  // method will be checked later when the bearer object is fetched.
  CreateDeviceFromModemProperties(properties);
}

void Modem::OnDeviceInfoAvailable(const std::string& link_name) {
  SLOG(this, 1) << __func__ << ": " << link_name
                << " pending: " << has_pending_device_info_;
  if (link_name_ != link_name || !has_pending_device_info_)
    return;

  // has_pending_device_info_ is only set if we've already been through
  // CreateDeviceFromModemProperties() and saved our initial properties.
  has_pending_device_info_ = false;
  CreateDeviceFromModemProperties(initial_properties_);
}

bool Modem::GetLinkName(const KeyValueStore& modem_props,
                        std::string* name) const {
  if (!modem_props.ContainsVariant(MM_MODEM_PROPERTY_PORTS)) {
    LOG(ERROR) << "Device missing property: " << MM_MODEM_PROPERTY_PORTS;
    return false;
  }

  auto ports = modem_props.GetVariant(MM_MODEM_PROPERTY_PORTS)
                   .Get<std::vector<std::tuple<std::string, uint32_t>>>();
  std::string net_port;
  for (const auto& port_pair : ports) {
    if (std::get<1>(port_pair) == MM_MODEM_PORT_TYPE_NET) {
      net_port = std::get<0>(port_pair);
      // TODO(b/175305412): Remove the special handling of `kRmnetIpa0`.
      // Now that ModemManager supports multiplexing, it reports the parent
      // interface name when the modem is created and the child link
      // `kRmnetData0` when the bearer is created. Shill only cares about the
      // child link. Until shill can handle this correctly, we override the
      // parent name with the child name.
      if (std::get<0>(port_pair) == kRmnetIpa0)
        net_port = kRmnetData0;
      break;
    }
  }

  if (net_port.empty()) {
    LOG(ERROR) << "Could not find net port used by the device.";
    return false;
  }

  *name = net_port;
  return true;
}

void Modem::CreateDeviceFromModemProperties(
    const InterfaceToProperties& properties) {
  SLOG(this, 1) << __func__;

  const auto iter = properties.find(std::string(MM_DBUS_INTERFACE_MODEM));
  if (iter == properties.end()) {
    LOG(ERROR) << "Unable to find modem interface properties.";
    return;
  }
  const KeyValueStore& modem_props = iter->second;

  std::string mac_address;
  if (GetLinkName(modem_props, &link_name_)) {
    interface_index_ = GetLinkDetailsFromDeviceInfo(&mac_address);
    if (!interface_index_.has_value()) {
      // Save our properties, wait for OnDeviceInfoAvailable to be called.
      LOG(WARNING) << "Delaying cellular device creation for interface "
                   << link_name_ << ".";
      initial_properties_ = properties;
      has_pending_device_info_ = true;
      return;
    }
    // Got the interface index and MAC address. Fall-through to actually
    // creating the Cellular object.
  } else {
    // Probably a PPP dongle.
    LOG(INFO) << "Cellular device without link name; assuming PPP dongle.";
    link_name_ = base::StringPrintf(kFakeDevNameFormat, fake_dev_serial_++);
    mac_address = kFakeDevAddress;
    interface_index_ = kFakeDevInterfaceIndex;
  }

  if (device_info_->IsDeviceBlocked(link_name_)) {
    LOG(INFO) << "Not creating cellular device for blocked interface "
              << link_name_ << ".";
    return;
  }

  CellularRefPtr device =
      GetOrCreateCellularDevice(interface_index_.value(), mac_address);
  device->SetInitialProperties(properties);

  SLOG(this, 1) << "Cellular device created: " << device->link_name()
                << " Enabled: " << device->enabled();
}

std::optional<int> Modem::GetLinkDetailsFromDeviceInfo(
    std::string* mac_address) {
  int interface_index = device_info_->GetIndex(link_name_);
  if (interface_index < 0) {
    return std::nullopt;
  }

  ByteString address_bytes;
  if (!device_info_->GetMacAddress(interface_index, &address_bytes)) {
    return std::nullopt;
  }

  *mac_address = address_bytes.HexEncode();
  return interface_index;
}

CellularRefPtr Modem::GetOrCreateCellularDevice(
    int interface_index, const std::string& mac_address) {
  LOG(INFO) << __func__ << " Index: " << interface_index;
  CellularRefPtr cellular = GetExistingCellularDevice(interface_index);
  if (cellular && cellular->link_name() != link_name_) {
    SLOG(this, 1) << "Cellular link name changed: " << link_name_;
    cellular = nullptr;
    device_info_->DeregisterDevice(interface_index);
  }
  if (cellular && (cellular->dbus_service() != service_)) {
    SLOG(this, 1) << "Cellular service changed: " << service_;
    cellular = nullptr;
    device_info_->DeregisterDevice(interface_index);
  }
  if (cellular) {
    LOG(INFO) << "Using existing Cellular Device: " << cellular->enabled();
    // Update the Cellular dbus path and mac address to match the new Modem.
    cellular->UpdateModemProperties(path_, mac_address);
    return cellular;
  }

  cellular = new Cellular(device_info_->manager(), link_name_, mac_address,
                          interface_index, service_, path_);
  device_info_->RegisterDevice(cellular);
  return cellular;
}

CellularRefPtr Modem::GetExistingCellularDevice(int interface_index) const {
  DeviceRefPtr device = device_info_->GetDevice(interface_index);
  if (!device)
    return nullptr;
  CHECK_EQ(device->technology(), Technology::kCellular);
  return static_cast<Cellular*>(device.get());
}

}  // namespace shill
