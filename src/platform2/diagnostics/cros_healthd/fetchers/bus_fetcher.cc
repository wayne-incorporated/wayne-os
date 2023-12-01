// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <algorithm>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <base/check.h>
#include <base/files/file_enumerator.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_piece.h>
#include <base/strings/stringprintf.h>
#include <brillo/udev/udev.h>
#include <brillo/udev/udev_device.h>
#include <fwupd/dbus-proxies.h>

#include "diagnostics/base/file_utils.h"
#include "diagnostics/cros_healthd/fetchers/bus_fetcher.h"
#include "diagnostics/cros_healthd/fetchers/bus_fetcher_constants.h"
#include "diagnostics/cros_healthd/utils/dbus_utils.h"
#include "diagnostics/cros_healthd/utils/error_utils.h"
#include "diagnostics/cros_healthd/utils/fwupd_utils.h"
#include "diagnostics/cros_healthd/utils/usb_utils.h"
#include "diagnostics/cros_healthd/utils/usb_utils_constants.h"

namespace diagnostics {

namespace {

namespace mojom = ::ash::cros_healthd::mojom;

template <typename T>
bool HexToUInt(base::StringPiece in, T* out) {
  uint32_t raw;
  if (!base::HexStringToUInt(in, &raw))
    return false;
  *out = static_cast<T>(raw);
  return true;
}

const auto& HexToU8 = HexToUInt<uint8_t>;
const auto& HexToU16 = HexToUInt<uint16_t>;

bool HexToNullableUint16WithZeroHandling(base::StringPiece in,
                                         mojom::NullableUint16Ptr* out) {
  uint16_t raw;
  if (!HexToU16(in, &raw))
    return false;
  // Subsystem device and subsystem vendor is 0x0000 when it is not available.
  if (raw == 0)
    return false;
  *out = mojom::NullableUint16::New(raw);
  return true;
}

std::vector<base::FilePath> ListDirectory(const base::FilePath& path) {
  std::vector<base::FilePath> res;
  base::FileEnumerator file_enum(
      path, /*recursive=*/false,
      base::FileEnumerator::FileType::FILES |
          base::FileEnumerator::FileType::DIRECTORIES |
          base::FileEnumerator::FileType::SHOW_SYM_LINKS);
  for (auto path = file_enum.Next(); !path.empty(); path = file_enum.Next()) {
    res.push_back(path);
  }
  return res;
}

std::optional<std::string> GetDriver(const base::FilePath& path) {
  base::FilePath driver_path;
  if (base::ReadSymbolicLink(path.Append(kFileDriver), &driver_path))
    return driver_path.BaseName().value();
  return std::nullopt;
}

mojom::PciBusInfoPtr FetchPciInfo(const base::FilePath& path) {
  auto info = mojom::PciBusInfo::New();
  uint32_t class_raw;
  if (!ReadInteger(path, kFilePciClass, &base::HexStringToUInt, &class_raw) ||
      !ReadInteger(path, kFilePciDevice, &HexToU16, &info->device_id) ||
      !ReadInteger(path, kFilePciVendor, &HexToU16, &info->vendor_id))
    return nullptr;
  ReadInteger(path, kFilePciSubVendor, &HexToNullableUint16WithZeroHandling,
              &info->sub_vendor_id);
  ReadInteger(path, kFilePciSubDevice, &HexToNullableUint16WithZeroHandling,
              &info->sub_device_id);
  info->class_id = GET_PCI_CLASS(class_raw);
  info->subclass_id = GET_PCI_SUBCLASS(class_raw);
  info->prog_if_id = GET_PCI_PROG_IF(class_raw);
  info->driver = GetDriver(path);
  return info;
}

// Some devices cannot be identified by their class id. Try to identify them by
// checking the sysfs structure.
mojom::BusDeviceClass GetDeviceClassBySysfs(const base::FilePath& path) {
  if (base::PathExists(path.Append("bluetooth")))
    return mojom::BusDeviceClass::kBluetoothAdapter;
  const auto net = path.Append("net");
  if (base::PathExists(net)) {
    for (const auto& nic_path : ListDirectory(net)) {
      const auto name = nic_path.BaseName().value();
      if (name.find("eth") == 0)
        return mojom::BusDeviceClass::kEthernetController;
      if (name.find("wlan") == 0)
        return mojom::BusDeviceClass::kWirelessController;
    }
  }
  if (base::PathExists(path.Append("sound")))
    return mojom::BusDeviceClass::kAudioCard;
  return mojom::BusDeviceClass::kOthers;
}

mojom::BusDeviceClass GetPciDeviceClass(const base::FilePath& path,
                                        const mojom::PciBusInfoPtr& info) {
  CHECK(info);
  if (info->class_id == pci_ids::display::kId)
    return mojom::BusDeviceClass::kDisplayController;
  if (info->class_id == pci_ids::network::kId) {
    if (info->subclass_id == pci_ids::network::ethernet::kId)
      return mojom::BusDeviceClass::kEthernetController;
    if (info->subclass_id == pci_ids::network::network::kId)
      return mojom::BusDeviceClass::kWirelessController;
  }
  return GetDeviceClassBySysfs(path);
}

mojom::BusDevicePtr FetchPciDevice(const base::FilePath& path,
                                   const std::unique_ptr<PciUtil>& pci_util) {
  auto pci_info = FetchPciInfo(path);
  if (pci_info.is_null())
    return nullptr;

  auto device = mojom::BusDevice::New();
  device->vendor_name = pci_util->GetVendorName(pci_info->vendor_id);
  device->product_name =
      pci_util->GetDeviceName(pci_info->vendor_id, pci_info->device_id);
  device->device_class = GetPciDeviceClass(path, pci_info);

  device->bus_info = mojom::BusInfo::NewPciBusInfo(std::move(pci_info));
  return device;
}

mojom::UsbBusInterfaceInfoPtr FetchUsbBusInterfaceInfo(
    const base::FilePath& path) {
  auto info = mojom::UsbBusInterfaceInfo::New();
  if (!ReadInteger(path, kFileUsbIFNumber, &HexToU8, &info->interface_number) ||
      !ReadInteger(path, kFileUsbIFClass, &HexToU8, &info->class_id) ||
      !ReadInteger(path, kFileUsbIFSubclass, &HexToU8, &info->subclass_id) ||
      !ReadInteger(path, kFileUsbIFProtocol, &HexToU8, &info->protocol_id))
    return nullptr;
  info->driver = GetDriver(path);
  return info;
}

mojom::FwupdFirmwareVersionInfoPtr GetUsbFirmwareVersion(
    const base::FilePath& path,
    const fwupd_utils::DeviceList& fwupd_devices,
    uint16_t vendor_id,
    uint16_t product_id) {
  std::optional<std::string> serial;
  if (!ReadAndTrimString(path, kFileUsbSerial, &serial)) {
    serial = std::nullopt;
  }

  fwupd_utils::UsbDeviceFilter usb_device_filter{
      .vendor_id = vendor_id,
      .product_id = product_id,
      .serial = serial,
  };

  return fwupd_utils::FetchUsbFirmwareVersion(fwupd_devices, usb_device_filter);
}

mojom::UsbBusInfoPtr FetchUsbBusInfo(
    const base::FilePath& path, const fwupd_utils::DeviceList& fwupd_devices) {
  auto info = mojom::UsbBusInfo::New();
  if (!ReadInteger(path, kFileUsbDevClass, &HexToU8, &info->class_id) ||
      !ReadInteger(path, kFileUsbDevSubclass, &HexToU8, &info->subclass_id) ||
      !ReadInteger(path, kFileUsbDevProtocol, &HexToU8, &info->protocol_id) ||
      !ReadInteger(path, kFileUsbVendor, &HexToU16, &info->vendor_id) ||
      !ReadInteger(path, kFileUsbProduct, &HexToU16, &info->product_id))
    return nullptr;

  info->spec_speed = GetUsbSpecSpeed(path);
  info->version = DetermineUsbVersion(path);
  info->fwupd_firmware_version_info = GetUsbFirmwareVersion(
      path, fwupd_devices, info->vendor_id, info->product_id);
  for (const auto& if_path : ListDirectory(path)) {
    auto if_info = FetchUsbBusInterfaceInfo(if_path);
    if (if_info) {
      info->interfaces.push_back(std::move(if_info));
    }
  }
  sort(info->interfaces.begin(), info->interfaces.end(),
       [](const mojom::UsbBusInterfaceInfoPtr& a,
          const mojom::UsbBusInterfaceInfoPtr& b) {
         return a->interface_number < b->interface_number;
       });
  return info;
}

mojom::BusDeviceClass GetUsbDeviceClass(const base::FilePath& path,
                                        const mojom::UsbBusInfoPtr& info) {
  CHECK(info);
  if (info->class_id == usb_ids::wireless::kId &&
      info->subclass_id == usb_ids::wireless::radio_frequency::kId &&
      info->protocol_id == usb_ids::wireless::radio_frequency::bluetooth::kId) {
    return mojom::BusDeviceClass::kBluetoothAdapter;
  }
  // Try to get the type by checking the type of each interface.
  for (const auto& if_path : ListDirectory(path)) {
    // |if_path| is an interface if and only if |kFileUsbIFNumber| exist.
    if (!base::PathExists(if_path.Append(kFileUsbIFNumber)))
      continue;
    auto type = GetDeviceClassBySysfs(if_path);
    if (type != mojom::BusDeviceClass::kOthers)
      return type;
  }
  return mojom::BusDeviceClass::kOthers;
}

mojom::BusDevicePtr FetchUsbDevice(
    const base::FilePath& path,
    const std::unique_ptr<brillo::UdevDevice>& udevice,
    const fwupd_utils::DeviceList& fwupd_devices) {
  auto usb_info = FetchUsbBusInfo(path, fwupd_devices);
  if (usb_info.is_null())
    return nullptr;
  auto device = mojom::BusDevice::New();
  device->vendor_name = GetUsbVendorName(udevice);
  device->product_name = GetUsbProductName(udevice);
  device->device_class = GetUsbDeviceClass(path, usb_info);

  device->bus_info = mojom::BusInfo::NewUsbBusInfo(std::move(usb_info));
  return device;
}

mojom::ThunderboltBusInterfaceInfoPtr FetchThunderboltBusInterfaceInfo(
    const base::FilePath& path, const std::string& domain_id) {
  // Check sysfs directory for interface attached to same domain.
  std::vector<std::string> components = path.GetComponents();
  // Get interface directory name which is the last component in path.
  auto interface_dir_name = components.back();
  // Check interface directory name starting with same domain number.
  auto interface_domain_id = interface_dir_name.substr(0, domain_id.length());

  if (interface_domain_id != domain_id)
    return nullptr;

  auto info = mojom::ThunderboltBusInterfaceInfo::New();
  std::string rx_speed, tx_speed;
  if (!ReadInteger(path, kFileThunderboltAuthorized, &HexToU8,
                   reinterpret_cast<uint8_t*>(&info->authorized)) ||
      !ReadAndTrimString(path.Append(kFileThunderboltRxSpeed), &rx_speed) ||
      !ReadAndTrimString(path.Append(kFileThunderboltTxSpeed), &tx_speed) ||
      !ReadAndTrimString(path.Append(kFileThunderboltVendorName),
                         &info->vendor_name) ||
      !ReadAndTrimString(path.Append(kFileThunderboltDeviceName),
                         &info->device_name) ||
      !ReadAndTrimString(path.Append(kFileThunderboltDeviceType),
                         &info->device_type) ||
      !ReadAndTrimString(path.Append(kFileThunderboltUUID),
                         &info->device_uuid) ||
      !ReadAndTrimString(path.Append(kFileThunderboltFWVer),
                         &info->device_fw_version))
    return nullptr;

  // Thunderbolt sysfs populate rx_speed and tx_speed value
  // as string "20.0 Gb/s" so reading first integer value.
  base::StringToUint(rx_speed.substr(0, rx_speed.find(".")),
                     &info->rx_speed_gbs);
  base::StringToUint(tx_speed.substr(0, tx_speed.find(".")),
                     &info->tx_speed_gbs);

  return info;
}

mojom::ThunderboltSecurityLevel StrToEnumThunderboltSecurity(
    const std::string& str) {
  if (str == "none")
    return mojom::ThunderboltSecurityLevel::kNone;
  if (str == "user")
    return mojom::ThunderboltSecurityLevel::kUserLevel;
  if (str == "secure")
    return mojom::ThunderboltSecurityLevel::kSecureLevel;
  if (str == "dponly")
    return mojom::ThunderboltSecurityLevel::kDpOnlyLevel;
  if (str == "usbonly")
    return mojom::ThunderboltSecurityLevel::kUsbOnlyLevel;
  if (str == "nopcie")
    return mojom::ThunderboltSecurityLevel::kNoPcieLevel;

  return mojom::ThunderboltSecurityLevel::kNone;
}

mojom::ThunderboltBusInfoPtr FetchThunderboltBusInfo(
    const base::FilePath& thunderbolt_path, const base::FilePath& dev_path) {
  auto info = mojom::ThunderboltBusInfo::New();
  std::string security;

  // Since thunderbolt sysfs has controller and connected interfaces in same
  // directory level, it is required to iterate interface directories which
  // are connected to same controller only. e.g. domain0 is directory for
  // controller 0 and connected interface directory is 0-0:1:0.
  std::vector<std::string> components = dev_path.GetComponents();
  auto domain_dir = components.back();
  std::string domain_id;

  if (domain_dir.find("domain") == 0)
    domain_id = domain_dir.substr(strlen("domain"));
  else
    return nullptr;

  if (ReadAndTrimString(dev_path.Append(kFileThunderboltSecurity), &security))
    info->security_level = StrToEnumThunderboltSecurity(security);
  else
    return nullptr;

  for (const auto& if_path : ListDirectory(thunderbolt_path)) {
    auto if_info = FetchThunderboltBusInterfaceInfo(if_path, domain_id);
    if (if_info) {
      info->thunderbolt_interfaces.push_back(std::move(if_info));
    }
  }

  return info;
}

mojom::BusDevicePtr FetchThunderboltDevice(
    const base::FilePath& thunderbolt_path, const base::FilePath& dev_path) {
  auto thunderbolt_bus_info =
      FetchThunderboltBusInfo(thunderbolt_path, dev_path);
  if (thunderbolt_bus_info.is_null())
    return nullptr;
  auto device = mojom::BusDevice::New();
  device->device_class = mojom::BusDeviceClass::kThunderboltController;
  device->bus_info =
      mojom::BusInfo::NewThunderboltBusInfo(std::move(thunderbolt_bus_info));
  for (const auto& path : ListDirectory(dev_path)) {
    if (base::PathExists(path.Append(kFileThunderboltDeviceName))) {
      ReadAndTrimString(path.Append(kFileThunderboltDeviceName),
                        &device->product_name);
    }
    if (base::PathExists(path.Append(kFileThunderboltVendorName))) {
      ReadAndTrimString(path.Append(kFileThunderboltVendorName),
                        &device->vendor_name);
    }
  }

  return device;
}

fwupd_utils::DeviceList ParseFwupdDevices(
    brillo::Error* err,
    const std::vector<brillo::VariantDictionary>& response) {
  if (err) {
    LOG(WARNING) << "Unable to get fwupd devices: " << err->GetMessage();
    return {};
  }
  return fwupd_utils::ParseDbusFwupdDeviceList(response);
}

void FetchBusDevicesWithFwupdInfo(
    Context* context,
    FetchSysfsPathsBusDeviceMapCallback callback,
    const fwupd_utils::DeviceList& fwupd_devices) {
  const auto& root = context->root_dir();
  std::vector<std::pair<base::FilePath, mojom::BusDevicePtr>> res;

  auto pci_util = context->CreatePciUtil();
  for (const auto& path : ListDirectory(root.Append(kPathSysPci))) {
    auto device = FetchPciDevice(path, pci_util);
    if (device) {
      res.push_back(
          std::make_pair(base::MakeAbsoluteFilePath(path), std::move(device)));
    }
  }
  for (const auto& path : ListDirectory(root.Append(kPathSysUsb))) {
    auto udevice =
        context->udev()->CreateDeviceFromSysPath(path.value().c_str());
    auto device = FetchUsbDevice(path, udevice, fwupd_devices);
    if (device) {
      res.push_back(
          std::make_pair(base::MakeAbsoluteFilePath(path), std::move(device)));
    }
  }
  auto thunderbolt_path = root.Append(kPathSysThunderbolt);
  for (const auto& dev_path : ListDirectory(thunderbolt_path)) {
    auto device = FetchThunderboltDevice(thunderbolt_path, dev_path);
    if (device) {
      res.push_back(std::make_pair(base::MakeAbsoluteFilePath(dev_path),
                                   std::move(device)));
    }
  }
  std::move(callback).Run(
      base::flat_map<base::FilePath, mojom::BusDevicePtr>{std::move(res)});
}

mojom::BusResultPtr ConvertBusDeviceMapToBusResult(
    base::flat_map<base::FilePath, mojom::BusDevicePtr> bus_device_map) {
  std::vector<mojom::BusDevicePtr> res;
  for (auto& item : bus_device_map) {
    res.push_back(std::move(item.second));
  }
  return mojom::BusResult::NewBusDevices(std::move(res));
}

}  // namespace

void FetchSysfsPathsBusDeviceMap(Context* context,
                                 FetchSysfsPathsBusDeviceMapCallback callback) {
  auto get_devices_cb = base::BindOnce(&ParseFwupdDevices)
                            .Then(base::BindOnce(&FetchBusDevicesWithFwupdInfo,
                                                 context, std::move(callback)));

  auto [on_success, on_error] = SplitDbusCallback(std::move(get_devices_cb));
  context->fwupd_proxy()->GetDevicesAsync(std::move(on_success),
                                          std::move(on_error));
}

void FetchBusDevices(Context* context, FetchBusDevicesCallback callback) {
  FetchSysfsPathsBusDeviceMap(context,
                              base::BindOnce(&ConvertBusDeviceMapToBusResult)
                                  .Then(std::move(callback)));
}

}  // namespace diagnostics
