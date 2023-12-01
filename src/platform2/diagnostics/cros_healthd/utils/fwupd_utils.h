// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_UTILS_FWUPD_UTILS_H_
#define DIAGNOSTICS_CROS_HEALTHD_UTILS_FWUPD_UTILS_H_

#include <optional>
#include <string>
#include <vector>

#include <brillo/variant_dictionary.h>

#include "diagnostics/mojom/public/cros_healthd_probe.mojom.h"

namespace diagnostics {
namespace fwupd_utils {

inline constexpr char kFwupdReusltKeyGuid[] = "Guid";
inline constexpr char kFwupdResultKeyInstanceIds[] = "InstanceIds";
inline constexpr char kFwupdResultKeyName[] = "Name";
inline constexpr char kFwupdResultKeySerial[] = "Serial";
inline constexpr char kFwupdResultKeyVendorId[] = "VendorId";
inline constexpr char kFwupdResultKeyVersion[] = "Version";
inline constexpr char kFwupdResultKeyVersionFormat[] = "VersionFormat";

// DeviceInfo stores the data of a fwupd device.
struct DeviceInfo {
  // The device name, e.g. "Type-C Video Adapter".
  std::optional<std::string> name;

  // The list of globally unique identifiers, e.g.
  // ["2082b5e0-7a64-478a-b1b2-e3404fab6dad"].
  std::vector<std::string> guids;

  // The list of device instance IDs, e.g. ["USB\VID_0A5C&PID_6412"].
  std::vector<std::string> instance_ids;

  // The device serial number, e.g. "0000084f2cb5".
  std::optional<std::string> serial;

  // The firmware version in string, e.g. "1.2.3", "v42".
  std::optional<std::string> version;

  // The format of device firmware version, e.g. PLAIN, HEX, BCD.
  ash::cros_healthd::mojom::FwupdVersionFormat version_format;

  // The device vendor IDs joined by '|', e.g. "USB:0x1234|PCI:0x5678".
  std::optional<std::string> joined_vendor_id;
};

// Information of an USB device. This struct is used in
// FetchhUsbFirmwareVersion() to fetch the firmware version of this USB device.
//
// Both |vendor_id| and |product_id| are required while |serial| can be null if
// the device does not have a serial.
struct UsbDeviceFilter {
  uint16_t vendor_id;
  uint16_t product_id;
  std::optional<std::string> serial;
};

using DeviceList = std::vector<DeviceInfo>;

// Returns a device constructed from |dictionary|, which is a device from the
// response of fwupd D-Bus GetDevices method.
DeviceInfo ParseDbusFwupdDeviceInfo(
    const brillo::VariantDictionary& dictionary);

// Returns a device list constructed from |response|, which is the response of
// fwupd D-Bus GetDevices method.
DeviceList ParseDbusFwupdDeviceList(
    const std::vector<brillo::VariantDictionary>& response);

// Returns whether |device_info| contains a specific |vendor_id|, e.g.
// "USB:0x1234".
bool ContainsVendorId(const DeviceInfo& device_info,
                      const std::string& vendor_id);

// Returns the device GUID generated from the instance ID or NULL if the
// conversion fails.
std::optional<std::string> InstanceIdToGuid(const std::string& instance_id);

// Returns the firmware version of the given |target_usb_device|. It will go
// through fwupd devices |device_infos| and find out the best-matched version
// to |target_usb_device|.
//
// Returns NULL if there are multiple firmware versions among the matched
// devices or that no devices are matched.
ash::cros_healthd::mojom::FwupdFirmwareVersionInfoPtr FetchUsbFirmwareVersion(
    const DeviceList& device_infos, const UsbDeviceFilter& target_usb_device);

}  // namespace fwupd_utils
}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_UTILS_FWUPD_UTILS_H_
