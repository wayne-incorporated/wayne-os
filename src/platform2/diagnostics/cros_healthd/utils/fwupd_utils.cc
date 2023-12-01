// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <algorithm>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include <base/strings/string_split.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>
#include <brillo/variant_dictionary.h>
#include <libfwupd/fwupd-common.h>
#include <libfwupd/fwupd-enums.h>

#include "diagnostics/cros_healthd/utils/fwupd_utils.h"
#include "diagnostics/mojom/public/cros_healthd_probe.mojom.h"

namespace diagnostics {
namespace fwupd_utils {

namespace {

namespace mojom = ::ash::cros_healthd::mojom;

// Returns whether some instance id of |device_info| starts with |instance_id|.
bool MatchInstanceIdPrefix(const DeviceInfo& device_info,
                           const std::string& instance_id) {
  return std::any_of(device_info.instance_ids.begin(),
                     device_info.instance_ids.end(),
                     [&instance_id](const std::string& value) {
                       return base::StartsWith(value, instance_id);
                     });
}

// Returns whether the |device_info| contains a specific |guid|.
bool MatchGuid(const DeviceInfo& device_info, const std::string& guid) {
  return std::any_of(
      device_info.guids.begin(), device_info.guids.end(),
      [&guid](const std::string& value) { return value == guid; });
}

// Returns whether |device_info| contains a vendor id "USB:0x{VID}".
bool MatchVendor(const DeviceInfo& device_info,
                 const UsbDeviceFilter& usb_device_filter) {
  std::string usb_vendor_id =
      base::StringPrintf("USB:0x%04X", usb_device_filter.vendor_id);
  return ContainsVendorId(device_info, usb_vendor_id);
}

// Returns true if VID and PID shows in |device_info| InstanceIds as a prefix
// or the |device_info| contains the GUID generated from a special instance
// id ("USB\VID_xxxx&PID_xxxx"). False otherwise.
bool MatchProduct(const DeviceInfo& device_info,
                  const UsbDeviceFilter& usb_device_filter) {
  std::string instance_id =
      base::StringPrintf("USB\\VID_%04X&PID_%04X", usb_device_filter.vendor_id,
                         usb_device_filter.product_id);
  std::optional<std::string> guid = InstanceIdToGuid(instance_id);

  return MatchInstanceIdPrefix(device_info, instance_id) ||
         (guid.has_value() && MatchGuid(device_info, guid.value()));
}

// Returns true if either |usb_device_filter.serial| is null or empty or it
// matches |device_info.serial|. False otherwise.
bool MatchSerial(const DeviceInfo& device_info,
                 const UsbDeviceFilter& usb_device_filter) {
  return !usb_device_filter.serial.has_value() ||
         usb_device_filter.serial->empty() ||
         usb_device_filter.serial == device_info.serial;
}

// Returns whether |device_info| and |target_usb_device| match regarding all of
// vendor, product and serial.
bool MatchUsbDevice(const DeviceInfo& device_info,
                    const UsbDeviceFilter& target_usb_device) {
  return MatchVendor(device_info, target_usb_device) &&
         MatchProduct(device_info, target_usb_device) &&
         MatchSerial(device_info, target_usb_device);
}

// Similar to brillo::GetVariantValueOrDefault but returns std::nullopt
// when the key does not exist or the type conversion fails.
template <typename T>
const std::optional<T> GetVariantOptionalValue(
    const brillo::VariantDictionary& dictionary, const std::string& key) {
  auto it = dictionary.find(key);
  if (it == dictionary.end()) {
    return std::nullopt;
  }
  T value;
  if (!it->second.GetValue(&value)) {
    return std::nullopt;
  }
  return value;
}

// Converts a fwupd format enum to the corresponding mojo enum.
mojom::FwupdVersionFormat ConvertFwupdVersionFormatToMojo(
    FwupdVersionFormat version_format) {
  switch (version_format) {
    case FWUPD_VERSION_FORMAT_UNKNOWN:
      return mojom::FwupdVersionFormat::kUnknown;
    case FWUPD_VERSION_FORMAT_PLAIN:
      return mojom::FwupdVersionFormat::kPlain;
    case FWUPD_VERSION_FORMAT_NUMBER:
      return mojom::FwupdVersionFormat::kNumber;
    case FWUPD_VERSION_FORMAT_PAIR:
      return mojom::FwupdVersionFormat::kPair;
    case FWUPD_VERSION_FORMAT_TRIPLET:
      return mojom::FwupdVersionFormat::kTriplet;
    case FWUPD_VERSION_FORMAT_QUAD:
      return mojom::FwupdVersionFormat::kQuad;
    case FWUPD_VERSION_FORMAT_BCD:
      return mojom::FwupdVersionFormat::kBcd;
    case FWUPD_VERSION_FORMAT_INTEL_ME:
      return mojom::FwupdVersionFormat::kIntelMe;
    case FWUPD_VERSION_FORMAT_INTEL_ME2:
      return mojom::FwupdVersionFormat::kIntelMe2;
    case FWUPD_VERSION_FORMAT_SURFACE_LEGACY:
      return mojom::FwupdVersionFormat::kSurfaceLegacy;
    case FWUPD_VERSION_FORMAT_SURFACE:
      return mojom::FwupdVersionFormat::kSurface;
    case FWUPD_VERSION_FORMAT_DELL_BIOS:
      return mojom::FwupdVersionFormat::kDellBios;
    case FWUPD_VERSION_FORMAT_HEX:
      return mojom::FwupdVersionFormat::kHex;
    case FWUPD_VERSION_FORMAT_LAST:
      return mojom::FwupdVersionFormat::kUnknown;
  }
}

// Gets the version format from |dictionary| with the given |key|.
mojom::FwupdVersionFormat GetVersionFormat(
    const brillo::VariantDictionary& dictionary, const std::string& key) {
  // Can not use brillo::GetVariantValueOrDefault here because when that
  // function returns 0, we cannot tell whether it represents a valid enum or
  // it means the key does not exist.
  std::optional<uint32_t> format_int =
      GetVariantOptionalValue<uint32_t>(dictionary, key);
  // Check that the value is within the valid enum range.
  if (format_int.has_value() &&
      format_int.value() < FWUPD_VERSION_FORMAT_LAST) {
    return ConvertFwupdVersionFormatToMojo(
        static_cast<FwupdVersionFormat>(format_int.value()));
  }
  return mojom::FwupdVersionFormat::kUnknown;
}

}  // namespace

DeviceInfo ParseDbusFwupdDeviceInfo(
    const brillo::VariantDictionary& dictionary) {
  DeviceInfo device_info;

  device_info.name =
      GetVariantOptionalValue<std::string>(dictionary, kFwupdResultKeyName);
  device_info.guids =
      brillo::GetVariantValueOrDefault<std::vector<std::string>>(
          dictionary, kFwupdReusltKeyGuid);
  device_info.instance_ids =
      brillo::GetVariantValueOrDefault<std::vector<std::string>>(
          dictionary, kFwupdResultKeyInstanceIds);
  device_info.serial =
      GetVariantOptionalValue<std::string>(dictionary, kFwupdResultKeySerial);
  device_info.version =
      GetVariantOptionalValue<std::string>(dictionary, kFwupdResultKeyVersion);
  device_info.version_format =
      GetVersionFormat(dictionary, kFwupdResultKeyVersionFormat);
  device_info.joined_vendor_id =
      GetVariantOptionalValue<std::string>(dictionary, kFwupdResultKeyVendorId);
  return device_info;
}

DeviceList ParseDbusFwupdDeviceList(
    const std::vector<brillo::VariantDictionary>& response) {
  DeviceList fwupd_devices;
  for (auto& raw_device_info : response) {
    fwupd_devices.push_back(ParseDbusFwupdDeviceInfo(raw_device_info));
  }
  return fwupd_devices;
}

bool ContainsVendorId(const DeviceInfo& device_info,
                      const std::string& vendor_id) {
  if (!device_info.joined_vendor_id.has_value()) {
    return false;
  }
  std::vector<base::StringPiece> ids =
      base::SplitStringPiece(device_info.joined_vendor_id.value(), "|",
                             base::TRIM_WHITESPACE, base::SPLIT_WANT_NONEMPTY);
  return std::any_of(
      ids.begin(), ids.end(),
      [&vendor_id](base::StringPiece value) { return value == vendor_id; });
}

std::optional<std::string> InstanceIdToGuid(const std::string& instance_id) {
  g_autofree gchar* guid_c_str = fwupd_guid_hash_string(instance_id.c_str());
  if (!guid_c_str) {
    return std::nullopt;
  }
  return std::string(guid_c_str);
}

mojom::FwupdFirmwareVersionInfoPtr FetchUsbFirmwareVersion(
    const DeviceList& device_infos, const UsbDeviceFilter& target_usb_device) {
  std::set<std::pair<std::optional<std::string>, mojom::FwupdVersionFormat>>
      version_info_set;

  for (int i = 0; i < device_infos.size(); ++i) {
    const auto& device = device_infos[i];
    if (MatchUsbDevice(device, target_usb_device)) {
      version_info_set.emplace(device.version, device.version_format);
    }
  }

  // Version info is not unique.
  if (version_info_set.size() != 1) {
    return nullptr;
  }

  const auto [version, version_format] = *version_info_set.begin();
  // No version string.
  if (!version.has_value()) {
    return nullptr;
  }

  auto info = mojom::FwupdFirmwareVersionInfo::New();
  info->version = version.value();
  info->version_format = version_format;

  return info;
}

}  // namespace fwupd_utils
}  // namespace diagnostics
