// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "flex_bluetooth/flex_bluetooth_overrides.h"

#include <base/logging.h>
#include <brillo/syslog_logging.h>
#include <brillo/udev/udev.h>
#include <brillo/udev/udev_device.h>
#include <brillo/udev/udev_enumerate.h>

namespace {

const char kAttributeDeviceClass[] = "bDeviceClass";
const char kAttributeDeviceSubClass[] = "bDeviceSubClass";
const char kAttributeIdProduct[] = "idProduct";
const char kAttributeIdVendor[] = "idVendor";
// The below DeviceClass and DeviceSubClass can be found at
// https://www.usb.org/defined-class-codes
const char kBluetoothDeviceClass[] = "e0";
const char kBluetoothDeviceSubClass[] = "01";

const base::FilePath kSyspropOverridePath = base::FilePath(
    "/var/lib/bluetooth/sysprops.conf.d/floss_reven_overrides.conf");

const std::map<flex_bluetooth::BluetoothAdapter,
               std::unordered_set<flex_bluetooth::SyspropOverride>>
    kAdapterSyspropOverrides = {
        {flex_bluetooth::BluetoothAdapter{0x0489, 0xe0a2},
         {flex_bluetooth::SyspropOverride::kDisableLEGetVendorCapabilities}},
        {flex_bluetooth::BluetoothAdapter{0x04ca, 0x3015},
         {flex_bluetooth::SyspropOverride::kDisableLEGetVendorCapabilities}},
        {flex_bluetooth::BluetoothAdapter{0x0cf3, 0xe007},
         {flex_bluetooth::SyspropOverride::kDisableLEGetVendorCapabilities}},
        {flex_bluetooth::BluetoothAdapter{0x0cf3, 0xe009},
         {flex_bluetooth::SyspropOverride::kDisableLEGetVendorCapabilities}},
        {flex_bluetooth::BluetoothAdapter{0x13d3, 0x3491},
         {flex_bluetooth::SyspropOverride::kDisableLEGetVendorCapabilities}},
};

}  // namespace

int main() {
  brillo::InitLog(brillo::kLogToSyslog);
  LOG(INFO) << "Started process_flex_bluetooth_overrides.";

  const auto udev = brillo::Udev::Create();
  const auto enumerate = udev->CreateEnumerate();
  if (!enumerate->AddMatchSysAttribute(kAttributeDeviceClass,
                                       kBluetoothDeviceClass) ||
      !enumerate->AddMatchSysAttribute(kAttributeDeviceSubClass,
                                       kBluetoothDeviceSubClass) ||
      !enumerate->ScanDevices()) {
    LOG(INFO) << "No Bluetooth adapter found. Exiting.";
    return 0;
  }

  const flex_bluetooth::FlexBluetoothOverrides bt(kSyspropOverridePath,
                                                  kAdapterSyspropOverrides);
  bool found_bt_adapter = false;
  uint16_t id_vendor;
  uint16_t id_product;
  for (std::unique_ptr<brillo::UdevListEntry> list_entry =
           enumerate->GetListEntry();
       list_entry; list_entry = list_entry->GetNext()) {
    const std::string sys_path = list_entry->GetName() ?: "";
    const std::unique_ptr<brillo::UdevDevice> device =
        udev->CreateDeviceFromSysPath(sys_path.c_str());
    if (!device)
      continue;

    const std::string vendor =
        device->GetSysAttributeValue(kAttributeIdVendor) ?: "";
    const std::string product =
        device->GetSysAttributeValue(kAttributeIdProduct) ?: "";

    LOG(INFO) << "Found Bluetooth adapter with idVendor: " << vendor
              << " and idProduct: " << product;

    if (!flex_bluetooth::HexStringToUInt16(vendor, &id_vendor)) {
      LOG(WARNING) << "Unable to convert vendor " << vendor << " to uint16_t.";
      continue;
    }

    if (!flex_bluetooth::HexStringToUInt16(product, &id_product)) {
      LOG(WARNING) << "Unable to convert product " << product
                   << " to uint16_t.";
      continue;
    }

    found_bt_adapter = true;
    bt.ProcessOverridesForVidPid(id_vendor, id_product);

    // TODO(b/277581437): Handle the case when there are multiple Bluetooth
    // adapters. There's currently only support for one Bluetooth adapter.
    // This presents issue where an external Bluetooth adapter cannot be
    // used over an existing internal Bluetooth adapter.
    // (To clarify, if a device has no internal Bluetooth adapter, a user can
    // still currently use an external Bluetooth adapter since there is only
    // one Bluetooth adapter to choose from).
    break;
  }

  if (!found_bt_adapter) {
    LOG(INFO) << "Didn't find a Bluetooth adapter. Removing overrides.";
    bt.RemoveOverrides();
  }

  LOG(INFO) << "Exiting process_flex_bluetooth_overrides.";
  return 0;
}
