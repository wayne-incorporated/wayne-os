// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "brillo/usb/usb_device_event_notifier.h"

#include <limits>

#include <base/check.h>
#include <base/functional/bind.h>
#include <base/functional/callback_helpers.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/stringprintf.h>
#include <brillo/udev/udev.h>
#include <brillo/udev/udev_device.h>
#include <brillo/udev/udev_enumerate.h>
#include <brillo/udev/udev_monitor.h>

#include "brillo/usb/usb_device_event_observer.h"

namespace brillo {

namespace {

const char kAttributeBusNumber[] = "busnum";
const char kAttributeDeviceAddress[] = "devnum";
const char kAttributeIdProduct[] = "idProduct";
const char kAttributeIdVendor[] = "idVendor";

}  // namespace

UsbDeviceEventNotifier::UsbDeviceEventNotifier(brillo::Udev* udev)
    : udev_(udev) {
  CHECK(udev_);
}

UsbDeviceEventNotifier::~UsbDeviceEventNotifier() = default;

bool UsbDeviceEventNotifier::Initialize() {
  udev_monitor_ = udev_->CreateMonitorFromNetlink("udev");
  if (!udev_monitor_) {
    LOG(ERROR) << "Could not create udev monitor.";
    return false;
  }

  if (!udev_monitor_->FilterAddMatchSubsystemDeviceType("usb", "usb_device")) {
    LOG(ERROR) << "Could not add udev monitor filter.";
    return false;
  }

  if (!udev_monitor_->EnableReceiving()) {
    LOG(ERROR) << "Could not enable udev monitoring.";
    return false;
  }

  int udev_monitor_fd = udev_monitor_->GetFileDescriptor();
  if (udev_monitor_fd == brillo::UdevMonitor::kInvalidFileDescriptor) {
    LOG(ERROR) << "Could not get udev monitor file descriptor.";
    return false;
  }

  udev_monitor_watcher_ = base::FileDescriptorWatcher::WatchReadable(
      udev_monitor_fd,
      base::BindRepeating(
          &UsbDeviceEventNotifier::OnUdevMonitorFileDescriptorReadable,
          base::Unretained(this)));
  if (!udev_monitor_watcher_) {
    LOG(ERROR) << "Could not watch udev monitor file descriptor.";
    return false;
  }

  return true;
}

bool UsbDeviceEventNotifier::ScanExistingDevices() {
  std::unique_ptr<brillo::UdevEnumerate> enumerate = udev_->CreateEnumerate();
  if (!enumerate || !enumerate->AddMatchSubsystem("usb") ||
      !enumerate->AddMatchProperty("DEVTYPE", "usb_device") ||
      !enumerate->ScanDevices()) {
    LOG(ERROR) << "Could not enumerate USB devices on the system.";
    return false;
  }

  for (std::unique_ptr<brillo::UdevListEntry> list_entry =
           enumerate->GetListEntry();
       list_entry; list_entry = list_entry->GetNext()) {
    std::string sys_path = ConvertNullToEmptyString(list_entry->GetName());

    std::unique_ptr<brillo::UdevDevice> device =
        udev_->CreateDeviceFromSysPath(sys_path.c_str());
    if (!device)
      continue;

    uint8_t bus_number;
    uint8_t device_address;
    uint16_t vendor_id;
    uint16_t product_id;
    if (!GetDeviceAttributes(device.get(), &bus_number, &device_address,
                             &vendor_id, &product_id))
      continue;

    for (UsbDeviceEventObserver& observer : observer_list_) {
      observer.OnUsbDeviceAdded(sys_path, bus_number, device_address, vendor_id,
                                product_id);
    }
  }
  return true;
}

void UsbDeviceEventNotifier::AddObserver(UsbDeviceEventObserver* observer) {
  CHECK(observer);

  observer_list_.AddObserver(observer);
}

void UsbDeviceEventNotifier::RemoveObserver(UsbDeviceEventObserver* observer) {
  CHECK(observer);

  observer_list_.RemoveObserver(observer);
}

void UsbDeviceEventNotifier::OnUdevMonitorFileDescriptorReadable() {
  VLOG(3) << "Udev file descriptor available for read.";

  std::unique_ptr<brillo::UdevDevice> device = udev_monitor_->ReceiveDevice();
  if (!device) {
    LOG(WARNING) << "Ignore device event with no associated udev device.";
    return;
  }

  VLOG(1) << base::StringPrintf(
      "udev (SysPath=%s, "
      "Node=%s, "
      "Subsystem=%s, "
      "DevType=%s, "
      "Action=%s, "
      "BusNumber=%s, "
      "DeviceAddress=%s, "
      "VendorId=%s, "
      "ProductId=%s)",
      device->GetSysPath(), device->GetDeviceNode(), device->GetSubsystem(),
      device->GetDeviceType(), device->GetAction(),
      device->GetSysAttributeValue(kAttributeBusNumber),
      device->GetSysAttributeValue(kAttributeDeviceAddress),
      device->GetSysAttributeValue(kAttributeIdVendor),
      device->GetSysAttributeValue(kAttributeIdProduct));

  std::string sys_path = ConvertNullToEmptyString(device->GetSysPath());
  if (sys_path.empty()) {
    LOG(WARNING) << "Ignore device event with no device sysfs path.";
    return;
  }

  std::string action = ConvertNullToEmptyString(device->GetAction());
  if (action == "add") {
    uint8_t bus_number;
    uint8_t device_address;
    uint16_t vendor_id;
    uint16_t product_id;
    if (!GetDeviceAttributes(device.get(), &bus_number, &device_address,
                             &vendor_id, &product_id)) {
      LOG(WARNING) << "Ignore device event of unidentifiable device.";
      return;
    }

    for (UsbDeviceEventObserver& observer : observer_list_) {
      observer.OnUsbDeviceAdded(sys_path, bus_number, device_address, vendor_id,
                                product_id);
    }
    return;
  }

  if (action == "remove") {
    for (UsbDeviceEventObserver& observer : observer_list_)
      observer.OnUsbDeviceRemoved(sys_path);
  }
}

// static
std::string UsbDeviceEventNotifier::ConvertNullToEmptyString(const char* str) {
  return str ? str : std::string();
}

// static
bool UsbDeviceEventNotifier::ConvertHexStringToUint16(const std::string& str,
                                                      uint16_t* value) {
  int temp_value = -1;
  if (str.size() != 4 || !base::HexStringToInt(str, &temp_value) ||
      temp_value < 0 || temp_value > std::numeric_limits<uint16_t>::max()) {
    return false;
  }

  *value = static_cast<uint16_t>(temp_value);
  return true;
}

// static
bool UsbDeviceEventNotifier::ConvertStringToUint8(const std::string& str,
                                                  uint8_t* value) {
  unsigned temp_value = 0;
  if (!base::StringToUint(str, &temp_value) ||
      temp_value > std::numeric_limits<uint8_t>::max()) {
    return false;
  }

  *value = static_cast<uint8_t>(temp_value);
  return true;
}

// static
bool UsbDeviceEventNotifier::GetDeviceAttributes(
    const brillo::UdevDevice* device,
    uint8_t* bus_number,
    uint8_t* device_address,
    uint16_t* vendor_id,
    uint16_t* product_id) {
  std::string bus_number_string = ConvertNullToEmptyString(
      device->GetSysAttributeValue(kAttributeBusNumber));
  if (!ConvertStringToUint8(bus_number_string, bus_number)) {
    LOG(WARNING) << "Invalid USB bus number '" << bus_number_string << "'.";
    return false;
  }

  std::string device_address_string = ConvertNullToEmptyString(
      device->GetSysAttributeValue(kAttributeDeviceAddress));
  if (!ConvertStringToUint8(device_address_string, device_address)) {
    LOG(WARNING) << "Invalid USB device address '" << device_address_string
                 << "'.";
    return false;
  }

  std::string vendor_id_string = ConvertNullToEmptyString(
      device->GetSysAttributeValue(kAttributeIdVendor));
  if (!ConvertHexStringToUint16(vendor_id_string, vendor_id)) {
    LOG(WARNING) << "Invalid USB vendor ID '" << vendor_id_string << "'.";
    return false;
  }

  std::string product_id_string = ConvertNullToEmptyString(
      device->GetSysAttributeValue(kAttributeIdProduct));
  if (!ConvertHexStringToUint16(product_id_string, product_id)) {
    LOG(WARNING) << "Invalid USB product ID '" << product_id_string << "'.";
    return false;
  }

  return true;
}

}  // namespace brillo
