// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBBRILLO_BRILLO_USB_USB_DEVICE_EVENT_NOTIFIER_H_
#define LIBBRILLO_BRILLO_USB_USB_DEVICE_EVENT_NOTIFIER_H_

#include <stdint.h>

#include <memory>
#include <string>

#include <base/files/file_descriptor_watcher_posix.h>
#include <base/observer_list.h>
#include <brillo/brillo_export.h>
#include <gtest/gtest_prod.h>

namespace brillo {

class Udev;
class UdevDevice;
class UdevMonitor;

}  // namespace brillo

namespace brillo {

class UsbDeviceEventObserver;

// A USB device event notifier, which monitors udev events for USB devices and
// notifies registered observers that implement UsbDeviceEventObserver
// interface.
class BRILLO_EXPORT UsbDeviceEventNotifier {
 public:
  // Constructs a UsbDeviceEventNotifier object by taking a raw pointer to a
  // brillo::Udev as |udev|. The ownership of |udev| is not transferred, and
  // thus they should outlive this object.
  explicit UsbDeviceEventNotifier(brillo::Udev* udev);
  UsbDeviceEventNotifier(const UsbDeviceEventNotifier&) = delete;
  UsbDeviceEventNotifier& operator=(const UsbDeviceEventNotifier&) = delete;

  ~UsbDeviceEventNotifier();

  // Initializes USB device event monitoring such that this object can notify
  // registered observers upon USB device events. Returns true on success.
  bool Initialize();

  // Scans existing USB devices on the system and notify registered observers
  // of these devices via UsbDeviceEventObserver::OnUsbDeviceAdded().
  bool ScanExistingDevices();

  // Adds |observer| to the observer list such that |observer| will be notified
  // on USB device events.
  void AddObserver(UsbDeviceEventObserver* observer);

  // Removes |observer| from the observer list such that |observer| will no
  // longer be notified on USB device events.
  void RemoveObserver(UsbDeviceEventObserver* observer);

  // Gets the bus number, device address, vendor ID, and product ID of |device|.
  // Return true on success.
  static bool GetDeviceAttributes(const brillo::UdevDevice* device,
                                  uint8_t* bus_number,
                                  uint8_t* device_address,
                                  uint16_t* vendor_id,
                                  uint16_t* product_id);

 private:
  FRIEND_TEST(UsbDeviceEventNotifierStaticTest, ConvertHexStringToUint16);
  FRIEND_TEST(UsbDeviceEventNotifierStaticTest, ConvertNullToEmptyString);
  FRIEND_TEST(UsbDeviceEventNotifierStaticTest, ConvertStringToUint8);
  FRIEND_TEST(UsbDeviceEventNotifierTest, OnUsbDeviceEventNotAddOrRemove);
  FRIEND_TEST(UsbDeviceEventNotifierTest, OnUsbDeviceEventWithInvalidBusNumber);
  FRIEND_TEST(UsbDeviceEventNotifierTest,
              OnUsbDeviceEventWithInvalidDeviceAddress);
  FRIEND_TEST(UsbDeviceEventNotifierTest, OnUsbDeviceEventWithInvalidProductId);
  FRIEND_TEST(UsbDeviceEventNotifierTest, OnUsbDeviceEventWithInvalidVendorId);
  FRIEND_TEST(UsbDeviceEventNotifierTest, OnUsbDeviceEvents);

  // Called when udev_monitor_'s file descriptor gets readable.
  void OnUdevMonitorFileDescriptorReadable();

  // Returns a string with value of |str| if |str| is not NULL, or an empty
  // string otherwise.
  static std::string ConvertNullToEmptyString(const char* str);

  // Converts a 4-digit hexadecimal ID string without the 0x prefix (e.g. USB
  // vendor/product ID) into an unsigned 16-bit value. Return true on success.
  static bool ConvertHexStringToUint16(const std::string& str, uint16_t* value);

  // Converts a decimal string, which denotes an integer between 0 and 255, into
  // an unsigned 8-bit integer. Return true on success.
  static bool ConvertStringToUint8(const std::string& str, uint8_t* value);

  base::ObserverList<UsbDeviceEventObserver> observer_list_;
  brillo::Udev* const udev_;
  std::unique_ptr<brillo::UdevMonitor> udev_monitor_;
  std::unique_ptr<base::FileDescriptorWatcher::Controller>
      udev_monitor_watcher_;
};

}  // namespace brillo

#endif  // LIBBRILLO_BRILLO_USB_USB_DEVICE_EVENT_NOTIFIER_H_
