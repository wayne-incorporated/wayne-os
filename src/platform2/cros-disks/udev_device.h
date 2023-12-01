// Copyright 2011 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CROS_DISKS_UDEV_DEVICE_H_
#define CROS_DISKS_UDEV_DEVICE_H_

#include <blkid/blkid.h>
#include <stdint.h>

#include <memory>
#include <string>
#include <vector>

#include <base/functional/callback.h>
#include <chromeos/dbus/service_constants.h>
#include <gtest/gtest_prod.h>

#include "cros-disks/disk.h"

namespace brillo {
class UdevDevice;
}  // namespace brillo

namespace cros_disks {

// A utility class that helps query information about a udev device.
class UdevDevice {
 public:
  explicit UdevDevice(std::unique_ptr<brillo::UdevDevice> dev);
  UdevDevice(const UdevDevice&) = delete;
  UdevDevice& operator=(const UdevDevice&) = delete;

  ~UdevDevice();

  // Gets the string value of a device attribute.
  std::string GetAttribute(const char* key) const;

  // Checks if the value of a device attribute represents a Boolean true.
  bool IsAttributeTrue(const char* key) const;

  // Checks if a device attribute exists.
  bool HasAttribute(const char* key) const;

  // Gets the string value of a device property.
  std::string GetProperty(const char* key) const;

  // Checks if the value of a device property represents a Boolean true.
  bool IsPropertyTrue(const char* key) const;

  // Checks if a device property exists.
  bool HasProperty(const char* key) const;

  // Gets the string value of a device property from blkid.
  std::string GetPropertyFromBlkId(const char* key);

  // Gets the total and remaining capacity of the device.
  void GetSizeInfo(uint64_t* total_size, uint64_t* remaining_size) const;

  // Gets the number of partitions on the device.
  size_t GetPartitionCount() const;

  // Gets the device media type used on the device.
  DeviceType GetDeviceMediaType() const;

  // Gets the USB vendor and product ID of the device. Returns true if the
  // IDs are found.
  bool GetVendorAndProductId(std::string* vendor_id,
                             std::string* product_id) const;

  // Gets the bus and device numbers for the device.
  void GetBusAndDeviceNumber(int* bus_number, int* device_number) const;

  // Checks if a device should be auto-mounted. Currently, all external
  // disk devices, which are neither on the boot device nor virtual,
  // are considered auto-mountable.
  bool IsAutoMountable() const;

  // Checks if a device should be hidden from the file browser.
  bool IsHidden();

  // Checks if the device is completely ignored by cros-disks. Unlike
  // IsAutoMountable() or IsHidden(), IsIgnored() prevents a device from being
  // reported by cros-disks during device enumeration and udev events, such that
  // the system does not even gather properties of the device. Currently, all
  // virtual devices, except loop devices, are ignored. Loop devices are used
  // by automated tests to simulate removable devices and thus not ignored.
  bool IsIgnored() const;

  // Checks if any media is available in the device.
  bool IsMediaAvailable() const;

  // Checks if the device is a mobile broadband device.
  bool IsMobileBroadbandDevice() const;

  // Checks if the device is on the boot device.
  bool IsOnBootDevice() const;

  // Checks if the device is on the removable device.
  bool IsOnRemovableDevice() const;

  // Checks if the device is a virtual device.
  bool IsVirtual() const;

  // Checks if the device is a loop device.
  bool IsLoopDevice() const;

  // Gets the native sysfs path of the device.
  std::string NativePath() const;

  // Gets the path of the storage device this device is a part of, if any.
  std::string StorageDevicePath() const;

  // Gets the mount paths for the device.
  std::vector<std::string> GetMountPaths() const;

  // Gets the mount paths for a given device path.
  static std::vector<std::string> GetMountPaths(const std::string& device_path);

  // Returns a Disk object based on the device information.
  Disk ToDisk();

 private:
  using EnumerateCallback =
      base::RepeatingCallback<bool(const brillo::UdevDevice& device)>;

  // Returns |str| if |str| is a valid UTF8 string (determined by
  // base::IsStringUTF8) or an empty string otherwise.
  static std::string EnsureUTF8String(const std::string& str);

  // Checks if the device is on a SD card device.
  bool IsOnSdDevice() const;

  // Walks up the device parents, starting at the current device, invoking
  // |callback| until |callback| returns true. Returns true if |callback|
  // returned true, and false if finished walking up the device tree.
  bool EnumerateParentDevices(EnumerateCallback callback) const;

  // Checks if a string contains a "1" (as Boolean true).
  static bool IsValueBooleanTrue(const char* value);

  const std::unique_ptr<brillo::UdevDevice> dev_;
  blkid_cache blkid_cache_;

  FRIEND_TEST(UdevDeviceTest, EnsureUTF8String);
  FRIEND_TEST(UdevDeviceTest, IsValueBooleanTrue);
};

}  // namespace cros_disks

#endif  // CROS_DISKS_UDEV_DEVICE_H_
