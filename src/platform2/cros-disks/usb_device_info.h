// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CROS_DISKS_USB_DEVICE_INFO_H_
#define CROS_DISKS_USB_DEVICE_INFO_H_

#include <map>
#include <string>

#include <chromeos/dbus/service_constants.h>
#include <gtest/gtest_prod.h>

namespace cros_disks {

struct USBDeviceEntry;

// A class for querying information from a USB device info file.
class USBDeviceInfo {
 public:
  USBDeviceInfo();
  USBDeviceInfo(const USBDeviceInfo&) = delete;
  USBDeviceInfo& operator=(const USBDeviceInfo&) = delete;

  ~USBDeviceInfo();

  // Returns the device media type of a USB device with |vendor_id| and
  // |product_id|.
  DeviceType GetDeviceMediaType(const std::string& vendor_id,
                                const std::string& product_id) const;

  // Retrieves the list of USB device info from a file at |path|.
  // Returns true on success.
  bool RetrieveFromFile(const std::string& path);

  // Gets the vendor and product name that correspond to |vendor_id| and
  // |product_id| from a USB ID database at |ids_file|.
  bool GetVendorAndProductName(const std::string& ids_file,
                               const std::string& vendor_id,
                               const std::string& product_id,
                               std::string* vendor_name,
                               std::string* product_name);

 private:
  // Converts from string to enum of a device media type.
  DeviceType ConvertToDeviceMediaType(const std::string& str) const;

  // Returns true if |line| contains a 4-digit hex identifier and a name
  // separated by two spaces, i.e. "<4-digit hex ID>  <descriptive name>".
  // The extracted identifier and name are returned via |id| and |name|,
  // respectively.
  bool ExtractIdAndName(const std::string& line,
                        std::string* id,
                        std::string* name) const;

  // Returns true if |line| is skippable, i.e. an empty or comment line.
  bool IsLineSkippable(const std::string& line) const;

  // A map from an ID string, in form of <vendor id>:<product id>, to a
  // USBDeviceEntry struct.
  std::map<std::string, USBDeviceEntry> entries_;

  FRIEND_TEST(USBDeviceInfoTest, ConvertToDeviceMediaType);
  FRIEND_TEST(USBDeviceInfoTest, ExtractIdAndName);
  FRIEND_TEST(USBDeviceInfoTest, IsLineSkippable);
};

}  // namespace cros_disks

#endif  // CROS_DISKS_USB_DEVICE_INFO_H_
