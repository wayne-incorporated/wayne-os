// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_DEVICE_ID_H_
#define SHILL_DEVICE_ID_H_

#include <stdint.h>

#include <memory>
#include <optional>
#include <ostream>
#include <string>

#include <base/files/file_path.h>

namespace shill {

// DeviceId is meant to encapsulate a device type so we can implement a quirks
// layer on top of network controller devices if we need to.
class DeviceId {
 public:
  // Add more bus types here as they need to be supported.
  enum class BusType {
    kPci,
    kUsb,
    kSoc,
  };

  // Location of the device (Currently only supported for PCI devices).
  enum class LocationType {
    kInternal,
    kExternal,
  };

  // Takes a device |syspath| as would be given by e.g. udev and tries to read
  // the bus type and device identifiers.
  static std::unique_ptr<DeviceId> CreateFromSysfs(
      const base::FilePath& syspath);

  // DeviceId matching all devices by a particular bus type.
  explicit constexpr DeviceId(BusType bus_type) : bus_type_(bus_type) {}
  // DeviceId matching all devices on a particular bus and location type.
  // Location type is currently only supported for PCI devices.
  explicit constexpr DeviceId(BusType bus_type, LocationType location_type)
      : bus_type_(bus_type), location_type_(location_type) {}
  // DeviceId matching all devices by a particular bus type and vendor id.
  constexpr DeviceId(BusType bus_type, uint16_t vendor_id)
      : bus_type_(bus_type), vendor_id_(vendor_id) {}
  // DeviceId matching device by a particular bus type, vendor id and
  // product id.
  constexpr DeviceId(BusType bus_type, uint16_t vendor_id, uint16_t product_id)
      : bus_type_(bus_type), vendor_id_(vendor_id), product_id_(product_id) {}

  // Returns true if |this| matches |pattern|.
  //
  // If |pattern| vendor id is *, then they don't have to match VID and PID
  // values.
  //
  // If |pattern| product id is *, then they don't have to match PID values.
  bool Match(const DeviceId& pattern) const;

  // This string should be unique for each value of DeviceId, so it can
  // be used to index maps, etc.
  // Format: [bus type]:[vendor id, or "*" if unspecified]:
  //         [product id, or "*" if unspecified]
  std::string AsString() const;

 private:
  BusType bus_type_;
  std::optional<LocationType> location_type_;
  std::optional<uint16_t> vendor_id_;
  std::optional<uint16_t> product_id_;
};

std::ostream& operator<<(std::ostream& stream, const DeviceId& device_id);

}  // namespace shill

#endif  // SHILL_DEVICE_ID_H_
