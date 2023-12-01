// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_CELLULAR_MODEM_H_
#define SHILL_CELLULAR_MODEM_H_

#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <base/files/file_util.h>
#include <gtest/gtest_prod.h>  // for FRIEND_TEST

#include "shill/cellular/cellular.h"
#include "shill/cellular/dbus_objectmanager_proxy_interface.h"
#include "shill/refptr_types.h"

namespace shill {

class DeviceInfo;

// Handles an instance of ModemManager.Modem and an instance of a Cellular
// device.
class Modem {
 public:
  // ||path| is the ModemManager.Modem DBus object path (e.g.,
  // "/org/freedesktop/ModemManager1/Modem/0").
  Modem(const std::string& service,
        const RpcIdentifier& path,
        DeviceInfo* device_info);
  Modem(const Modem&) = delete;
  Modem& operator=(const Modem&) = delete;

  ~Modem();

  // Gathers information and passes it to CreateDeviceFromModemProperties.
  void CreateDevice(const InterfaceToProperties& properties);

  void OnDeviceInfoAvailable(const std::string& link_name);

  const std::string& link_name() const { return link_name_; }
  const std::string& service() const { return service_; }
  const RpcIdentifier& path() const { return path_; }

  std::optional<int> interface_index_for_testing() const {
    return interface_index_;
  }
  bool has_pending_device_info_for_testing() const {
    return has_pending_device_info_;
  }

  // Constants associated with fake network devices for PPP dongles.
  // See |fake_dev_serial_|, below, for more info.
  static constexpr char kFakeDevNameFormat[] = "no_netdev_%zu";
  static const char kFakeDevAddress[];
  static const int kFakeDevInterfaceIndex;

 private:
  friend class ModemTest;

  bool GetLinkName(const KeyValueStore& properties, std::string* name) const;

  // Asynchronously initializes support for the modem.
  // If the |properties| are valid and the MAC address is present,
  // constructs and registers a Cellular device in |device_| based on
  // |properties|.
  void CreateDeviceFromModemProperties(const InterfaceToProperties& properties);

  // Finds the interface index and MAC address for the kernel network device
  // with name |link_name_|. If no interface index exists, returns nullopt.
  // Otherwise sets |mac_address| if available and returns the interface index.
  std::optional<int> GetLinkDetailsFromDeviceInfo(std::string* mac_address);

  CellularRefPtr GetOrCreateCellularDevice(int interface_index,
                                           const std::string& mac_address);
  CellularRefPtr GetExistingCellularDevice(int interface_index) const;

  InterfaceToProperties initial_properties_;

  const std::string service_;
  const RpcIdentifier path_;

  DeviceInfo* device_info_;
  std::optional<int> interface_index_;
  std::string link_name_;
  bool has_pending_device_info_ = false;

  // Serial number used to uniquify fake device names for Cellular
  // devices that don't have network devices. (Names must be unique
  // for D-Bus, and PPP dongles don't have network devices.)
  static size_t fake_dev_serial_;
};

}  // namespace shill

#endif  // SHILL_CELLULAR_MODEM_H_
