// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_VIRTUAL_DEVICE_H_
#define SHILL_VIRTUAL_DEVICE_H_

#include <memory>
#include <string>

#include "shill/device.h"
#include "shill/error.h"
#include "shill/ipconfig.h"
#include "shill/service.h"
#include "shill/technology.h"

namespace shill {

// A VirtualDevice represents a device that doesn't provide its own
// physical layer. This includes, e.g., tunnel interfaces used for
// OpenVPN, and PPP devices used for L2TPIPsec and 3G PPP dongles.
class VirtualDevice : public Device {
 public:
  VirtualDevice(Manager* manager,
                const std::string& link_name,
                int interface_index,
                Technology technology,
                bool fixed_ip_params = false);
  VirtualDevice(const VirtualDevice&) = delete;
  VirtualDevice& operator=(const VirtualDevice&) = delete;

  ~VirtualDevice() override;

  bool Load(const StoreInterface* storage) override;
  bool Save(StoreInterface* storage) override;

  void Start(EnabledStateChangedCallback callback) override;
  void Stop(EnabledStateChangedCallback callback) override;

  virtual void UpdateIPConfig(
      std::unique_ptr<IPConfig::Properties> ipv4_properties,
      std::unique_ptr<IPConfig::Properties> ipv6_properties);

  // Drops the current connection and the selected service, if any.  Does not
  // change the state of the previously selected service.
  mockable void ResetConnection();

  // Expose protected device methods to manager of this device.
  // (E.g. Cellular, L2TPIPsecDriver, OpenVPNDriver.)
  void DropConnection() override;
  virtual void SelectService(const ServiceRefPtr& service);
  void SetServiceState(Service::ConnectState state) override;
  void SetServiceFailure(Service::ConnectFailure failure_state) override;
  void SetServiceFailureSilent(Service::ConnectFailure failure_state) override;
};

}  // namespace shill

#endif  // SHILL_VIRTUAL_DEVICE_H_
