// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_DBUS_CLIENT_FAKE_CLIENT_H_
#define SHILL_DBUS_CLIENT_FAKE_CLIENT_H_

#include <memory>
#include <vector>

#include "shill/dbus/client/client.h"

namespace shill {

class BRILLO_EXPORT FakeClient : public Client {
 public:
  explicit FakeClient(scoped_refptr<dbus::Bus> bus);
  virtual ~FakeClient() = default;

  // Client methods.

  void RegisterOnAvailableCallback(
      base::OnceCallback<void(bool)> handler) override;
  void RegisterProcessChangedHandler(
      const base::RepeatingCallback<void(bool)>& handler) override;
  void RegisterDefaultServiceChangedHandler(
      const DefaultServiceChangedHandler& handler) override;
  void RegisterDefaultDeviceChangedHandler(
      const DeviceChangedHandler& handler) override;
  void RegisterDeviceChangedHandler(
      const DeviceChangedHandler& handler) override;
  void RegisterDeviceAddedHandler(const DeviceChangedHandler& handler) override;
  void RegisterDeviceRemovedHandler(
      const DeviceChangedHandler& handler) override;

  std::unique_ptr<ManagerPropertyAccessor> ManagerProperties(
      const base::TimeDelta& timeout) const override;

  std::unique_ptr<Client::Device> DefaultDevice(bool exclude_vpn) override;
  std::vector<std::unique_ptr<Device>> GetDevices() const override;

 protected:
  base::OnceCallback<void(bool)> available_handler_;
  base::RepeatingCallback<void(bool)> process_handler_;
  std::vector<DefaultServiceChangedHandler> default_service_handlers_;
  std::vector<DeviceChangedHandler> default_device_handlers_;
  std::vector<DeviceChangedHandler> device_handlers_;
  std::vector<DeviceChangedHandler> device_added_handlers_;
  std::vector<DeviceChangedHandler> device_removed_handlers_;
};

}  // namespace shill

#endif  // SHILL_DBUS_CLIENT_FAKE_CLIENT_H_
