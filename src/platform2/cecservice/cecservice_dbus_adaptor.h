// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CECSERVICE_CECSERVICE_DBUS_ADAPTOR_H_
#define CECSERVICE_CECSERVICE_DBUS_ADAPTOR_H_

#include <memory>
#include <vector>

#include <base/memory/ref_counted.h>
#include <brillo/dbus/dbus_object.h>
#include <dbus/bus.h>

#include "cecservice/cec_device.h"
#include "cecservice/cec_fd.h"
#include "cecservice/cec_manager.h"
#include "cecservice/dbus_adaptors/org.chromium.CecService.h"

namespace cecservice {

class CecServiceDBusAdaptor : public org::chromium::CecServiceAdaptor,
                              public org::chromium::CecServiceInterface {
 public:
  explicit CecServiceDBusAdaptor(scoped_refptr<dbus::Bus> bus);
  CecServiceDBusAdaptor(const CecServiceDBusAdaptor&) = delete;
  CecServiceDBusAdaptor& operator=(const CecServiceDBusAdaptor&) = delete;

  ~CecServiceDBusAdaptor() override;

  // Register the D-Bus object and interfaces.
  void RegisterAsync(
      brillo::dbus_utils::AsyncEventSequencer::CompletionAction cb);

  // org::chromium::CecServiceInterface overrides; D-Bus methods.
  void GetTvsPowerStatus(std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
                             std::vector<int32_t>>> response) override;
  bool SendStandByToAllDevices(brillo::ErrorPtr* error) override;
  bool SendWakeUpToAllDevices(brillo::ErrorPtr* error) override;

 private:
  CecFdOpenerImpl cec_fd_opener_;
  CecDeviceFactoryImpl cec_device_factory_;
  CecManager cec_;
  brillo::dbus_utils::DBusObject dbus_object_;
};

}  // namespace cecservice

#endif  // CECSERVICE_CECSERVICE_DBUS_ADAPTOR_H_
