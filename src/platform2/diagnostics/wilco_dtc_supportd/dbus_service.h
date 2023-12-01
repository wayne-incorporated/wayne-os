// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_WILCO_DTC_SUPPORTD_DBUS_SERVICE_H_
#define DIAGNOSTICS_WILCO_DTC_SUPPORTD_DBUS_SERVICE_H_

#include <memory>

#include <base/files/scoped_file.h>
#include <base/memory/scoped_refptr.h>
#include <brillo/dbus/async_event_sequencer.h>
#include <brillo/dbus/dbus_object.h>
#include <brillo/errors/error.h>

namespace diagnostics {
namespace wilco {

class MojoServiceFactory;

// Implements the "org.chromium.WilcoDtcSupportdInterface" D-Bus interface
// exposed by the wilco_dtc_supportd daemon (see constants for the API methods
// at src/platform/system_api/dbus/wilco_dtc_supportd/dbus-constants.h).
class DBusService final {
 public:
  explicit DBusService(MojoServiceFactory* mojo_service_factory);
  DBusService(const DBusService&) = delete;
  DBusService& operator=(const DBusService&) = delete;

  ~DBusService();

  // Implementation of the "org.chromium.WilcoDtcSupportdInterface" D-Bus
  // interface:
  bool BootstrapMojoConnection(brillo::ErrorPtr* error,
                               const base::ScopedFD& mojo_fd);

  // Registers the D-Bus object that the wilco_dtc_supportd daemon exposes and
  // ties methods exposed by this object with the actual implementation.
  void RegisterDBusObjectsAsync(
      const scoped_refptr<dbus::Bus>& bus,
      brillo::dbus_utils::AsyncEventSequencer* sequencer);

  // Destroys |dbus_object_|.
  void ShutDown();

 private:
  // Unowned. The factory should outlive this instance.
  MojoServiceFactory* const mojo_service_factory_ = nullptr;

  // Manages the D-Bus interfaces exposed by the wilco_dtc_supportd daemon.
  std::unique_ptr<brillo::dbus_utils::DBusObject> dbus_object_;
};

}  // namespace wilco
}  // namespace diagnostics

#endif  // DIAGNOSTICS_WILCO_DTC_SUPPORTD_DBUS_SERVICE_H_
