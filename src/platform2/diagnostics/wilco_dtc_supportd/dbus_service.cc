// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/wilco_dtc_supportd/dbus_service.h"

#include <optional>
#include <string>

#include <base/check.h>
#include <base/location.h>
#include <base/logging.h>
#include <brillo/errors/error_codes.h>
#include <dbus/dbus-protocol.h>
#include <dbus/object_path.h>
#include <dbus/wilco_dtc_supportd/dbus-constants.h>

#include "diagnostics/wilco_dtc_supportd/mojo_service_factory.h"

namespace diagnostics {
namespace wilco {

DBusService::DBusService(MojoServiceFactory* mojo_service_factory)
    : mojo_service_factory_(mojo_service_factory) {
  DCHECK(mojo_service_factory_);
}

DBusService::~DBusService() = default;

bool DBusService::BootstrapMojoConnection(brillo::ErrorPtr* error,
                                          const base::ScopedFD& mojo_fd) {
  VLOG(0) << "Received BootstrapMojoConnection D-Bus request";
  const std::optional<std::string> bootstrap_error =
      mojo_service_factory_->BootstrapMojoConnection(mojo_fd);
  if (bootstrap_error.has_value()) {
    *error = brillo::Error::Create(FROM_HERE, brillo::errors::dbus::kDomain,
                                   DBUS_ERROR_FAILED, bootstrap_error.value());
    return false;
  }
  return true;
}

void DBusService::RegisterDBusObjectsAsync(
    const scoped_refptr<dbus::Bus>& bus,
    brillo::dbus_utils::AsyncEventSequencer* sequencer) {
  DCHECK(bus);
  DCHECK(!dbus_object_);
  dbus_object_ = std::make_unique<brillo::dbus_utils::DBusObject>(
      nullptr /* object_manager */, bus,
      dbus::ObjectPath(kWilcoDtcSupportdServicePath));
  brillo::dbus_utils::DBusInterface* dbus_interface =
      dbus_object_->AddOrGetInterface(kWilcoDtcSupportdServiceInterface);
  DCHECK(dbus_interface);
  dbus_interface->AddSimpleMethodHandlerWithError(
      kWilcoDtcSupportdBootstrapMojoConnectionMethod, base::Unretained(this),
      &DBusService::BootstrapMojoConnection);
  dbus_object_->RegisterAsync(sequencer->GetHandler(
      "Failed to register D-Bus object" /* descriptive_message */,
      true /* failure_is_fatal */));
}

void DBusService::ShutDown() {
  dbus_object_.reset();
}

}  // namespace wilco
}  // namespace diagnostics
