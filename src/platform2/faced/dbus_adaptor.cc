// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "faced/dbus_adaptor.h"

#include <string>
#include <utility>

#include <base/memory/scoped_refptr.h>
#include <chromeos/dbus/service_constants.h>
#include <dbus/bus.h>

namespace faced {

DBusAdaptor::DBusAdaptor(scoped_refptr<dbus::Bus> bus,
                         FaceAuthServiceInterface& face_auth_service)
    : org::chromium::FaceAuthDaemonAdaptor(this),
      dbus_object_(nullptr, bus, dbus::ObjectPath(kFaceAuthDaemonPath)),
      face_auth_service_(face_auth_service) {}

void DBusAdaptor::RegisterAsync(
    brillo::dbus_utils::AsyncEventSequencer::CompletionAction cb) {
  RegisterWithDBusObject(&dbus_object_);
  dbus_object_.RegisterAsync(std::move(cb));
}

void DBusAdaptor::BootstrapMojoConnection(
    BootstrapMojoConnectionCallback response,
    const base::ScopedFD& file_handle) {
  // Duplicate the input file handle.
  //
  // libbrillo's D-Bus wrappers currently don't support passing us a
  // base::ScopedFD by value, so we need to duplicate the underlying
  // FD so that we retain ownership.
  base::ScopedFD ipc_handle(HANDLE_EINTR(dup(file_handle.get())));

  if (!ipc_handle.is_valid()) {
    brillo::ErrorPtr err = brillo::Error::Create(
        FROM_HERE, "faced", "INTERNAL", "file descriptor is not valid");
    std::move(response)->ReplyWithError(err.get());
    return;
  }

  if (!base::SetCloseOnExec(ipc_handle.get())) {
    brillo::ErrorPtr err =
        brillo::Error::Create(FROM_HERE, "faced", "INTERNAL",
                              "Failed setting FD_CLOEXEC on file descriptor");
    std::move(response)->ReplyWithError(err.get());
    return;
  }

  scoped_refptr<dbus::Bus> bus = dbus_object_.GetBus();

  face_auth_service_.ReceiveMojoInvitation(
      std::move(ipc_handle),
      base::BindOnce(&DBusAdaptor::OnBootstrapMojoConnectionResponse,
                     weak_ptr_factory_.GetWeakPtr(), std::move(response)),
      base::WrapRefCounted(bus->GetDBusTaskRunner()));
}

void DBusAdaptor::OnBootstrapMojoConnectionResponse(
    BootstrapMojoConnectionCallback response, bool success) {
  scoped_refptr<dbus::Bus> bus = dbus_object_.GetBus();
  DCHECK(bus->GetDBusTaskRunner()->RunsTasksInCurrentSequence());

  if (success) {
    std::move(response)->Return();
    return;
  }

  brillo::ErrorPtr err = brillo::Error::Create(FROM_HERE, "faced", "INTERNAL",
                                               "Failure Bootstrapping Mojo");
  std::move(response)->ReplyWithError(err.get());
}

}  // namespace faced
