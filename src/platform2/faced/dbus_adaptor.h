// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef FACED_DBUS_ADAPTOR_H_
#define FACED_DBUS_ADAPTOR_H_

#include <memory>

#include <base/memory/weak_ptr.h>
#include <brillo/dbus/dbus_object.h>
#include <dbus/exported_object.h>

#include "faced/dbus_adaptors/org.chromium.FaceAuthDaemon.h"
#include "faced/face_auth_service.h"

namespace faced {

// DBusAdaptor is used to expose methods/objects to DBus
class DBusAdaptor : public org::chromium::FaceAuthDaemonInterface,
                    public org::chromium::FaceAuthDaemonAdaptor {
 public:
  DBusAdaptor(scoped_refptr<dbus::Bus> bus,
              FaceAuthServiceInterface& face_auth_service);
  ~DBusAdaptor() override = default;

  // Disallow copy and move.
  DBusAdaptor(const DBusAdaptor&) = delete;
  DBusAdaptor& operator=(const DBusAdaptor&) = delete;

  // Register DBus objects
  void RegisterAsync(
      brillo::dbus_utils::AsyncEventSequencer::CompletionAction cb);

  using BootstrapMojoConnectionCallback =
      std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<>>;

  // `FaceAuthDaemonInterface` implementation.
  //
  // This method takes a handle to a Mojo message pipe which will then be
  // bound to an implementation of the FaceAuthenticationService Mojo interface.
  void BootstrapMojoConnection(BootstrapMojoConnectionCallback response,
                               const base::ScopedFD& file_handle) override;

 private:
  void OnBootstrapMojoConnectionResponse(
      BootstrapMojoConnectionCallback response, bool success);

  brillo::dbus_utils::DBusObject dbus_object_;

  FaceAuthServiceInterface& face_auth_service_;

  base::WeakPtrFactory<DBusAdaptor> weak_ptr_factory_{this};
};

}  // namespace faced

#endif  // FACED_DBUS_ADAPTOR_H_
