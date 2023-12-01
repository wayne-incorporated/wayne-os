// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MEDIA_PERCEPTION_CROS_DBUS_SERVICE_H_
#define MEDIA_PERCEPTION_CROS_DBUS_SERVICE_H_

#include "media_perception/dbus_service.h"

#include <dbus/dbus.h>
#include <string>
#include <vector>

#include "media_perception/mojo_connector.h"

namespace mri {

class CrOSDbusService : public DbusService {
 public:
  CrOSDbusService() : connection_(nullptr) {}
  CrOSDbusService(const CrOSDbusService&) = delete;
  CrOSDbusService& operator=(const CrOSDbusService&) = delete;

  // |mojo_connector| is owned externally but is instantiated in the main() so
  // it will live for as long as the program is running.
  void SetMojoConnector(MojoConnector* mojo_connector) {
    mojo_connector_ = mojo_connector;
  }

  // Disconnects dbus connection.
  ~CrOSDbusService() override;

  // Establishes dbus connection. bus_type could be either DBUS_BUS_SYSTEM or
  // DBUS_BUS_SESSION in order to use system bus or session bus, respectively.
  // service_ownership_mask is a bitmask that indicates how this service
  // provider is going to own the service name. All valid bitmasks can be found
  // in third_party/dbus/src/dbus/dbus-shared.h. For example,
  // Connect(DBUS_BUS_SYSTEM, DBUS_NAME_FLAG_REPLACE_EXISTING) means this
  // dbus entity will be connected to system bus, and take ownership of the
  // service name from the exitsing owner (if there is any).
  void Connect(const mri::Service service) override;

  // Checks if dbus connection has been established.
  bool IsConnected() const override;

  // Publish a signal to dbus.
  bool PublishSignal(const mri::Signal signal,
                     const std::vector<uint8_t>* bytes) override;

  // Polls the message queue periodically for handling dbus method calls. Valid
  // requests will be processed by the set MessageHandler.
  void PollMessageQueue() override;

 private:
  // Processes this dbus message and stores the reply in |bytes|. Return value
  // indicates if processing the message was successful and if a reply should be
  // sent.
  bool ProcessMessage(DBusMessage* message, std::vector<uint8_t>* bytes);

  // This mutex is used to guard concurrent access to the dbus connection.
  mutable std::mutex connection_lock_;

  // The service takes ownership of the pointer. Its deletion or decommissioning
  // has to be handled specifically by dbus_connection_unref().
  DBusConnection* connection_;

  // The MojoConnector object pointer for bootstrapping the mojo connection over
  // D-Bus.
  MojoConnector* mojo_connector_;
};

}  // namespace mri

#endif  // MEDIA_PERCEPTION_CROS_DBUS_SERVICE_H_
