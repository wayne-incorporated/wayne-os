// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "midis/daemon.h"

#include <fcntl.h>

#include <memory>
#include <utility>

#include <base/check.h>
#include <base/files/file_util.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <chromeos/dbus/service_constants.h>
#include <dbus/bus.h>
#include <dbus/message.h>

#include "midis/client_tracker.h"
#include "midis/device_tracker.h"

namespace midis {

Daemon::Daemon()
    : device_tracker_(std::make_unique<DeviceTracker>()),
      client_tracker_(std::make_unique<ClientTracker>()),
      weak_factory_(this) {}

Daemon::~Daemon() {}

int Daemon::OnInit() {
  if (!device_tracker_->InitDeviceTracker()) {
    return -1;
  }

  // It's OK to set |device_tracker_| here because the D-Bus connection
  // has not yet been initialized, so it is impossible for clients to be
  // registered.
  client_tracker_->SetDeviceTracker(device_tracker_.get());
  client_tracker_->InitClientTracker();
  InitDBus();
  return 0;
}

void Daemon::InitDBus() {
  dbus::Bus::Options options;
  options.bus_type = dbus::Bus::SYSTEM;
  scoped_refptr<dbus::Bus> bus(new dbus::Bus(options));
  CHECK(bus->Connect());
  dbus::ExportedObject* exported_object =
      bus->GetExportedObject(dbus::ObjectPath(kMidisServicePath));

  CHECK(exported_object);
  CHECK(exported_object->ExportMethodAndBlock(
      kMidisInterfaceName, kBootstrapMojoConnectionMethod,
      base::BindRepeating(&Daemon::BootstrapMojoConnection,
                          weak_factory_.GetWeakPtr())));
  CHECK(bus->RequestOwnershipAndBlock(kMidisServiceName,
                                      dbus::Bus::REQUIRE_PRIMARY));
  VLOG(1) << "D-Bus Registration succeeded";
}

void Daemon::BootstrapMojoConnection(
    dbus::MethodCall* method_call,
    dbus::ExportedObject::ResponseSender response_sender) {
  LOG(INFO) << "Successfully received call from D-Bus client.";
  if (client_tracker_->IsProxyConnected()) {
    LOG(WARNING) << "Midis can only instantiate one Mojo Proxy instance.";
    return;
  }

  base::ScopedFD file_handle;
  dbus::MessageReader reader(method_call);

  if (!reader.PopFileDescriptor(&file_handle)) {
    LOG(ERROR) << "Couldn't extract Mojo IPC handle.";
    return;
  }

  if (!file_handle.is_valid()) {
    LOG(ERROR) << "Couldn't get file handle sent over D-Bus.";
    return;
  }

  if (!base::SetCloseOnExec(file_handle.get())) {
    PLOG(ERROR) << "Failed setting FD_CLOEXEC on fd.";
    return;
  }

  client_tracker_->AcceptProxyConnection(std::move(file_handle));
  LOG(INFO) << "MojoBridger connection established.";
  std::unique_ptr<dbus::Response> response =
      dbus::Response::FromMethodCall(method_call);
  std::move(response_sender).Run(std::move(response));
}

}  // namespace midis
