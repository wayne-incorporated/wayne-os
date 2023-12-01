// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef IIOSERVICE_DAEMON_DAEMON_H_
#define IIOSERVICE_DAEMON_DAEMON_H_

#include <memory>
#include <string>

#include <base/memory/weak_ptr.h>
#include <brillo/daemons/dbus_daemon.h>
#include <dbus/exported_object.h>
#include <mojo/core/embedder/scoped_ipc_support.h>
#include <mojo_service_manager/lib/connect.h>

#include "iioservice/daemon/iio_sensor.h"

namespace iioservice {

class Daemon : public brillo::DBusDaemon {
 public:
  ~Daemon() override;

 protected:
  // brillo::DBusDaemon:
  int OnInit() override;

 private:
  // This function initializes the D-Bus service. The primary function of the
  // D-Bus interface is to get notified by mems_setup that a device is ready to
  // be used.
  void InitDBus();

  void ConnectToMojoServiceManager();

  void ServiceManagerDisconnected(uint32_t custom_reason,
                                  const std::string& description);

  // Method called when kMemsSetupDoneMethod is received from mems_setup.
  // Handles reporting of a device setup by mems_setup and ready to be used.
  void HandleMemsSetupDone(
      dbus::MethodCall* method_call,
      dbus::ExportedObject::ResponseSender response_sender);
  // Method called when kMemsRemoveDoneMethod is received from mems_setup.
  // Handles reporting of a device removed and no longer available.
  void HandleMemsRemoveDone(
      dbus::MethodCall* method_call,
      dbus::ExportedObject::ResponseSender response_sender);

  // IPC Support
  std::unique_ptr<mojo::core::ScopedIPCSupport> ipc_support_;

  mojo::Remote<chromeos::mojo_service_manager::mojom::ServiceManager>
      service_manager_;

  IioSensor::ScopedIioSensor iio_sensor_ = {nullptr,
                                            IioSensor::IioSensorDeleter};

  // Must be last class member.
  base::WeakPtrFactory<Daemon> weak_factory_{this};
};

}  // namespace iioservice

#endif  // IIOSERVICE_DAEMON_DAEMON_H_
