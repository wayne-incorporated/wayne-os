// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "iioservice/daemon/daemon.h"

#include <sysexits.h>

#include <memory>
#include <string>
#include <utility>

#include <base/check.h>
#include <base/files/file_util.h>
#include <base/files/scoped_file.h>
#include <base/functional/bind.h>
#include <chromeos/dbus/service_constants.h>
#include <chromeos/mojo/service_constants.h>
#include <dbus/bus.h>
#include <dbus/message.h>
#include <dbus/object_proxy.h>
#include <mojo/core/embedder/embedder.h>
#include <mojo/public/cpp/system/invitation.h>
#include <mojo_service_manager/lib/connect.h>

#include "iioservice/daemon/iio_sensor.h"
#include "iioservice/daemon/sensor_metrics.h"
#include "iioservice/include/common.h"
#include "iioservice/include/dbus-constants.h"

namespace iioservice {

Daemon::~Daemon() {
  iio_sensor_.reset();
  SensorMetrics::Shutdown();
}

int Daemon::OnInit() {
  int exit_code = DBusDaemon::OnInit();
  if (exit_code != EX_OK)
    return exit_code;

  SensorMetrics::Initialize();

  InitDBus();

  mojo::core::Init();
  ipc_support_ = std::make_unique<mojo::core::ScopedIPCSupport>(
      base::SingleThreadTaskRunner::GetCurrentDefault(),
      mojo::core::ScopedIPCSupport::ShutdownPolicy::CLEAN);

  ConnectToMojoServiceManager();

  return 0;
}

void Daemon::InitDBus() {
  dbus::ExportedObject* const iioservice_exported_object =
      bus_->GetExportedObject(
          dbus::ObjectPath(::iioservice::kIioserviceServicePath));
  CHECK(iioservice_exported_object);

  // Register a handler of the MemsSetupDone method.
  CHECK(iioservice_exported_object->ExportMethodAndBlock(
      ::iioservice::kIioserviceInterface, ::iioservice::kMemsSetupDoneMethod,
      base::BindRepeating(&Daemon::HandleMemsSetupDone,
                          weak_factory_.GetWeakPtr())));

  // Register a handler of the MemsRemoveDone method.
  CHECK(iioservice_exported_object->ExportMethodAndBlock(
      ::iioservice::kIioserviceInterface, ::iioservice::kMemsRemoveDoneMethod,
      base::BindRepeating(&Daemon::HandleMemsRemoveDone,
                          weak_factory_.GetWeakPtr())));

  // Take ownership of the IIO service.
  CHECK(bus_->RequestOwnershipAndBlock(::iioservice::kIioserviceServiceName,
                                       dbus::Bus::REQUIRE_PRIMARY));
}

void Daemon::ConnectToMojoServiceManager() {
  auto service_manager_remote =
      chromeos::mojo_service_manager::ConnectToMojoServiceManager();

  if (!service_manager_remote) {
    LOGF(FATAL) << "Failed to connect to Mojo Service Manager";

    Quit();
    return;
  }

  service_manager_.Bind(std::move(service_manager_remote));
  service_manager_.set_disconnect_with_reason_handler(base::BindOnce(
      &Daemon::ServiceManagerDisconnected, base::Unretained(this)));

  mojo::PendingRemote<chromeos::mojo_service_manager::mojom::ServiceProvider>
      service_provider_remote;

  iio_sensor_ = IioSensor::Create(
      base::SingleThreadTaskRunner::GetCurrentDefault(),
      service_provider_remote.InitWithNewPipeAndPassReceiver());
  service_manager_->Register(chromeos::mojo_services::kIioSensor,
                             std::move(service_provider_remote));
}

void Daemon::ServiceManagerDisconnected(uint32_t custom_reason,
                                        const std::string& description) {
  auto error = static_cast<chromeos::mojo_service_manager::mojom::ErrorCode>(
      custom_reason);
  LOG(ERROR) << "ServiceManagerDisconnected, error: " << error
             << ", description: " << description;

  // As iioservice couldn't handle any error properly, and it still might need
  // to rely on the Mojo Service Manager's restart, quit and restart iioservice
  // directly.
  Quit();
}

void Daemon::HandleMemsSetupDone(
    dbus::MethodCall* method_call,
    dbus::ExportedObject::ResponseSender response_sender) {
  if (iio_sensor_) {
    dbus::MessageReader reader(method_call);
    int32_t iio_device_id;
    if (!reader.PopInt32(&iio_device_id) || iio_device_id < 0) {
      LOGF(ERROR) << "Couldn't extract iio_device_id (int32_t) from D-Bus call";
      std::move(response_sender)
          .Run(dbus::ErrorResponse::FromMethodCall(
              method_call, DBUS_ERROR_FAILED,
              "Couldn't extract iio_device_id (int32_t)"));
      return;
    }

    iio_sensor_->OnDeviceAdded(iio_device_id);
  }

  // Send success response.
  std::move(response_sender).Run(dbus::Response::FromMethodCall(method_call));
}

void Daemon::HandleMemsRemoveDone(
    dbus::MethodCall* method_call,
    dbus::ExportedObject::ResponseSender response_sender) {
  if (iio_sensor_) {
    dbus::MessageReader reader(method_call);
    int32_t iio_device_id;
    if (!reader.PopInt32(&iio_device_id) || iio_device_id < 0) {
      LOGF(ERROR) << "Couldn't extract iio_device_id (int32_t) from D-Bus call";
      std::move(response_sender)
          .Run(dbus::ErrorResponse::FromMethodCall(
              method_call, DBUS_ERROR_FAILED,
              "Couldn't extract iio_device_id (int32_t)"));
      return;
    }

    iio_sensor_->OnDeviceRemoved(iio_device_id);
  }

  // Send success response.
  std::move(response_sender).Run(dbus::Response::FromMethodCall(method_call));
}

}  // namespace iioservice
