// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "iioservice/daemon/iio_sensor.h"

#include <memory>
#include <utility>

#include <base/check.h>
#include <base/functional/bind.h>
#include <libmems/iio_channel_impl.h>
#include <libmems/iio_context_impl.h>
#include <libmems/iio_device_impl.h>

#include "iioservice/include/common.h"

namespace iioservice {

// static
void IioSensor::IioSensorDeleter(IioSensor* server) {
  if (server == nullptr)
    return;

  if (!server->ipc_task_runner_->RunsTasksInCurrentSequence()) {
    server->ipc_task_runner_->PostTask(
        FROM_HERE, base::BindOnce(&IioSensor::IioSensorDeleter, server));
    return;
  }

  delete server;
}

// static
IioSensor::ScopedIioSensor IioSensor::Create(
    scoped_refptr<base::SequencedTaskRunner> ipc_task_runner,
    mojo::PendingReceiver<
        chromeos::mojo_service_manager::mojom::ServiceProvider> receiver) {
  DCHECK(ipc_task_runner->RunsTasksInCurrentSequence());

  ScopedIioSensor server(
      new IioSensor(std::move(ipc_task_runner), std::move(receiver)),
      IioSensorDeleter);

  server->SetSensorService();

  return server;
}

void IioSensor::Request(
    chromeos::mojo_service_manager::mojom::ProcessIdentityPtr identity,
    mojo::ScopedMessagePipeHandle receiver) {
  DCHECK(ipc_task_runner_->RunsTasksInCurrentSequence());
  DCHECK(sensor_service_);

  LOGF(INFO) << "Received SensorService from Mojo Service Manager";

  sensor_service_->AddReceiver(
      mojo::PendingReceiver<cros::mojom::SensorService>(std::move(receiver)));
}

void IioSensor::OnDeviceAdded(int iio_device_id) {
  DCHECK(ipc_task_runner_->RunsTasksInCurrentSequence());
  DCHECK(sensor_service_);

  LOGF(INFO) << "iio device id: " << iio_device_id;
  sensor_service_->OnDeviceAdded(iio_device_id);
}

void IioSensor::OnDeviceRemoved(int iio_device_id) {
  DCHECK(ipc_task_runner_->RunsTasksInCurrentSequence());
  DCHECK(sensor_service_);

  LOGF(INFO) << "iio device id: " << iio_device_id;
  sensor_service_->OnDeviceRemoved(iio_device_id);
}

IioSensor::IioSensor(
    scoped_refptr<base::SequencedTaskRunner> ipc_task_runner,
    mojo::PendingReceiver<
        chromeos::mojo_service_manager::mojom::ServiceProvider> receiver)
    : ipc_task_runner_(std::move(ipc_task_runner)),
      receiver_(this, std::move(receiver)) {
  DCHECK(ipc_task_runner_->RunsTasksInCurrentSequence());

  // Ignore |receiver_|'s disconnect handler, as ServiceManager mojo pipe should
  // also disconnect when ServiceProvider does.
}

void IioSensor::SetSensorService() {
  DCHECK(ipc_task_runner_->RunsTasksInCurrentSequence());

  sensor_service_ = SensorServiceImpl::Create(
      ipc_task_runner_, std::make_unique<libmems::IioContextImpl>());
}

}  // namespace iioservice
