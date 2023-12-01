// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef IIOSERVICE_DAEMON_IIO_SENSOR_H_
#define IIOSERVICE_DAEMON_IIO_SENSOR_H_

#include <memory>

#include <base/functional/callback.h>
#include <base/memory/weak_ptr.h>
#include <base/task/sequenced_task_runner.h>
#include <mojo/public/cpp/bindings/receiver.h>
#include <mojo_service_manager/lib/mojom/service_manager.mojom.h>

#include "iioservice/daemon/sensor_service_impl.h"

namespace iioservice {

class IioSensor
    : public chromeos::mojo_service_manager::mojom::ServiceProvider {
 public:
  static void IioSensorDeleter(IioSensor* server);
  using ScopedIioSensor =
      std::unique_ptr<IioSensor, decltype(&IioSensorDeleter)>;

  using MojoOnFailureCallback = base::OnceCallback<void()>;

  // Should be used on |ipc_task_runner|.
  static ScopedIioSensor Create(
      scoped_refptr<base::SequencedTaskRunner> ipc_task_runner,
      mojo::PendingReceiver<
          chromeos::mojo_service_manager::mojom::ServiceProvider> receiver);

  // chromeos::mojo_service_manager::mojom::ServiceProvider overrides:
  void Request(
      chromeos::mojo_service_manager::mojom::ProcessIdentityPtr identity,
      mojo::ScopedMessagePipeHandle receiver) override;

  void OnDeviceAdded(int iio_device_id);
  void OnDeviceRemoved(int iio_device_id);

 protected:
  IioSensor(
      scoped_refptr<base::SequencedTaskRunner> ipc_task_runner,
      mojo::PendingReceiver<
          chromeos::mojo_service_manager::mojom::ServiceProvider> receiver);

  virtual void SetSensorService();

  scoped_refptr<base::SequencedTaskRunner> ipc_task_runner_;
  mojo::Receiver<chromeos::mojo_service_manager::mojom::ServiceProvider>
      receiver_;

  SensorServiceImpl::ScopedSensorServiceImpl sensor_service_ = {
      nullptr, SensorServiceImpl::SensorServiceImplDeleter};

  base::WeakPtrFactory<IioSensor> weak_factory_{this};
};

}  // namespace iioservice

#endif  // IIOSERVICE_DAEMON_IIO_SENSOR_H_
