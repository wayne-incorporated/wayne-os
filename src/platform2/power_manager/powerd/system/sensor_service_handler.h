// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef POWER_MANAGER_POWERD_SYSTEM_SENSOR_SERVICE_HANDLER_H_
#define POWER_MANAGER_POWERD_SYSTEM_SENSOR_SERVICE_HANDLER_H_

#include <vector>

#include <base/functional/callback.h>
#include <base/memory/weak_ptr.h>
#include <base/observer_list.h>
#include <base/sequence_checker.h>
#include <iioservice/mojo/sensor.mojom.h>
#include <mojo/public/cpp/bindings/receiver.h>
#include <mojo/public/cpp/bindings/remote.h>

#include "power_manager/powerd/system/sensor_service_handler_observer.h"

namespace power_manager::system {

class SensorServiceHandler
    : public cros::mojom::SensorServiceNewDevicesObserver {
 public:
  using OnIioSensorDisconnectCallback =
      base::OnceCallback<void(base::TimeDelta)>;

  SensorServiceHandler();
  ~SensorServiceHandler() override;

  void SetUpChannel(
      mojo::PendingRemote<cros::mojom::SensorService> pending_remote,
      OnIioSensorDisconnectCallback on_iio_sensor_disconnect_callback =
          base::DoNothing());

  // cros::mojom::SensorServiceNewDevicesObserver overrides:
  void OnNewDeviceAdded(
      int32_t iio_device_id,
      const std::vector<cros::mojom::DeviceType>& types) override;

  // Devices will be reported in a new task on the same thread, i.e. in a
  // callback.
  void AddObserver(SensorServiceHandlerObserver* observer);
  void RemoveObserver(SensorServiceHandlerObserver* observer);

  // Passes |pending_receiver| to |SensorService::GetDevice|.
  void GetDevice(
      int32_t iio_device_id,
      mojo::PendingReceiver<cros::mojom::SensorDevice> pending_receiver);

  void ResetSensorService(bool reconnect = true);

 private:
  void OnSensorServiceDisconnect();
  void OnNewDevicesObserverDisconnect();

  void GetAllDeviceIdsCallback(
      const base::flat_map<int32_t, std::vector<cros::mojom::DeviceType>>&
          iio_device_ids_types);

  void NotifyObserverWithCurrentDevices(SensorServiceHandlerObserver* observer);

  mojo::Remote<cros::mojom::SensorService> sensor_service_remote_;
  OnIioSensorDisconnectCallback on_iio_sensor_disconnect_callback_;
  uint32_t reconnect_delay_in_seconds_ = 1;

  // The Mojo channel to get notified when new devices are added to IIO Service.
  mojo::Receiver<cros::mojom::SensorServiceNewDevicesObserver>
      new_devices_observer_{this};

  base::flat_map<int32_t, std::vector<cros::mojom::DeviceType>>
      iio_device_ids_types_;

  base::ObserverList<SensorServiceHandlerObserver> observers_;

  base::WeakPtrFactory<SensorServiceHandler> weak_factory_{this};

  SEQUENCE_CHECKER(sequence_checker_);
};

}  // namespace power_manager::system

#endif  // POWER_MANAGER_POWERD_SYSTEM_SENSOR_SERVICE_HANDLER_H_
