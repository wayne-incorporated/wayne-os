// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef IIOSERVICE_DAEMON_SENSOR_SERVICE_IMPL_H_
#define IIOSERVICE_DAEMON_SENSOR_SERVICE_IMPL_H_

#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>

#include <base/functional/bind.h>
#include <base/memory/weak_ptr.h>
#include <base/task/sequenced_task_runner.h>
#include <libmems/iio_context.h>
#include <mojo/public/cpp/bindings/receiver_set.h>

#include "iioservice/daemon/sensor_device_fusion.h"
#include "iioservice/daemon/sensor_device_impl.h"
#include "iioservice/mojo/sensor.mojom.h"

namespace iioservice {

class SensorServiceImpl : public cros::mojom::SensorService {
 public:
  static void SensorServiceImplDeleter(SensorServiceImpl* service);
  using ScopedSensorServiceImpl =
      std::unique_ptr<SensorServiceImpl, decltype(&SensorServiceImplDeleter)>;

  static ScopedSensorServiceImpl Create(
      scoped_refptr<base::SequencedTaskRunner> ipc_task_runner,
      std::unique_ptr<libmems::IioContext> context);

  ~SensorServiceImpl();

  virtual void AddReceiver(
      mojo::PendingReceiver<cros::mojom::SensorService> request);

  void ClearReceiversWithReason(
      cros::mojom::SensorServiceDisconnectReason reason,
      const std::string& description);

  void OnDeviceAdded(int iio_device_id);
  void OnDeviceRemoved(int iio_device_id);

  // cros::mojom::SensorService overrides:
  void GetDeviceIds(cros::mojom::DeviceType type,
                    GetDeviceIdsCallback callback) override;
  void GetAllDeviceIds(GetAllDeviceIdsCallback callback) override;
  void GetDevice(
      int32_t iio_device_id,
      mojo::PendingReceiver<cros::mojom::SensorDevice> device_request) override;
  void RegisterNewDevicesObserver(
      mojo::PendingRemote<cros::mojom::SensorServiceNewDevicesObserver>
          observer) override;

 protected:
  SensorServiceImpl(scoped_refptr<base::SequencedTaskRunner> ipc_task_runner,
                    std::unique_ptr<libmems::IioContext> context,
                    SensorDeviceImpl::ScopedSensorDeviceImpl sensor_device);

 private:
  void AddDevice(libmems::IioDevice* device);
  void AddDevice(int32_t id,
                 const std::vector<cros::mojom::DeviceType>& types,
                 Location location);

  void CheckGravity(int32_t id,
                    cros::mojom::DeviceType type,
                    Location location);

  void OnSensorServiceDisconnect();

  scoped_refptr<base::SequencedTaskRunner> ipc_task_runner_;
  std::unique_ptr<libmems::IioContext> context_;

  SensorDeviceImpl::ScopedSensorDeviceImpl sensor_device_;

  // First is the iio_device's id, second is the types.
  std::map<int32_t, std::vector<cros::mojom::DeviceType>> device_types_map_;

  // Maps from device type and location to id.
  std::map<cros::mojom::DeviceType, std::map<Location, int32_t>> device_maps_;

  int32_t fusion_device_counter_ = 0;
  // First is the fusion device's id, second is the handler of the fusion
  // device.
  std::map<int32_t, SensorDeviceFusion::ScopedSensorDeviceFusion>
      sensor_device_fusions_;

  mojo::ReceiverSet<cros::mojom::SensorService> receiver_set_;
  std::vector<mojo::Remote<cros::mojom::SensorServiceNewDevicesObserver>>
      observers_;

  base::WeakPtrFactory<SensorServiceImpl> weak_factory_{this};
};

}  // namespace iioservice

#endif  // IIOSERVICE_DAEMON_SENSOR_SERVICE_IMPL_H_
