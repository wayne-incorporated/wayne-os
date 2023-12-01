// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef IIOSERVICE_IIOSERVICE_SIMPLECLIENT_OBSERVER_H_
#define IIOSERVICE_IIOSERVICE_SIMPLECLIENT_OBSERVER_H_

#include <vector>

#include <base/memory/weak_ptr.h>
#include <mojo/public/cpp/bindings/remote.h>

#include "iioservice/iioservice_simpleclient/sensor_client.h"
#include "iioservice/mojo/sensor.mojom.h"

namespace iioservice {

class Observer : public SensorClient {
 protected:
  Observer(scoped_refptr<base::SequencedTaskRunner> ipc_task_runner,
           QuitCallback quit_callback,
           int device_id,
           cros::mojom::DeviceType device_type,
           int num);

  // SensorClient overrides:
  void Start() override;

  void OnDeviceDisconnect();
  void OnObserverDisconnect();

  void GetDeviceIdsByType();
  void GetDeviceIdsCallback(const std::vector<int32_t>& iio_device_ids);
  virtual void GetSensorDevice();

  void AddTimestamp(int64_t timestamp);
  void AddSuccessRead();

  virtual base::TimeDelta GetLatencyTolerance() const;

  int device_id_ = -1;
  cros::mojom::DeviceType device_type_ = cros::mojom::DeviceType::NONE;
  int num_;

  int num_success_reads_ = 0;

  base::TimeDelta total_latency_;
  std::vector<base::TimeDelta> latencies_;

  mojo::Remote<cros::mojom::SensorDevice> sensor_device_remote_;

  base::WeakPtrFactory<Observer> weak_factory_{this};
};

}  // namespace iioservice

#endif  // IIOSERVICE_IIOSERVICE_SIMPLECLIENT_OBSERVER_H_
