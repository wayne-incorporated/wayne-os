// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef IIOSERVICE_IIOSERVICE_SIMPLECLIENT_SENSOR_CLIENT_H_
#define IIOSERVICE_IIOSERVICE_SIMPLECLIENT_SENSOR_CLIENT_H_

#include <memory>

#include <base/functional/callback.h>
#include <base/memory/weak_ptr.h>
#include <base/task/sequenced_task_runner.h>
#include <mojo/public/cpp/bindings/receiver.h>
#include <mojo/public/cpp/bindings/remote.h>

#include "iioservice/mojo/sensor.mojom.h"

namespace iioservice {

class SensorClient {
 public:
  using QuitCallback = base::OnceCallback<void()>;

  static void SensorClientDeleter(SensorClient* observer);

  virtual ~SensorClient();

  using ScopedSensorClient =
      std::unique_ptr<SensorClient, decltype(&SensorClientDeleter)>;

  void SetUpChannel(
      mojo::PendingRemote<cros::mojom::SensorService> pending_remote);

 protected:
  SensorClient(scoped_refptr<base::SequencedTaskRunner> ipc_task_runner,
               QuitCallback quit_callback);

  void SetUpChannelTimeout();

  virtual void Start() = 0;
  virtual void Reset();

  void OnServiceDisconnect();

  scoped_refptr<base::SequencedTaskRunner> ipc_task_runner_;
  QuitCallback quit_callback_;

  mojo::Remote<cros::mojom::SensorService> sensor_service_remote_;

  bool sensor_service_setup_ = false;

  base::WeakPtrFactory<SensorClient> weak_factory_{this};
};

}  // namespace iioservice

#endif  // IIOSERVICE_IIOSERVICE_SIMPLECLIENT_SENSOR_CLIENT_H_
