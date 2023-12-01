// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef IIOSERVICE_IIOSERVICE_SIMPLECLIENT_QUERY_IMPL_H_
#define IIOSERVICE_IIOSERVICE_SIMPLECLIENT_QUERY_IMPL_H_

#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <base/memory/weak_ptr.h>
#include <base/task/sequenced_task_runner.h>
#include <mojo/public/cpp/bindings/remote_set.h>

#include "iioservice/iioservice_simpleclient/sensor_client.h"
#include "iioservice/mojo/cros_sensor_service.mojom.h"
#include "iioservice/mojo/sensor.mojom.h"

namespace iioservice {

class QueryImpl final : public SensorClient {
 public:
  using ScopedQueryImpl =
      std::unique_ptr<QueryImpl, decltype(&SensorClientDeleter)>;

  static ScopedQueryImpl Create(
      scoped_refptr<base::SequencedTaskRunner> ipc_task_runner,
      cros::mojom::DeviceType device_type,
      std::vector<std::string> attributes,
      QuitCallback quit_callback);

 private:
  QueryImpl(scoped_refptr<base::SequencedTaskRunner> ipc_task_runner,
            cros::mojom::DeviceType device_type,
            std::vector<std::string> attributes,
            QuitCallback quit_callback);

  // SensorClient overrides:
  void Start() override;

  void OnDeviceDisconnect(mojo::RemoteSetElementId id);

  void GetAllDeviceIdsCallback(
      const base::flat_map<int32_t, std::vector<cros::mojom::DeviceType>>&
          iio_device_ids_types);
  void GetDeviceIdsCallback(const std::vector<int32_t>& iio_device_ids);

  void GetAttributesCallback(
      int32_t iio_device_id,
      std::vector<cros::mojom::DeviceType> types,
      const std::vector<std::optional<std::string>>& values);

  cros::mojom::DeviceType device_type_;
  std::vector<std::string> attributes_;

  // First is the iio device id, second is the id in |remotes_|.
  std::map<int32_t, mojo::RemoteSetElementId> device_ids_;
  mojo::RemoteSet<cros::mojom::SensorDevice> remotes_;

  base::WeakPtrFactory<QueryImpl> weak_factory_{this};
};

}  // namespace iioservice

#endif  // IIOSERVICE_IIOSERVICE_SIMPLECLIENT_QUERY_IMPL_H_
