// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "iioservice/iioservice_simpleclient/query_impl.h"

#include <optional>
#include <utility>

#include <base/functional/bind.h>

#include "iioservice/include/common.h"

namespace iioservice {

QueryImpl::ScopedQueryImpl QueryImpl::Create(
    scoped_refptr<base::SequencedTaskRunner> ipc_task_runner,
    cros::mojom::DeviceType device_type,
    std::vector<std::string> attributes,
    QuitCallback quit_callback) {
  ScopedQueryImpl query(
      new QueryImpl(ipc_task_runner, device_type, std::move(attributes),
                    std::move(quit_callback)),
      SensorClientDeleter);

  return query;
}

QueryImpl::QueryImpl(scoped_refptr<base::SequencedTaskRunner> ipc_task_runner,
                     cros::mojom::DeviceType device_type,
                     std::vector<std::string> attributes,
                     QuitCallback quit_callback)
    : SensorClient(std::move(ipc_task_runner), std::move(quit_callback)),
      device_type_(device_type),
      attributes_(std::move(attributes)) {
  DCHECK(!attributes_.empty());

  remotes_.set_disconnect_handler(base::BindRepeating(
      &QueryImpl::OnDeviceDisconnect, weak_factory_.GetWeakPtr()));
}

void QueryImpl::Start() {
  DCHECK(ipc_task_runner_->RunsTasksInCurrentSequence());

  if (device_type_ == cros::mojom::DeviceType::NONE) {
    sensor_service_remote_->GetAllDeviceIds(base::BindOnce(
        &QueryImpl::GetAllDeviceIdsCallback, weak_factory_.GetWeakPtr()));
    return;
  }

  sensor_service_remote_->GetDeviceIds(
      device_type_, base::BindOnce(&QueryImpl::GetDeviceIdsCallback,
                                   weak_factory_.GetWeakPtr()));
}

void QueryImpl::OnDeviceDisconnect(mojo::RemoteSetElementId id) {
  DCHECK(ipc_task_runner_->RunsTasksInCurrentSequence());

  LOGF(ERROR) << "SensorDevice disconnected with RemoteSetElementId: " << id;

  if (remotes_.empty())
    Reset();
}

void QueryImpl::GetAllDeviceIdsCallback(
    const base::flat_map<int32_t, std::vector<cros::mojom::DeviceType>>&
        iio_device_ids_types) {
  DCHECK(ipc_task_runner_->RunsTasksInCurrentSequence());

  if (iio_device_ids_types.empty()) {
    LOGF(WARNING) << "No device found";
    Reset();
  }

  for (const auto& [id, types] : iio_device_ids_types) {
    mojo::Remote<cros::mojom::SensorDevice> remote;
    sensor_service_remote_->GetDevice(id, remote.BindNewPipeAndPassReceiver());

    remote->GetAttributes(
        attributes_, base::BindOnce(&QueryImpl::GetAttributesCallback,
                                    weak_factory_.GetWeakPtr(), id, types));

    device_ids_[id] = remotes_.Add(std::move(remote));
  }
}

void QueryImpl::GetDeviceIdsCallback(
    const std::vector<int32_t>& iio_device_ids) {
  DCHECK(ipc_task_runner_->RunsTasksInCurrentSequence());

  if (iio_device_ids.empty()) {
    LOGF(WARNING) << "No device found for type: " << device_type_;
    Reset();
  }

  for (const int32_t& id : iio_device_ids) {
    mojo::Remote<cros::mojom::SensorDevice> remote;
    sensor_service_remote_->GetDevice(id, remote.BindNewPipeAndPassReceiver());

    remote->GetAttributes(
        attributes_,
        base::BindOnce(&QueryImpl::GetAttributesCallback,
                       weak_factory_.GetWeakPtr(), id,
                       std::vector<cros::mojom::DeviceType>{device_type_}));

    device_ids_[id] = remotes_.Add(std::move(remote));
  }
}

void QueryImpl::GetAttributesCallback(
    int32_t iio_device_id,
    std::vector<cros::mojom::DeviceType> types,
    const std::vector<std::optional<std::string>>& values) {
  DCHECK(ipc_task_runner_->RunsTasksInCurrentSequence());
  DCHECK(device_ids_.find(iio_device_id) != device_ids_.end());
  DCHECK_EQ(attributes_.size(), values.size());

  // TODO(gwendal): Please tell me the format of output that's easy to parse in
  // the tast test.
  LOGF(INFO) << "Device id: " << iio_device_id;

  for (auto type : types)
    LOGF(INFO) << "Type: " << type;

  for (size_t i = 0; i < values.size(); ++i)
    LOGF(INFO) << attributes_[i] << ": " << values[i].value_or("");

  remotes_.Remove(device_ids_[iio_device_id]);

  if (remotes_.empty())
    Reset();
}

}  // namespace iioservice
