// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "iioservice/iioservice_simpleclient/sensor_client.h"

#include <utility>

#include <base/functional/bind.h>

#include "iioservice/include/common.h"

namespace iioservice {

namespace {

constexpr int kSetUpChannelTimeoutInMilliseconds = 3000;

}  // namespace

// static
void SensorClient::SensorClientDeleter(SensorClient* sensor_client) {
  if (sensor_client == nullptr)
    return;

  if (!sensor_client->ipc_task_runner_->RunsTasksInCurrentSequence()) {
    sensor_client->ipc_task_runner_->PostTask(
        FROM_HERE,
        base::BindOnce(&SensorClient::SensorClientDeleter, sensor_client));
    return;
  }

  delete sensor_client;
}

SensorClient::~SensorClient() = default;

void SensorClient::SetUpChannel(
    mojo::PendingRemote<cros::mojom::SensorService> pending_remote) {
  DCHECK(ipc_task_runner_->RunsTasksInCurrentSequence());
  DCHECK(!sensor_service_remote_.is_bound());

  sensor_service_setup_ = true;

  sensor_service_remote_.Bind(std::move(pending_remote));
  sensor_service_remote_.set_disconnect_handler(base::BindOnce(
      &SensorClient::OnServiceDisconnect, weak_factory_.GetWeakPtr()));

  Start();
}

SensorClient::SensorClient(
    scoped_refptr<base::SequencedTaskRunner> ipc_task_runner,
    QuitCallback quit_callback)
    : ipc_task_runner_(std::move(ipc_task_runner)),
      quit_callback_(std::move(quit_callback)) {
  ipc_task_runner_->PostDelayedTask(
      FROM_HERE,
      base::BindOnce(&SensorClient::SetUpChannelTimeout,
                     weak_factory_.GetWeakPtr()),
      base::Milliseconds(kSetUpChannelTimeoutInMilliseconds));
}

void SensorClient::SetUpChannelTimeout() {
  DCHECK(ipc_task_runner_->RunsTasksInCurrentSequence());

  if (sensor_service_setup_)
    return;

  // Don't Change: Used as a check sentence in the tast test.
  LOGF(ERROR) << "SetUpChannelTimeout";
  Reset();
}

void SensorClient::Reset() {
  DCHECK(ipc_task_runner_->RunsTasksInCurrentSequence());

  sensor_service_remote_.reset();

  if (quit_callback_)
    std::move(quit_callback_).Run();
}

void SensorClient::OnServiceDisconnect() {
  DCHECK(ipc_task_runner_->RunsTasksInCurrentSequence());

  LOGF(ERROR) << "SensorService disconnected";
  Reset();
}

}  // namespace iioservice
