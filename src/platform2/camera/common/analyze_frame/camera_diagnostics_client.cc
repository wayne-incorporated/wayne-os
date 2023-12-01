// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "common/analyze_frame/camera_diagnostics_client.h"

#include <cstdint>
#include <utility>

#include <base/no_destructor.h>
#include <base/task/sequenced_task_runner.h>
#include <mojo/core/embedder/embedder.h>

#include "cros-camera/camera_mojo_channel_manager.h"
#include "cros-camera/camera_mojo_channel_manager_token.h"
#include "cros-camera/common.h"

namespace cros {

CameraDiagnosticsClient::CameraDiagnosticsClient(
    CameraMojoChannelManagerToken* mojo_manager_token)
    : mojo_manager_token_(mojo_manager_token),
      ipc_task_runner_(
          cros::CameraMojoChannelManager::GetInstance()->GetIpcTaskRunner()) {
  Bind();
}

CameraDiagnosticsClient* CameraDiagnosticsClient::GetInstance(
    CameraMojoChannelManagerToken* mojo_manager_token) {
  static base::NoDestructor<CameraDiagnosticsClient> instance(
      mojo_manager_token);
  return instance.get();
}

void CameraDiagnosticsClient::ResetRemotePtr() {
  if (!ipc_task_runner_->BelongsToCurrentThread()) {
    ipc_task_runner_->PostTask(
        FROM_HERE, base::BindOnce(&CameraDiagnosticsClient::ResetRemotePtr,
                                  base::Unretained(this)));
    return;
  }
  remote_.reset();
}

void CameraDiagnosticsClient::Bind() {
  if (!ipc_task_runner_->BelongsToCurrentThread()) {
    ipc_task_runner_->PostTask(
        FROM_HERE,
        base::BindOnce(&CameraDiagnosticsClient::Bind, base::Unretained(this)));
    return;
  }
  CameraMojoChannelManager::FromToken(mojo_manager_token_)
      ->BindServiceToMojoServiceManager(
          "CameraDiagnostics", remote_.BindNewPipeAndPassReceiver().PassPipe());
  remote_.set_disconnect_handler(base::BindOnce(
      &CameraDiagnosticsClient::OnDisconnect, base::Unretained(this)));
}

void CameraDiagnosticsClient::OnDisconnect() {
  LOGF(INFO) << "cros-camera disconnected from camera diagnostics service";
  ResetRemotePtr();
}

void CameraDiagnosticsClient::AnalyzeYuvFrame(
    mojom::CameraDiagnosticsFramePtr buffer) {
  if (!ipc_task_runner_->BelongsToCurrentThread()) {
    ipc_task_runner_->PostTask(
        FROM_HERE, base::BindOnce(&CameraDiagnosticsClient::AnalyzeYuvFrame,
                                  base::Unretained(this), std::move(buffer)));
    return;
  }
  remote_->AnalyzeYuvFrame(
      std::move(buffer),
      base::BindOnce(&CameraDiagnosticsClient::OnAnalyzedFrameReply,
                     base::Unretained(this)));
}

void CameraDiagnosticsClient::OnAnalyzedFrameReply(mojom::Response res) {
  LOGF(INFO) << "Reply from camera diagnostics: " << static_cast<uint32_t>(res);
}

}  // namespace cros
