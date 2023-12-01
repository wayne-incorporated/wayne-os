// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CAMERA_COMMON_ANALYZE_FRAME_CAMERA_DIAGNOSTICS_CLIENT_H_
#define CAMERA_COMMON_ANALYZE_FRAME_CAMERA_DIAGNOSTICS_CLIENT_H_

#include <mojo/public/cpp/bindings/remote.h>

#include "camera/mojo/camera_diagnostics.mojom.h"
#include "cros-camera/camera_mojo_channel_manager_token.h"

namespace cros {

// A wrapper for mojo call to camera diagnostics service. Example use :
// CameraDiagnosticsClient::GetInstance(mojo_manager_token_)
// ->AnalyzeYuvFrame(std::move(buffer));
class CameraDiagnosticsClient {
 public:
  explicit CameraDiagnosticsClient(
      CameraMojoChannelManagerToken* mojo_manager_token);
  CameraDiagnosticsClient(const CameraDiagnosticsClient&) = delete;
  CameraDiagnosticsClient& operator=(const CameraDiagnosticsClient&) = delete;
  ~CameraDiagnosticsClient();
  static CameraDiagnosticsClient* GetInstance(
      CameraMojoChannelManagerToken* mojo_manager_token);
  // Used to dispatch a frame to camera diagnostics service.
  void AnalyzeYuvFrame(mojom::CameraDiagnosticsFramePtr buffer);

 private:
  void ResetRemotePtr();
  // Binds the mojo remote.
  void Bind();
  void OnDisconnect();
  void OnAnalyzedFrameReply(mojom::Response res);
  CameraMojoChannelManagerToken* mojo_manager_token_;
  const scoped_refptr<base::SingleThreadTaskRunner> ipc_task_runner_;
  mojo::Remote<cros::mojom::CameraDiagnostics> remote_;
};

}  // namespace cros

#endif  // CAMERA_COMMON_ANALYZE_FRAME_CAMERA_DIAGNOSTICS_CLIENT_H_
