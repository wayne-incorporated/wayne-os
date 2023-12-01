// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CAMERA_DIAGNOSTICS_CAMERA_DIAGNOSTICS_H_
#define CAMERA_DIAGNOSTICS_CAMERA_DIAGNOSTICS_H_

#include <memory>

#include <mojo/core/embedder/scoped_ipc_support.h>

#include "diagnostics/diagnostics_service_provider.h"

namespace cros {

class CameraDiagnostics {
 public:
  CameraDiagnostics() = default;
  CameraDiagnostics(const CameraDiagnostics&) = delete;
  CameraDiagnostics& operator=(const CameraDiagnostics&) = delete;

  // Initialize Mojo IPC and register the service
  // in mojo service manager.
  void Start();

 private:
  std::unique_ptr<mojo::core::ScopedIPCSupport> ipc_support_;
  DiagnosticsServiceProvider service_provider_;
};

}  // namespace cros

#endif  // CAMERA_DIAGNOSTICS_CAMERA_DIAGNOSTICS_H_
