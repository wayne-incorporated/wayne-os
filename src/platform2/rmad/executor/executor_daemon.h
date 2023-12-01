// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef RMAD_EXECUTOR_EXECUTOR_DAEMON_H_
#define RMAD_EXECUTOR_EXECUTOR_DAEMON_H_

#include <memory>

#include <brillo/daemons/daemon.h>
#include <mojo/core/embedder/scoped_ipc_support.h>
#include <mojo/public/cpp/platform/platform_channel_endpoint.h>

#include "rmad/executor/executor.h"

namespace rmad {

// Daemon class for rmad's root-level executor.
class ExecutorDaemon final : public brillo::Daemon {
 public:
  explicit ExecutorDaemon(mojo::PlatformChannelEndpoint endpoint);
  ExecutorDaemon(const ExecutorDaemon&) = delete;
  ExecutorDaemon& operator=(const ExecutorDaemon&) = delete;
  ~ExecutorDaemon() override = default;

 private:
  // Necessary to establish Mojo communication with rmad.
  std::unique_ptr<mojo::core::ScopedIPCSupport> ipc_support_;
  // Implements the executor's Mojo methods.
  std::unique_ptr<Executor> mojo_service_;
};

}  // namespace rmad

#endif  // RMAD_EXECUTOR_EXECUTOR_DAEMON_H_
