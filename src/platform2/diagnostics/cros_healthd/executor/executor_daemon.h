// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_EXECUTOR_EXECUTOR_DAEMON_H_
#define DIAGNOSTICS_CROS_HEALTHD_EXECUTOR_EXECUTOR_DAEMON_H_

#include <memory>

#include <base/memory/scoped_refptr.h>
#include <base/task/single_thread_task_runner.h>
#include <brillo/daemons/daemon.h>
#include <brillo/process/process_reaper.h>
#include <mojo/core/embedder/scoped_ipc_support.h>
#include <mojo/public/cpp/platform/platform_channel_endpoint.h>

#include "diagnostics/cros_healthd/executor/executor.h"

namespace diagnostics {

// Daemon class for cros_healthd's root-level executor.
class ExecutorDaemon final : public brillo::Daemon {
 public:
  explicit ExecutorDaemon(mojo::PlatformChannelEndpoint endpoint);
  ExecutorDaemon(const ExecutorDaemon&) = delete;
  ExecutorDaemon& operator=(const ExecutorDaemon&) = delete;
  ~ExecutorDaemon() override;

 private:
  // Used as the task runner for all Mojo IPCs.
  const scoped_refptr<base::SingleThreadTaskRunner> mojo_task_runner_;
  // Necessary to establish Mojo communication with cros_healthd.
  std::unique_ptr<mojo::core::ScopedIPCSupport> ipc_support_;
  // Implements the executor's Mojo methods.
  std::unique_ptr<Executor> mojo_service_;
  // Used to monitor child process status.
  brillo::ProcessReaper process_reaper_;
};

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_EXECUTOR_EXECUTOR_DAEMON_H_
