// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef PRINTSCANMGR_EXECUTOR_EXECUTOR_H_
#define PRINTSCANMGR_EXECUTOR_EXECUTOR_H_

#include <memory>

#include <base/task/single_thread_task_runner.h>
#include <brillo/daemons/daemon.h>
#include <mojo/core/embedder/scoped_ipc_support.h>
#include <mojo/public/cpp/platform/platform_channel_endpoint.h>

#include "printscanmgr/executor/mojo_adaptor.h"

namespace printscanmgr {

// Daemon providing root-level privilege for printscanmgr.
class Executor final : public brillo::Daemon {
 public:
  explicit Executor(mojo::PlatformChannelEndpoint endpoint);
  Executor(const Executor&) = delete;
  Executor& operator=(const Executor&) = delete;
  ~Executor() override;

 private:
  // Used as the task runner for all Mojo IPCs.
  const scoped_refptr<base::SingleThreadTaskRunner> mojo_task_runner_;
  // Necessary to establish Mojo communication with printscanmgr.
  std::unique_ptr<mojo::core::ScopedIPCSupport> ipc_support_;
  // Implements the executor's Mojo methods.
  std::unique_ptr<MojoAdaptor> mojo_adaptor_;
};

}  // namespace printscanmgr

#endif  // PRINTSCANMGR_EXECUTOR_EXECUTOR_H_
