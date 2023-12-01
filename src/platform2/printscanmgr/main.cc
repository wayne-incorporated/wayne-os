// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <unistd.h>

#include <cstdlib>
#include <utility>

#include <base/check_op.h>
#include <base/logging.h>
#include <brillo/syslog_logging.h>
#include <mojo/core/embedder/embedder.h>
#include <mojo/public/cpp/platform/platform_channel.h>

#include "printscanmgr/daemon/daemon.h"
#include "printscanmgr/executor/executor.h"
#include "printscanmgr/minijail/minijail_configuration.h"

int main(int arg, char** argv) {
  brillo::InitLog(brillo::kLogToSyslog | brillo::kLogToStderrIfTty);

  // Init the Mojo Embedder API here, since both the executor and printscanmgr
  // use it.
  mojo::core::Init();

  // The parent and child processes will each keep one end of this message pipe
  // and use it to bootstrap a Mojo connection to each other.
  mojo::PlatformChannel channel;
  auto printscanmgr_endpoint = channel.TakeLocalEndpoint();
  auto executor_endpoint = channel.TakeRemoteEndpoint();

  // The root-level parent process will continue on as the executor, and the
  // child will become the sandboxed printscanmgr daemon.
  pid_t pid = fork();

  if (pid == -1) {
    PLOG(FATAL) << "Failed to fork";
    return EXIT_FAILURE;
  }

  if (pid == 0) {
    CHECK_EQ(getuid(), 0) << "Executor must run as root";

    printscanmgr::EnterExecutorMinijail();

    printscanmgr_endpoint.reset();
    return printscanmgr::Executor(std::move(executor_endpoint)).Run();
  }

  LOG(INFO) << "Starting printscanmgr daemon.";

  printscanmgr::EnterDaemonMinijail();

  executor_endpoint.reset();
  return printscanmgr::Daemon(std::move(printscanmgr_endpoint)).Run();
}
