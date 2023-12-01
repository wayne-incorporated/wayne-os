// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <sys/types.h>
#include <unistd.h>

#include <cstdlib>
#include <utility>

#include <base/check_op.h>
#include <base/logging.h>
#include <brillo/flag_helper.h>
#include <brillo/syslog_logging.h>
#include <brillo/udev/udev.h>
#include <brillo/udev/udev_monitor.h>
#include <mojo/core/embedder/embedder.h>
#include <mojo/public/cpp/platform/platform_channel.h>

#include "diagnostics/cros_healthd/cros_healthd_daemon.h"
#include "diagnostics/cros_healthd/executor/executor_daemon.h"
#include "diagnostics/cros_healthd/minijail/minijail_configuration.h"

namespace {
void SetVerbosityLevel(uint32_t verbosity_level) {
  verbosity_level = std::min(verbosity_level, 3u);
  // VLOG uses negative log level.
  logging::SetMinLogLevel(-(static_cast<int32_t>(verbosity_level)));
}
}  // namespace

int main(int argc, char** argv) {
  brillo::InitLog(brillo::kLogToSyslog | brillo::kLogToStderrIfTty);

  DEFINE_uint32(verbosity, 0, "Set verbosity level. Allowed value: 0 to 3");
  brillo::FlagHelper::Init(
      argc, argv, "cros_healthd - Device telemetry and diagnostics daemon.");

  SetVerbosityLevel(FLAGS_verbosity);

  // Init the Mojo Embedder API here, since both the executor and
  // cros_healthd use it.
  mojo::core::Init();

  // The parent and child processes will each keep one end of this message pipe
  // and use it to bootstrap a Mojo connection to each other.
  mojo::PlatformChannel channel;
  auto healthd_endpoint = channel.TakeLocalEndpoint();
  auto executor_endpoint = channel.TakeRemoteEndpoint();

  // The root-level parent process will continue on as the executor, and the
  // child will become the sandboxed cros_healthd daemon.
  pid_t pid = fork();

  if (pid == -1) {
    PLOG(FATAL) << "Failed to fork";
    return EXIT_FAILURE;
  }

  if (pid == 0) {
    // Child process.
    CHECK_EQ(getuid(), 0) << "Executor must run as root";

    // Enter a new process group so it won't be killed by upstart on stopping.
    // Let the mojo disconnect handler handle the lifecycle of executor process.
    if (setpgid(0, 0) < 0) {
      PLOG(FATAL) << "Failed to set pgid";
      return EXIT_FAILURE;
    }

    // Put the root-level executor in a light sandbox.
    diagnostics::EnterExecutorMinijail();

    // Run the root-level executor.
    healthd_endpoint.reset();
    return diagnostics::ExecutorDaemon(std::move(executor_endpoint)).Run();
  }

  // Parent process.
  auto udev = brillo::Udev::Create();
  if (!udev) {
    LOG(FATAL) << "Failed to initialize udev object.";
    return EXIT_FAILURE;
  }

  auto udev_monitor = udev->CreateMonitorFromNetlink("udev");
  if (!udev_monitor) {
    LOG(FATAL) << "Failed to create udev monitor.";
    return EXIT_FAILURE;
  }

  // Sandbox the Healthd process.
  diagnostics::EnterHealthdMinijail();

  // Run the cros_healthd daemon.
  executor_endpoint.reset();
  auto service = diagnostics::CrosHealthdDaemon(std::move(healthd_endpoint),
                                                std::move(udev_monitor));
  return service.Run();
}
