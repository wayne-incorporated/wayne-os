// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <sys/types.h>
#include <unistd.h>

#include <base/logging.h>
#include <base/task/thread_pool/thread_pool_instance.h>
#include <brillo/flag_helper.h>
#include <brillo/syslog_logging.h>
#include <mojo/core/embedder/embedder.h>
#include <mojo/public/cpp/platform/platform_channel.h>

#include "rmad/daemon/dbus_service.h"
#include "rmad/executor/executor_daemon.h"
#include "rmad/interface/rmad_interface_impl.h"
#include "rmad/minijail/minijail_configuration.h"
#include "rmad/utils/write_protect_utils_impl.h"

namespace {

void CheckWriteProtectAndEnterMinijail() {
  bool set_admin_caps = false;
  rmad::WriteProtectUtilsImpl write_protect_utils;
  bool hwwp_enabled;
  if (write_protect_utils.GetHardwareWriteProtectionStatus(&hwwp_enabled) &&
      !hwwp_enabled) {
    VLOG(1) << "Hardware write protection off.";
    set_admin_caps = true;
  } else {
    VLOG(1) << "Hardware write protection on.";
  }
  rmad::EnterMinijail(set_admin_caps);
}

}  // namespace

int main(int argc, char* argv[]) {
  brillo::InitLog(brillo::kLogToSyslog | brillo::kLogToStderrIfTty);
  brillo::FlagHelper::Init(argc, argv, "ChromeOS RMA Daemon");

  mojo::core::Init();

  // The parent and child processes will each keep one end of this message pipe
  // and use it to bootstrap a Mojo connection between them. The connection
  // handler on both sides are set to exit the process whenever the Mojo
  // communication disconnects.
  mojo::PlatformChannel channel;

  // The parent process will run as the RMA daemon in a sandbox, and the child
  // process will run as the executor.
  pid_t pid = fork();

  if (pid == -1) {
    LOG(FATAL) << "Failed to fork.";
  }

  if (pid != 0) {
    // Parent process. Run as RMA daemon.
    VLOG(1) << "Starting ChromeOS RMA Daemon.";

    // Enter sandbox and run as rmad user.
    CheckWriteProtectAndEnterMinijail();

    base::ThreadPoolInstance::CreateAndStartWithDefaultParams(
        "rmad_thread_pool");

    rmad::RmadInterfaceImpl rmad_interface;
    rmad::DBusService dbus_service(channel.TakeRemoteEndpoint(),
                                   &rmad_interface);
    return dbus_service.Run();
  } else {
    // Child process. Run as root-level executor.
    if (getuid() != 0) {
      LOG(FATAL) << "Executor must run as root";
    }

    // Put the root-level executor in a light sandbox.
    rmad::NewMountNamespace();

    return rmad::ExecutorDaemon(channel.TakeLocalEndpoint()).Run();
  }
}
