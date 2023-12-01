// Copyright 2016 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <signal.h>
#include <sys/capability.h>
#include <sys/prctl.h>

#include <iterator>

#include <base/at_exit.h>
#include <base/check.h>
#include <base/files/file_descriptor_watcher_posix.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/run_loop.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_util.h>
#include <base/task/single_thread_task_executor.h>
#include <brillo/syslog_logging.h>
#include <dbus/bus.h>

#include "arc/container/obb-mounter/service.h"

namespace {

// Drops all capabilities except CAP_SYS_ADMIN (needed for fuse) and
// CAP_DAC_READ_SEARCH (needed to access /data/media/obb).
bool DropUnnecessaryCapabilities() {
  const cap_value_t kKeep[2] = {CAP_SYS_ADMIN, CAP_DAC_READ_SEARCH};
  // Read cap_last_cap.
  base::FilePath last_cap_path("/proc/sys/kernel/cap_last_cap");
  std::string contents;
  int last_cap = 0;
  if (!base::ReadFileToString(last_cap_path, &contents) ||
      !base::StringToInt(
          base::TrimWhitespaceASCII(contents, base::TRIM_TRAILING),
          &last_cap)) {
    LOG(ERROR) << "Failed to read cap_last_cap";
    return false;
  }
  // Drop cap bset.
  for (int i = 0; i <= last_cap; ++i) {
    if (std::count(kKeep, kKeep + std::size(kKeep), i) == 0) {
      if (prctl(PR_CAPBSET_DROP, i)) {
        PLOG(ERROR) << "Failed to drop bset " << i;
        return false;
      }
    }
  }
  // Drop capabilities.
  std::unique_ptr<std::remove_pointer<cap_t>::type, int (*)(void*)> cap(
      cap_get_proc(), cap_free);
  if (!cap) {
    PLOG(ERROR) << "Failed to cap_get_proc()";
    return false;
  }
  if (cap_clear_flag(cap.get(), CAP_EFFECTIVE) ||
      cap_clear_flag(cap.get(), CAP_PERMITTED) ||
      cap_clear_flag(cap.get(), CAP_INHERITABLE)) {
    PLOG(ERROR) << "Failed to cap_clear_flag()";
    return false;
  }
  if (cap_set_flag(cap.get(), CAP_EFFECTIVE, std::size(kKeep), kKeep,
                   CAP_SET) ||
      cap_set_flag(cap.get(), CAP_PERMITTED, std::size(kKeep), kKeep,
                   CAP_SET) ||
      cap_set_flag(cap.get(), CAP_INHERITABLE, std::size(kKeep), kKeep,
                   CAP_SET)) {
    PLOG(ERROR) << "Failed to cap_set_flag()";
    return false;
  }
  if (cap_set_proc(cap.get())) {
    PLOG(ERROR) << "Failed to cap_set_proc()";
    return false;
  }
  return true;
}

}  // namespace

int main(int argc, char** argv) {
  // Not to make child processes zombies when they die.
  signal(SIGCHLD, SIG_IGN);

  brillo::InitLog(brillo::kLogToSyslog | brillo::kLogToStderr);

  CHECK(DropUnnecessaryCapabilities());

  base::AtExitManager at_exit_manager;
  base::SingleThreadTaskExecutor task_executor(base::MessagePumpType::IO);
  base::FileDescriptorWatcher watcher(task_executor.task_runner());

  // Connect the bus.
  dbus::Bus::Options options;
  options.bus_type = dbus::Bus::SYSTEM;
  scoped_refptr<dbus::Bus> bus = new dbus::Bus(options);
  CHECK(bus->Connect());

  // Initialize the service.
  arc::obb_mounter::Service service;
  CHECK(service.Initialize(bus));

  base::RunLoop().Run();
  return 0;
}
