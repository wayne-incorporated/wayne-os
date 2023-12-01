// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// This file is meant for debugging use to manually trigger a proper
// reboot, exercising the full path through the power manager.

#include <unistd.h>

#include <memory>

#include <base/at_exit.h>
#include <base/files/file_descriptor_watcher_posix.h>
#include <base/task/single_thread_task_executor.h>
#include <brillo/flag_helper.h>
#include <chromeos/dbus/service_constants.h>
#include <dbus/bus.h>
#include <dbus/message.h>
#include <dbus/object_proxy.h>

#include "power_manager/common/util.h"

int main(int argc, char* argv[]) {
  DEFINE_int32(delay, 1, "Delay before rebooting in seconds.");
  DEFINE_int32(request_reason,
               power_manager::RequestRestartReason::REQUEST_RESTART_FOR_USER,
               "RequestRestartReason value to send in the DBus message.");

  brillo::FlagHelper::Init(
      argc, argv,
      "Instruct powerd to reboot the system. The default request "
      "reason is REQUEST_RESTART_FOR_USER, unless specified by "
      "--request_reason.");
  base::AtExitManager at_exit_manager;
  base::SingleThreadTaskExecutor task_executor(base::MessagePumpType::IO);
  base::FileDescriptorWatcher watcher(task_executor.task_runner());

  dbus::Bus::Options options;
  options.bus_type = dbus::Bus::SYSTEM;
  scoped_refptr<dbus::Bus> bus(new dbus::Bus(options));
  CHECK(bus->Connect());
  dbus::ObjectProxy* powerd_proxy = bus->GetObjectProxy(
      power_manager::kPowerManagerServiceName,
      dbus::ObjectPath(power_manager::kPowerManagerServicePath));

  if (FLAGS_delay)
    sleep(FLAGS_delay);

  // Send a restart request.
  dbus::MethodCall method_call(power_manager::kPowerManagerInterface,
                               power_manager::kRequestRestartMethod);
  dbus::MessageWriter writer(&method_call);
  writer.AppendInt32(FLAGS_request_reason);
  std::unique_ptr<dbus::Response> response(powerd_proxy->CallMethodAndBlock(
      &method_call, dbus::ObjectProxy::TIMEOUT_USE_DEFAULT));
  CHECK(response) << power_manager::kRequestRestartMethod << " failed";

  return 0;
}
