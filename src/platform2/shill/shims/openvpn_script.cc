// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <cstdlib>
#include <map>
#include <string>

#include <base/at_exit.h>
#include <base/check.h>
#include <base/command_line.h>
#include <base/logging.h>
#include <base/memory/ref_counted.h>
#include <brillo/syslog_logging.h>

#include "shill/rpc_task.h"
#include "shill/shims/environment.h"
#include "shill/shims/task_proxy.h"

int main(int argc, char** argv) {
  base::AtExitManager exit_manager;
  base::CommandLine::Init(argc, argv);
  brillo::InitLog(brillo::kLogToSyslog | brillo::kLogHeader);

  shill::shims::Environment* environment =
      shill::shims::Environment::GetInstance();
  std::string service, path, reason;
  if (!environment->GetVariable(shill::kRpcTaskServiceVariable, &service) ||
      !environment->GetVariable(shill::kRpcTaskPathVariable, &path) ||
      !environment->GetVariable("script_type", &reason)) {
    LOG(ERROR) << "Environment variables not available.";
    return EXIT_FAILURE;
  }

  scoped_refptr<dbus::Bus> bus;
  dbus::Bus::Options options;
  options.bus_type = dbus::Bus::SYSTEM;
  bus = new dbus::Bus(options);
  CHECK(bus->Connect());

  shill::shims::TaskProxy proxy(bus, path, service);
  std::map<std::string, std::string> env = environment->AsMap();
  proxy.Notify(reason, env);
  if (bus) {
    bus->ShutdownAndBlock();
  }
  return EXIT_SUCCESS;
}
