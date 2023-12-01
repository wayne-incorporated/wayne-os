// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <string>

#include <base/command_line.h>
#include <base/logging.h>
#include <brillo/syslog_logging.h>
#include <chromeos/dbus/service_constants.h>

#include "ml/dbus_service/adaptive_charging_service.h"
#include "ml/dbus_service/dbus_service_daemon.h"
#include "ml/process.h"

namespace {

constexpr char kMojoServiceTask[] = "mojo_service";
constexpr char kAdaptiveChargingTask[] = "adaptive_charging";

}  // namespace

int main(int argc, char* argv[]) {
  brillo::InitLog(brillo::kLogToSyslog | brillo::kLogToStderrIfTty);
  // Parses the command line arguments. Shared within the current process.
  base::CommandLine::Init(argc, argv);

  const std::string task =
      base::CommandLine::ForCurrentProcess()->GetSwitchValueASCII("task");

  if (task == kMojoServiceTask)
    return ml::Process::GetInstance()->Run();

  if (task == kAdaptiveChargingTask)
    return ml::DBusServiceDaemon<
               ml::AdaptiveChargingService,
               org::chromium::MachineLearning::AdaptiveChargingAdaptor>(
               ml::kMachineLearningAdaptiveChargingServiceName)
        .Run();

  LOG(ERROR) << "ml-service received unknown task " << task;
  return 0;
}
