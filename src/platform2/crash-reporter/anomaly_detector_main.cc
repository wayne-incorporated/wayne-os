// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Lines in log files are parsed by a LogReader and a Parser each defined
// in anomaly_detector_log_reader.h and anomaly_detector.h. LogReader uses
// TextFileReader class to open a log file. TextFileReader is responsible for
// detecting log rotation and reopening the newly created log file.

#include "crash-reporter/anomaly_detector_service.h"

#include <memory>

#include <base/at_exit.h>
#include <base/check.h>
#include <base/files/file_util.h>
#include <base/run_loop.h>
#include <base/task/single_thread_task_executor.h>
#include <brillo/flag_helper.h>
#include <brillo/syslog_logging.h>
#include <base/files/file_descriptor_watcher_posix.h>

int main(int argc, char* argv[]) {
  DEFINE_bool(testonly_send_all, false,
              "True iff the anomaly detector should send all reports. "
              "Only use for testing.");
  brillo::FlagHelper::Init(argc, argv, "ChromeOS Anomaly Detector");
  // Sim sala bim!  These are needed to send D-Bus signals and receive messages.
  // Even though they are not used directly, they set up some global state
  // needed by the D-Bus library.
  base::SingleThreadTaskExecutor task_executor(base::MessagePumpType::IO);
  base::FileDescriptorWatcher watcher(task_executor.task_runner());
  base::AtExitManager at_exit_manager;

  brillo::OpenLog("anomaly_detector", true);
  brillo::InitLog(brillo::kLogToSyslog | brillo::kLogToStderrIfTty);

  base::RunLoop run_loop;

  auto service = std::make_unique<anomaly::Service>(run_loop.QuitClosure(),
                                                    FLAGS_testonly_send_all);
  CHECK(service->Init());

  run_loop.Run();

  return 0;
}
