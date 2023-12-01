// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "debugd/src/container_tool.h"

#include <base/functional/bind.h>
#include <base/location.h>
#include <base/logging.h>
#include <base/process/launch.h>
#include <base/process/process_iterator.h>
#include <base/task/single_thread_task_runner.h>

namespace {

const char kRunOci[] = "/usr/bin/run_oci";

}

namespace debugd {

void ContainerTool::ContainerStarted() {
  if (device_jail_started_)
    return;

  LOG(INFO) << "Starting up device jail";
  base::LaunchOptions options;
  options.wait = true;
  base::LaunchProcess({"start", "device-jail"}, options);
  device_jail_started_ = true;
}

void ContainerTool::ContainerStopped() {
  // If there are still active containers, ignore.
  if (base::GetProcessCount(kRunOci, nullptr) > 0) {
    LOG(INFO) << "Containers are present, deferring cleanup";
    return;
  }

  LOG(INFO) << "Cleaning up device jail";
  base::LaunchOptions options;
  options.wait = true;
  base::LaunchProcess({"stop", "device-jail"}, options);
  device_jail_started_ = false;
}

}  // namespace debugd
