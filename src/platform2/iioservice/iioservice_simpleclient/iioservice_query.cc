// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <atomic>
#include <signal.h>

#include <base/logging.h>
#include <base/strings/string_split.h>
#include <brillo/daemons/daemon.h>
#include <brillo/flag_helper.h>

#include "iioservice/iioservice_simpleclient/common.h"
#include "iioservice/iioservice_simpleclient/daemon_query.h"
#include "iioservice/include/common.h"
#include "iioservice/mojo/sensor.mojom.h"

namespace {

std::atomic<bool> daemon_running(false);
std::unique_ptr<iioservice::DaemonQuery> exec_daemon;

void quit_daemon() {
  if (!daemon_running)
    return;

  daemon_running = false;
  LOGF(INFO) << "Quiting daemon";
  exec_daemon->Quit();
}

void signal_handler_stop(int signal) {
  LOGF(INFO) << "Signal: " << signal;

  quit_daemon();
}

}  // namespace

int main(int argc, char** argv) {
  DEFINE_int32(log_level, 0,
               "Logging level - 0: LOG(INFO), 1: LOG(WARNING), 2: LOG(ERROR), "
               "-1: VLOG(1), -2: VLOG(2), ...");

  std::string device_types =
      "The IIO device type to query, if NONE, query all types. It follows the "
      "mojo interface's order: " +
      iioservice::GetDeviceTypesInString();
  DEFINE_int32(device_type, 0, device_types.c_str());
  DEFINE_string(attributes, "", "Specify space separated attributes to query");

  brillo::FlagHelper::Init(argc, argv, "Chromium OS iioservice_query");
  logging::LoggingSettings settings;
  LOG_ASSERT(logging::InitLogging(settings));
  logging::SetMinLogLevel(FLAGS_log_level);

  std::vector<std::string> attributes = base::SplitString(
      FLAGS_attributes, " ", base::TRIM_WHITESPACE, base::SPLIT_WANT_NONEMPTY);
  if (attributes.empty()) {
    LOGF(ERROR)
        << "iioservice_query must be called with at least one attribute "
           "to query.";
    exit(1);
  }

  exec_daemon = std::make_unique<iioservice::DaemonQuery>(
      static_cast<cros::mojom::DeviceType>(FLAGS_device_type),
      std::move(attributes));
  signal(SIGTERM, signal_handler_stop);
  signal(SIGINT, signal_handler_stop);
  daemon_running = true;
  exec_daemon->Run();
  daemon_running = false;
}
