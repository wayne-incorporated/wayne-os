// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <atomic>
#include <signal.h>
#include <vector>

#include <base/logging.h>
#include <base/strings/string_split.h>
#include <brillo/daemons/daemon.h>
#include <brillo/flag_helper.h>

#include "iioservice/iioservice_simpleclient/common.h"
#include "iioservice/iioservice_simpleclient/daemon_samples_observer.h"
#include "iioservice/include/common.h"
#include "iioservice/mojo/sensor.mojom.h"

namespace {

static const int kNumSuccessReads = 100;

std::atomic<bool> daemon_running(false);
std::unique_ptr<iioservice::DaemonSamplesObserver> exec_daemon;

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
  DEFINE_int32(device_id, -1, "The IIO device id to test.");

  std::string device_types =
      "The IIO device type to test. It follows the mojo interface's order: " +
      iioservice::GetDeviceTypesInString();
  DEFINE_int32(device_type, 0, device_types.c_str());
  DEFINE_string(channels, "", "Specify space separated channels to be enabled");
  DEFINE_double(frequency, -1.0, "frequency in Hz set to the device.");
  DEFINE_uint64(timeout, 1000, "Timeout for I/O operations. 0 as no timeout");
  DEFINE_uint64(samples, kNumSuccessReads, "Number of samples to wait for");

  brillo::FlagHelper::Init(argc, argv, "Chromium OS iioservice_simpleclient");
  logging::LoggingSettings settings;
  LOG_ASSERT(logging::InitLogging(settings));
  logging::SetMinLogLevel(FLAGS_log_level);

  std::vector<std::string> channel_ids = base::SplitString(
      FLAGS_channels, " ", base::TRIM_WHITESPACE, base::SPLIT_WANT_NONEMPTY);

  if (FLAGS_device_id == -1 && FLAGS_device_type == 0) {
    LOGF(ERROR)
        << "iioservice_simpleclient must be called with a sensor specified.";
    exit(1);
  }
  if (FLAGS_frequency < 0.0) {
    LOGF(ERROR) << "iioservice_simpleclient must be called with frequency set.";
    exit(1);
  }
  if (channel_ids.empty()) {
    LOGF(ERROR) << "iioservice_simpleclient must be called with at least one "
                   "channel enabled.";
    exit(1);
  }

  exec_daemon = std::make_unique<iioservice::DaemonSamplesObserver>(
      FLAGS_device_id, static_cast<cros::mojom::DeviceType>(FLAGS_device_type),
      std::move(channel_ids), FLAGS_frequency, FLAGS_timeout, FLAGS_samples);
  signal(SIGTERM, signal_handler_stop);
  signal(SIGINT, signal_handler_stop);
  daemon_running = true;
  exec_daemon->Run();
  daemon_running = false;
}
