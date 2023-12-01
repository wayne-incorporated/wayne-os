// Copyright 2009 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <base/at_exit.h>
#include <base/command_line.h>
#include <base/logging.h>
#include <base/strings/string_util.h>
#include <brillo/flag_helper.h>
#include <brillo/syslog_logging.h>
#include <rootdev/rootdev.h>

#include "metrics/metrics_daemon.h"

namespace {

const char kPersistentIntegerBackingDir[] = "/var/lib/metrics";

const char kScalingMaxFreqPath[] =
    "/sys/devices/system/cpu/cpu0/cpufreq/scaling_max_freq";
const char kCpuinfoMaxFreqPath[] =
    "/sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq";

// Returns the path to the disk stats in the sysfs.  Returns the null string if
// it cannot find the disk stats file.
const std::string MetricsMainDiskStatsPath() {
  char dev_path_cstr[PATH_MAX];
  std::string dev_prefix = "/dev/";
  std::string dev_path;
  std::string dev_name;

  int ret = rootdev(dev_path_cstr, sizeof(dev_path_cstr), true, true);
  if (ret != 0) {
    LOG(WARNING) << "error " << ret << " determining root device";
    return "";
  }
  dev_path = dev_path_cstr;
  // Check that rootdev begins with "/dev/".
  if (!base::StartsWith(dev_path, dev_prefix, base::CompareCase::SENSITIVE)) {
    LOG(WARNING) << "unexpected root device " << dev_path;
    return "";
  }
  // Get the device name, e.g. "sda" from "/dev/sda".
  dev_name = dev_path.substr(dev_prefix.length());
  return "/sys/class/block/" + dev_name + "/stat";
}

}  // namespace

int main(int argc, char** argv) {
  DEFINE_bool(daemon, true, "run as daemon (use -nodaemon for debugging)");

  // The uploader is disabled by default on ChromeOS as Chrome is responsible
  // for sending the metrics.
  DEFINE_bool(uploader, false, "activate the uploader");

  // Upload the metrics once and exit. (used for testing)
  DEFINE_bool(uploader_test, false, "run the uploader once and exit");

  // Upload Service flags.
  DEFINE_int32(upload_interval_secs, 1800,
               "Interval at which metrics_daemon sends the metrics. (needs "
               "-uploader)");
  DEFINE_string(server, "https://clients4.google.com/uma/v2",
                "Server to upload the metrics to. (needs -uploader)");
  DEFINE_string(metrics_file, "/var/lib/metrics/uma-events",
                "File to use as a proxy for uploading the metrics");
  DEFINE_string(config_root, "/",
                "Root of the configuration files (testing only)");

  brillo::FlagHelper::Init(argc, argv, "Chromium OS Metrics Daemon");

  // Also log to stderr when not running as daemon on a TTY.
  brillo::InitLog(brillo::kLogToSyslog | brillo::kLogHeader |
                  (FLAGS_daemon ? 0 : brillo::kLogToStderrIfTty));

  if (FLAGS_daemon && daemon(0, 0) != 0) {
    return errno;
  }

  base::FilePath backing_dir_path(kPersistentIntegerBackingDir);
  MetricsLibrary metrics_lib;
  chromeos_metrics::MetricsDaemon daemon;
  daemon.Init(FLAGS_uploader_test, FLAGS_uploader | FLAGS_uploader_test,
              &metrics_lib, MetricsMainDiskStatsPath(), "/proc/vmstat",
              kScalingMaxFreqPath, kCpuinfoMaxFreqPath,
              base::Seconds(FLAGS_upload_interval_secs), FLAGS_server,
              FLAGS_metrics_file, FLAGS_config_root, backing_dir_path);

  if (FLAGS_uploader_test) {
    daemon.RunUploaderTest();
    return 0;
  }

  daemon.Run();
}
