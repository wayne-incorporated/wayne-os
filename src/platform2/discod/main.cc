// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <base/files/file_path.h>
#include <base/logging.h>
#include <brillo/blkdev_utils/disk_iostat.h>
#include <brillo/flag_helper.h>
#include <brillo/syslog_logging.h>
#include <rootdev/rootdev.h>

#include "discod/controls/file_based_binary_control.h"
#include "discod/controls/real_ufs_write_booster_control_logic.h"
#include "discod/daemon.h"
#include "discod/metrics/real_metrics.h"
#include "discod/utils/ufs.h"

namespace discod {

base::FilePath GetRootDevice() {
  char buf[PATH_MAX];
  int ret =
      rootdev(buf, PATH_MAX, /*use_slave=*/true, /*strip_partition=*/true);
  if (ret == 0) {
    return base::FilePath(buf);
  } else {
    LOG(ERROR) << "Could not query rootdev, error=" << ret;
    return base::FilePath();
  }
}

base::FilePath GetRoot() {
  return base::FilePath("/");
}

std::unique_ptr<ControlLoop> MakeControlLoop(const base::FilePath& root_device,
                                             const base::FilePath& root) {
  if (!IsUfs(root_device, root)) {
    VLOG(1) << "Not a UFS device: " << root_device;
    return nullptr;
  }

  if (!IsWriteBoosterSupported(root_device, root)) {
    VLOG(1) << "WriteBooster is not supported: " << root_device;
    return nullptr;
  }

  base::FilePath device_node = GetUfsDeviceNode(root_device, root);
  base::FilePath ufs_wb_node = GetUfsWriteBoosterNode(root_device, root);

  if (device_node == base::FilePath()) {
    LOG(FATAL) << "Could not query iostat node for: " << root_device;
  }

  if (ufs_wb_node == base::FilePath()) {
    LOG(FATAL) << "Could not query ufs wb node for: " << root_device;
  }

  VLOG(1) << "root_device=" << root_device;
  VLOG(1) << "root=" << root;
  VLOG(1) << "device_node=" << device_node;
  VLOG(1) << "ufs_wb_node=" << ufs_wb_node;

  LOG(INFO) << "UFS device found:" << root_device;

  std::unique_ptr<RealMetrics> metrics = RealMetrics::Create();
  auto* raw_metrics = metrics.get();

  return std::make_unique<ControlLoop>(
      std::make_unique<RealUfsWriteBoosterControlLogic>(
          std::make_unique<FileBasedBinaryControl>(ufs_wb_node), raw_metrics),
      std::make_unique<brillo::DiskIoStat>(device_node), std::move(metrics));
}

}  // namespace discod

int main(int argc, char** argv) {
  DEFINE_bool(foreground, false, "Run in foreground");
  DEFINE_int32(log_level, 0,
               "Logging level - 0: LOG(INFO), 1: LOG(WARNING), 2: LOG(ERROR), "
               "-1: VLOG(1), -2: VLOG(2), ...");
  DEFINE_string(root_dev, "", "Override root device");

  brillo::FlagHelper::Init(argc, argv, "ChromiumOS Disc Control Daemon");

  brillo::InitLog(brillo::kLogToSyslog | brillo::kLogToStderrIfTty);
  logging::SetMinLogLevel(FLAGS_log_level);

  if (!FLAGS_foreground)
    PCHECK(daemon(0, 0) == 0);

  base::FilePath root_device = FLAGS_root_dev.empty()
                                   ? discod::GetRootDevice()
                                   : base::FilePath(FLAGS_root_dev);

  LOG(INFO) << "Starting service...";
  const int ret =
      discod::Daemon(discod::MakeControlLoop(root_device, discod::GetRoot()))
          .Run();
  LOG(INFO) << "Service stopped with exit code " << ret;
}
