// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "hps/daemon/hps_daemon.h"

#include <stdint.h>
#include <string.h>

#include <base/check.h>
#include <base/command_line.h>
#include <base/files/file_path.h>
#include <base/logging.h>
#include <base/task/thread_pool/thread_pool_instance.h>
#include <brillo/flag_helper.h>
#include <brillo/syslog_logging.h>

#include "hps/hal/fake_dev.h"
#include "hps/hal/i2c.h"
#include "hps/hal/mcp.h"
#include "hps/hps_impl.h"
#include "hps/utils.h"

int main(int argc, char* argv[]) {
  base::AtExitManager at_exit;

  DEFINE_string(bus, "/dev/i2c-hps-controller", "I2C device");
  DEFINE_string(hps_dev, "/dev/cros-hps", "HPS device");
  DEFINE_uint32(addr, 0x30, "I2C address of module");
  DEFINE_uint32(speed, 200, "I2C bus speed in KHz");
  DEFINE_bool(mcp, false, "Use MCP2221A connection");
  DEFINE_bool(test, false, "Use internal test fake");
  DEFINE_bool(skipboot, false, "Skip boot sequence");
  DEFINE_int32(fake_feature0_score, 127,
               "Feature 0 score reported by test fake");
  DEFINE_int32(fake_feature1_score, -128,
               "Feature 1 score reported by test fake");
  DEFINE_int64(version, -1, "Override MCU firmware version");
  DEFINE_string(version_file, "", "MCU firmware version file");
  DEFINE_string(mcu_fw_image, "", "MCU firmware file");
  DEFINE_string(fpga_bitstream, "", "FPGA bitstream file");
  DEFINE_string(fpga_app_image, "", "FPGA application file");
  DEFINE_uint32(poll_timer_ms, 200,
                "How frequently to poll HPS hardware for results (in ms).");
  brillo::FlagHelper::Init(argc, argv, "hps_daemon - HPS services daemon");

  // Always log to syslog and log to stderr if we are connected to a tty.
  brillo::InitLog(brillo::kLogToSyslog | brillo::kLogToStderrIfTty);

  uint32_t version;
  if (FLAGS_version < 0) {
    if (!hps::ReadVersionFromFile(base::FilePath(FLAGS_version_file),
                                  &version)) {
      return 1;
    }
  } else {
    version = base::checked_cast<uint32_t>(FLAGS_version);
  }

  // Determine the hardware connection.
  std::unique_ptr<hps::DevInterface> dev;
  uint8_t addr = base::checked_cast<uint8_t>(FLAGS_addr);
  if (FLAGS_mcp) {
    dev = hps::Mcp::Create(addr, FLAGS_speed);
  } else if (FLAGS_test) {
    // Initialise the fake device as already booted so that
    // features can be enabled/disabled.
    auto fake = std::make_unique<hps::FakeDev>();
    fake->SkipBoot();
    fake->SetVersion(version);
    CHECK(FLAGS_fake_feature0_score <= INT8_MAX);
    CHECK(FLAGS_fake_feature0_score >= INT8_MIN);
    fake->SetF0Result(static_cast<int8_t>(FLAGS_fake_feature0_score),
                      /* valid */ true);
    CHECK(FLAGS_fake_feature1_score <= INT8_MAX);
    CHECK(FLAGS_fake_feature1_score >= INT8_MIN);
    fake->SetF1Result(static_cast<int8_t>(FLAGS_fake_feature1_score),
                      /* valid */ true);
    dev = std::move(fake);
  } else {
    dev = hps::I2CDev::Create(FLAGS_bus, addr, FLAGS_hps_dev);
  }

  CHECK(dev) << "Hardware device failed to initialise";

  int exit_code =
      hps::HpsDaemon(std::move(dev), FLAGS_poll_timer_ms, FLAGS_skipboot,
                     version, base::FilePath(FLAGS_mcu_fw_image),
                     base::FilePath(FLAGS_fpga_bitstream),
                     base::FilePath(FLAGS_fpga_app_image))
          .Run();
  LOG(INFO) << "HPS Service ended with exit_code=" << exit_code;

  return exit_code;
}
