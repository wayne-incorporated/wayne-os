// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

/*
 * Main command program.
 */

#include <iostream>
#include <memory>
#include <utility>

#include <getopt.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>

#include <base/check.h>
#include <base/command_line.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <base/time/time.h>
#include <brillo/flag_helper.h>

#include "hps/hal/fake_dev.h"
#include "hps/hal/i2c.h"
#include "hps/hal/mcp.h"
#include "hps/hal/retry.h"
#include "hps/hps.h"
#include "hps/hps_impl.h"
#include "hps/util/command.h"

// Static allocation of global command list head.
Command* Command::list_;

namespace {

class DownloadProgressIndicator {
 public:
  void Update(const base::FilePath& file_path,
              uint64_t total_bytes,
              uint64_t downloaded_bytes,
              base::TimeDelta elapsed_time) {
    bool done = downloaded_bytes == total_bytes;

    // Don't flood the console too frequently.
    if (!done && (elapsed_time - last_update_).InMilliseconds() < 100)
      return;
    last_update_ = elapsed_time;

    constexpr const char kMessage[] = "Downloading ";
    constexpr int kStatsWidth = 40;
    std::string file = file_path.MaybeAsASCII();
    int term_width = GetTerminalWidth();
    int file_width = strlen(kMessage) + file.size();

    // Bail out if the terminal is too narrow.
    if (term_width <= file_width + kStatsWidth)
      return;

    // Print the file name.
    std::cout << kMessage << file;

    // Print the progress bar (if there's space).
    int bar_width = term_width - file_width - kStatsWidth - 8;
    if (total_bytes > 0 && bar_width > 0 && !done) {
      std::cout << " [";
      for (int i = 0; i < bar_width; i++) {
        std::cout << (i > (bar_width * downloaded_bytes) / total_bytes ? '-'
                                                                       : '#');
      }
      std::cout << "]" << std::setw(3) << std::right
                << (100 * downloaded_bytes) / total_bytes << "%";
    }

    // Print statistics.
    int seconds = elapsed_time.InSeconds();
    std::cout << " (" << downloaded_bytes << " in " << (seconds / 60) << ":"
              << std::setw(2) << std::setfill('0') << (seconds % 60)
              << std::setfill(' ');
    if (elapsed_time.InSeconds()) {
      std::cout << ", " << std::setprecision(1) << std::fixed
                << downloaded_bytes / (1024 * elapsed_time.InSecondsF())
                << " KiB/s";
    }
    std::cout << ")";

    // Erase the rest of the line and move the cursor back to the beginning of
    // the line for the next update (unless we're done).
    std::cout << "\033[K";
    if (!done) {
      std::cout << std::flush << "\r";
    } else {
      std::cout << std::endl;
    }
  }

 private:
  static int GetTerminalWidth() {
    winsize window_size;
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &window_size) != 0)
      return -1;
    return window_size.ws_col;
  }

  base::TimeDelta last_update_{};
};

}  // namespace

int main(int argc, char* argv[]) {
  DEFINE_string(bus, "/dev/i2c-hps-controller", "I2C device");
  DEFINE_uint32(addr, 0x30, "I2C address of module");
  DEFINE_uint32(speed, 200, "I2C bus speed in KHz");
  DEFINE_uint32(retries, 0, "Max I2C retries");
  DEFINE_uint32(retry_delay, 10, "Delay in ms between retries");
  DEFINE_bool(mcp, false, "Use MCP2221A connection");
  DEFINE_string(test, "none",
                "Use internal test fake, optionally setting the emulated state "
                "to one of: boot, ready");
  brillo::FlagHelper::Init(argc, argv,
                           "usage: hps [ --mcp | --test[=<state>] | --bus "
                           "<i2c-bus> ] [ --addr <i2c-addr> ]\n"
                           "           <command> <command arguments>\n\n" +
                               Command::GetHelp());

  const logging::LoggingSettings ls;
  logging::InitLogging(ls);

  auto args = base::CommandLine::ForCurrentProcess()->GetArgs();
  if (args.size() == 0) {
    std::cerr << "no command, " << Command::GetHelp();
    return 1;
  }
  std::unique_ptr<hps::DevInterface> dev;
  if (FLAGS_mcp) {
    dev = hps::Mcp::Create(FLAGS_addr, FLAGS_speed);
  } else if (FLAGS_test != "none") {
    // Optionally initialise the fake device as already booted so that
    // features can be enabled/disabled.
    auto fake = std::make_unique<hps::FakeDev>();
    if (FLAGS_test == "ready" || FLAGS_test == "") {
      fake->SkipBoot();
    } else if (FLAGS_test != "boot") {
      std::cerr << "Unsupported fake device state: " << FLAGS_test << std::endl;
      return 1;
    }
    dev = std::move(fake);
  } else {
    dev = hps::I2CDev::Create(FLAGS_bus, FLAGS_addr, /*power_control=*/"");
  }
  if (FLAGS_retries > 0) {
    // If retries are required, add a retry device.
    std::cout << "Enabling retries: " << FLAGS_retries
              << ", delay per retry: " << FLAGS_retry_delay << " ms"
              << std::endl;
    auto baseDevice = std::move(dev);
    dev =
        std::make_unique<hps::RetryDev>(std::move(baseDevice), FLAGS_retries,
                                        base::Milliseconds(FLAGS_retry_delay));
  }
  auto hps = std::make_unique<hps::HPS_impl>(
      std::move(dev), std::make_unique<hps::HpsNoMetrics>());

  // Show download progress when run interactively.
  if (isatty(STDOUT_FILENO)) {
    hps->SetDownloadObserver(
        base::BindRepeating(&DownloadProgressIndicator::Update,
                            std::make_unique<DownloadProgressIndicator>()));
  }

  // Pass args to the command for any following arguments.
  // args[0] is command name.
  return Command::Execute(args[0].c_str(), std::move(hps), args);
}
