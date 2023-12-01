// Copyright 2016 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "debugd/src/swap_tool.h"

#include <string>

#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/strings/stringprintf.h>
#include <chromeos/dbus/debugd/dbus-constants.h>

#include "debugd/src/error_utils.h"
#include "debugd/src/process_with_output.h"

namespace debugd {

namespace {

// This script holds the bulk of the real logic.
const char kSwapHelperScript[] = "/usr/share/cros/init/swap.sh";
// The path of the kstaled ratio file.
const char kMGLRUEnabledPath[] = "/sys/kernel/mm/lru_gen/enabled";
const char kSwapToolErrorString[] = "org.chromium.debugd.error.Swap";
base::FilePath kZramDevicePath("/sys/block/zram0");
base::FilePath kSwappinessPath("/proc/sys/vm/swappiness");

constexpr base::TimeDelta kMaxIdleAge = base::Days(30);

std::string RunSwapHelper(const ProcessWithOutput::ArgList& arguments,
                          int* result) {
  std::string stdout, stderr;
  *result = ProcessWithOutput::RunProcessFromHelper(
      kSwapHelperScript, arguments, nullptr, &stdout, &stderr);
  return *result ? stderr : stdout;
}

}  // namespace

std::string SwapTool::SwapEnable(int32_t size, bool change_now) const {
  int result;
  std::string output, buf;

  buf = base::StringPrintf("%d", size);
  output = RunSwapHelper({"enable", buf}, &result);
  if (result != EXIT_SUCCESS)
    return output;

  if (change_now)
    output = SwapStartStop(true);

  return output;
}

std::string SwapTool::SwapDisable(bool change_now) const {
  int result;
  std::string output;

  output = RunSwapHelper({"disable"}, &result);
  if (result != EXIT_SUCCESS)
    return output;

  if (change_now)
    output = SwapStartStop(false);

  return output;
}

std::string SwapTool::SwapStartStop(bool on) const {
  int result;
  std::string output;

  // We always turn off swap because the config might have changed.
  // Also because the code doesn't like to turn on twice.
  output = RunSwapHelper({"stop"}, &result);
  if (result != EXIT_SUCCESS)
    return output;

  if (on)
    output = RunSwapHelper({"start"}, &result);

  return output;
}

std::string SwapTool::SwapStatus() const {
  int result;
  return RunSwapHelper({"status"}, &result);
}

std::string SwapTool::SwapSetParameter(const std::string& parameter_name,
                                       int32_t parameter_value) const {
  int result;
  std::string buf;

  buf = base::StringPrintf("%d", parameter_value);
  return RunSwapHelper({"set_parameter", parameter_name, buf}, &result);
}

// static
bool SwapTool::WriteValueToFile(const base::FilePath& file,
                                const std::string& val,
                                std::string* msg) {
  if (!base::WriteFile(file, val)) {
    if (msg) {
      *msg =
          base::StringPrintf("ERROR: Failed to write %s to %s. Error %d (%s)",
                             val.c_str(), file.MaybeAsASCII().c_str(), errno,
                             base::safe_strerror(errno).c_str());
    }
    return false;
  }

  if (msg) {
    *msg = "SUCCESS";
  }
  return true;
}

// Zram writeback configuration.
std::string SwapTool::SwapZramEnableWriteback(uint32_t size_mb) const {
  int result;
  std::string buf;

  // For now throw out values >32gb.
  constexpr int kMaxSizeMb = 32 << 10;
  if (size_mb == 0 || size_mb >= kMaxSizeMb) {
    return "ERROR: Invalid size specified.";
  }

  std::string res = RunSwapHelper(
      {"enable_zram_writeback", std::to_string(size_mb)}, &result);
  if (result && res.empty()) {
    res = "unknown error";
  }

  return std::string(result ? "ERROR: " : "SUCCESS: ").append(res);
}

std::string SwapTool::SwapZramSetWritebackLimit(uint32_t num_pages) const {
  // Always make sure the writeback limit mode is enabled.
  base::FilePath enable_file(kZramDevicePath.Append("writeback_limit_enable"));
  std::string msg;
  if (!WriteValueToFile(enable_file, "1", &msg)) {
    return msg;
  }

  base::FilePath filepath(kZramDevicePath.Append("writeback_limit"));
  std::string pages_str = std::to_string(num_pages);

  // We ignore the return value of WriteValueToFile because |msg|
  // contains the free form text response.
  WriteValueToFile(filepath, pages_str, &msg);
  return msg;
}

std::string SwapTool::SwapZramMarkIdle(uint32_t age_seconds) const {
  const auto age = base::Seconds(age_seconds);
  if (age > kMaxIdleAge) {
    // Only allow marking pages as idle between 0sec and 30 days.
    return base::StringPrintf("ERROR: Invalid age: %d", age_seconds);
  }

  base::FilePath filepath(kZramDevicePath.Append("idle"));
  std::string age_str = std::to_string(age.InSeconds());
  std::string msg;

  // We ignore the return value of WriteValueToFile because |msg|
  // contains the free form text response.
  WriteValueToFile(filepath, age_str, &msg);
  return msg;
}

std::string SwapTool::InitiateSwapZramWriteback(uint32_t mode) const {
  base::FilePath filepath(kZramDevicePath.Append("writeback"));
  std::string mode_str;
  if (mode == WRITEBACK_IDLE) {
    mode_str = "idle";
  } else if (mode == WRITEBACK_HUGE) {
    mode_str = "huge";
  } else if (mode == WRITEBACK_HUGE_IDLE) {
    mode_str = "huge_idle";
  } else {
    return "ERROR: Invalid mode";
  }

  std::string msg;

  // We ignore the return value of WriteValueToFile because |msg|
  // contains the free form text response.
  WriteValueToFile(filepath, mode_str, &msg);
  return msg;
}

std::string SwapTool::SwapSetSwappiness(uint32_t swappiness_value) const {
  if (swappiness_value > 100) {
    // Only allow swappiness_value between 0 and 100.
    return base::StringPrintf("ERROR: Invalid swappiness: %d",
                              swappiness_value);
  }

  base::FilePath filepath(kSwappinessPath);
  std::string swappiness_str = std::to_string(swappiness_value);
  std::string msg;

  // We ignore the return value of WriteValueToFile because |msg|
  // contains the free form text response.
  WriteValueToFile(filepath, swappiness_str, &msg);
  return msg;
}

bool SwapTool::KstaledSetRatio(brillo::ErrorPtr* error,
                               uint8_t kstaled_ratio) const {
  std::string buf = std::to_string(kstaled_ratio);

  errno = 0;
  size_t res = base::WriteFile(base::FilePath(kMGLRUEnabledPath), buf.c_str(),
                               buf.size());
  if (res != buf.size()) {
    DEBUGD_ADD_ERROR(error, kSwapToolErrorString, strerror(errno));
    return false;
  }

  return true;
}

}  // namespace debugd
