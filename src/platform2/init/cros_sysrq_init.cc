// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <string>

#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <vboot/crossystem.h>

namespace {

// The path to the sysrq config file.
constexpr char kSysrqPath[] = "/proc/sys/kernel/sysrq";

// When dev-mode is enabled, allow all keys.
constexpr char kSysrqDevValue[] = "1";

// When dev-mode is disabled, only allow the 'x' key.
constexpr char kSysrqNormalValue[] = "0x1000";

bool IsDevMode() {
  int value = ::VbGetSystemPropertyInt("cros_debug");
  return value == 1;
}

}  // namespace

int main(int argc, char* argv[]) {
  const base::FilePath sysrq(kSysrqPath);
  const std::string value = IsDevMode() ? kSysrqDevValue : kSysrqNormalValue;
  return base::WriteFile(sysrq, value.c_str(), value.size()) == value.size()
             ? 0
             : 1;
}
