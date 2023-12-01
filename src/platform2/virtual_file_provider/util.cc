// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "virtual_file_provider/util.h"

#include <memory>
#include <string>

#include <sys/capability.h>
#include <sys/prctl.h>

#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_util.h>
#include <base/logging.h>

namespace virtual_file_provider {

// Clears all capabilities.
bool ClearCapabilities() {
  // Read cap_last_cap.
  const base::FilePath last_cap_path("/proc/sys/kernel/cap_last_cap");
  std::string contents;
  int last_cap = 0;
  if (!base::ReadFileToString(last_cap_path, &contents) ||
      !base::StringToInt(
          base::TrimWhitespaceASCII(contents, base::TRIM_TRAILING),
          &last_cap)) {
    LOG(ERROR) << "Failed to read cap_last_cap";
    return false;
  }
  // Drop cap bset.
  for (int i = 0; i <= last_cap; ++i) {
    if (prctl(PR_CAPBSET_DROP, i)) {
      PLOG(ERROR) << "Failed to drop bset " << i;
      return false;
    }
  }
  // Drop capabilities.
  std::unique_ptr<std::remove_pointer<cap_t>::type, decltype(&cap_free)> cap(
      cap_init(), cap_free);
  if (!cap) {
    PLOG(ERROR) << "Failed to cap_init()";
    return false;
  }
  if (cap_set_proc(cap.get())) {
    PLOG(ERROR) << "Failed to cap_set_proc()";
    return false;
  }
  return true;
}

}  // namespace virtual_file_provider
