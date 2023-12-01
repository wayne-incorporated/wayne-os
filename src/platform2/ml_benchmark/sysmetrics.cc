// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "ml_benchmark/sysmetrics.h"

#include <base/check.h>
#include <base/files/file.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <re2/re2.h>

#include <string>

namespace {
static const char* kProcFile = "/proc/self/status";

int64_t GetStatusField(const std::string field_name) {
  const std::string field_matcher = field_name + ":\\s+(\\d+)\\s+kB";
  std::string status;
  int64_t value;

  CHECK(base::ReadFileToString(base::FilePath(kProcFile), &status))
      << "Could not read " << kProcFile;
  if (!RE2::PartialMatch(status, field_matcher, &value)) {
    LOG(ERROR) << "Couldn't parse " << field_name << " from " << kProcFile;
    return -1;
  }

  return value;
}
}  // namespace

namespace ml_benchmark {

int64_t GetVMSizeBytes() {
  return GetStatusField("VmSize") * 1024;
}

int64_t GetVMPeakBytes() {
  return GetStatusField("VmPeak") * 1024;
}

int64_t GetSwapAndRSSBytes() {
  return GetStatusField("VmRSS") * 1024 + GetStatusField("VmSwap") * 1024;
}

}  // namespace ml_benchmark
