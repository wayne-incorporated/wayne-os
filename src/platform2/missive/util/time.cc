// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "missive/util/time.h"

#include <cerrno>
#include <cstring>
#include <ctime>
#include <string>

#include <base/strings/strcat.h>

#include "missive/util/status.h"
#include "missive/util/statusor.h"

namespace reporting {

namespace {
std::string GetSystemErrorMessage() {
  static constexpr size_t kBufSize = 256U;
  std::string error_msg;
  error_msg.reserve(kBufSize);
  const char* error_str = strerror_r(errno, error_msg.data(), error_msg.size());
  if (error_str == nullptr) {
    error_msg = "Unknown error";
  }
  return error_msg;
}
}  // namespace

StatusOr<time_t> GetCurrentTime(TimeType type) {
  clockid_t clock_id;
  const char* readable_type;

  switch (type) {
    case TimeType::kWall:
      clock_id = CLOCK_REALTIME;
      readable_type = "wall-clock";
      break;
    case TimeType::kProcessCpu:
      clock_id = CLOCK_PROCESS_CPUTIME_ID;
      readable_type = "process CPU";
      break;
    default:
      // Should be impossible to reach here
      return Status(error::INVALID_ARGUMENT, "Unknown TimeType.");
  }

  struct timespec tp;
  if (clock_gettime(clock_id, &tp)) {
    return Status(error::UNKNOWN,
                  base::StrCat({"Failed to retrieve ", readable_type,
                                " time: ", GetSystemErrorMessage()}));
  }

  return tp.tv_sec;
}
}  // namespace reporting
