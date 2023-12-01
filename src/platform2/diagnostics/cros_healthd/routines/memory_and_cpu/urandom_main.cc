// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stdlib.h>

#include <base/files/file.h>
#include <base/files/file_path.h>
#include <base/time/time.h>
#include <brillo/flag_helper.h>

namespace {
constexpr int kNumBytesRead = 1024 * 1024;
}

// 'urandom' command-line tool:
//
// Based on the urandom python factory test. Reads 1MiB of data from
// /dev/urandom for a specified amount of time.
int main(int argc, char** argv) {
  DEFINE_int64(time_delta_ms, 0, "TimeDelta in ms to run routine for.");
  DEFINE_string(urandom_path, "/dev/urandom", "Path to urandom interface.");
  brillo::FlagHelper::Init(argc, argv, "urandom - diagnostic routine.");

  base::File urandom_file(base::FilePath(FLAGS_urandom_path),
                          base::File::FLAG_OPEN | base::File::FLAG_READ);
  if (!urandom_file.IsValid())
    return EXIT_FAILURE;

  char urandom_data[kNumBytesRead];
  base::TimeTicks end_time =
      base::TimeTicks::Now() + base::Milliseconds(FLAGS_time_delta_ms);
  while (base::TimeTicks::Now() < end_time) {
    if (kNumBytesRead != urandom_file.Read(0, urandom_data, kNumBytesRead))
      return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}
