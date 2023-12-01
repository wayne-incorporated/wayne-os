// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <fstream>
#include <unistd.h>

#include <base/logging.h>

namespace {

const char kResetCounterPath[] = "/var/lib/metrics/structured/reset-counter";
const int kMaxResetCounterLength = 19;

}  // namespace

int main(int argc, char** argv) {
  if (argc != 1) {
    LOG(ERROR) << "Unexpected command line arguments";
    return 1;
  }

  int64_t reset_counter = 0;

  std::ifstream infile(kResetCounterPath);
  if (!infile.is_open()) {
    PLOG(ERROR) << "Error when opening input file " << kResetCounterPath;
    return 1;
  }

  // Get the length of the reset counter integer in the file. There could be
  // the following situations:
  // - length > 0 and length <= kMaxResetCounterLength: The length is valid.
  //     Read the reset counter value from the file.
  // - length == 0: The file is empty. This could happen if it is the first
  //     time to boot or after power wash.
  // - length > kMaxResetCounterLength: The file is corrupted. It is not
  //     possible that the reset counter value can be so large.
  // - length < 0: Can not get the length.
  infile.seekg(0, infile.end);
  int length = infile.tellg();
  infile.seekg(0, infile.beg);
  if (length > 0 && length <= kMaxResetCounterLength) {
    infile >> reset_counter;
    if (infile.bad()) {
      PLOG(ERROR) << "Error when reading " << kResetCounterPath;
      return 1;
    }
    if (reset_counter < 0 || reset_counter == INT64_MAX) {
      // This should not happen unless the file is corrupted. In that case,
      // reset the reset counter.
      reset_counter = 0;
      LOG(ERROR) << "Invalid reset counter value. The reset counter is reset.";
    }
  } else if (length != 0) {
    // This should not happen unless the file is corrupted. In that case,
    // reset the reset counter.
    LOG(ERROR) << "Invalid reset counter value. The reset counter is reset.";
  }
  infile.close();
  if (infile.fail()) {
    PLOG(ERROR) << "Error when closing input file " << kResetCounterPath;
  }

  // Increment the reset counter.
  reset_counter++;

  // Update the reset counter file.
  std::ofstream outfile(kResetCounterPath);
  if (!outfile.is_open()) {
    // Only metrics and root will be able to open the output file. Other users
    // will get permission denied.
    PLOG(ERROR) << "Error when opening output file " << kResetCounterPath;
    return 1;
  }
  outfile << reset_counter;
  if (outfile.bad()) {
    PLOG(ERROR) << "Error when writing " << kResetCounterPath;
    return 1;
  }
  outfile.close();
  if (outfile.fail()) {
    PLOG(ERROR) << "Error when closing output file " << kResetCounterPath;
  }

  return 0;
}
