// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <iostream>
#include <string>

#include <debugd/src/helpers/modetest_helper_utils.h>

int main(int argc, char** argv) {
  debugd::modetest_helper_utils::EDIDFilter edid_filter;
  debugd::modetest_helper_utils::BlobFilter gamma_blob_filter("GAMMA_LUT");
  debugd::modetest_helper_utils::BlobFilter degamma_blob_filter("DEGAMMA_LUT");
  std::string line;
  bool first_skipped_line = true;
  while (std::getline(std::cin, line)) {
    bool keep_line = true;
    edid_filter.ProcessLine(line);
    keep_line &= gamma_blob_filter.ProcessLine(line);
    keep_line &= degamma_blob_filter.ProcessLine(line);
    if (!keep_line && first_skipped_line) {
      first_skipped_line = false;
      std::cout << "<stripped blob value>" << std::endl;
    }
    if (keep_line) {
      std::cout << line << std::endl;
      first_skipped_line = true;
    }
  }
  return 0;
}
