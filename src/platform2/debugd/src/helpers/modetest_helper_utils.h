// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DEBUGD_SRC_HELPERS_MODETEST_HELPER_UTILS_H_
#define DEBUGD_SRC_HELPERS_MODETEST_HELPER_UTILS_H_

#include <string>

#include <re2/re2.h>

namespace debugd {
namespace modetest_helper_utils {

// EDIDFilter will scrub the serial number from the EDID property of `modetest`
// output.
class EDIDFilter {
 public:
  EDIDFilter();
  // Call ProcessLine for each line of `modetest`. ProcessLine may modify the
  // line in place when it finds an EDID serial number.
  void ProcessLine(std::string& line);

 private:
  bool saw_edid_property_;
  bool saw_value_;
};

// BlobFilter will remove the blob value of the specified property.
class BlobFilter {
 public:
  explicit BlobFilter(const std::string& property_name);
  // Returns |false| if this line should be skipped.
  bool ProcessLine(const std::string& line);

 private:
  bool saw_property_;
  bool saw_value_;
  RE2 property_pattern_;
};
}  // namespace modetest_helper_utils
}  // namespace debugd

#endif  // DEBUGD_SRC_HELPERS_MODETEST_HELPER_UTILS_H_
