// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "debugd/src/helpers/modetest_helper_utils.h"

#include <iostream>
#include <string>
#include <vector>

#include <gtest/gtest.h>

using debugd::modetest_helper_utils::BlobFilter;
using debugd::modetest_helper_utils::EDIDFilter;

namespace {
std::vector<std::string> SplitLines(const std::string& str) {
  std::vector<std::string> lines;
  std::stringstream ss(str);
  std::string line;
  while (std::getline(ss, line, '\n'))
    lines.push_back(line);
  return lines;
}
}  // namespace

TEST(ModetestHelperUtils, EDIDStripSerialNumber) {
  // Excerpt of modetest, and the line number containing the EDID serial
  // number.
  constexpr int edid_serial_line = 7;
  std::string edid_property = R"(
  props:
    1 EDID:
        flags: immutable blob
        blobs:

        value:
            00ffffffffffff004c83424112345678
            131d0104b51d11780238d1ae513bb823
)";

  // Split test data lines and save a copy to compare with.
  std::vector<std::string> lines = SplitLines(edid_property);
  std::vector<std::string> lines_original = lines;

  // ASSERT that we have defined the correct line number for the serial number.
  ASSERT_EQ(lines[edid_serial_line],
            "            00ffffffffffff004c83424112345678");

  // Use EDIDFilter to filter out the serial number.
  EDIDFilter edid_filter;
  for (auto& line : lines) {
    edid_filter.ProcessLine(line);
  }

  // Check that the serial number was stripped out in the expected way.
  EXPECT_EQ(lines[edid_serial_line],
            "            00ffffffffffff004c83424100000000");

  // Check that no other lines were modified.
  for (int i = 0; i < lines.size(); ++i) {
    if (i == edid_serial_line)
      continue;
    EXPECT_EQ(lines[i], lines_original[i]);
  }
}

TEST(ModetestHelperUtils, EDIDWrongHeader) {
  // Excerpt of modetest, but with an unexpected EDID header.
  std::string edid_property = R"(
  props:
    1 EDID:
        flags: immutable blob
        blobs:

        value:
            00ffdeadbeefff004c83424112345678
            131d0104b51d11780238d1ae513bb823
)";

  // Split modetest by lines.
  std::vector<std::string> lines = SplitLines(edid_property);

  // Run through EDIDFilter and check that nothing was altered.
  EDIDFilter edid_filter;
  for (auto& line : lines) {
    std::string line_original = line;
    edid_filter.ProcessLine(line);
    EXPECT_EQ(line, line_original);
  }
}

TEST(ModetestHelperUtils, MultipleEDIDProperties) {
  // modetest-like test data, and the line numbers containing the EDID serial
  // numbers.
  constexpr int edid_serial_lines[2] = {10, 23};
  std::string modetest_excerpt = R"(
Connectors:
  modes:
    index name refresh (Hz) hdisp hss hse htot vdisp vss vse vtot
  props:
    1 EDID:
        flags: immutable blob
        blobs:

        value:
            00ffffffffffff004c83424112345678
            131d0104b51d11780238d1ae513bb823
            0b505400000001010101010101010101
    2 DPMS:
        flags: enum
        enums: On=0 Standby=1 Suspend=2 Off=3
        value: 0
  props:
    1 EDID:
        flags: immutable blob
        blobs:

        value:
            00ffffffffffff004c83424187654321
            131d0104b51d11780238d1ae513bb823
            0b505400000001010101010101010101
    2 DPMS:
        flags: enum
        enums: On=0 Standby=1 Suspend=2 Off=3
        value: 0
)";

  // Split modetest by lines, and get a copy to compare with.
  std::vector<std::string> lines = SplitLines(modetest_excerpt);
  std::vector<std::string> lines_original = lines;

  // Double-check we have the correct line number for the serial numbers.
  ASSERT_EQ(lines[edid_serial_lines[0]],
            "            00ffffffffffff004c83424112345678");
  ASSERT_EQ(lines[edid_serial_lines[1]],
            "            00ffffffffffff004c83424187654321");

  // Use EDIDFilter to filter out the serial numbers.
  EDIDFilter edid_filter;
  for (auto& line : lines) {
    edid_filter.ProcessLine(line);
  }

  // Check that the serial numbers were stripped out in the expected way.
  EXPECT_EQ(lines[edid_serial_lines[0]],
            "            00ffffffffffff004c83424100000000");
  EXPECT_EQ(lines[edid_serial_lines[1]],
            "            00ffffffffffff004c83424100000000");

  // Check that no other lines were modified.
  for (int i = 0; i < lines.size(); ++i) {
    if (i == edid_serial_lines[0] || i == edid_serial_lines[1])
      continue;
    EXPECT_EQ(lines[i], lines_original[i]);
  }
}

TEST(ModetestHelperUtils, NotEDIDProperty) {
  // Looks like a property from `modetest`, but not an EDID.
  std::string property_with_blob = R"(
  props:
    1 NOTEDID:
        flags: immutable blob
        blobs:

        value:
            00ffffffffffff004c83424112345678
            131d0104b51d11780238d1ae513bb823
)";

  // Split test data by lines.
  std::vector<std::string> lines = SplitLines(property_with_blob);

  // Run through EDIDFilter and check that nothing was altered.
  EDIDFilter edid_filter;
  for (auto& line : lines) {
    std::string line_original = line;
    edid_filter.ProcessLine(line);
    EXPECT_EQ(line, line_original);
  }
}

TEST(ModetestHelperUtils, FilterBlob) {
  // modetest-like test data, and the line numbers describing the data.
  constexpr int kBlobValueLineNum = 6;
  constexpr int kNumBlobLines = 4;
  std::string property_with_blob = R"(
  props:
    1 BLOBBY:
        flags: immutable blob
        blobs:

        value:
            00ffffffffffff004c83424112345678
            131d0104b51d11780238d1ae513bb823
            131d0104b51d11780238d1ae513bb823
            131d0104b51d11780238d1ae513bb823
    2 DPMS:
        flags: enum
        enums: On=0 Standby=1 Suspend=2 Off=3
        value: 0
)";
  BlobFilter blob_filter("BLOBBY");

  // Split test data by lines.
  std::vector<std::string> lines = SplitLines(property_with_blob);
  std::vector<std::string> filtered_lines;

  // Validate the expectations about the input before validating below.

  ASSERT_EQ(lines[kBlobValueLineNum], "        value:");
  // Line after "value:" and the blob values.
  ASSERT_EQ(lines[kBlobValueLineNum + kNumBlobLines + 1], "    2 DPMS:");

  for (auto& line : lines) {
    if (blob_filter.ProcessLine(line))
      filtered_lines.push_back(line);
  }

  // The blob takes up four lines.
  EXPECT_EQ(lines.size() - filtered_lines.size(), kNumBlobLines);
  // Line after "value:" should be the next property.
  EXPECT_EQ(filtered_lines[kBlobValueLineNum + 1], "    2 DPMS:");
}
