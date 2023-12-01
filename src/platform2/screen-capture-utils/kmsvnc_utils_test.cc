// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <gtest/gtest.h>
#include <vector>

#include "screen-capture-utils/kmsvnc_utils.h"

namespace screenshot {

namespace {
void runConvertBuffer(uint32_t crtc_width, uint32_t crtc_height) {
  uint32_t stride = crtc_width * kBytesPerPixel;

  uint32_t vnc_width = getVncWidth(crtc_width);
  uint32_t vnc_height = crtc_height;

  // Display buffer initialized with dummy val of 'A'
  char dummyDisplayValue = 'A';

  std::vector<char> displayBuffer(crtc_width * crtc_height * kBytesPerPixel,
                                  dummyDisplayValue);
  std::vector<char> vncBuffer(vnc_width * vnc_height * kBytesPerPixel);

  DisplayBuffer::Result display{crtc_width, crtc_height, stride};
  display.buffer = displayBuffer.data();

  ConvertBuffer(display, vncBuffer.data(), vnc_width);

  int index = 0;
  bool bufferMatched = true;
  int padIdx = crtc_width * kBytesPerPixel;

  for (char c : vncBuffer) {
    int displayIdx = index % (vnc_width * kBytesPerPixel);
    if (displayIdx < padIdx) {
      if (c != dummyDisplayValue) {
        bufferMatched = false;
        break;
      }
    } else {
      if (c != 0) {
        bufferMatched = false;
        break;
      }
    }
    index++;
  }
  EXPECT_EQ(bufferMatched, true);
}
}  // namespace

TEST(VncServerTest, HandlesPadding) {
  EXPECT_EQ(getVncWidth(5), 8);
  EXPECT_EQ(getVncWidth(12), 12);
}

TEST(VncServerTest, ConvertBuffer) {
  // Given: A display (W x H)
  // When: Convert display buffer to VNC Buffer where width is a mult of 4
  // Then: VNC Buffer contains display buffer data, but right padded with 0
  //       if display width is not a multiple of 4

  runConvertBuffer(40, 2);
  runConvertBuffer(1366, 768);  // width not a mult of 4
}

}  // namespace screenshot
