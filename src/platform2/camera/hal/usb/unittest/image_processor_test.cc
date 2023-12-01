/*
 * Copyright 2017 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "hal/usb/image_processor.h"

#include <sys/mman.h>

#include <base/at_exit.h>
#include <gtest/gtest.h>

#include "hal/usb/frame_buffer.h"

namespace cros {

namespace tests {

class ImageProcessorTest : public ::testing::Test {
 public:
  ImageProcessorTest() = default;
  ImageProcessorTest(const ImageProcessorTest&) = delete;
  ImageProcessorTest& operator=(const ImageProcessorTest&) = delete;
};

TEST_F(ImageProcessorTest, GetConvertedSize) {
  std::unique_ptr<SharedFrameBuffer> frame(new SharedFrameBuffer(0));
  std::unique_ptr<ImageProcessor> image_processor(new ImageProcessor());
  // Size should be 0 if format, width, and height are not set up correctly.
  EXPECT_EQ(image_processor->GetConvertedSize(*frame.get()), 0);
  frame->SetFourcc(V4L2_PIX_FMT_YUV420);
  EXPECT_EQ(image_processor->GetConvertedSize(*frame.get()), 0);
  frame->SetWidth(1280);
  EXPECT_EQ(image_processor->GetConvertedSize(*frame.get()), 0);
  frame->SetHeight(720);
  EXPECT_EQ(image_processor->GetConvertedSize(*frame.get()), 1280 * 720 * 1.5);
}

}  // namespace tests

}  // namespace cros

int main(int argc, char** argv) {
  base::AtExitManager exit_manager;
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
