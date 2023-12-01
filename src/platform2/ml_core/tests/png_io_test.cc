// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stdio.h>
#include <stdlib.h>

#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/values.h>
#include <gtest/gtest.h>

#include "ml_core/tests/png_io.h"
#include "ml_core/tests/test_utilities.h"

namespace {

class PngIoTest : public ::testing::Test {
 protected:
  void SetUp() override {}
};

TEST_F(PngIoTest, ReadPngFileExtractsCorrectMetadata) {
  const base::FilePath input_file("testdata/tom_blur_720_hd.png");

  PngImageIO pngio_ = PngImageIO();
  auto info = pngio_.ReadPngFile(input_file).value();

  EXPECT_EQ(720, info.height);
  EXPECT_EQ(1280, info.width);
  EXPECT_EQ(8, info.bit_depth);
  EXPECT_EQ(1280 * 4, info.num_row_bytes);
}

TEST_F(PngIoTest, GetRawData) {
  const base::FilePath input_file("testdata/tiny_sample.png");

  PngImageIO pngio_ = PngImageIO();
  auto info = pngio_.ReadPngFile(input_file).value();

  std::unique_ptr<uint8_t> raw_data_buf(
      new uint8_t[info.num_row_bytes * info.height]);
  EXPECT_FALSE(info.GetRawData(raw_data_buf.get(), info.num_row_bytes));
  EXPECT_TRUE(
      info.GetRawData(raw_data_buf.get(), info.num_row_bytes * info.height));
  ASSERT_EQ(8, info.num_row_bytes);
  ASSERT_EQ(2, info.height);
  uint8_t expected_buf[16] = {65,  148, 224, 255, 224, 148, 65, 255,
                              148, 224, 65,  255, 0,   0,   0,  255};

  for (int i = 0; i < info.num_row_bytes * info.height; ++i)
    EXPECT_EQ(expected_buf[i], static_cast<int>(raw_data_buf.get()[i]));
}

TEST_F(PngIoTest, PngWrite) {
  const base::FilePath input_file("testdata/tom_blur_720_hd.png");
  base::FilePath output_file(
      "testdata/tom_blur_720_hd_model_png_write_output.png");
  base::CreateTemporaryFile(&output_file);
  LOG(INFO) << output_file;

  PngImageIO pngio_ = PngImageIO();
  auto info1 = pngio_.ReadPngFile(input_file).value();
  pngio_.WritePngFile(output_file, info1);

  auto info2 = pngio_.ReadPngFile(output_file).value();

  EXPECT_EQ(info1, info2);
  remove(output_file.value().c_str());
}

}  // namespace

int main(int argc, char* argv[]) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
