// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "lorgnette/image_readers/jpeg_reader.h"

#include <brillo/errors/error.h>
#include <dbus/lorgnette/dbus-constants.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <optional>

#include "lorgnette/constants.h"
#include "lorgnette/sane_client.h"

using ::testing::ContainsRegex;

namespace lorgnette {

namespace {

constexpr FrameFormat kDefaultFrameFormat = kGrayscale;
constexpr int kDefaultBytesPerLine = 100;
constexpr int kDefaultPixelsPerLine = 100;
constexpr int kDefaultLines = 10;
constexpr int kDefaultDepth = 8;

ScanParameters CreateDefaultScanParameters() {
  ScanParameters parameters;
  parameters.format = kDefaultFrameFormat;
  parameters.bytes_per_line = kDefaultBytesPerLine;
  parameters.pixels_per_line = kDefaultPixelsPerLine;
  parameters.lines = kDefaultLines;
  parameters.depth = kDefaultDepth;
  return parameters;
}

}  // namespace

TEST(JpegReaderTest, CreateWithInvalidRgbBitDepth) {
  ScanParameters parameters = CreateDefaultScanParameters();
  parameters.format = kRGB;
  parameters.depth = 1;

  brillo::ErrorPtr error;

  EXPECT_FALSE(JpegReader::Create(&error, parameters, std::nullopt, nullptr));

  ASSERT_TRUE(error);
  EXPECT_EQ(error->GetDomain(), kDbusDomain);
  EXPECT_EQ(error->GetCode(), kManagerServiceError);
  EXPECT_THAT(error->GetMessage(), ContainsRegex("bit depth"));
}

TEST(JpegReaderTest, CreateWithUnknownLength) {
  ScanParameters parameters = CreateDefaultScanParameters();
  parameters.lines = -1;

  brillo::ErrorPtr error;

  EXPECT_FALSE(JpegReader::Create(&error, parameters, std::nullopt, nullptr));

  ASSERT_TRUE(error);
  EXPECT_EQ(error->GetDomain(), kDbusDomain);
  EXPECT_EQ(error->GetCode(), kManagerServiceError);
  EXPECT_THAT(error->GetMessage(), ContainsRegex("unknown lengths"));
}

TEST(JpegReaderTest, CreateWithNoLines) {
  ScanParameters parameters = CreateDefaultScanParameters();
  parameters.lines = 0;

  brillo::ErrorPtr error;

  EXPECT_FALSE(JpegReader::Create(&error, parameters, std::nullopt, nullptr));

  ASSERT_TRUE(error);
  EXPECT_EQ(error->GetDomain(), kDbusDomain);
  EXPECT_EQ(error->GetCode(), kManagerServiceError);
  EXPECT_THAT(error->GetMessage(), ContainsRegex("0 lines"));
}

TEST(JpegReaderTest, CreateWithInvalidHeight) {
  ScanParameters parameters = CreateDefaultScanParameters();
  parameters.lines = 65535 + 1;

  brillo::ErrorPtr error;

  EXPECT_FALSE(JpegReader::Create(&error, parameters, std::nullopt, nullptr));

  ASSERT_TRUE(error);
  EXPECT_EQ(error->GetDomain(), kDbusDomain);
  EXPECT_EQ(error->GetCode(), kManagerServiceError);
  EXPECT_THAT(error->GetMessage(), ContainsRegex("invalid height"));
}

TEST(JpegReaderTest, CreateWithNegativeWidth) {
  ScanParameters parameters = CreateDefaultScanParameters();
  parameters.pixels_per_line = -1;

  brillo::ErrorPtr error;

  EXPECT_FALSE(JpegReader::Create(&error, parameters, std::nullopt, nullptr));

  ASSERT_TRUE(error);
  EXPECT_EQ(error->GetDomain(), kDbusDomain);
  EXPECT_EQ(error->GetCode(), kManagerServiceError);
  EXPECT_THAT(error->GetMessage(), ContainsRegex("invalid width"));
}

TEST(JpegReaderTest, CreateWithInvalidWidth) {
  ScanParameters parameters = CreateDefaultScanParameters();
  parameters.pixels_per_line = 65535 + 1;

  brillo::ErrorPtr error;

  EXPECT_FALSE(JpegReader::Create(&error, parameters, std::nullopt, nullptr));

  ASSERT_TRUE(error);
  EXPECT_EQ(error->GetDomain(), kDbusDomain);
  EXPECT_EQ(error->GetCode(), kManagerServiceError);
  EXPECT_THAT(error->GetMessage(), ContainsRegex("invalid width"));
}

TEST(JpegReaderTest, CreateWithInvalidBytesPerLine) {
  ScanParameters parameters = CreateDefaultScanParameters();
  parameters.format = kGrayscale;
  parameters.bytes_per_line = 10;
  parameters.pixels_per_line = 20;

  brillo::ErrorPtr error;

  EXPECT_FALSE(JpegReader::Create(&error, parameters, std::nullopt, nullptr));

  ASSERT_TRUE(error);
  EXPECT_EQ(error->GetDomain(), kDbusDomain);
  EXPECT_EQ(error->GetCode(), kManagerServiceError);
  EXPECT_THAT(error->GetMessage(), ContainsRegex("too small to hold"));
}

TEST(JpegReaderTest, CreateWithInvalidImageSize) {
  ScanParameters parameters = CreateDefaultScanParameters();
  parameters.bytes_per_line = 65535;
  parameters.lines = 65535;

  brillo::ErrorPtr error;

  EXPECT_FALSE(JpegReader::Create(&error, parameters, std::nullopt, nullptr));

  ASSERT_TRUE(error);
  EXPECT_EQ(error->GetDomain(), kDbusDomain);
  EXPECT_EQ(error->GetCode(), kManagerServiceError);
  EXPECT_THAT(error->GetMessage(), ContainsRegex("too large"));
}

TEST(JpegReaderTest, CreateWithInvalidBitDepth) {
  ScanParameters parameters = CreateDefaultScanParameters();
  parameters.bytes_per_line = kDefaultPixelsPerLine * 2;
  parameters.depth = 16;

  brillo::ErrorPtr error;

  EXPECT_FALSE(JpegReader::Create(&error, parameters, std::nullopt, nullptr));

  ASSERT_TRUE(error);
  EXPECT_EQ(error->GetDomain(), kDbusDomain);
  EXPECT_EQ(error->GetCode(), kManagerServiceError);
  EXPECT_THAT(error->GetMessage(),
              ContainsRegex("Invalid JPEG scan bit depth"));
}

}  // namespace lorgnette
