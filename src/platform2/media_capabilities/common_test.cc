// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "media_capabilities/common.h"

#include <algorithm>
#include <random>
#include <utility>

#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <gtest/gtest.h>

namespace {
bool CreateSampleFile(const base::FilePath& path) {
  const char* text = "abcdefg";
  return base::WriteFile(path, text, sizeof(text)) == sizeof(text);
}
}  // namespace

TEST(CommonTest, GetAllFilesWithPrefix) {
  base::ScopedTempDir temp_dir;
  ASSERT_TRUE(temp_dir.CreateUniqueTempDir());
  const base::FilePath& temp_path =
      base::MakeAbsoluteFilePath(temp_dir.GetPath());
  ASSERT_FALSE(temp_path.empty());
  ASSERT_TRUE(base::CreateDirectory(temp_path.AppendASCII("video")));
  const std::vector<base::FilePath> expected_paths = {
      temp_path.AppendASCII("video-dec"),
      temp_path.AppendASCII("video0"),
  };
  const std::vector<base::FilePath> expected_paths2 = {
      temp_path.AppendASCII("video/a.txt"),
      temp_path.AppendASCII("video/b.txt"),
  };
  ASSERT_TRUE(std::is_sorted(expected_paths.begin(), expected_paths.end()));
  ASSERT_TRUE(std::is_sorted(expected_paths2.begin(), expected_paths2.end()));
  for (const auto& path : expected_paths)
    ASSERT_TRUE(CreateSampleFile(path));
  for (const auto& path : expected_paths2)
    ASSERT_TRUE(CreateSampleFile(path));

  // Directory status
  // tmp
  //   - video
  //       - a.txt
  //       - b.txt
  //   - video-dec
  //   - video0
  auto result_paths = GetAllFilesWithPrefix(temp_path.AppendASCII("video"));
  auto result_paths2 = GetAllFilesWithPrefix(temp_path.AppendASCII("video/"));
  std::sort(result_paths.begin(), result_paths.end());
  EXPECT_EQ(result_paths, expected_paths);
  std::sort(result_paths2.begin(), result_paths2.end());
  EXPECT_EQ(result_paths2, expected_paths2);
}

TEST(CommonTest, GetInterestingResolutionsUpTo) {
  const struct {
    std::pair<int, int> resolution;
    std::vector<Resolution> expected_results;
  } kTestCases[] = {
      {{1280, 720}, {}},
      {{1920, 1080}, {Resolution::k1080p}},
      {{2560, 1440}, {Resolution::k1080p}},
      {{3840, 2160}, {Resolution::k1080p, Resolution::k2160p}},
      {{2160, 2160}, {Resolution::k1080p}},
  };

  for (const auto& t : kTestCases)
    EXPECT_EQ(GetInterestingResolutionsUpTo(t.resolution), t.expected_results);
}

TEST(CommonTest, CapabilityConstructorAndToString) {
  Capability cap(Profile::kH264High, true, Resolution::k1080p,
                 Subsampling::kYUV420, ColorDepth::k8bit);
  EXPECT_EQ(cap.ToString(), "h264_high_decode_1080p");
  cap = Capability(Profile::kJPEG, true, Resolution::k1080p,
                   Subsampling::kYUV422, ColorDepth::k8bit);
  EXPECT_EQ(cap.ToString(), "jpeg_decode_1080p_422");
  cap = Capability(Profile::kJPEG, false, Resolution::k1080p,
                   Subsampling::kYUV420, ColorDepth::k8bit);
  EXPECT_EQ(cap.ToString(), "jpeg_encode_1080p");
  cap = Capability(Profile::kVP9Profile2, true, Resolution::k2160p,
                   Subsampling::kYUV420, ColorDepth::k10bit);
  EXPECT_EQ(cap.ToString(), "vp9_2_decode_2160p_10bpp");
  cap = Capability(Profile::kAV1Main, true, Resolution::k1080p,
                   Subsampling::kYUV420, ColorDepth::k8bit);
  EXPECT_EQ(cap.ToString(), "av1_main_decode_1080p");
  cap = Capability(Profile::kAV1Main, true, Resolution::k2160p,
                   Subsampling::kYUV420, ColorDepth::k10bit);
  EXPECT_EQ(cap.ToString(), "av1_main_decode_2160p_10bpp");
  cap = Capability(CameraDescription::kBuiltinUSBCamera);
  EXPECT_EQ(cap.ToString(), "builtin_usb_camera");
  cap = Capability(CameraDescription::kVividCamera);
  EXPECT_EQ(cap.ToString(), "vivid_camera");
}

TEST(CommonTest, CapabilityCompareOperators) {
  const std::vector<Capability> caps = {
      Capability(Profile::kH264Baseline, true, Resolution::k1080p,
                 Subsampling::kYUV420, ColorDepth::k8bit),
      Capability(Profile::kH264Baseline, true, Resolution::k2160p,
                 Subsampling::kYUV420, ColorDepth::k8bit),
      Capability(Profile::kH264Baseline, false, Resolution::k1080p,
                 Subsampling::kYUV420, ColorDepth::k8bit),
      Capability(Profile::kVP8, false, Resolution::k1080p, Subsampling::kYUV420,
                 ColorDepth::k8bit),
      Capability(Profile::kAV1Main, true, Resolution::k1080p,
                 Subsampling::kYUV420, ColorDepth::k10bit),
      Capability(Profile::kAV1Main, true, Resolution::k2160p,
                 Subsampling::kYUV420, ColorDepth::k8bit),
      Capability(Profile::kJPEG, true, Resolution::k1080p, Subsampling::kYUV420,
                 ColorDepth::k8bit),
      Capability(Profile::kJPEG, false, Resolution::k1080p,
                 Subsampling::kYUV420, ColorDepth::k8bit),
      Capability(Profile::kJPEG, false, Resolution::k1080p,
                 Subsampling::kYUV444, ColorDepth::k8bit),
      Capability(CameraDescription::kBuiltinUSBCamera),
      Capability(CameraDescription::kBuiltinMIPICamera),
      Capability(CameraDescription::kBuiltinOrVividCamera),
  };
  for (size_t i = 0; i < caps.size(); ++i) {
    EXPECT_EQ(caps[i], caps[i]);
    for (size_t j = i + 1; j < caps.size(); ++j) {
      EXPECT_NE(caps[i], caps[j]);
      EXPECT_LT(caps[i], caps[j]) << i << ", " << j;
    }
  }
}

TEST(CommonTest, CapabilitySortAndUnique) {
  const std::vector<Capability> expected_caps = {
      Capability(Profile::kH264Baseline, true, Resolution::k1080p,
                 Subsampling::kYUV420, ColorDepth::k8bit),
      Capability(Profile::kH264Baseline, true, Resolution::k2160p,
                 Subsampling::kYUV420, ColorDepth::k8bit),
      Capability(Profile::kH264Baseline, false, Resolution::k1080p,
                 Subsampling::kYUV420, ColorDepth::k8bit),
      Capability(Profile::kVP8, false, Resolution::k1080p, Subsampling::kYUV420,
                 ColorDepth::k8bit),
      Capability(Profile::kAV1Main, true, Resolution::k1080p,
                 Subsampling::kYUV420, ColorDepth::k10bit),
      Capability(Profile::kAV1Main, true, Resolution::k2160p,
                 Subsampling::kYUV420, ColorDepth::k8bit),
      Capability(Profile::kJPEG, true, Resolution::k1080p, Subsampling::kYUV420,
                 ColorDepth::k8bit),
      Capability(Profile::kJPEG, false, Resolution::k1080p,
                 Subsampling::kYUV420, ColorDepth::k8bit),
      Capability(Profile::kJPEG, false, Resolution::k1080p,
                 Subsampling::kYUV444, ColorDepth::k8bit),
      Capability(CameraDescription::kBuiltinUSBCamera),
      Capability(CameraDescription::kBuiltinMIPICamera),
      Capability(CameraDescription::kBuiltinOrVividCamera),
  };
  std::vector<Capability> caps = expected_caps;
  auto rng = std::default_random_engine(12345);
  std::shuffle(caps.begin(), caps.end(), rng);
  EXPECT_NE(caps, expected_caps);

  // Test sort.
  std::sort(caps.begin(), caps.end());
  EXPECT_EQ(caps, expected_caps);

  // Test unique.
  caps.insert(caps.end(), expected_caps.begin(), expected_caps.end());
  std::sort(caps.begin(), caps.end());
  auto last = std::unique(caps.begin(), caps.end());
  caps.erase(last, caps.end());
  EXPECT_EQ(caps, expected_caps);
}

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
