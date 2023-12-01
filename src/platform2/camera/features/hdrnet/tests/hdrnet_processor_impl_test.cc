/*
 * Copyright 2021 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include <memory>
#include <optional>
#include <string>

#include <base/at_exit.h>
#include <base/command_line.h>
#include <base/files/file_util.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_split.h>
#include <base/strings/string_util.h>
#include <base/test/test_timeouts.h>
#include <brillo/flag_helper.h>
#pragma push_macro("None")
#pragma push_macro("Bool")
#undef None
#undef Bool

// gtest's internal typedef of None and Bool conflicts with the None and Bool
// macros in X11/X.h (https://github.com/google/googletest/issues/371).
// X11/X.h is pulled in by the GL headers we include.
#include <gtest/gtest.h>

#pragma pop_macro("None")
#pragma pop_macro("Bool")
#include <hardware/gralloc.h>
#include <sync/sync.h>
#include <system/graphics.h>

#include "cros-camera/common.h"
#include "features/hdrnet/tests/hdrnet_processor_test_fixture.h"

namespace cros::tests {

struct Options {
  int iterations = 1000;
  Size input_size{1920, 1080};
  std::vector<Size> output_sizes{{1920, 1080}, {1280, 720}};
  bool dump_buffer = false;
  std::optional<base::FilePath> input_image_file;
  uint32_t input_image_format = HAL_PIXEL_FORMAT_YCbCr_420_888;
  std::optional<base::FilePath> input_metadata_file;
  std::optional<base::FilePath> hdrnet_config_file;
  bool use_noop_adapter = false;
} g_args;

cros::Size ParseSize(std::string size_str) {
  CHECK(!size_str.empty());
  std::vector<std::string> arg_split = base::SplitString(
      size_str, "x", base::TRIM_WHITESPACE, base::SPLIT_WANT_NONEMPTY);
  CHECK_EQ(arg_split.size(), 2);
  Size ret;
  CHECK(base::StringToUint(arg_split[0], &ret.width));
  CHECK(base::StringToUint(arg_split[1], &ret.height));
  return ret;
}

void ParseInputSize(std::string argv, Options& opts) {
  opts.input_size = ParseSize(argv);
  VLOGF(1) << "Input buffer size: " << opts.input_size.ToString();
}

void ParseOutputSizes(std::string argv, Options& opts) {
  opts.output_sizes.clear();
  for (auto s : base::SplitString(argv, ",", base::TRIM_WHITESPACE,
                                  base::SPLIT_WANT_NONEMPTY)) {
    opts.output_sizes.push_back(ParseSize(s));
  }
  for (auto s : opts.output_sizes) {
    VLOGF(1) << "Output buffer size: " << s.ToString();
  }
}

void ParseInputImageFile(std::string argv, Options& opts) {
  if (argv.empty()) {
    VLOGF(1) << "No input image file given; will use generated image";
    return;
  }
  base::FilePath path(argv);
  CHECK(base::PathExists(path)) << ": Input image file does not exist";
  opts.input_image_file = path;
  VLOGF(1) << "Input image file: " << opts.input_image_file->value();
}

void ParseInputImageFormat(std::string argv, Options& opts) {
  CHECK(!argv.empty());
  std::string upper_argv = base::ToUpperASCII(argv);

  CHECK(upper_argv == "NV12" || upper_argv == "P010")
      << "Unrecognized input format: " << argv;
  if (upper_argv == "NV12") {
    opts.input_image_format = HAL_PIXEL_FORMAT_YCBCR_420_888;
  } else {  // upper_argv == "P010"
    opts.input_image_format = HAL_PIXEL_FORMAT_YCBCR_P010;
  }
  VLOGF(1) << "Input image format: " << upper_argv;
}

void ParseInputMetadataFile(std::string argv, Options& opts) {
  if (argv.empty()) {
    VLOGF(1) << "No input metadata given; will use fake metadata";
    return;
  }
  base::FilePath path(argv);
  CHECK(base::PathExists(path)) << ": Input metadata file does not exist";
  opts.input_metadata_file = path;
  VLOGF(1) << "Input metadata file: " << opts.input_metadata_file->value();
}

void ParseHdrnetConfigFile(std::string argv, Options& opts) {
  if (argv.empty()) {
    VLOGF(1) << "No HDRnet config given; will use default config";
    return;
  }
  base::FilePath path(argv);
  CHECK(base::PathExists(path)) << ": HDRnet config file does not exist";
  opts.hdrnet_config_file = path;
  VLOGF(1) << "HDRnet config file: " << opts.hdrnet_config_file->value();
}

class HdrNetProcessorTest : public testing::Test {
 public:
  HdrNetProcessorTest()
      : fixture_(g_args.input_size,
                 g_args.input_image_format,
                 g_args.output_sizes,
                 g_args.use_noop_adapter) {}
  ~HdrNetProcessorTest() override = default;

 protected:
  HdrNetProcessorTestFixture fixture_;
};

TEST_F(HdrNetProcessorTest, FullPipelineTest) {
  if (g_args.input_image_file) {
    fixture_.LoadInputFile(*g_args.input_image_file);
  }
  if (g_args.input_metadata_file) {
    fixture_.LoadProcessingMetadata(*g_args.input_metadata_file);
  }
  if (g_args.hdrnet_config_file) {
    fixture_.LoadHdrnetConfig(*g_args.hdrnet_config_file);
  }
  HdrnetMetrics metrics;
  for (int i = 0; i < g_args.iterations; ++i) {
    Camera3CaptureDescriptor result = fixture_.ProduceFakeCaptureResult();
    fixture_.ProcessResultMetadata(&result);
    base::ScopedFD fence = fixture_.Run(i, metrics);
    constexpr int kFenceWaitTimeoutMs = 300;
    ASSERT_EQ(sync_wait(fence.get(), kFenceWaitTimeoutMs), 0);
  }
  if (g_args.dump_buffer) {
    fixture_.DumpBuffers(testing::UnitTest::GetInstance()
                             ->current_test_info()
                             ->test_case_name());
  }
}

}  // namespace cros::tests

int main(int argc, char** argv) {
  base::AtExitManager exit_manager;
  ::testing::InitGoogleTest(&argc, argv);
  base::CommandLine::Init(argc, argv);
  TestTimeouts::Initialize();
  LOG_ASSERT(logging::InitLogging(logging::LoggingSettings()));

  DEFINE_int32(iterations, 1000, "number of iterations to run in the test");
  DEFINE_string(input_size, "1920x1080", "[width]x[height] of the input image");
  DEFINE_string(
      output_sizes, "1920x1080,1280x720",
      "comma separated [width]x[height] of the output images to produce");
  DEFINE_bool(dump_buffer, false, "dump all the buffers used in the test");
  DEFINE_string(input_image_file, "", "path to the input image");
  DEFINE_string(input_image_format, "nv12", "pixel format of the input image");
  DEFINE_string(input_metadata_file, "", "path to the input metadata");
  DEFINE_string(hdrnet_config_file, "", "path to the HDRnet config file");
  DEFINE_bool(use_noop_adapter, false,
              "use the default no-op HDRnet device adapter to test only the "
              "core HDRnet pipeline");
  brillo::FlagHelper::Init(argc, argv, "HDRnet processor test.");

  cros::tests::g_args.iterations = FLAGS_iterations;
  cros::tests::ParseInputSize(FLAGS_input_size, cros::tests::g_args);
  cros::tests::ParseOutputSizes(FLAGS_output_sizes, cros::tests::g_args);
  cros::tests::g_args.dump_buffer = FLAGS_dump_buffer;
  cros::tests::ParseInputImageFile(FLAGS_input_image_file, cros::tests::g_args);
  cros::tests::ParseInputImageFormat(FLAGS_input_image_format,
                                     cros::tests::g_args);
  cros::tests::ParseInputMetadataFile(FLAGS_input_metadata_file,
                                      cros::tests::g_args);
  cros::tests::ParseHdrnetConfigFile(FLAGS_hdrnet_config_file,
                                     cros::tests::g_args);
  cros::tests::g_args.use_noop_adapter = FLAGS_use_noop_adapter;

  return RUN_ALL_TESTS();
}
