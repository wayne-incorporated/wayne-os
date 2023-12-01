/*
 * Copyright 2021 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include <cstring>
#include <memory>
#include <string>
#include <vector>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/functional/bind.h>
#include <base/functional/callback.h>
#include <base/json/json_file_value_serializer.h>
#include <base/logging.h>
#include <base/native_library.h>
#include <base/scoped_native_library.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/stringprintf.h>
#include <base/test/bind.h>
#include <base/time/time.h>
#include <base/timer/elapsed_timer.h>
#include <brillo/flag_helper.h>
#include <chromeos/libdocumentscanner/document_scanner.h>
#include <gtest/gtest.h>

namespace ml {

namespace {

using LibDocumentScanner = chromeos_camera::document_scanning::DocumentScanner;
using chromeos_camera::document_scanning::CreateDocumentScannerFn;

constexpr int kWarmUpIterationCount = 5;
constexpr int kActualIterationCount = 20;

constexpr char kLibDocumentScannerLibraryPath[] =
    "/usr/share/cros-camera/libfs/libdocumentscanner.so";

std::vector<uint8_t> ReadFile(const base::FilePath& path) {
  int64_t size;
  auto success = base::GetFileSize(path, &size);
  if (!success) {
    LOG(ERROR) << "Failed to get file size: " << path;
    return {};
  }
  std::vector<uint8_t> buffer(size);
  if (base::ReadFile(path, reinterpret_cast<char*>(buffer.data()), size) !=
      size) {
    LOG(ERROR) << "Failed to read file: " << path;
    return {};
  }
  return buffer;
}

}  // namespace

class DocumentScannerPerfTestEnvironment;
DocumentScannerPerfTestEnvironment* g_env;

class DocumentScannerPerfTestEnvironment : public ::testing::Environment {
 public:
  DocumentScannerPerfTestEnvironment(const std::string& output_path,
                                     const std::string& jpeg_image_path,
                                     const std::string& nv12_image_path)
      : output_path_(output_path) {
    jpeg_image_ = ReadFile(base::FilePath(jpeg_image_path));
    nv12_image_ = ReadFile(base::FilePath(nv12_image_path));
  }

  void SetUp() {
    ASSERT_GT(jpeg_image_.size(), 0);
    ASSERT_GT(nv12_image_.size(), 0);

    base::NativeLibraryOptions native_library_options = {
        .prefer_own_symbols = true,
    };
    base::NativeLibraryLoadError error;
    base::FilePath library_path(kLibDocumentScannerLibraryPath);
    library_ = base::ScopedNativeLibrary(base::LoadNativeLibraryWithOptions(
        library_path, native_library_options, &error));
    ASSERT_TRUE(library_.is_valid())
        << "Library is invalid: " << error.ToString();

    create_fn_ = reinterpret_cast<CreateDocumentScannerFn>(
        library_.GetFunctionPointer("CreateDocumentScanner"));
    ASSERT_NE(create_fn_, nullptr);
  }

  void TearDown() {
    JSONFileValueSerializer json_serializer(output_path_);
    EXPECT_TRUE(json_serializer.Serialize(perf_values_));
  }

  void Benchmark(const std::string& metrics_name,
                 base::RepeatingClosure target_ops) {
    for (int i = 0; i < kWarmUpIterationCount; ++i) {
      target_ops.Run();
    }

    base::ElapsedTimer timer;
    for (int i = 0; i < kActualIterationCount; ++i) {
      target_ops.Run();
    }
    int avg_duration = timer.Elapsed().InMilliseconds() / kActualIterationCount;
    perf_values_.Set(metrics_name, avg_duration);

    LOG(INFO) << "Perf: " << metrics_name << " => " << avg_duration << " ms";
  }

  base::Value::Dict perf_values_;
  base::FilePath output_path_;
  std::vector<uint8_t> jpeg_image_;
  std::vector<uint8_t> nv12_image_;
  base::ScopedNativeLibrary library_;
  CreateDocumentScannerFn create_fn_;
};

class DocumentScannerPerfTest : public ::testing::Test {
 protected:
  DocumentScannerPerfTest() {}

  void SetUp() override {
    scanner_ = (*g_env->create_fn_)(0.0);
    ASSERT_NE(scanner_, nullptr);
  }

  std::unique_ptr<LibDocumentScanner> scanner_;
};

TEST_F(DocumentScannerPerfTest, DetectNV12Image) {
  g_env->Benchmark("DetectNV12Image", base::BindLambdaForTesting([&]() {
                     std::vector<LibDocumentScanner::Point> corners;
                     scanner_->DetectCornersFromNV12Image(
                         g_env->nv12_image_.data(), &corners);
                     ASSERT_EQ(corners.size(), 4);
                   }));
}

TEST_F(DocumentScannerPerfTest, DetectJPEGImage) {
  g_env->Benchmark("DetectJPEGImage", base::BindLambdaForTesting([&]() {
                     std::vector<LibDocumentScanner::Point> corners;
                     scanner_->DetectCornersFromJPEGImage(
                         g_env->jpeg_image_.data(), g_env->jpeg_image_.size(),
                         &corners);
                     ASSERT_EQ(corners.size(), 4);
                   }));
}

TEST_F(DocumentScannerPerfTest, DoPostProcessing) {
  std::vector<LibDocumentScanner::Point> corners;
  scanner_->DetectCornersFromJPEGImage(g_env->jpeg_image_.data(),
                                       g_env->jpeg_image_.size(), &corners);
  ASSERT_EQ(corners.size(), 4);

  g_env->Benchmark("DoPostProcessing", base::BindLambdaForTesting([&]() {
                     std::vector<uint8_t> processed_jpeg_image;
                     scanner_->DoPostProcessingFromJPEGImage(
                         g_env->jpeg_image_.data(), g_env->jpeg_image_.size(),
                         corners,
                         chromeos_camera::document_scanning::DocumentScanner::
                             Rotation::ROTATION_0,
                         &processed_jpeg_image);
                     ASSERT_GT(processed_jpeg_image.size(), 0);
                   }));
}

}  // namespace ml

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);

  // TODO(b/195618587): Support multiple resolutions for JPEG images
  // detection/processing.

  DEFINE_string(output_path, "", "The path to store the output perf result");
  DEFINE_string(jpeg_image, "", "The test image in JPEG format");
  DEFINE_string(
      nv12_image, "",
      "The test image in NV12 format. The image size should be 256x256.");

  // Add a newline at the beginning of the usage text to separate the help
  // message from gtest.
  brillo::FlagHelper::Init(argc, argv,
                           "\nTest document scanner functionalities.");

  if (FLAGS_output_path.empty()) {
    LOG(ERROR) << "No output path is specified";
    return -1;
  }
  if (FLAGS_jpeg_image.empty()) {
    LOG(ERROR) << "No jpeg image is specified";
    return -1;
  }
  if (FLAGS_nv12_image.empty()) {
    LOG(ERROR) << "No nv12 image is specified";
    return -1;
  }

  ml::g_env = new ml::DocumentScannerPerfTestEnvironment(
      FLAGS_output_path, FLAGS_jpeg_image, FLAGS_nv12_image);
  ::testing::AddGlobalTestEnvironment(ml::g_env);
  return RUN_ALL_TESTS();
}
