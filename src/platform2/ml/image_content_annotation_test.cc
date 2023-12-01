// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "ml/image_content_annotation.h"

#include <string>

#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/run_loop.h>
#include <base/strings/string_util.h>
#include <gtest/gtest.h>
#include <opencv2/core.hpp>
#include <opencv2/imgcodecs/imgcodecs.hpp>
#include <opencv2/imgproc.hpp>

#include "chrome/knowledge/ica/ica.pb.h"

namespace ml {

static base::FilePath LibPath() {
  return base::FilePath("/build/share/ml_core/libcros_ml_core_internal.so");
}

TEST(ImageContentAnnotationLibraryTest, CanLoadLibrary) {
  auto* instance = ImageContentAnnotationLibrary::GetInstance(LibPath());
  ASSERT_EQ(instance->GetStatus(), ImageContentAnnotationLibrary::Status::kOk);
}

TEST(ImageContentAnnotationLibraryTest, AnnotateImage) {
  auto* instance = ImageContentAnnotationLibrary::GetInstance(LibPath());
  ASSERT_EQ(instance->GetStatus(), ImageContentAnnotationLibrary::Status::kOk);
  ImageContentAnnotator* annotator = instance->CreateImageContentAnnotator();
  ASSERT_NE(annotator, nullptr);
  ASSERT_TRUE(instance->InitImageContentAnnotator(annotator, "en-US"));

  std::string image_encoded;
  ASSERT_TRUE(base::ReadFileToString(
      base::FilePath("/build/share/ml_core/moon_big.jpg"), &image_encoded));

  auto mat =
      cv::imdecode(cv::_InputArray(image_encoded.data(), image_encoded.size()),
                   cv::IMREAD_COLOR);
  cv::cvtColor(mat, mat, cv::COLOR_BGR2RGB);

  chrome_knowledge::AnnotationScoreList annotation_scores;
  instance->AnnotateImage(annotator, mat.data, mat.cols, mat.rows, mat.step,
                          &annotation_scores);

  ASSERT_GE(annotation_scores.annotation_size(), 1);
  EXPECT_EQ(annotation_scores.annotation(0).id(), 335);
  EXPECT_GE(annotation_scores.annotation(0).confidence(), 232);
  EXPECT_EQ(annotation_scores.annotation(0).mid(), "/m/06wqb");
  EXPECT_EQ(base::ToLowerASCII(annotation_scores.annotation(0).name()),
            "space");

  instance->DestroyImageContentAnnotator(annotator);
}

}  // namespace ml
