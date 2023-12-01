// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "ml/web_platform_handwriting_proto_mojom_conversion.h"

#include <optional>
#include <string>
#include <utility>

#include <base/time/time.h>
#include <gtest/gtest.h>

#include "ml/handwriting.h"

namespace ml {

using chromeos::machine_learning::web_platform::mojom::HandwritingHints;
using chromeos::machine_learning::web_platform::mojom::HandwritingPoint;
using chromeos::machine_learning::web_platform::mojom::HandwritingStroke;
using chromeos::machine_learning::web_platform::mojom::HandwritingStrokePtr;
using gfx::mojom::PointF;

// Tests `WebPlatformHandwritingStrokesAndHintsToProto` works correctly.
TEST(WebPlatformHandwritingProtoMojoConversionTest,
     HandwritingStrokesAndHintsToProto) {
  // Generate some strokes.
  std::vector<HandwritingStrokePtr> strokes;
  auto stroke1 = HandwritingStroke::New();
  stroke1->points.push_back(
      HandwritingPoint::New(PointF::New(1., 2.), base::Milliseconds(3)));
  stroke1->points.push_back(
      HandwritingPoint::New(PointF::New(4., 5.), base::Milliseconds(6)));
  auto stroke2 = HandwritingStroke::New();
  stroke2->points.push_back(
      HandwritingPoint::New(PointF::New(7., 8.), base::Milliseconds(9)));
  strokes.push_back(std::move(stroke1));
  strokes.push_back(std::move(stroke2));

  auto hints = HandwritingHints::New("text", "mouse", "", 100u, "context");

  const auto proto = WebPlatformHandwritingStrokesAndHintsToProto(
      std::move(strokes), std::move(hints));

  // Checks correctness.
  // Checks correctness of ink.
  ASSERT_TRUE(proto.has_ink());
  // Checks the first stroke.
  EXPECT_EQ(proto.ink().strokes().size(), 2u);
  ASSERT_EQ(proto.ink().strokes()[0].points().size(), 2u);
  ASSERT_TRUE(proto.ink().strokes()[0].points()[0].has_x());
  EXPECT_EQ(proto.ink().strokes()[0].points()[0].x(), 1.);
  ASSERT_TRUE(proto.ink().strokes()[0].points()[0].has_y());
  EXPECT_EQ(proto.ink().strokes()[0].points()[0].y(), 2.);
  ASSERT_TRUE(proto.ink().strokes()[0].points()[0].has_t());
  EXPECT_EQ(proto.ink().strokes()[0].points()[0].t(), 3);
  ASSERT_TRUE(proto.ink().strokes()[0].points()[1].has_x());
  EXPECT_EQ(proto.ink().strokes()[0].points()[1].x(), 4.);
  ASSERT_TRUE(proto.ink().strokes()[0].points()[1].has_y());
  EXPECT_EQ(proto.ink().strokes()[0].points()[1].y(), 5.);
  ASSERT_TRUE(proto.ink().strokes()[0].points()[1].has_t());
  EXPECT_EQ(proto.ink().strokes()[0].points()[1].t(), 6);
  // Checks the second stroke.
  ASSERT_EQ(proto.ink().strokes()[1].points().size(), 1u);
  ASSERT_TRUE(proto.ink().strokes()[1].points()[0].has_x());
  EXPECT_EQ(proto.ink().strokes()[1].points()[0].x(), 7.);
  ASSERT_TRUE(proto.ink().strokes()[1].points()[0].has_y());
  EXPECT_EQ(proto.ink().strokes()[1].points()[0].y(), 8.);
  ASSERT_TRUE(proto.ink().strokes()[1].points()[0].has_t());
  EXPECT_EQ(proto.ink().strokes()[1].points()[0].t(), 9);

  ASSERT_TRUE(proto.context().has_pre_context());
  EXPECT_EQ(proto.context().pre_context(), "context");
  // Currently, we do not support writing guide.
  ASSERT_FALSE(proto.context().has_writing_guide());
  ASSERT_TRUE(proto.has_max_num_results());
  EXPECT_EQ(proto.max_num_results(), 100u);
  // We always ask for segmentation for HWR API.
  ASSERT_TRUE(proto.has_return_segmentation());
  EXPECT_TRUE(proto.return_segmentation());
}

// Tests `WebPlatformHandwritingPredictionsFromProto` works correctly.
TEST(WebPlatformHandwritingProtoMojoConversionTest,
     HandwritingPredictionsFromProto) {
  // Generates some strokes.
  std::vector<HandwritingStrokePtr> strokes;
  auto stroke1 = HandwritingStroke::New();
  stroke1->points.push_back(
      HandwritingPoint::New(PointF::New(11., 12.), base::Milliseconds(13)));
  stroke1->points.push_back(
      HandwritingPoint::New(PointF::New(14., 15.), base::Milliseconds(16)));
  auto stroke2 = HandwritingStroke::New();
  stroke2->points.push_back(
      HandwritingPoint::New(PointF::New(17., 18.), base::Milliseconds(19)));
  strokes.push_back(std::move(stroke1));
  strokes.push_back(std::move(stroke2));

  // Generates recognition result proto.
  chrome_knowledge::HandwritingRecognizerCandidate candidate;
  candidate.set_text("recognition result");
  auto* const segmentation = candidate.mutable_segmentation();
  auto* const segment = segmentation->add_segments();
  segment->set_sublabel("sublabel");
  auto* const ink_range = segment->add_ink_ranges();
  ink_range->set_start_stroke(0);
  ink_range->set_end_stroke(1);
  ink_range->set_start_point(1);
  ink_range->set_end_point(0);
  chrome_knowledge::HandwritingRecognizerResult proto;
  *proto.add_candidates() = candidate;

  // First tries an empty input strokes and it should return std::nullopt.
  const auto predictions_empty_input_stroke =
      WebPlatformHandwritingPredictionsFromProto({}, proto);
  EXPECT_FALSE(predictions_empty_input_stroke.has_value());

  // Now input valid strokes.
  const auto optional_predictions =
      WebPlatformHandwritingPredictionsFromProto(strokes, proto);

  ASSERT_TRUE(optional_predictions.has_value());

  const auto& predictions = optional_predictions.value();
  ASSERT_EQ(predictions.size(), 1u);
  EXPECT_EQ(predictions[0]->text, "recognition result");
  ASSERT_EQ(predictions[0]->segmentation_result.size(), 1u);
  EXPECT_EQ(predictions[0]->segmentation_result[0]->grapheme, "sublabel");
  EXPECT_EQ(predictions[0]->segmentation_result[0]->begin_index, 0u);
  EXPECT_EQ(predictions[0]->segmentation_result[0]->end_index, 8u);
  ASSERT_EQ(predictions[0]->segmentation_result[0]->drawing_segments.size(),
            2u);
  EXPECT_EQ(
      predictions[0]->segmentation_result[0]->drawing_segments[0]->stroke_index,
      0u);
  EXPECT_EQ(predictions[0]
                ->segmentation_result[0]
                ->drawing_segments[0]
                ->begin_point_index,
            1u);
  EXPECT_EQ(predictions[0]
                ->segmentation_result[0]
                ->drawing_segments[0]
                ->end_point_index,
            2u);
  EXPECT_EQ(
      predictions[0]->segmentation_result[0]->drawing_segments[1]->stroke_index,
      1u);
  EXPECT_EQ(predictions[0]
                ->segmentation_result[0]
                ->drawing_segments[1]
                ->begin_point_index,
            0u);
  EXPECT_EQ(predictions[0]
                ->segmentation_result[0]
                ->drawing_segments[1]
                ->end_point_index,
            1u);
}

}  // namespace ml
