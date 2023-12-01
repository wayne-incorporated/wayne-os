// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <gtest/gtest.h>
#include <string>

#include "ml/handwriting.h"
#include "ml/handwriting_proto_mojom_conversion.h"

namespace ml {

using chromeos::machine_learning::mojom::HandwritingRecognitionQueryPtr;
using chromeos::machine_learning::mojom::HandwritingRecognizerSpec;

// Gets a test request proto with two strokes.
chrome_knowledge::HandwritingRecognizerRequest
GetHandwritingRecognizerRequestProto() {
  chrome_knowledge::HandwritingRecognizerRequest request;
  request.set_max_num_results(3);
  request.set_return_segmentation(true);

  chrome_knowledge::RecognitionContext& context = *request.mutable_context();
  context.set_pre_context("random_pre_context");
  context.mutable_writing_guide()->set_width(0.4f);
  context.mutable_writing_guide()->set_height(0.6f);

  chrome_knowledge::InkPoint p1, p2;
  p1.set_x(11);
  p1.set_y(12);
  p1.set_t(13);

  // Point p2 doesn't have a time information.
  p2.set_x(21);
  p2.set_y(22);

  chrome_knowledge::InkStroke s1, s2;
  *s1.add_points() = p1;

  *s2.add_points() = p1;
  *s2.add_points() = p2;

  chrome_knowledge::Ink ink;
  *ink.add_strokes() = s1;
  *ink.add_strokes() = s2;

  *request.mutable_ink() = ink;
  return request;
}

// Tests that proto->mojom->proto->mojom returns the same result as expected.
TEST(HandwritingProtoMojomConversionTest, RequestProtoToQuery) {
  const chrome_knowledge::HandwritingRecognizerRequest proto =
      GetHandwritingRecognizerRequestProto();

  const HandwritingRecognitionQueryPtr query =
      HandwritingRecognitionQueryFromProtoForTesting(proto);

  const chrome_knowledge::HandwritingRecognizerRequest proto_constructed =
      HandwritingRecognitionQueryToProto(
          HandwritingRecognitionQueryFromProtoForTesting(proto));

  const HandwritingRecognitionQueryPtr query_constructed =
      HandwritingRecognitionQueryFromProtoForTesting(proto_constructed);

  EXPECT_TRUE(query.Equals(query_constructed));

  EXPECT_EQ(proto.SerializeAsString(), proto_constructed.SerializeAsString());
}

}  // namespace ml
