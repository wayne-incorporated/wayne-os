// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <base/time/time.h>
#include <utility>

#include "ml/handwriting_proto_mojom_conversion.h"

namespace ml {
namespace {

using ::chromeos::machine_learning::mojom::HandwritingRecognitionQuery;
using ::chromeos::machine_learning::mojom::HandwritingRecognitionQueryPtr;
using ::chromeos::machine_learning::mojom::HandwritingRecognizerCandidate;
using ::chromeos::machine_learning::mojom::HandwritingRecognizerCandidatePtr;
using ::chromeos::machine_learning::mojom::HandwritingRecognizerInkRange;
using ::chromeos::machine_learning::mojom::HandwritingRecognizerInkRangePtr;
using ::chromeos::machine_learning::mojom::HandwritingRecognizerResult;
using ::chromeos::machine_learning::mojom::HandwritingRecognizerResultPtr;
using ::chromeos::machine_learning::mojom::HandwritingRecognizerSegment;
using ::chromeos::machine_learning::mojom::HandwritingRecognizerSegmentation;
using ::chromeos::machine_learning::mojom::HandwritingRecognizerSegmentationPtr;
using ::chromeos::machine_learning::mojom::HandwritingRecognizerSegmentPtr;
using ::chromeos::machine_learning::mojom::InkPoint;
using ::chromeos::machine_learning::mojom::InkPointPtr;
using ::chromeos::machine_learning::mojom::InkStroke;
using ::chromeos::machine_learning::mojom::InkStrokePtr;
using ::chromeos::machine_learning::mojom::RecognitionContext;
using ::chromeos::machine_learning::mojom::RecognitionContextPtr;
using ::chromeos::machine_learning::mojom::WritingGuide;
using ::chromeos::machine_learning::mojom::WritingGuidePtr;

}  // namespace

chrome_knowledge::HandwritingRecognizerRequest
HandwritingRecognitionQueryToProto(
    chromeos::machine_learning::mojom::HandwritingRecognitionQueryPtr query) {
  chrome_knowledge::HandwritingRecognizerRequest request;
  // Simple fields.
  request.set_return_segmentation(query->return_segmentation);
  request.set_max_num_results(query->max_num_results);

  // For RecognitionContext;
  if (!query->context.is_null()) {
    // For pre_context.
    const auto& context = *query->context;
    auto& context_proto = *request.mutable_context();
    if (context.pre_context.has_value()) {
      context_proto.set_pre_context(context.pre_context.value());
    }

    // For writing_guide.
    if (!context.writing_guide.is_null()) {
      const auto& writing_guide = *context.writing_guide;
      auto& writing_guide_proto = *context_proto.mutable_writing_guide();

      writing_guide_proto.set_width(writing_guide.width);
      writing_guide_proto.set_height(writing_guide.height);
    }
  }

  // For ink;
  if (!query->ink.empty()) {
    for (const auto& ink_stroke : query->ink) {
      auto& stroke_proto = *request.mutable_ink()->add_strokes();
      for (const auto& point : ink_stroke->points) {
        auto& point_proto = *stroke_proto.add_points();
        point_proto.set_x(point->x);
        point_proto.set_y(point->y);
        if (point->t) {
          point_proto.set_t(point->t->InMilliseconds());
        }
      }
    }
  }
  return request;
}

chromeos::machine_learning::mojom::HandwritingRecognitionQueryPtr
HandwritingRecognitionQueryFromProtoForTesting(
    const chrome_knowledge::HandwritingRecognizerRequest& request_proto) {
  HandwritingRecognitionQueryPtr query = HandwritingRecognitionQuery::New();

  // For simple fields.
  query->return_segmentation = request_proto.return_segmentation();
  query->max_num_results = request_proto.max_num_results();

  // For RecognitionContext;
  if (request_proto.has_context()) {
    query->context = RecognitionContext::New();
    const auto& context_proto = request_proto.context();

    // For pre_context.
    if (context_proto.has_pre_context()) {
      query->context->pre_context = context_proto.pre_context();
    }

    // For writing_guide.
    if (context_proto.has_writing_guide()) {
      query->context->writing_guide = WritingGuide::New();
      const auto& writing_guide_proto = context_proto.writing_guide();
      query->context->writing_guide->width = writing_guide_proto.width();
      query->context->writing_guide->height = writing_guide_proto.height();
    }
  }

  // For ink;
  if (request_proto.has_ink()) {
    for (const auto& stroke_proto : request_proto.ink().strokes()) {
      InkStrokePtr stroke = InkStroke::New();
      for (const auto& point_proto : stroke_proto.points()) {
        InkPointPtr point = InkPoint::New();
        point->x = point_proto.x();
        point->y = point_proto.y();
        if (point_proto.has_t()) {
          point->t = base::Milliseconds(point_proto.t());
        }

        stroke->points.push_back(std::move(point));
      }
      query->ink.push_back(std::move(stroke));
    }
  }
  return query;
}

chromeos::machine_learning::mojom::HandwritingRecognizerResultPtr
HandwritingRecognizerResultFromProto(
    const chrome_knowledge::HandwritingRecognizerResult& result_proto) {
  HandwritingRecognizerResultPtr result = HandwritingRecognizerResult::New();

  // For status; set default value as OK.
  result->status = HandwritingRecognizerResult::Status::OK;

  // For candidates.
  if (!result_proto.candidates().empty()) {
    for (const auto& candidate_proto : result_proto.candidates()) {
      HandwritingRecognizerCandidatePtr candidate =
          HandwritingRecognizerCandidate::New();
      candidate->text = candidate_proto.text();
      candidate->score = candidate_proto.score();

      // Each candidate_proto contains a segmentation, which contains a list of
      // segments.
      if (candidate_proto.has_segmentation()) {
        candidate->segmentation = HandwritingRecognizerSegmentation::New();
        for (const auto& segment_proto :
             candidate_proto.segmentation().segments()) {
          HandwritingRecognizerSegmentPtr segment =
              HandwritingRecognizerSegment::New();
          // For sublabel.
          segment->sublabel = segment_proto.sublabel();
          // For ink_ranges.
          for (const auto& ink_range_proto : segment_proto.ink_ranges()) {
            HandwritingRecognizerInkRangePtr ink_range =
                HandwritingRecognizerInkRange::New();
            ink_range->start_stroke = ink_range_proto.start_stroke();
            ink_range->end_stroke = ink_range_proto.end_stroke();
            ink_range->start_point = ink_range_proto.start_point();
            ink_range->end_point = ink_range_proto.end_point();
            segment->ink_ranges.push_back(std::move(ink_range));
          }

          candidate->segmentation->segments.push_back(std::move(segment));
        }
      }

      result->candidates.push_back(std::move(candidate));
    }
  }
  return result;
}

}  // namespace ml
