// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <gtest/gtest.h>
#include <string>
#include <utility>

#include "ml/text_suggester_proto_mojom_conversion.h"

namespace ml {
namespace {

using ::chromeos::machine_learning::mojom::MultiWordExperimentGroup;
using ::chromeos::machine_learning::mojom::NextWordCompletionCandidate;
using ::chromeos::machine_learning::mojom::NextWordCompletionCandidatePtr;
using ::chromeos::machine_learning::mojom::TextSuggesterQuery;
using ::chromeos::machine_learning::mojom::TextSuggesterQueryPtr;
using ::chromeos::machine_learning::mojom::TextSuggesterResult;
using ::chromeos::machine_learning::mojom::TextSuggesterResultPtr;
using ::chromeos::machine_learning::mojom::TextSuggestionMode;

TEST(TextSuggesterMojomConversionTest, CompletionQueryMojomToRequestProto) {
  TextSuggesterQueryPtr query = TextSuggesterQuery::New();
  query->text = "how are y";
  query->suggestion_mode = TextSuggestionMode::kCompletion;

  const chrome_knowledge::TextSuggesterRequest request_proto =
      TextSuggesterQueryToProto(std::move(query));

  EXPECT_EQ(request_proto.text(), "how are y");
  EXPECT_EQ(request_proto.next_word_candidates_size(), 0);
  EXPECT_EQ(
      request_proto.suggestion_mode(),
      chrome_knowledge::RequestSuggestionMode::SUGGESTION_MODE_COMPLETION);
}

TEST(TextSuggesterMojomConversionTest, PredictionQueryMojomToRequestProto) {
  TextSuggesterQueryPtr query = TextSuggesterQuery::New();
  query->text = "how are y";
  query->suggestion_mode = TextSuggestionMode::kPrediction;

  const chrome_knowledge::TextSuggesterRequest request_proto =
      TextSuggesterQueryToProto(std::move(query));

  EXPECT_EQ(request_proto.text(), "how are y");
  EXPECT_EQ(request_proto.next_word_candidates_size(), 0);
  EXPECT_EQ(
      request_proto.suggestion_mode(),
      chrome_knowledge::RequestSuggestionMode::SUGGESTION_MODE_PREDICTION);
}

TEST(TextSuggesterMojomConversionTest,
     QueryMojomToRequestProtoWithNextWordCandidates) {
  TextSuggesterQueryPtr query = TextSuggesterQuery::New();
  query->text = "how are y";

  NextWordCompletionCandidatePtr candidate_one =
      NextWordCompletionCandidate::New();
  candidate_one->text = "you";
  candidate_one->normalized_score = 0.15f;
  query->next_word_candidates.push_back(std::move(candidate_one));

  NextWordCompletionCandidatePtr candidate_two =
      NextWordCompletionCandidate::New();
  candidate_two->text = "your";
  candidate_two->normalized_score = 0.4f;
  query->next_word_candidates.push_back(std::move(candidate_two));

  const chrome_knowledge::TextSuggesterRequest request_proto =
      TextSuggesterQueryToProto(std::move(query));

  EXPECT_EQ(request_proto.text(), "how are y");
  ASSERT_EQ(request_proto.next_word_candidates_size(), 2);
  EXPECT_EQ(request_proto.next_word_candidates(0).text(), "you");
  EXPECT_EQ(request_proto.next_word_candidates(0).normalized_score(), 0.15f);
  EXPECT_EQ(request_proto.next_word_candidates(1).text(), "your");
  EXPECT_EQ(request_proto.next_word_candidates(1).normalized_score(), 0.4f);
}

TEST(TextSuggesterMojomConversionTest, ResultProtoToResultMojom) {
  chrome_knowledge::TextSuggesterResult result_proto;

  chrome_knowledge::TextSuggestionCandidate* candidate_one =
      result_proto.add_candidates();
  chrome_knowledge::MultiWordSuggestionCandidate* multi_word_candidate_one =
      candidate_one->mutable_multi_word();
  multi_word_candidate_one->set_text("you doing");
  multi_word_candidate_one->set_normalized_score(0.15f);

  chrome_knowledge::TextSuggestionCandidate* candidate_two =
      result_proto.add_candidates();
  chrome_knowledge::MultiWordSuggestionCandidate* multi_word_candidate_two =
      candidate_two->mutable_multi_word();
  multi_word_candidate_two->set_text("you going");
  multi_word_candidate_two->set_normalized_score(0.35f);

  TextSuggesterResultPtr result = TextSuggesterResultFromProto(result_proto);

  EXPECT_EQ(result->status, TextSuggesterResult::Status::OK);
  ASSERT_EQ(result->candidates.size(), 2);
  EXPECT_TRUE(result->candidates[0]->is_multi_word());
  EXPECT_EQ(result->candidates[0]->get_multi_word()->text, "you doing");
  EXPECT_EQ(result->candidates[0]->get_multi_word()->normalized_score, 0.15f);
  EXPECT_TRUE(result->candidates[1]->is_multi_word());
  EXPECT_EQ(result->candidates[1]->get_multi_word()->text, "you going");
  EXPECT_EQ(result->candidates[1]->get_multi_word()->normalized_score, 0.35f);
}

TEST(TextSuggesterMojomConversionTest, ExperimentGroupToCorrectProto) {
  EXPECT_EQ(
      MultiWordExperimentGroupToProto(MultiWordExperimentGroup::kGboard),
      chrome_knowledge::MultiWordExperiment::MULTI_WORD_EXPERIMENT_GBOARD);
  EXPECT_EQ(MultiWordExperimentGroupToProto(
                MultiWordExperimentGroup::kGboardRelaxedA),
            chrome_knowledge::MultiWordExperiment::
                MULTI_WORD_EXPERIMENT_GBOARD_RELAXED_A);
  EXPECT_EQ(MultiWordExperimentGroupToProto(
                MultiWordExperimentGroup::kGboardRelaxedB),
            chrome_knowledge::MultiWordExperiment::
                MULTI_WORD_EXPERIMENT_GBOARD_RELAXED_B);
  EXPECT_EQ(MultiWordExperimentGroupToProto(
                MultiWordExperimentGroup::kGboardRelaxedC),
            chrome_knowledge::MultiWordExperiment::
                MULTI_WORD_EXPERIMENT_GBOARD_RELAXED_C);
  EXPECT_EQ(
      MultiWordExperimentGroupToProto(MultiWordExperimentGroup::kGboardD),
      chrome_knowledge::MultiWordExperiment::MULTI_WORD_EXPERIMENT_GBOARD_D);
  EXPECT_EQ(
      MultiWordExperimentGroupToProto(MultiWordExperimentGroup::kGboardE),
      chrome_knowledge::MultiWordExperiment::MULTI_WORD_EXPERIMENT_GBOARD_E);
  EXPECT_EQ(
      MultiWordExperimentGroupToProto(MultiWordExperimentGroup::kGboardF),
      chrome_knowledge::MultiWordExperiment::MULTI_WORD_EXPERIMENT_GBOARD_F);
  EXPECT_EQ(
      MultiWordExperimentGroupToProto(MultiWordExperimentGroup::kDefault),
      chrome_knowledge::MultiWordExperiment::MULTI_WORD_EXPERIMENT_UNSPECIFIED);
}

}  // namespace
}  // namespace ml
