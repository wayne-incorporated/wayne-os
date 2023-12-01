// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "ml/text_suggester_proto_mojom_conversion.h"

#include <utility>

namespace ml {
namespace {

using ::chromeos::machine_learning::mojom::MultiWordExperimentGroup;
using ::chromeos::machine_learning::mojom::MultiWordSuggestionCandidate;
using ::chromeos::machine_learning::mojom::MultiWordSuggestionCandidatePtr;
using ::chromeos::machine_learning::mojom::TextSuggesterQuery;
using ::chromeos::machine_learning::mojom::TextSuggesterQueryPtr;
using ::chromeos::machine_learning::mojom::TextSuggesterResult;
using ::chromeos::machine_learning::mojom::TextSuggesterResultPtr;
using ::chromeos::machine_learning::mojom::TextSuggestionCandidate;
using ::chromeos::machine_learning::mojom::TextSuggestionCandidatePtr;
using ::chromeos::machine_learning::mojom::TextSuggestionMode;

chrome_knowledge::RequestSuggestionMode ToRequestSuggestionMode(
    TextSuggestionMode suggestion_mode) {
  switch (suggestion_mode) {
    case TextSuggestionMode::kCompletion:
      return chrome_knowledge::RequestSuggestionMode::
          SUGGESTION_MODE_COMPLETION;
    case TextSuggestionMode::kPrediction:
      return chrome_knowledge::RequestSuggestionMode::
          SUGGESTION_MODE_PREDICTION;
    default:
      return chrome_knowledge::RequestSuggestionMode::SUGGESTION_MODE_UNKNOWN;
  }
}

}  // namespace

chrome_knowledge::TextSuggesterRequest TextSuggesterQueryToProto(
    TextSuggesterQueryPtr query) {
  chrome_knowledge::TextSuggesterRequest request_proto;
  request_proto.set_text(query->text);
  request_proto.set_suggestion_mode(
      ToRequestSuggestionMode(query->suggestion_mode));

  for (const auto& candidate : query->next_word_candidates) {
    chrome_knowledge::NextWordCompletionCandidate next_word_candidate;
    next_word_candidate.set_text(candidate->text);
    next_word_candidate.set_normalized_score(candidate->normalized_score);
    *request_proto.add_next_word_candidates() = next_word_candidate;
  }

  return request_proto;
}

TextSuggesterResultPtr TextSuggesterResultFromProto(
    const chrome_knowledge::TextSuggesterResult& result_proto) {
  TextSuggesterResultPtr result = TextSuggesterResult::New();

  // This method is called only when generating suggestions succeeds, so
  // status is always set to OK.
  result->status = TextSuggesterResult::Status::OK;

  // For candidates.
  for (const auto& candidate_proto : result_proto.candidates()) {
    TextSuggestionCandidatePtr candidate;
    if (candidate_proto.has_multi_word()) {
      MultiWordSuggestionCandidatePtr multi_word_candidate =
          MultiWordSuggestionCandidate::New();
      multi_word_candidate->text = candidate_proto.multi_word().text();
      multi_word_candidate->normalized_score =
          candidate_proto.multi_word().normalized_score();

      candidate = TextSuggestionCandidate::NewMultiWord(
          std::move(multi_word_candidate));

      result->candidates.push_back(std::move(candidate));
    }
  }

  return result;
}

chrome_knowledge::MultiWordExperiment MultiWordExperimentGroupToProto(
    MultiWordExperimentGroup experiment) {
  switch (experiment) {
    case MultiWordExperimentGroup::kGboard:
      return chrome_knowledge::MultiWordExperiment::
          MULTI_WORD_EXPERIMENT_GBOARD;
    case MultiWordExperimentGroup::kGboardRelaxedA:
      return chrome_knowledge::MultiWordExperiment::
          MULTI_WORD_EXPERIMENT_GBOARD_RELAXED_A;
    case MultiWordExperimentGroup::kGboardRelaxedB:
      return chrome_knowledge::MultiWordExperiment::
          MULTI_WORD_EXPERIMENT_GBOARD_RELAXED_B;
    case MultiWordExperimentGroup::kGboardRelaxedC:
      return chrome_knowledge::MultiWordExperiment::
          MULTI_WORD_EXPERIMENT_GBOARD_RELAXED_C;
    case MultiWordExperimentGroup::kGboardD:
      return chrome_knowledge::MultiWordExperiment::
          MULTI_WORD_EXPERIMENT_GBOARD_D;
    case MultiWordExperimentGroup::kGboardE:
      return chrome_knowledge::MultiWordExperiment::
          MULTI_WORD_EXPERIMENT_GBOARD_E;
    case MultiWordExperimentGroup::kGboardF:
      return chrome_knowledge::MultiWordExperiment::
          MULTI_WORD_EXPERIMENT_GBOARD_F;
    case MultiWordExperimentGroup::kDefault:
    default:
      return chrome_knowledge::MultiWordExperiment::
          MULTI_WORD_EXPERIMENT_UNSPECIFIED;
  }
}

}  // namespace ml
