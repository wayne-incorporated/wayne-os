// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "ml/grammar_proto_mojom_conversion.h"

#include <utility>

namespace ml {
namespace {

using ::chromeos::machine_learning::mojom::GrammarCheckerCandidate;
using ::chromeos::machine_learning::mojom::GrammarCheckerCandidatePtr;
using ::chromeos::machine_learning::mojom::GrammarCheckerQuery;
using ::chromeos::machine_learning::mojom::GrammarCheckerQueryPtr;
using ::chromeos::machine_learning::mojom::GrammarCheckerResult;
using ::chromeos::machine_learning::mojom::GrammarCheckerResultPtr;
using ::chromeos::machine_learning::mojom::GrammarCorrectionFragment;
using ::chromeos::machine_learning::mojom::GrammarCorrectionFragmentPtr;

}  // namespace

chrome_knowledge::GrammarCheckerRequest GrammarCheckerQueryToProto(
    GrammarCheckerQueryPtr query) {
  chrome_knowledge::GrammarCheckerRequest request;
  request.set_text(query->text);
  request.set_language(query->language);

  return request;
}

GrammarCheckerQueryPtr GrammarCheckerQueryFromProtoForTesting(
    const chrome_knowledge::GrammarCheckerRequest& request_proto) {
  GrammarCheckerQueryPtr query = GrammarCheckerQuery::New();
  query->text = request_proto.text();
  query->language = request_proto.language();

  return query;
}

GrammarCheckerResultPtr GrammarCheckerResultFromProto(
    const chrome_knowledge::GrammarCheckerResult& result_proto) {
  GrammarCheckerResultPtr result = GrammarCheckerResult::New();

  // This method is called only when Grammar Check succeeds, so status is
  // always set to OK.
  result->status = GrammarCheckerResult::Status::OK;

  // For candidates.
  for (const auto& candidate_proto : result_proto.candidates()) {
    GrammarCheckerCandidatePtr candidate = GrammarCheckerCandidate::New();
    candidate->text = candidate_proto.text();
    candidate->score = candidate_proto.score();

    for (const auto& fragment_proto : candidate_proto.fragments()) {
      GrammarCorrectionFragmentPtr fragment = GrammarCorrectionFragment::New();
      fragment->offset = fragment_proto.offset();
      fragment->length = fragment_proto.length();
      fragment->replacement = fragment_proto.replacement();

      candidate->fragments.push_back(std::move(fragment));
    }

    result->candidates.push_back(std::move(candidate));
  }

  return result;
}

}  // namespace ml
