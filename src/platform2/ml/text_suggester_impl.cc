// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "ml/text_suggester_impl.h"

#include <utility>
#include <vector>

#include "ml/request_metrics.h"
#include "ml/text_suggester_proto_mojom_conversion.h"

namespace ml {
namespace {

using ::chromeos::machine_learning::mojom::TextSuggester;
using ::chromeos::machine_learning::mojom::TextSuggesterQueryPtr;
using ::chromeos::machine_learning::mojom::TextSuggesterResult;
using ::chromeos::machine_learning::mojom::TextSuggestionCandidatePtr;

}  // namespace

bool TextSuggesterImpl::Create(
    mojo::PendingReceiver<TextSuggester> receiver,
    chromeos::machine_learning::mojom::TextSuggesterSpecPtr spec) {
  auto suggester_impl =
      new TextSuggesterImpl(std::move(receiver), std::move(spec));

  // Set the disconnection handler to strongly bind `checker_impl` to delete
  // `suggester_impl` when the connection is gone.
  suggester_impl->receiver_.set_disconnect_handler(base::BindOnce(
      [](const TextSuggesterImpl* const suggester_impl) {
        delete suggester_impl;
      },
      base::Unretained(suggester_impl)));

  return suggester_impl->successfully_loaded_;
}

TextSuggesterImpl::TextSuggesterImpl(
    mojo::PendingReceiver<TextSuggester> receiver,
    chromeos::machine_learning::mojom::TextSuggesterSpecPtr spec)
    : library_(ml::TextSuggestions::GetInstance()),
      receiver_(this, std::move(receiver)) {
  DCHECK(library_->GetStatus() == ml::TextSuggestions::Status::kOk)
      << "TextSuggesterImpl should be created only if TextSuggestions is "
         "initialized successfully.";

  chrome_knowledge::MultiWordExperiment experiment =
      !spec.is_null()
          ? MultiWordExperimentGroupToProto(spec->multi_word_experiment)
          : chrome_knowledge::MultiWordExperiment::
                MULTI_WORD_EXPERIMENT_UNSPECIFIED;

  suggester_ = library_->CreateTextSuggester();
  successfully_loaded_ = library_->LoadTextSuggester(suggester_, experiment);
}

TextSuggesterImpl::~TextSuggesterImpl() {
  library_->DestroyTextSuggester(suggester_);
}

void TextSuggesterImpl::Suggest(TextSuggesterQueryPtr query,
                                SuggestCallback callback) {
  DCHECK(successfully_loaded_);

  RequestMetrics request_metrics("TextSuggester", "Suggest");
  request_metrics.StartRecordingPerformanceMetrics();

  chrome_knowledge::TextSuggesterResult result_proto;

  if (library_->GenerateSuggestions(suggester_,
                                    TextSuggesterQueryToProto(std::move(query)),
                                    &result_proto)) {
    // Suggest succeeded, run callback on the result.
    std::move(callback).Run(TextSuggesterResultFromProto(result_proto));
    request_metrics.FinishRecordingPerformanceMetrics();
    request_metrics.RecordRequestEvent(TextSuggesterResult::Status::OK);
  } else {
    // Suggest failed, run callback on empty result and status = ERROR.
    std::move(callback).Run(
        TextSuggesterResult::New(TextSuggesterResult::Status::ERROR,
                                 std::vector<TextSuggestionCandidatePtr>()));
    request_metrics.RecordRequestEvent(TextSuggesterResult::Status::ERROR);
  }
}

}  // namespace ml
