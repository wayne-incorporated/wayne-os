// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <gtest/gtest.h>

#include "ml/text_suggestions.h"
#include "ml/util.h"

namespace ml {
namespace {

const float kScoringEqualityDelta = 0.02f;

TEST(TextSuggestionsTest, CanLoadLibrary) {
  auto* const instance = ml::TextSuggestions::GetInstance();
  if (IsAsan()) {
    EXPECT_FALSE(ml::TextSuggestions::IsTextSuggestionsSupported());
    EXPECT_EQ(instance->GetStatus(),
              ml::TextSuggestions::Status::kNotSupported);
    return;
  }

  if (ml::TextSuggestions::IsTextSuggestionsSupported()) {
    EXPECT_EQ(instance->GetStatus(), ml::TextSuggestions::Status::kOk);
  } else {
    EXPECT_EQ(instance->GetStatus(),
              ml::TextSuggestions::Status::kNotSupported);
  }
}

TEST(TextSuggestionsText, ExampleCompletionRequestWithDefaultSettings) {
  auto* const instance = ml::TextSuggestions::GetInstance();
  if (instance->GetStatus() == ml::TextSuggestions::Status::kNotSupported) {
    return;
  }

  ASSERT_EQ(instance->GetStatus(), TextSuggestions::Status::kOk);

  TextSuggester const suggester = instance->CreateTextSuggester();
  instance->LoadTextSuggester(
      suggester,
      chrome_knowledge::MultiWordExperiment::MULTI_WORD_EXPERIMENT_UNSPECIFIED);

  chrome_knowledge::TextSuggesterRequest request;
  request.set_text("How are y");
  request.set_suggestion_mode(
      chrome_knowledge::RequestSuggestionMode::SUGGESTION_MODE_COMPLETION);

  chrome_knowledge::NextWordCompletionCandidate* candidate =
      request.add_next_word_candidates();
  candidate->set_text("you");
  candidate->set_normalized_score(-1.0f);

  chrome_knowledge::TextSuggesterResult result;
  instance->GenerateSuggestions(suggester, request, &result);

  ASSERT_GT(result.candidates_size(), 0);
  EXPECT_EQ(result.candidates(0).has_multi_word(), true);
  EXPECT_EQ(result.candidates(0).multi_word().text(), "you doing");
  EXPECT_NEAR(result.candidates(0).multi_word().normalized_score(), -0.680989f,
              kScoringEqualityDelta);

  instance->DestroyTextSuggester(suggester);
}

TEST(TextSuggestionsText, ExamplePredictionRequestWithDefaultSettings) {
  auto* const instance = ml::TextSuggestions::GetInstance();
  if (instance->GetStatus() == ml::TextSuggestions::Status::kNotSupported) {
    return;
  }

  ASSERT_EQ(instance->GetStatus(), TextSuggestions::Status::kOk);

  TextSuggester const suggester = instance->CreateTextSuggester();
  instance->LoadTextSuggester(
      suggester,
      chrome_knowledge::MultiWordExperiment::MULTI_WORD_EXPERIMENT_UNSPECIFIED);

  chrome_knowledge::TextSuggesterRequest request;
  request.set_text("How are ");
  request.set_suggestion_mode(
      chrome_knowledge::RequestSuggestionMode::SUGGESTION_MODE_PREDICTION);

  chrome_knowledge::TextSuggesterResult result;
  instance->GenerateSuggestions(suggester, request, &result);

  ASSERT_GT(result.candidates_size(), 0);
  ASSERT_EQ(result.candidates(0).has_multi_word(), true);
  EXPECT_EQ(result.candidates(0).multi_word().text(), "you doing");
  EXPECT_NEAR(result.candidates(0).multi_word().normalized_score(), -0.8141749f,
              kScoringEqualityDelta);

  instance->DestroyTextSuggester(suggester);
}

TEST(TextSuggestionsText,
     ExperimentGboardGroupIsSetAndTriggersExpectedSuggestions) {
  auto* const instance = ml::TextSuggestions::GetInstance();
  if (instance->GetStatus() == ml::TextSuggestions::Status::kNotSupported) {
    return;
  }

  ASSERT_EQ(instance->GetStatus(), TextSuggestions::Status::kOk);

  TextSuggester const suggester = instance->CreateTextSuggester();
  instance->LoadTextSuggester(
      suggester,
      chrome_knowledge::MultiWordExperiment::MULTI_WORD_EXPERIMENT_GBOARD);

  chrome_knowledge::TextSuggesterRequest request;
  request.set_text("I'll send her file as ");
  request.set_suggestion_mode(
      chrome_knowledge::RequestSuggestionMode::SUGGESTION_MODE_PREDICTION);

  chrome_knowledge::TextSuggesterResult result;
  instance->GenerateSuggestions(suggester, request, &result);

  ASSERT_GT(result.candidates_size(), 0);
  EXPECT_EQ(result.candidates(0).has_multi_word(), true);
  EXPECT_EQ(result.candidates(0).multi_word().text(), "soon as I get");
  EXPECT_NEAR(result.candidates(0).multi_word().normalized_score(), -0.53198f,
              kScoringEqualityDelta);

  instance->DestroyTextSuggester(suggester);
}

TEST(TextSuggestionsText,
     ExperimentGboardRelaxedGroupAIsSetAndTriggersExpectedSuggestions) {
  auto* const instance = ml::TextSuggestions::GetInstance();
  if (instance->GetStatus() == ml::TextSuggestions::Status::kNotSupported) {
    return;
  }

  ASSERT_EQ(instance->GetStatus(), TextSuggestions::Status::kOk);

  TextSuggester const suggester = instance->CreateTextSuggester();
  instance->LoadTextSuggester(suggester,
                              chrome_knowledge::MultiWordExperiment::
                                  MULTI_WORD_EXPERIMENT_GBOARD_RELAXED_A);

  chrome_knowledge::TextSuggesterRequest request;
  request.set_text("please let me ");
  request.set_suggestion_mode(
      chrome_knowledge::RequestSuggestionMode::SUGGESTION_MODE_PREDICTION);

  chrome_knowledge::TextSuggesterResult result;
  instance->GenerateSuggestions(suggester, request, &result);

  ASSERT_GT(result.candidates_size(), 0);
  EXPECT_EQ(result.candidates(0).has_multi_word(), true);
  EXPECT_EQ(result.candidates(0).multi_word().text(), "know when you");
  EXPECT_NEAR(result.candidates(0).multi_word().normalized_score(), -0.7348f,
              kScoringEqualityDelta);

  instance->DestroyTextSuggester(suggester);
}

TEST(TextSuggestionsText,
     ExperimentGboardRelaxedGroupBIsSetAndTriggersExpectedSuggestions) {
  auto* const instance = ml::TextSuggestions::GetInstance();
  if (instance->GetStatus() == ml::TextSuggestions::Status::kNotSupported) {
    return;
  }

  ASSERT_EQ(instance->GetStatus(), TextSuggestions::Status::kOk);

  TextSuggester const suggester = instance->CreateTextSuggester();
  instance->LoadTextSuggester(suggester,
                              chrome_knowledge::MultiWordExperiment::
                                  MULTI_WORD_EXPERIMENT_GBOARD_RELAXED_B);

  chrome_knowledge::TextSuggesterRequest request;
  request.set_text("please let me ");
  request.set_suggestion_mode(
      chrome_knowledge::RequestSuggestionMode::SUGGESTION_MODE_PREDICTION);

  chrome_knowledge::TextSuggesterResult result;
  instance->GenerateSuggestions(suggester, request, &result);

  ASSERT_GT(result.candidates_size(), 0);
  EXPECT_EQ(result.candidates(0).has_multi_word(), true);
  EXPECT_EQ(result.candidates(0).multi_word().text(), "know when you");
  EXPECT_NEAR(result.candidates(0).multi_word().normalized_score(), -0.7348f,
              kScoringEqualityDelta);

  instance->DestroyTextSuggester(suggester);
}

TEST(TextSuggestionsText,
     ExperimentGboardRelaxedGroupCIsSetAndTriggersExpectedSuggestions) {
  auto* const instance = ml::TextSuggestions::GetInstance();
  if (instance->GetStatus() == ml::TextSuggestions::Status::kNotSupported) {
    return;
  }

  ASSERT_EQ(instance->GetStatus(), TextSuggestions::Status::kOk);

  TextSuggester const suggester = instance->CreateTextSuggester();
  instance->LoadTextSuggester(suggester,
                              chrome_knowledge::MultiWordExperiment::
                                  MULTI_WORD_EXPERIMENT_GBOARD_RELAXED_C);

  chrome_knowledge::TextSuggesterRequest request;
  request.set_text("please let me ");
  request.set_suggestion_mode(
      chrome_knowledge::RequestSuggestionMode::SUGGESTION_MODE_PREDICTION);

  chrome_knowledge::TextSuggesterResult result;
  instance->GenerateSuggestions(suggester, request, &result);

  ASSERT_GT(result.candidates_size(), 0);
  EXPECT_EQ(result.candidates(0).has_multi_word(), true);
  EXPECT_EQ(result.candidates(0).multi_word().text(), "know when you");
  EXPECT_NEAR(result.candidates(0).multi_word().normalized_score(), -0.7348f,
              kScoringEqualityDelta);

  instance->DestroyTextSuggester(suggester);
}

TEST(TextSuggestionsText,
     ExperimentGboardGroupDIsSetAndTriggersExpectedSuggestions) {
  auto* const instance = ml::TextSuggestions::GetInstance();
  if (instance->GetStatus() == ml::TextSuggestions::Status::kNotSupported) {
    return;
  }

  ASSERT_EQ(instance->GetStatus(), TextSuggestions::Status::kOk);

  TextSuggester const suggester = instance->CreateTextSuggester();
  instance->LoadTextSuggester(
      suggester,
      chrome_knowledge::MultiWordExperiment::MULTI_WORD_EXPERIMENT_GBOARD_D);

  chrome_knowledge::TextSuggesterRequest request;
  request.set_text("please let me ");
  request.set_suggestion_mode(
      chrome_knowledge::RequestSuggestionMode::SUGGESTION_MODE_PREDICTION);

  chrome_knowledge::TextSuggesterResult result;
  instance->GenerateSuggestions(suggester, request, &result);

  ASSERT_GT(result.candidates_size(), 0);
  EXPECT_EQ(result.candidates(0).has_multi_word(), true);
  EXPECT_EQ(result.candidates(0).multi_word().text(), "know if you");
  EXPECT_NEAR(result.candidates(0).multi_word().normalized_score(), -0.5560128f,
              kScoringEqualityDelta);

  instance->DestroyTextSuggester(suggester);
}

TEST(TextSuggestionsText,
     ExperimentGboardGroupEIsSetAndTriggersExpectedSuggestions) {
  auto* const instance = ml::TextSuggestions::GetInstance();
  if (instance->GetStatus() == ml::TextSuggestions::Status::kNotSupported) {
    return;
  }

  ASSERT_EQ(instance->GetStatus(), TextSuggestions::Status::kOk);

  TextSuggester const suggester = instance->CreateTextSuggester();
  instance->LoadTextSuggester(
      suggester,
      chrome_knowledge::MultiWordExperiment::MULTI_WORD_EXPERIMENT_GBOARD_E);

  chrome_knowledge::TextSuggesterRequest request;
  request.set_text("please let me ");
  request.set_suggestion_mode(
      chrome_knowledge::RequestSuggestionMode::SUGGESTION_MODE_PREDICTION);

  chrome_knowledge::TextSuggesterResult result;
  instance->GenerateSuggestions(suggester, request, &result);

  ASSERT_GT(result.candidates_size(), 0);
  EXPECT_EQ(result.candidates(0).has_multi_word(), true);
  EXPECT_EQ(result.candidates(0).multi_word().text(), "know if");
  EXPECT_NEAR(result.candidates(0).multi_word().normalized_score(), -0.534f,
              kScoringEqualityDelta);

  instance->DestroyTextSuggester(suggester);
}

}  // namespace
}  // namespace ml
