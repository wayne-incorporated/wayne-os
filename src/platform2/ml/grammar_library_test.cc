// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <gtest/gtest.h>

#include "ml/grammar_library.h"
#include "ml/util.h"

namespace ml {

TEST(GrammarLibraryTest, CanLoadLibrary) {
  auto* const instance = ml::GrammarLibrary::GetInstance();
  if (IsAsan()) {
    EXPECT_FALSE(ml::GrammarLibrary::IsGrammarLibrarySupported());
    EXPECT_EQ(instance->GetStatus(), ml::GrammarLibrary::Status::kNotSupported);
    return;
  }

  if (ml::GrammarLibrary::IsGrammarLibrarySupported()) {
    EXPECT_EQ(instance->GetStatus(), ml::GrammarLibrary::Status::kOk);
  } else {
    EXPECT_EQ(instance->GetStatus(), ml::GrammarLibrary::Status::kNotSupported);
  }
}

TEST(GrammarLibraryTest, ExampleRequest) {
  auto* const instance = ml::GrammarLibrary::GetInstance();
  // Nothing to test on an unsupported platform.
  if (instance->GetStatus() == ml::GrammarLibrary::Status::kNotSupported) {
    return;
  }
  ASSERT_EQ(instance->GetStatus(), GrammarLibrary::Status::kOk);

  GrammarChecker const checker = instance->CreateGrammarChecker();
  instance->LoadGrammarChecker(checker);

  chrome_knowledge::GrammarCheckerRequest request;
  request.set_text("They is student.");
  request.set_language("en-US");

  chrome_knowledge::GrammarCheckerResult result;
  instance->CheckGrammar(checker, request, &result);

  ASSERT_GE(result.candidates_size(), 1);
  EXPECT_EQ(result.candidates(0).text(), "They are students.");

  ASSERT_EQ(result.candidates(0).fragments_size(), 1);
  const chrome_knowledge::CorrectionFragment fragment =
      result.candidates(0).fragments(0);
  EXPECT_EQ(fragment.offset(), 5);
  EXPECT_EQ(fragment.length(), 10);
  EXPECT_EQ(fragment.replacement(), "are students");

  instance->DestroyGrammarChecker(checker);
}

}  // namespace ml
