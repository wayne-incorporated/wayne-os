// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "backend/test/backend_test.h"

#include "backend/text_input_enums.h"

namespace cros_im {
namespace test {

namespace {

zcr_extended_text_input_v1_input_type kDefaultInputType =
    ZCR_EXTENDED_TEXT_INPUT_V1_INPUT_TYPE_TEXT;
zcr_extended_text_input_v1_input_mode kDefaultInputMode =
    ZCR_EXTENDED_TEXT_INPUT_V1_INPUT_MODE_DEFAULT;
uint32_t kDefaultInputFlags = ZCR_EXTENDED_TEXT_INPUT_V1_INPUT_FLAGS_NONE;
zcr_extended_text_input_v1_learning_mode kDefaultLearningMode =
    ZCR_EXTENDED_TEXT_INPUT_V1_LEARNING_MODE_ENABLED;
zcr_extended_text_input_v1_inline_composition_support
    kDefaultInlineCompositionSupport =
        ZCR_EXTENDED_TEXT_INPUT_V1_INLINE_COMPOSITION_SUPPORT_SUPPORTED;

}  // namespace

BACKEND_TEST(GtkContentTypeTest, ContentHints) {
  ExpectCreateTextInput<0>();
  Ignore<0>(Request::kActivate);
  Ignore<0>(Request::kDeactivate);
  Ignore<0>(Request::kReset);
  Unignore<0>(Request::kShowInputPanel);
  Unignore<0>(Request::kSetInputType);

  ExpectSetInputType<0>(
      kDefaultInputType, kDefaultInputMode,
      ZCR_EXTENDED_TEXT_INPUT_V1_INPUT_FLAGS_SPELLCHECK_ON |
          ZCR_EXTENDED_TEXT_INPUT_V1_INPUT_FLAGS_AUTOCAPITALIZE_CHARACTERS,
      kDefaultLearningMode, kDefaultInlineCompositionSupport);
  Expect<0>(Request::kShowInputPanel);
  SendCommitString<0>("a");

  ExpectCreateTextInput<1>();
  Ignore<1>(Request::kActivate);
  Ignore<1>(Request::kDeactivate);
  Ignore<1>(Request::kReset);
  Unignore<1>(Request::kShowInputPanel);
  Unignore<1>(Request::kSetInputType);

  ExpectSetInputType<1>(
      kDefaultInputType, kDefaultInputMode,
      ZCR_EXTENDED_TEXT_INPUT_V1_INPUT_FLAGS_AUTOCOMPLETE_ON |
          ZCR_EXTENDED_TEXT_INPUT_V1_INPUT_FLAGS_SPELLCHECK_OFF |
          ZCR_EXTENDED_TEXT_INPUT_V1_INPUT_FLAGS_AUTOCAPITALIZE_NONE,
      kDefaultLearningMode, kDefaultInlineCompositionSupport);
  Expect<1>(Request::kShowInputPanel);
  SendCommitString<1>("b");

  ExpectSetInputType<0>(
      kDefaultInputType, kDefaultInputMode,
      ZCR_EXTENDED_TEXT_INPUT_V1_INPUT_FLAGS_AUTOCAPITALIZE_WORDS,
      kDefaultLearningMode, kDefaultInlineCompositionSupport);
  Expect<0>(Request::kShowInputPanel);
  SendCommitString<0>("c");

  ExpectSetInputType<1>(
      kDefaultInputType, kDefaultInputMode,
      ZCR_EXTENDED_TEXT_INPUT_V1_INPUT_FLAGS_AUTOCAPITALIZE_SENTENCES,
      kDefaultLearningMode, kDefaultInlineCompositionSupport);
  Expect<1>(Request::kShowInputPanel);
  SendCommitString<1>("d");

  ExpectSetInputType<0>(kDefaultInputType,
                        ZCR_EXTENDED_TEXT_INPUT_V1_INPUT_MODE_NONE,
                        kDefaultInputFlags, kDefaultLearningMode,
                        kDefaultInlineCompositionSupport);
  // No call to ShowInputPanel
  SendCommitString<0>("e");
}

BACKEND_TEST(GtkContentTypeTest, ContentPurpose) {
  ExpectCreateTextInput<0>();
  Ignore<0>(Request::kActivate);
  Ignore<0>(Request::kDeactivate);
  Ignore<0>(Request::kReset);
  Unignore<0>(Request::kSetInputType);

  // INPUT_PURPOSE_ALPHA
  ExpectSetInputType<0>(kDefaultInputType, kDefaultInputMode,
                        kDefaultInputFlags, kDefaultLearningMode,
                        kDefaultInlineCompositionSupport);
  SendCommitString<0>("a");

  ExpectCreateTextInput<1>();
  Ignore<1>(Request::kActivate);
  Ignore<1>(Request::kDeactivate);
  Ignore<1>(Request::kReset);
  Unignore<1>(Request::kSetInputType);

  // INPUT_PURPOSE_DIGITS
  ExpectSetInputType<1>(ZCR_EXTENDED_TEXT_INPUT_V1_INPUT_TYPE_NUMBER,
                        ZCR_EXTENDED_TEXT_INPUT_V1_INPUT_MODE_NUMERIC,
                        kDefaultInputFlags, kDefaultLearningMode,
                        kDefaultInlineCompositionSupport);
  SendCommitString<1>("1");

  // INPUT_PURPOSE_EMAIL
  ExpectSetInputType<0>(ZCR_EXTENDED_TEXT_INPUT_V1_INPUT_TYPE_EMAIL,
                        ZCR_EXTENDED_TEXT_INPUT_V1_INPUT_MODE_EMAIL,
                        kDefaultInputFlags, kDefaultLearningMode,
                        kDefaultInlineCompositionSupport);
  SendCommitString<0>("c");

  // INPUT_PURPOSE_PIN
  ExpectSetInputType<1>(ZCR_EXTENDED_TEXT_INPUT_V1_INPUT_TYPE_NUMBER,
                        ZCR_EXTENDED_TEXT_INPUT_V1_INPUT_MODE_NUMERIC,
                        kDefaultInputFlags,
                        ZCR_EXTENDED_TEXT_INPUT_V1_LEARNING_MODE_DISABLED,
                        kDefaultInlineCompositionSupport);
  SendCommitString<1>("0");

  // INPUT_PURPOSE_PASSWORD
  ExpectSetInputType<0>(ZCR_EXTENDED_TEXT_INPUT_V1_INPUT_TYPE_PASSWORD,
                        kDefaultInputMode, kDefaultInputFlags,
                        ZCR_EXTENDED_TEXT_INPUT_V1_LEARNING_MODE_DISABLED,
                        kDefaultInlineCompositionSupport);
  SendCommitString<0>("e");
}

}  // namespace test
}  // namespace cros_im
