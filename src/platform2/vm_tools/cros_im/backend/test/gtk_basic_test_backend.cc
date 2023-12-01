// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "backend/test/backend_test.h"

namespace cros_im {
namespace test {

// These tests exist to verify the requests sent in basic cases. There is no
// 'correct' sequence of requests, as Chrome may handle different sequences
// identically. This file documents the current behaviour and ensures changes
// to it are noticed.

BACKEND_TEST(GtkBasicTest, TextViewShownImmediately) {
  Expect(Request::kCreateTextInput);

  Expect(Request::kSetCursorRectangle);
  ExpectSetSurroundingText("", 0, 0);
  Expect(Request::kActivate);
  ExpectSetSurroundingTextSupport(
      ZCR_EXTENDED_TEXT_INPUT_V1_SURROUNDING_TEXT_SUPPORT_UNSUPPORTED);
  ExpectSetInputType(
      ZCR_EXTENDED_TEXT_INPUT_V1_INPUT_TYPE_TEXT,
      ZCR_EXTENDED_TEXT_INPUT_V1_INPUT_MODE_DEFAULT,
      ZCR_EXTENDED_TEXT_INPUT_V1_INPUT_FLAGS_NONE,
      ZCR_EXTENDED_TEXT_INPUT_V1_LEARNING_MODE_ENABLED,
      ZCR_EXTENDED_TEXT_INPUT_V1_INLINE_COMPOSITION_SUPPORT_SUPPORTED);
  Expect(Request::kShowInputPanel);

  ExpectSetSurroundingText("", 0, 0);
  Expect(Request::kHideInputPanel);
  Expect(Request::kDeactivate);
  Expect(Request::kExtensionDestroy);
  Expect(Request::kDestroy);
}

BACKEND_TEST(GtkBasicTest, SwitchFocus) {
  Expect<0>(Request::kCreateTextInput);

  Expect<0>(Request::kSetCursorRectangle);
  ExpectSetSurroundingText<0>("", 0, 0);
  Expect<0>(Request::kActivate);
  ExpectSetSurroundingTextSupport<0>(
      ZCR_EXTENDED_TEXT_INPUT_V1_SURROUNDING_TEXT_SUPPORT_UNSUPPORTED);
  ExpectSetInputType<0>(
      ZCR_EXTENDED_TEXT_INPUT_V1_INPUT_TYPE_TEXT,
      ZCR_EXTENDED_TEXT_INPUT_V1_INPUT_MODE_DEFAULT,
      ZCR_EXTENDED_TEXT_INPUT_V1_INPUT_FLAGS_NONE,
      ZCR_EXTENDED_TEXT_INPUT_V1_LEARNING_MODE_ENABLED,
      ZCR_EXTENDED_TEXT_INPUT_V1_INLINE_COMPOSITION_SUPPORT_SUPPORTED);
  Expect<0>(Request::kShowInputPanel);
  ExpectSetSurroundingText<0>("", 0, 0);

  Expect<0>(Request::kSetCursorRectangle);
  ExpectSetSurroundingText<0>("", 0, 0);

  Expect<1>(Request::kCreateTextInput);
  Expect<1>(Request::kSetCursorRectangle);
  ExpectSetSurroundingText<1>("", 0, 0);

  Expect<0>(Request::kHideInputPanel);
  Expect<0>(Request::kDeactivate);

  Expect<1>(Request::kActivate);
  ExpectSetSurroundingTextSupport<1>(
      ZCR_EXTENDED_TEXT_INPUT_V1_SURROUNDING_TEXT_SUPPORT_UNSUPPORTED);
  ExpectSetInputType<1>(
      ZCR_EXTENDED_TEXT_INPUT_V1_INPUT_TYPE_TEXT,
      ZCR_EXTENDED_TEXT_INPUT_V1_INPUT_MODE_DEFAULT,
      ZCR_EXTENDED_TEXT_INPUT_V1_INPUT_FLAGS_NONE,
      ZCR_EXTENDED_TEXT_INPUT_V1_LEARNING_MODE_ENABLED,
      ZCR_EXTENDED_TEXT_INPUT_V1_INLINE_COMPOSITION_SUPPORT_SUPPORTED);
  Expect<1>(Request::kShowInputPanel);
  ExpectSetSurroundingText<1>("", 0, 0);

  Expect<0>(Request::kSetCursorRectangle);
  ExpectSetSurroundingText<0>("", 0, 0);

  Expect<1>(Request::kSetCursorRectangle);
  ExpectSetSurroundingText<1>("", 0, 0);

  Expect<1>(Request::kHideInputPanel);
  Expect<1>(Request::kDeactivate);
  Expect<1>(Request::kExtensionDestroy);
  Expect<1>(Request::kDestroy);

  Expect<0>(Request::kExtensionDestroy);
  Expect<0>(Request::kDestroy);
}

}  // namespace test
}  // namespace cros_im
