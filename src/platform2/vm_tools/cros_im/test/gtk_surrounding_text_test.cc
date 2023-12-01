// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "test/gtk_test_base.h"

#ifdef DISABLE_SURROUNDING

namespace cros_im {
namespace test {

namespace {

using GtkSetSurroundingTextTest = GtkSimpleTextViewTest;
using GtkDeleteSurroundingTextTest = GtkSimpleTextViewTest;

}  // namespace

// RunUntilIdle() is used in these tests to force set_surrounding_text to be
// sent, rather than immediately going to the next step / exiting.

TEST_F(GtkSetSurroundingTextTest, BasicTextInput) {
  RunAndExpectTextChangeTo("a");
  RunAndExpectTextChangeTo("abc");
  RunAndExpectTextChangeTo("abcあ");
  RunAndExpectTextChangeTo("abcあz");
  RunUntilIdle();
}

TEST_F(GtkSetSurroundingTextTest, CursorMovement) {
  RunAndExpectTextChangeTo("piñata");
  RunUntilIdle();

  MoveCursor(3);
  MoveCursor(2);
  MoveCursor(0);
  MoveCursor(5);
}

TEST_F(GtkSetSurroundingTextTest, MultiLine) {
  RunAndExpectTextChangeTo("line 1\nline 2\nline 3");
  RunUntilIdle();

  MoveCursor(5);
  MoveCursor(7);
  MoveCursor(0);
  MoveCursor(17);
}

TEST_F(GtkSetSurroundingTextTest, DirectTextChanges) {
  RunUntilFocused();
  SetText("smart");
  RunUntilIdle();
  SetText("trams");
  RunUntilIdle();
  SetText("soufflé");
  RunUntilIdle();
}

TEST_F(GtkDeleteSurroundingTextTest, Basic) {
  RunAndExpectTextChangeTo("hello");
  RunAndExpectTextChangeTo("hell");
  RunAndExpectTextChangeTo("he");
  RunAndExpectTextChangeTo("hey");
  RunAndExpectTextChangeTo("");
  RunUntilIdle();
}

TEST_F(GtkDeleteSurroundingTextTest, NonAscii) {
  RunAndExpectTextChangeTo("三角バラ");
  RunUntilIdle();
  MoveCursor(2);
  RunAndExpectTextChangeTo("三角ラ");
  RunAndExpectTextChangeTo("");
  RunUntilIdle();
}

}  // namespace test
}  // namespace cros_im

#endif  // DISABLE_SURROUNDING
