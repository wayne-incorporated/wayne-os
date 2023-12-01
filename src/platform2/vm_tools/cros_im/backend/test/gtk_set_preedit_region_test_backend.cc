// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "backend/test/backend_test.h"

#ifdef DISABLE_SURROUNDING

namespace cros_im {
namespace test {

// TODO(timloh): Update these tests to use the cursor_position API once that is
// implemented.

BACKEND_TEST(GtkSetPreeditRegionTest, AsciiLeft) {
  ExpectCreateTextInput();
  // Tests for SetPreeditRegion where the region is to the left of the cursor.

  Expect(Request::kActivate);

  SendCommitString("a");

  SendSetPreeditRegion(-1, 1);
  SendCommitString("cat fish dog");

  SendSetPreeditRegion(-2, 2);
  SendCommitString("eer");

  // Front-end moves cursor to "cat fish| deer"
  // Moving the cursor causes a reset in gtk_text_view_mark_set_handler(), but
  // only the first time apparently.
  Expect(Request::kReset);
  SendSetPreeditRegion(-4, 4);
  SendCommitString("cow");

  // Front-end moves cursor to "cat| cow deer"
  SendSetPreeditRegion(-3, 3);

  Expect(Request::kDeactivate);
}

BACKEND_TEST(GtkSetPreeditRegionTest, AsciiRight) {
  ExpectCreateTextInput();
  // Tests for SetPreeditRegion where the region is to the right of the cursor.

  Expect(Request::kActivate);

  SendCommitString("rabbit");

  // Front-end moves cursor to "|rabbit"
  Expect(Request::kReset);
  SendSetPreeditRegion(0, 6);
  SendCommitString("cow");

  // Front-end moves cursor to "|cow"
  SendSetPreeditRegion(0, 1);
  SendCommitString("oh w");

  SendSetPreeditRegion(0, 2);
  SendCommitString("hat");

  Expect(Request::kDeactivate);
}

BACKEND_TEST(GtkSetPreeditRegionTest, AsciiContains) {
  ExpectCreateTextInput();
  // Tests for SetPreeditRegion where the region contains the cursor.

  Expect(Request::kActivate);

  SendCommitString("fire");
  // Front-end moves cursor to "fir|e"
  Expect(Request::kReset);
  SendSetPreeditRegion(-3, 4);
  SendCommitString("Fire os hot");

  // Front-end moves cursor to "Fire o|s hot"
  SendSetPreeditRegion(-1, 2);
  SendCommitString("is");

  Expect(Request::kDeactivate);
}

BACKEND_TEST(GtkSetPreeditRegionTest, NonAscii) {
  ExpectCreateTextInput();
  // Tests for SetPreeditRegion with non-ascii characters.

  Expect(Request::kActivate);

  // Under UTF-8, ä is 2 bytes.
  SendCommitString("aä");
  SendSetPreeditRegion(-3, 3);

  // Characters are 2, 1, 3 bytes respectively. Front-end moves cursor to the
  // start.
  SendCommitString("π*廿");
  Expect(Request::kReset);
  SendSetPreeditRegion(0, 3);
  // Characters are 2 and 4 bytes respectively.
  SendCommitString("±𝛑");

  SendSetPreeditRegion(-4, 7);
  SendCommitString("!");

  Expect(Request::kDeactivate);
}

BACKEND_TEST(GtkSetPreeditRegionTest, Invalid) {
  ExpectCreateTextInput();
  // Tests for SetPreeditRegion with invalid inputs.

  Expect(Request::kActivate);

  // UTF-8 byte lengths are 3, 1, 3, 2, 4.
  SendCommitString("あiうé😮");
  // Front-end moves cursor to "あi|うé😮"
  Expect(Request::kReset);

  // Regions must include or border the cursor.
  SendSetPreeditRegion(-1, 0);
  SendSetPreeditRegion(-4, 3);
  SendSetPreeditRegion(3, 2);

  // Region must not exceed the surrounding text.
  SendSetPreeditRegion(-5, 5);
  SendSetPreeditRegion(-10, 10);
  SendSetPreeditRegion(-1, 8);
  SendSetPreeditRegion(0, 7);

  // Regions can not break up multi-byte characters.
  SendSetPreeditRegion(-4, 5);
  SendSetPreeditRegion(-3, 3);
  SendSetPreeditRegion(-2, 2);
  SendSetPreeditRegion(-1, 2);
  SendSetPreeditRegion(-1, 3);
  SendSetPreeditRegion(-1, 5);
  SendSetPreeditRegion(-1, 7);
  SendSetPreeditRegion(0, 1);
  SendSetPreeditRegion(0, 2);
  SendSetPreeditRegion(0, 7);
  SendSetPreeditRegion(0, 8);

  // There must not be any preedit text present.
  SendSetPreeditRegion(-1, 4);
  SendSetPreeditRegion(-1, 1);
  SendSetPreeditRegion(-3, 3);

  // Signal to front-end to finish the test.
  SendCommitString("q");

  Expect(Request::kDeactivate);
}

}  // namespace test
}  // namespace cros_im

#endif  // DISABLE_SURROUNDING
