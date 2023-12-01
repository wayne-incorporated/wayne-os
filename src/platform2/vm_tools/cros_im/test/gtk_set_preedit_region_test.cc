// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "test/gtk_test_base.h"

#ifdef DISABLE_SURROUNDING

namespace cros_im {
namespace test {

namespace {

using GtkSetPreeditRegionTest = GtkSimpleTextViewTest;

}  // namespace

TEST_F(GtkSetPreeditRegionTest, AsciiLeft) {
  RunAndExpectTextChangeTo("a");

  RunAndExpectPreeditChangeTo("a");
  ExpectTextIs("");
  RunAndExpectTextChangeTo("cat fish dog");

  RunAndExpectPreeditChangeTo("og");
  ExpectTextIs("cat fish d");
  RunAndExpectTextChangeTo("cat fish deer");

  MoveCursor(8);
  RunAndExpectPreeditChangeTo("fish");
  ExpectTextIs("cat  deer");
  RunAndExpectTextChangeTo("cat cow deer");

  MoveCursor(3);
  RunAndExpectPreeditChangeTo("cat");
  ExpectTextIs(" cow deer");
}

TEST_F(GtkSetPreeditRegionTest, AsciiRight) {
  RunAndExpectTextChangeTo("rabbit");

  MoveCursor(0);
  RunAndExpectPreeditChangeTo("rabbit");
  ExpectTextIs("");
  RunAndExpectTextChangeTo("cow");

  MoveCursor(0);
  RunAndExpectPreeditChangeTo("c");
  ExpectTextIs("ow");
  RunAndExpectTextChangeTo("oh wow");

  RunAndExpectPreeditChangeTo("ow");
  ExpectTextIs("oh w");
  RunAndExpectTextChangeTo("oh what");
}

TEST_F(GtkSetPreeditRegionTest, AsciiContains) {
  RunAndExpectTextChangeTo("fire");

  MoveCursor(3);
  RunAndExpectPreeditChangeTo("fire");
  ExpectTextIs("");
  RunAndExpectTextChangeTo("Fire os hot");

  MoveCursor(6);
  RunAndExpectPreeditChangeTo("os");
  ExpectTextIs("Fire  hot");
  RunAndExpectTextChangeTo("Fire is hot");
}

TEST_F(GtkSetPreeditRegionTest, NonAscii) {
  RunAndExpectTextChangeTo("aä");

  RunAndExpectPreeditChangeTo("aä");
  ExpectTextIs("");
  RunAndExpectTextChangeTo("π*廿");

  MoveCursor(0);
  RunAndExpectPreeditChangeTo("π*");
  ExpectTextIs("廿");
  RunAndExpectTextChangeTo("±𝛑廿");

  RunAndExpectPreeditChangeTo("𝛑廿");
  ExpectTextIs("±");
  RunAndExpectTextChangeTo("±!");
}

TEST_F(GtkSetPreeditRegionTest, Invalid) {
  RunAndExpectTextChangeTo("あiうé😮");
  MoveCursor(2);

  RunAndExpectPreeditChangeTo("iう");
  ExpectTextIs("あé😮");

  RunAndExpectTextChangeTo("あqé😮");
}

}  // namespace test
}  // namespace cros_im

#endif  // DISABLE_SURROUNDING
