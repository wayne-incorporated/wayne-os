// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "test/gtk_test_base.h"

namespace cros_im {
namespace test {

namespace {

using GtkCommitStringTest = GtkSimpleTextViewTest;

}  // namespace

TEST_F(GtkCommitStringTest, SingleCharacters) {
  RunAndExpectTextChangeTo("c");
  RunAndExpectTextChangeTo("co");
  RunAndExpectTextChangeTo("coo");
  RunAndExpectTextChangeTo("cool");
  RunAndExpectTextChangeTo("cool!");
  RunAndExpectTextChangeTo("cool!\n");
}

TEST_F(GtkCommitStringTest, LongStrings) {
  std::string expectation = "hello world!\n";
  RunAndExpectTextChangeTo(expectation);

  expectation += "committing a long string all at once!\n";
  RunAndExpectTextChangeTo(expectation);

  expectation += "string string string! :)\n";
  RunAndExpectTextChangeTo(expectation);
}

}  // namespace test
}  // namespace cros_im
