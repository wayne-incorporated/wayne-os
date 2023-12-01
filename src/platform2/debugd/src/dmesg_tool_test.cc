// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "debugd/src/dmesg_tool.h"

#include <string>

#include <base/strings/string_piece.h>
#include <base/strings/string_util.h>
#include <gtest/gtest.h>

namespace debugd {

namespace {
// A simple function to replace newlines with the actual two character sequence
// \ and n. Makes error messages easier to read.
std::string EscapeNewlines(base::StringPiece str) {
  std::string result;
  base::ReplaceChars(str, "\n", "\\n", &result);
  return result;
}
}  // namespace

TEST(DmesgToolTests, Tail) {
  const std::string kInput = "line 1\nline 2\nline 3\nline 4\nand line 5\n";
  const std::string kInputNoEndingNewline =
      "line 1\nline 2\nline 3\nline 4\nand line 5";
  const std::string kInputBlankLastLine =
      "line 1\nline 2\nline 3\nline 4\nand line 5\n\n";
  const std::string kInputBlankFourthLine =
      "line 1\nline 2\nline 3\n\nand line 5\n";
  const std::string kInputBlankFirstLine =
      "\nline 2\nline 3\nline 4\nand line 5\n";
  struct Test {
    std::string input_string;
    int lines;
    std::string expected;
  };

  const Test kTests[] = {
      // Tests where the string has fewer lines than |lines|.
      {kInput, 10, kInput},
      {kInputNoEndingNewline, 10, kInputNoEndingNewline},
      {kInputBlankLastLine, 10, kInputBlankLastLine},
      {kInputBlankFourthLine, 10, kInputBlankFourthLine},
      {kInputBlankFirstLine, 10, kInputBlankFirstLine},

      // Tests where the string has more lines than |lines|.
      {kInput, 2, "line 4\nand line 5\n"},
      {kInputNoEndingNewline, 2, "line 4\nand line 5"},
      {kInputBlankLastLine, 3, "line 4\nand line 5\n\n"},
      {kInputBlankFourthLine, 2, "\nand line 5\n"},
      {kInputBlankFirstLine, 2, "line 4\nand line 5\n"},
      // First line of returned input is blank:
      {"line 1\nline 2\n\nline 4\nand line 5\n", 3, "\nline 4\nand line 5\n"},
      {"line 1\nline 2\n\nline 4\nand line 5", 3, "\nline 4\nand line 5"},

      // Tests where the string has exactly |lines| lines.
      {kInput, 5, kInput},
      {kInputNoEndingNewline, 5, kInputNoEndingNewline},
      {kInputBlankLastLine, 6, kInputBlankLastLine},
      {kInputBlankFourthLine, 5, kInputBlankFourthLine},
      {kInputBlankFirstLine, 5, kInputBlankFirstLine},

      // Tests where the string has exactly |lines| - 1 lines.
      {kInput, 6, kInput},
      {kInputNoEndingNewline, 6, kInputNoEndingNewline},
      {kInputBlankLastLine, 7, kInputBlankLastLine},
      {kInputBlankFourthLine, 6, kInputBlankFourthLine},
      {kInputBlankFirstLine, 6, kInputBlankFirstLine},

      // Tests where the string has exactly |lines| + 1 lines.
      {kInput, 4, "line 2\nline 3\nline 4\nand line 5\n"},
      {kInputNoEndingNewline, 4, "line 2\nline 3\nline 4\nand line 5"},
      {kInputBlankLastLine, 5, "line 2\nline 3\nline 4\nand line 5\n\n"},
      {kInputBlankFourthLine, 4, "line 2\nline 3\n\nand line 5\n"},
      {kInputBlankFirstLine, 4, "line 2\nline 3\nline 4\nand line 5\n"},

      // Just a blank string.
      {"\n", 10, "\n"},
      {"", 10, ""},
  };

  for (const Test& test : kTests) {
    std::string str = test.input_string;
    DmesgTool::Tail(test.lines, str);
    EXPECT_EQ(test.expected, str)
        << " after getting last " << test.lines << " lines of '"
        << EscapeNewlines(test.input_string) << "'";
  }
}

}  // namespace debugd
