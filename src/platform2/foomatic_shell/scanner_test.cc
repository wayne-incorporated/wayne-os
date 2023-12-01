// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "foomatic_shell/grammar.h"
#include "foomatic_shell/scanner.h"

#include <gtest/gtest.h>
#include <string>
#include <vector>

namespace foomatic_shell {

namespace {

// This function takes the input script as |input| and a sequence of tokens
// produced by a scanner (|tokens|). It generates and returns the string
// representation of the generated tokens. The returned string has the same
// length as |input|. The corresponding characters are set depending on the
// type of token covering given range according to the following rules:
// - 'B' - Byte
// - 'E' - ExecutedString
// - 'I' - InterpretedString
// - 'L' - LiteralString
// - 'S' - Space
// Positions that do not belong to any token are set to spaces.
// Example:
//   - input string  : abcde'rft'  "dsfds"; `aaa` | bbb
//   - representation: NNNNN LLL SS IIIII BS EEE SBSNNN
//
// The returned representation is calculated from |tokens|, not from |input|.
// The |input| string must be a reference to the same string as given to the
// scanner that produced |tokens|.
std::string CreateTokensRepresentation(const std::string& input,
                                       const std::vector<Token>& tokens) {
  std::string out(input.size(), ' ');
  for (const Token& token : tokens) {
    char c = 'x';
    switch (token.type) {
      case Token::Type::kByte:
        c = 'B';
        break;
      case Token::Type::kExecutedString:
        c = 'E';
        break;
      case Token::Type::kInterpretedString:
        c = 'I';
        break;
      case Token::Type::kLiteralString:
        c = 'L';
        break;
      case Token::Type::kNativeString:
        c = 'N';
        break;
      case Token::Type::kSpace:
        c = 'S';
        break;
      default:
        break;
    }
    const size_t begin = token.begin - input.begin();
    const size_t end = token.end - input.begin();
    for (size_t i = begin; i < end; ++i)
      out[i] = c;
  }
  return out;
}

TEST(Scanner, StringTypes) {
  const std::string input = "command 'lit str' `exe str`  \"int str\" nat str";
  const std::string types = "NNNNNNNS LLLLLLL S EEEEEEE SS IIIIIII SNNNSNNN";
  Scanner scanner(input);
  std::vector<Token> tokens;
  EXPECT_TRUE(scanner.ParseWholeInput(&tokens));
  EXPECT_EQ(types, CreateTokensRepresentation(input, tokens));
}

TEST(Scanner, ExecutedStringInsideInterpretedString) {
  const std::string input = "command \"int str1`exe str`int str2\"  ";
  const std::string types = "NNNNNNNS IIIIIIII EEEEEEE IIIIIIII SS";
  Scanner scanner(input);
  std::vector<Token> tokens;
  EXPECT_TRUE(scanner.ParseWholeInput(&tokens));
  EXPECT_EQ(types, CreateTokensRepresentation(input, tokens));
}

TEST(Scanner, UnterminatedLiteralString) {
  const std::string input = "command 'int str1`exe str`int s";
  Scanner scanner(input);
  std::vector<Token> tokens;
  EXPECT_FALSE(scanner.ParseWholeInput(&tokens));
  EXPECT_EQ(scanner.GetPosition(), input.end());
}

TEST(Scanner, UnterminatedInterpretedString) {
  const std::string input = "command \"int str1`exe str`int s";
  Scanner scanner(input);
  std::vector<Token> tokens;
  EXPECT_FALSE(scanner.ParseWholeInput(&tokens));
  EXPECT_EQ(scanner.GetPosition(), input.end());
}

TEST(Scanner, UnterminatedExecutedString) {
  const std::string input = "command 'int str1' `exe str";
  Scanner scanner(input);
  std::vector<Token> tokens;
  EXPECT_FALSE(scanner.ParseWholeInput(&tokens));
  EXPECT_EQ(scanner.GetPosition(), input.end());
}

TEST(Scanner, CommandWithParameters) {
  const std::string input =
      "pdftops '9195' 'root' 'split_streams.pdf' '1' "
      "' finishings=3 number-up=1 document=split.pdf' '/cups/tmp/foo-B65TL1'";
  const std::string types =
      "NNNNNNNS LLLL S LLLL S LLLLLLLLLLLLLLLLL S L S"
      " LLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLL S LLLLLLLLLLLLLLLLLLLL ";
  std::vector<Token> tokens;
  Scanner scanner(input);
  EXPECT_TRUE(scanner.ParseWholeInput(&tokens));
  EXPECT_EQ(types, CreateTokensRepresentation(input, tokens));
}

TEST(Scanner, Pipeline) {
  const std::string input = "ls -h | grep 'XXX' | wc -l; echo \"Done\"; ";
  const std::string types = "NNSNNSBSNNNNS LLL SBSNNSNNBSNNNNS IIII BS";
  std::vector<Token> tokens;
  Scanner scanner(input);
  EXPECT_TRUE(scanner.ParseWholeInput(&tokens));
  EXPECT_EQ(types, CreateTokensRepresentation(input, tokens));
}

TEST(Scanner, Subshell) {
  const std::string input =
      "VAR1='xx' VAR=acs'zzz'qq  my_app  -par1 par2'qqq'"
      " ; (echo ttt | tr t T; echo Done) | cat myfile.txt";
  const std::string types =
      "NNNNB LL SNNNBNNN LLL NNSSNNNNNNSSNNNNNSNNNN LLL "
      "SBSBNNNNSNNNSBSNNSNSNBSNNNNSNNNNBSBSNNNSNNNNNNNNNN";
  std::vector<Token> tokens;
  Scanner scanner(input);
  EXPECT_TRUE(scanner.ParseWholeInput(&tokens));
  EXPECT_EQ(types, CreateTokensRepresentation(input, tokens));
}

}  // namespace

}  // namespace foomatic_shell
