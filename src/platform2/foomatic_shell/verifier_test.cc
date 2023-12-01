// Copyright 2022 The ChromiumOS Authors.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "foomatic_shell/parser.h"
#include "foomatic_shell/scanner.h"
#include "foomatic_shell/verifier.h"
#include <gtest/gtest.h>
#include <string>
#include <utility>

namespace foomatic_shell {

bool VerifyScript(const std::string& command) {
  Script script;
  std::vector<Token> tokens;

  Scanner scanner(command);
  if (!scanner.ParseWholeInput(&tokens))
    return false;
  Parser parser(std::move(tokens));
  if (!parser.ParseWholeInput(&script))
    return false;

  Verifier verifier;
  return verifier.VerifyScript(&script);
}

TEST(Verifier, cat) {
  EXPECT_TRUE(VerifyScript("cat"));
}

TEST(Verifier, cat2) {
  EXPECT_TRUE(VerifyScript("cat -"));
}

TEST(Verifier, catFail) {
  EXPECT_FALSE(VerifyScript("cat somefile"));
}

TEST(Verifier, cut) {
  EXPECT_TRUE(VerifyScript("cut -b 1-"));
}

TEST(Verifier, date) {
  EXPECT_TRUE(VerifyScript("date"));
}

TEST(Verifier, dateFail) {
  EXPECT_FALSE(VerifyScript("date -s"));
}

TEST(Verifier, dateFail2) {
  EXPECT_FALSE(VerifyScript("date --set"));
}

TEST(Verifier, echo) {
  EXPECT_TRUE(VerifyScript("echo something"));
}

TEST(Verifier, gs) {
  EXPECT_TRUE(VerifyScript("gs -dSAFER -sOutputFile=- somefile.ps"));
}

TEST(Verifier, gsFail) {
  EXPECT_FALSE(VerifyScript("gs -dSAFER -sOutputFile=- -dNOSAFER somefile.ps"));
}

TEST(Verifier, gsFail2) {
  EXPECT_FALSE(VerifyScript("gs -dSAFER -sOutputFile=- -dALLOWPSTRANSPARENCY"));
}

TEST(Verifier, gsFail3) {
  EXPECT_FALSE(VerifyScript("gs -dSAFER -sOutputFile=xyz.out somefile.ps"));
}

TEST(Verifier, gsFail4) {
  EXPECT_FALSE(VerifyScript("gs -dSAFER somefile.ps"));
}

TEST(Verifier, gsFail5) {
  EXPECT_FALSE(VerifyScript("gs -sOutputFile=- somefile.ps"));
}

TEST(Verifier, pdftops) {
  EXPECT_TRUE(VerifyScript("pdftops"));
}

TEST(Verifier, printf) {
  EXPECT_TRUE(VerifyScript("printf"));
}

TEST(Verifier, sed) {
  EXPECT_TRUE(VerifyScript("sed 's/foo/bar/' somefile"));
}

TEST(Verifier, sedFail) {
  EXPECT_FALSE(VerifyScript("sed -ui 's/foo/bar/' somefile"));
}

TEST(Verifier, sedFail2) {
  EXPECT_FALSE(VerifyScript("sed --in-place 's/foo/bar/' somefile"));
}

TEST(Verifier, disallowedCommand) {
  EXPECT_FALSE(VerifyScript("rm"));
}

}  // namespace foomatic_shell
