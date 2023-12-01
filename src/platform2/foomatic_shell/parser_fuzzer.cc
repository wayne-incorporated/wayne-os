// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "foomatic_shell/grammar.h"
#include "foomatic_shell/parser.h"
#include "foomatic_shell/scanner.h"

#include <cstdint>
#include <string>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  const std::string input(reinterpret_cast<const char*>(data), size);

  foomatic_shell::Scanner scanner(input);
  std::vector<foomatic_shell::Token> tokens;
  if (!scanner.ParseWholeInput(&tokens)) {
    // The input is not correct. However, we still want to feed a parser with
    // produced tokens. The EOF token must be added at the end to mimic a
    // correct sequence of tokens.
    foomatic_shell::Token eof;
    eof.type = foomatic_shell::Token::Type::kEOF;
    eof.begin = eof.end = input.end();
    tokens.push_back(eof);
  }

  foomatic_shell::Parser parser(tokens);
  foomatic_shell::Script script;
  parser.ParseWholeInput(&script);

  return 0;
}
