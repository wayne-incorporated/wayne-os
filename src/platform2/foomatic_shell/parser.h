// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef FOOMATIC_SHELL_PARSER_H_
#define FOOMATIC_SHELL_PARSER_H_

#include <memory>
#include <string>
#include <vector>

#include "foomatic_shell/grammar.h"

namespace foomatic_shell {

// This class is responsible for converting a sequence of tokens into a Script
// structure (see grammar.h for details).
class Parser {
 public:
  // Constructor. |tokens| is a reference to the input sequence of tokens.
  // |tokens| must be constant and valid during the lifetime of the object.
  explicit Parser(const std::vector<Token>& tokens);

  ~Parser();
  Parser(const Parser&) = delete;
  Parser(Parser&&) = delete;

  // Parses the sequence of tokens given in the constructor and saves the
  // resultant tree in |out|. |out| must point to the empty Script structure.
  // Returns false in case of an error. The parsing stops on the first error.
  bool ParseWholeInput(Script* out);

  // Returns the begin iterator from the current token. It is used to report
  // a position of an error when the method ParseWholeInput(...) fails.
  std::string::const_iterator GetPosition() const;

  // Returns an error message if the call ParseWholeInput(...) failed.
  // Returns an empty string if the call succeeded.
  const std::string& GetMessage() const { return message_; }

 private:
  bool ParseScript(Script* out);
  bool ParseScriptImpl(Script* out);
  bool ParsePipeline(Pipeline* out);
  bool ParsePipeSegment(PipeSegment* out);
  bool ParseCommand(Command* out);
  void ParseString(StringAtom* out);
  class InputTokens;
  std::unique_ptr<InputTokens> tokens_;
  std::string message_;
  // This counter tracks a level of recursive calls to ParseScript(...).
  int script_recursion_level_ = 0;
};

}  // namespace foomatic_shell

#endif  // FOOMATIC_SHELL_PARSER_H_
