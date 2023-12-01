// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef FOOMATIC_SHELL_SCANNER_H_
#define FOOMATIC_SHELL_SCANNER_H_

#include "foomatic_shell/grammar.h"

#include <memory>
#include <string>
#include <vector>

namespace foomatic_shell {

// Converts a script into a sequences of Tokens.  See the struct Token defined
// in grammar.h.
class Scanner {
 public:
  // Constructor. |data| is a reference to the input buffer. The input buffer
  // must be constant and valid during the lifetime of this object.
  explicit Scanner(const std::string& data);

  ~Scanner();
  Scanner(const Scanner&) = delete;
  Scanner(Scanner&&) = delete;

  // Parses the input given in the constructor and stores the resultant
  // sequence in |tokens|. Returns true when succeed. Otherwise it stops
  // on the first error and returns false. |tokens| must not be nullptr.
  bool ParseWholeInput(std::vector<Token>* tokens);

  // Returns the current position of the scanner as an iterator of the string
  // given in the constructor. It is used to report a position of the error
  // when the method ParseWholeInput(...) fails.
  std::string::const_iterator GetPosition() const;

  // Returns an error message if the call ParseWholeInput(...) failed.
  // Returns an empty string if the call succeeded.
  const std::string& GetMessage() const { return message_; }

 private:
  bool ParseLiteralString(std::vector<Token>* tokens);
  bool ParseExecutedString(std::vector<Token>* tokens);
  bool ParseInterpretedString(std::vector<Token>* tokens);
  bool ParseNativeString(std::vector<Token>* tokens);
  class Input;
  std::unique_ptr<Input> data_;
  std::string message_;
};

}  // namespace foomatic_shell

#endif  // FOOMATIC_SHELL_SCANNER_H_
