// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef FOOMATIC_SHELL_VERIFIER_H_
#define FOOMATIC_SHELL_VERIFIER_H_

#include <string>
#include <vector>

#include "foomatic_shell/grammar.h"

namespace foomatic_shell {

// A simple class used to verify given script. All commands in the script
// must be on the list of allowed commands. All variables used in the script
// must be on the list of allowed variables. Moreover, each allowed command has
// specific requirements that must be met.
class Verifier {
 public:
  // Verifies given Script. |script| must be not nullptr. Returns false in
  // the case of failure. |script| may be modified by the method (e.g. a
  // parameter "--sandbox" is added to every invocation of "sed" command).
  bool VerifyScript(Script* script, int recursion_level = 0);

  // It is used to report a position of the error when the method
  // VerifyScript(...) fails.
  std::string::const_iterator GetPosition() const { return position_; }

  // Returns an error message from the last call of VerifyScript(...).
  // Returns an empty string if the call succeeded.
  const std::string& GetMessage() const { return message_; }

 private:
  // Verifies given Command. |command| must be not nullptr.
  bool VerifyCommand(Command* command);
  // Verifies parameters of "gs" command.
  bool VerifyGs(const std::vector<StringAtom>& parameters);

  // Internal field holding an error message from the last call of
  // VerifyScript(...).
  std::string message_;
  // Internal field holding a position where the last error occurred.
  std::string::const_iterator position_;
};

}  // namespace foomatic_shell

#endif  // FOOMATIC_SHELL_VERIFIER_H_
