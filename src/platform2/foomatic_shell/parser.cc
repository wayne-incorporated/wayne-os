// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "foomatic_shell/parser.h"

#include <string>
#include <vector>

#include <base/check.h>
#include <base/logging.h>

namespace foomatic_shell {

namespace {

// Returns true if |token| may be a prefix of PipeSegment.
// Corresponding grammar rules:
//  Command = {Variable,"=",StringAtom,Space}, Application, {Space,Parameter} ;
//  Variable = NativeString ;
//  Application = NativeString ;
//  Parameter = StringAtom ;
bool MatchAPrefixOfPipeSegment(const Token& token) {
  // Check if the token may be a prefix of: "(", Script, ")"
  if (token.type == Token::kByte && *token.begin == '(')
    return true;
  // Check if the token may be a prefix of a Command.
  if (token.type == Token::kNativeString)
    return true;
  // It cannot be a PipeSegment.
  return false;
}

}  // namespace

// This class encapsulates an iterator representing the current position
// (token) in the input sequence.
class Parser::InputTokens {
 public:
  // Constructor. |tokens| is a reference to the input sequence. The input
  // sequence must remain constant and valid during the lifetime of the object.
  // The current position is set to the first element in the |tokens|. The last
  // token in the sequence must be of type EOF.
  explicit InputTokens(const std::vector<Token>& tokens)
      : tokens_(tokens), current_(tokens_.begin()) {
    DCHECK(!tokens.empty());
    DCHECK(tokens.back().type == Token::Type::kEOF);
  }

  InputTokens(const InputTokens&) = delete;
  InputTokens(InputTokens&&) = delete;

  // Returns the reference to the current token. It is always valid.
  const Token& GetCurrentToken() const { return *current_; }

  // Returns true <=> the current token is of type EOF.
  bool CurrentTokenIsEOF() const {
    return (current_->type == Token::Type::kEOF);
  }

  // Returns true <=> the current token is of type Space.
  bool CurrentTokenIsSpace() const {
    return (current_->type == Token::Type::kSpace);
  }

  // Returns true <=> the current token is of type NativeString.
  bool CurrentTokenIsNativeString() const {
    return (current_->type == Token::Type::kNativeString);
  }

  // Returns true <=> the current token is one of the types: LiteralString,
  // ExecutedString, InterpretedString, NativeString.
  bool CurrentTokenIsAnyString() const {
    return (current_->type == Token::Type::kExecutedString ||
            current_->type == Token::Type::kInterpretedString ||
            current_->type == Token::Type::kLiteralString ||
            current_->type == Token::Type::kNativeString);
  }

  // Returns true <=> the current token is of type Byte and its value equals
  // |c|.
  bool CurrentTokenIsByte(char c) const {
    return (current_->type == Token::Type::kByte && *(current_->begin) == c);
  }

  // Moves the current position to the next token. If the current token is of
  // type EOF, it does nothing.
  void MoveToNext() {
    if (current_->type != Token::Type::kEOF)
      ++current_;
  }

  // Moves the current position to the previous token. It the current position
  // points to the first token in the sequence, it does nothing.
  void ReturnToPrevious() {
    if (current_ != tokens_.begin())
      --current_;
  }

 private:
  const std::vector<Token>& tokens_;
  std::vector<Token>::const_iterator current_;
};

Parser::Parser(const std::vector<Token>& tokens)
    : tokens_(std::make_unique<InputTokens>(tokens)) {}

Parser::~Parser() {}

bool Parser::ParseWholeInput(Script* out) {
  DCHECK(out != nullptr);

  if (!ParseScript(out))
    return false;
  if (!tokens_->CurrentTokenIsEOF()) {
    message_ = "Not everything was parsed";
    return false;
  }
  return true;
}

std::string::const_iterator Parser::GetPosition() const {
  return tokens_->GetCurrentToken().begin;
}

// This is a wrapper around ParseScriptImpl(...) to limit the number of
// recursive (...) operators (sub-shells invocations).
bool Parser::ParseScript(Script* out) {
  if (script_recursion_level_ > 4) {
    message_ = "Too many recursive shells executions";
    return false;
  }

  ++script_recursion_level_;
  const bool result = ParseScriptImpl(out);
  --script_recursion_level_;
  return result;
}

// Parses the following (see grammar.h for details):
//  Script = OptSpace, {SepP,OptSpace}, Pipeline,
//           { {SepP,OptSpace}-, Pipeline }, {SepP,OptSpace} ;
// or:
//  Script = OptSpace , { SepP , OptSpace } ;
// If succeed, the method shifts the current position to the first token after
// the end of a whole Script. The resultant Script is saved in |out|. |out| must
// contain a pointer to an empty Script structure. Returns false in case of an
// error.
bool Parser::ParseScriptImpl(Script* out) {
  DCHECK(out != nullptr);

  // Parsing: OptSpace
  if (tokens_->CurrentTokenIsSpace())
    tokens_->MoveToNext();

  // Parsing: { SepP , OptSpace }
  while (tokens_->CurrentTokenIsByte('\n') ||
         tokens_->CurrentTokenIsByte(';')) {
    tokens_->MoveToNext();
    if (tokens_->CurrentTokenIsSpace())
      tokens_->MoveToNext();
  }

  // If the next token matches a Pipeline prefix, we go forward with the first
  // Script definition. Otherwise, we match the second Script definition (the
  // shorter one) and finish here with success.
  if (!MatchAPrefixOfPipeSegment(tokens_->GetCurrentToken()))
    return true;

  // Parsing: Pipeline
  out->pipelines.resize(1);
  if (!ParsePipeline(&out->pipelines.back()))
    return false;

  // Parsing: { {SepP,OptSpace}-, Pipeline }, {SepP,OptSpace}
  while (tokens_->CurrentTokenIsByte('\n') ||
         tokens_->CurrentTokenIsByte(';')) {
    // Parsing: {SepP,OptSpace}- or {SepP,OptSpace}
    do {
      tokens_->MoveToNext();
      if (tokens_->CurrentTokenIsSpace())
        tokens_->MoveToNext();
    } while (tokens_->CurrentTokenIsByte('\n') ||
             tokens_->CurrentTokenIsByte(';'));

    // If the next token is not a prefix of a Pipeline, we reach the end of
    // the Script.
    if (!MatchAPrefixOfPipeSegment(tokens_->GetCurrentToken()))
      break;

    // Parsing: Pipeline
    out->pipelines.emplace_back();
    if (!ParsePipeline(&out->pipelines.back()))
      return false;
  }

  return true;
}

// Parses the following (see grammar.h for details):
//  Pipeline = PipeSegment, OptSpace, {"|",OptSpace,PipeSegment,OptSpace} ;
// The current token must be a first token of a Pipeline. If succeed, the
// method shifts the current position to the first token after the end of a
// whole Pipeline. The resultant Pipeline is saved in |out|. |out| must
// contain a pointer to an empty Pipeline structure. Returns false in case
// of an error.
bool Parser::ParsePipeline(Pipeline* out) {
  DCHECK(out != nullptr);
  DCHECK(MatchAPrefixOfPipeSegment(tokens_->GetCurrentToken()));

  // Parsing: PipeSegment
  out->segments.resize(1);
  if (!ParsePipeSegment(&out->segments.back()))
    return false;

  // Parsing: OptSpace
  if (tokens_->CurrentTokenIsSpace())
    tokens_->MoveToNext();

  // Parsing: {"|",OptSpace,PipeSegment,OptSpace}
  while (tokens_->CurrentTokenIsByte('|')) {
    tokens_->MoveToNext();
    // Parsing: OptSpace
    if (tokens_->CurrentTokenIsSpace())
      tokens_->MoveToNext();
    // Parsing: PipeSegment
    if (!MatchAPrefixOfPipeSegment(tokens_->GetCurrentToken())) {
      message_ = "Missing Pipe Segment after |";
      return false;
    }
    out->segments.emplace_back();
    if (!ParsePipeSegment(&out->segments.back()))
      return false;
    // Parsing: OptSpace
    if (tokens_->CurrentTokenIsSpace())
      tokens_->MoveToNext();
  }

  return true;
}

// Parses the following (see grammar.h for details):
//  PipeSegment = ("(",Script,")") | Command ;
// The current token must be a first token of a PipeSegment. If succeed, the
// method shifts the current position to the first token after the end of a
// whole PipeSegment. The resultant PipeSegment is saved in |out|. |out| must
// contain a pointer to an empty PipeSegment structure. Returns false in case
// of an error.
bool Parser::ParsePipeSegment(PipeSegment* out) {
  DCHECK(out != nullptr);
  DCHECK(MatchAPrefixOfPipeSegment(tokens_->GetCurrentToken()));

  if (tokens_->CurrentTokenIsByte('(')) {
    // Parsing: "(", Script, ")"
    tokens_->MoveToNext();
    out->script = std::make_unique<Script>();
    if (!ParseScript(out->script.get()))
      return false;
    if (!tokens_->CurrentTokenIsByte(')')) {
      message_ = "Missing closing parenthesis )";
      return false;
    }
    tokens_->MoveToNext();
    return true;
  }

  // Parsing: Command
  out->command = std::make_unique<Command>();
  return ParseCommand(out->command.get());
}

// Parses the following (see grammar.h for details):
//  Command = {Variable,"=",StringAtom,Space}, Application, {Space,Parameter} ;
// The current token must be of type NativeString. If succeed, the method
// shifts the current position to the first token after the end of a whole
// command statement. The resultant command is saved in |out|. |out| must
// contain a pointer to an empty Command structure. Returns false in case of
// an error.
bool Parser::ParseCommand(Command* out) {
  DCHECK(out != nullptr);
  DCHECK(tokens_->CurrentTokenIsNativeString());

  // Parsing: {Variable,"=",StringAtom,Space}, Application
  while (true) {
    // Save the current token (NativeString) and check the next one.
    // If the next token is "=", we are inside variable definition:
    // Variable,"=",StringAtom,Space
    // Otherwise, we just parsed Application.
    const Token& first = tokens_->GetCurrentToken();
    tokens_->MoveToNext();
    if (tokens_->CurrentTokenIsByte('=')) {
      // The token |first| is a Variable.
      // Parsing: "=",StringAtom,Space
      tokens_->MoveToNext();
      if (!tokens_->CurrentTokenIsAnyString()) {
        message_ = "Variable assignment with missing value";
        return false;
      }
      // Save the variable and parse its value.
      out->variables_with_values.emplace_back();
      out->variables_with_values.back().variable = first;
      ParseString(&out->variables_with_values.back().new_value);
      // Now we expect Space.
      if (!tokens_->CurrentTokenIsSpace()) {
        message_ = "Unexpected token after variable assignment";
        return false;
      }
      tokens_->MoveToNext();
      // The next token must be a Variable or an Application.
      // Both are NativeString.
      if (!tokens_->CurrentTokenIsNativeString()) {
        message_ = "Missing command";
        return false;
      }
    } else {
      // The token |first| is an Application.
      out->application = first;
      // The current token is the first token after the Application.
      // Exit the loop and parse parameters.
      break;
    }
  }

  // Parsing: {Space,Parameter}
  while (true) {
    // If the current token is not a Space, it does not match.
    if (!tokens_->CurrentTokenIsSpace())
      break;
    // It is a Space, check the next token.
    tokens_->MoveToNext();
    // If the next token is a beginning of StringAtom, we have next parameter.
    // If not, we have to move back (to return a Space token) and exit.
    if (!tokens_->CurrentTokenIsAnyString() &&
        !tokens_->CurrentTokenIsByte('=')) {
      tokens_->ReturnToPrevious();
      break;
    }
    // It is a parameter, let's parse it.
    out->parameters.emplace_back();
    ParseString(&out->parameters.back());
  }

  return true;
}

// Parses the following (see grammar.h for details):
//  StringAtom = { LiteralString | ExecutedString | InterpretedString
//              | NativeString | "=" }- ;
// The current token must be the first token of the string. The method shifts
// the current position to the first token after the end of the string. The
// resultant string is saved in |out|. |out| must contain pointer to the empty
// StringAtom structure.
void Parser::ParseString(StringAtom* out) {
  DCHECK(out != nullptr);
  DCHECK(tokens_->CurrentTokenIsAnyString() ||
         tokens_->CurrentTokenIsByte('='));

  while (tokens_->CurrentTokenIsAnyString() ||
         tokens_->CurrentTokenIsByte('=')) {
    out->components.push_back(tokens_->GetCurrentToken());
    tokens_->MoveToNext();
  }
}

}  // namespace foomatic_shell
