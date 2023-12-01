// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "foomatic_shell/scanner.h"

#include <string>
#include <vector>

#include <base/check.h>
#include <base/logging.h>

namespace foomatic_shell {

// This class encapsulates an iterator representing the current position in the
// input string.
class Scanner::Input {
 public:
  // Constructor. |data| is a reference to the input string. The input string
  // must remain constant and valid during the lifetime of the object. The
  // current position is set to the first element in the |data|.
  explicit Input(const std::string& data)
      : data_(data), current_(data_.begin()) {}

  Input(const Input&) = delete;
  Input(Input&&) = delete;

  // Returns the iterator to the current position. The iterator is from the
  // input string given in the constructor and is always valid (but may be
  // equal |data.end()|).
  std::string::const_iterator GetCurrentPosition() const { return current_; }

  // Returns the value of the current character. If the current position is set
  // to |data.end()|, this method returns '\0'.
  char GetCurrentCharacter() const {
    if (current_ == data_.end())
      return '\0';
    return *current_;
  }

  // Returns true <=> a character at the current position equals |c|. If the
  // current position is set to |data.end()|, it returns false.
  bool CurrentCharIs(char c) const {
    return (current_ != data_.end() && *current_ == c);
  }

  // Returns true <=> a character at the current position is ByteNative (see
  // grammar.h for details). If the current position is set to |data.end()|,
  // it returns false.
  bool CurrentCharIsByteNative() const {
    if (current_ == data_.end())
      return false;
    if (*current_ >= 'A' && *current_ <= 'Z')
      return true;
    if (*current_ >= 'a' && *current_ <= 'z')
      return true;
    if (*current_ >= '0' && *current_ <= '9')
      return true;
    return (std::string("./_+-@%").find(*current_) != std::string::npos);
  }

  // Returns true <=> a character at the current position equals to one of the
  // elements of |chars|. If the current position is set to |data.end()|,
  // it returns false.
  bool CurrentCharIsOneOf(const std::string& chars) const {
    if (current_ == data_.end())
      return false;
    return (chars.find(*current_) != std::string::npos);
  }

  // Returns true <=> the current position is set to |data.end()|.
  bool CurrentCharIsEOF() const { return (current_ == data_.end()); }

  // Move the current position to the next element. If the current position
  // is set to |data.end()|, it does nothing.
  void MoveToNext() {
    if (current_ != data_.end())
      ++current_;
  }

 private:
  const std::string& data_;
  std::string::const_iterator current_;
};

Scanner::Scanner(const std::string& data)
    : data_(std::make_unique<Input>(data)) {}
Scanner::~Scanner() {}

// Parses the following (see grammar.h for details):
//   LiteralString = "'" , { ByteCommon | '"' | "`" | "\" } , "'" ;
// The current position must be one the opening '. It moves cursor to the first
// character after the closing '. The resultant token is added to |tokens|.
// |tokens| must not be nullptr. Returns false in case of an error.
bool Scanner::ParseLiteralString(std::vector<Token>* tokens) {
  DCHECK(tokens != nullptr);
  DCHECK(data_->CurrentCharIs('\''));

  // Skip the opening '.
  data_->MoveToNext();

  // Create a new token.
  tokens->resize(tokens->size() + 1);
  Token* out = &(tokens->back());
  out->type = Token::Type::kLiteralString;
  out->begin = data_->GetCurrentPosition();

  // Move forward until we find EOF or the closing '.
  while (!data_->CurrentCharIsEOF()) {
    if (data_->CurrentCharIs('\'')) {
      // The closing ' was found.
      out->end = data_->GetCurrentPosition();
      out->value.assign(out->begin, out->end);
      // Skip the closing '.
      data_->MoveToNext();
      // Success!
      return true;
    }
    data_->MoveToNext();
  }

  // There is no closing '.
  out->end = data_->GetCurrentPosition();
  message_ = "Unexpected EOF when parsing '...' (literal string)";
  return false;
}

// Parses the following (see grammar.h for details):
//   ExecutedString = "`" , { ByteCommon | "'" | '"' | ("\",ByteAny) } , "`" ;
// The current position must be one the opening `. It moves cursor to the first
// character after the closing `. The resultant token is added to |tokens|.
// |tokens| must not be nullptr. Returns false in case of an error.
bool Scanner::ParseExecutedString(std::vector<Token>* tokens) {
  DCHECK(tokens != nullptr);
  DCHECK(data_->CurrentCharIs('`'));

  // Skip the opening `.
  data_->MoveToNext();

  // Create a new token.
  tokens->resize(tokens->size() + 1);
  Token* out = &(tokens->back());
  out->type = Token::Type::kExecutedString;
  out->begin = data_->GetCurrentPosition();

  // Move forward until we find EOF or the closing `.
  while (!data_->CurrentCharIsEOF()) {
    if (data_->CurrentCharIs('`')) {
      // The closing ` was found.
      out->end = data_->GetCurrentPosition();
      // Skip the closing `.
      data_->MoveToNext();
      // Success!
      return true;
    }
    // The escape character (\) works in ExecutedString for ByteAny.
    if (data_->CurrentCharIs('\\')) {
      data_->MoveToNext();
      if (data_->CurrentCharIsEOF())
        break;
    }
    // Save the current character and move to the next element.
    out->value.push_back(data_->GetCurrentCharacter());
    data_->MoveToNext();
  }

  // There is no closing `.
  out->end = data_->GetCurrentPosition();
  message_ = "Unexpected EOF when parsing `...` (executed string)";
  return false;
}

// Parses the following (see grammar.h for details):
//   InterpretedString = '"' , { ByteCommon | "'" | "\" | ("\",'"') | ("\","`")
//                       | ("\","\") | ExecutedString } , '"' ;
// The current position must be one the opening ". It moves cursor to the first
// character after the closing ". If the string contains one or more
// ExecutedString, it is split into a sequence of consecutive tokens of types
// InterpretedString and ExecutedString. The resultant tokens are added to
// |tokens|. |tokens| must not be nullptr. Returns false in case of an error.
bool Scanner::ParseInterpretedString(std::vector<Token>* tokens) {
  DCHECK(tokens != nullptr);
  DCHECK(data_->CurrentCharIs('"'));

  // Skip the opening ".
  data_->MoveToNext();

  // Create a sequence of alternating InterpretedString and ExecutedString
  // tokens.
  while (true) {
    // Create a new InterpretedString token.
    tokens->resize(tokens->size() + 1);
    Token* out = &(tokens->back());
    out->type = Token::Type::kInterpretedString;
    out->begin = data_->GetCurrentPosition();

    // Move forward until we find EOF, the closing " or the opening `.
    while (true) {
      if (data_->CurrentCharIs('"')) {
        // The closing " was found.
        out->end = data_->GetCurrentPosition();
        data_->MoveToNext();
        return true;
      }
      if (data_->CurrentCharIs('`')) {
        // The opening ` was found. We finish the current token and
        // add a new ExecutedString token.
        out->end = data_->GetCurrentPosition();
        if (!ParseExecutedString(tokens))
          return false;
        // We break the internal loop to create a new InterpretedString
        // token.
        break;
      }
      if (data_->CurrentCharIs('\\')) {
        // It may be an escape character for " or `.
        data_->MoveToNext();
        if (data_->CurrentCharIsOneOf("\"`\\")) {
          // The next character is " or `. Just skip \ and go ahead.
        } else {
          // It was not an escape character. We have to add a skipped \.
          out->value.push_back('\\');
        }
      }
      if (data_->CurrentCharIsEOF()) {
        // There is no closing ".
        out->end = data_->GetCurrentPosition();
        message_ = "Unexpected EOF when parsing \"...\" (interpreted string)";
        return false;
      }
      // Save the current character and move to the next element.
      out->value.push_back(data_->GetCurrentCharacter());
      data_->MoveToNext();
    }
  }
}

// Parses the following (see grammar.h for details):
//   NativeString = { ByteNative | ("\",ByteAny) }- ;
// The current position must be one the first character of NativeString. It
// moves cursor to the first character after the end of the string. The
// resultant token is added to |tokens|. |tokens| must not be nullptr. Returns
// false in case of an error.
bool Scanner::ParseNativeString(std::vector<Token>* tokens) {
  DCHECK(tokens != nullptr);
  DCHECK(data_->CurrentCharIsByteNative() || data_->CurrentCharIs('\\'));

  // Create a new token.
  tokens->resize(tokens->size() + 1);
  Token* out = &(tokens->back());
  out->type = Token::Type::kNativeString;
  out->begin = data_->GetCurrentPosition();

  // Move forward until we find EOF or the end of the string.
  while (!data_->CurrentCharIsEOF()) {
    if (data_->CurrentCharIs('\\')) {
      // This is an escape character.
      data_->MoveToNext();
      if (data_->CurrentCharIsEOF()) {
        // It is an error: EOF after the escape character.
        out->end = data_->GetCurrentPosition();
        message_ = "Unexpected EOF after escape character (\\)";
        return false;
      }
      // Add the escaped character to the string.
      out->value.push_back(data_->GetCurrentCharacter());
      // Go to the next character.
      data_->MoveToNext();
      continue;
    }

    // If the current character is not a ByteNative, we found the end of the
    // string.
    if (!data_->CurrentCharIsByteNative())
      break;

    // Save the current character and move to the next element.
    out->value.push_back(data_->GetCurrentCharacter());
    data_->MoveToNext();
  }

  // We are at EOF or at the first character not being part of the string.
  out->end = data_->GetCurrentPosition();
  return true;
}

bool Scanner::ParseWholeInput(std::vector<Token>* tokens) {
  DCHECK(tokens != nullptr);

  while (!data_->CurrentCharIsEOF()) {
    // Check for different types of string.
    if (data_->CurrentCharIs('\'')) {
      if (!ParseLiteralString(tokens))
        return false;
      continue;
    }
    if (data_->CurrentCharIs('"')) {
      if (!ParseInterpretedString(tokens))
        return false;
      continue;
    }
    if (data_->CurrentCharIs('`')) {
      if (!ParseExecutedString(tokens))
        return false;
      continue;
    }
    if (data_->CurrentCharIsByteNative() || data_->CurrentCharIs('\\')) {
      if (!ParseNativeString(tokens))
        return false;
      continue;
    }

    // Create a new token.
    tokens->resize(tokens->size() + 1);
    Token& token = tokens->back();

    if (data_->CurrentCharIsOneOf(" \t")) {
      // It is a Space token.
      //   Space = { " " | Tabulator }- ;
      token.type = Token::Type::kSpace;
      token.begin = data_->GetCurrentPosition();
      // Move forward until we find the first character not being part of
      // the Space token. It stops also at EOF.
      while (data_->CurrentCharIsOneOf(" \t"))
        data_->MoveToNext();
      token.end = data_->GetCurrentPosition();
      continue;
    }

    // Add a single character as a token.
    token.type = Token::Type::kByte;
    token.begin = data_->GetCurrentPosition();
    data_->MoveToNext();
    token.end = data_->GetCurrentPosition();
    token.value.assign(token.begin, token.end);
  }

  // Add a special EOF token at the end.
  tokens->resize(tokens->size() + 1);
  tokens->back().type = Token::Type::kEOF;
  tokens->back().begin = tokens->back().end = data_->GetCurrentPosition();
  return true;
}

std::string::const_iterator Scanner::GetPosition() const {
  return data_->GetCurrentPosition();
}

}  // namespace foomatic_shell
