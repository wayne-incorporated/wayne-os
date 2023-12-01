// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef FOOMATIC_SHELL_GRAMMAR_H_
#define FOOMATIC_SHELL_GRAMMAR_H_

#include <memory>
#include <string>
#include <utility>
#include <vector>

// This is a definition of the grammar in EBNF notation (ISO/IEC 14977).
//
// Terminal symbols are quoted by '...' or "...". Parenthesis (...) are used
// for grouping. ?...? is used to mark informal description. Other operators:
// - (minus) : exception operator (A-'xx' means "all products of A but 'xx')
// , (comma) : concatenation
// | (pipe)  : or
// Repetitions (including an empty product) are denoted by {...}. Empty product
// may be excluded by using minus without following symbol: {...}-.
//
//
// First, a list of all symbols corresponding to a single byte:
//
//  ByteAny    = ? any byte ? ;
//  ByteCommon = ByteAny - "'" - '"' - "`" - "\" ;
//  ByteNative = ? any alphanumeric character (0-9,A-Z,a-z) or . (dot) or
//               / (slash) or _ (underscore) or - (minus) or + (plus) or
//               @ (at) or % (percent) ? ;
//  Tabulator = ? byte 0x09 (horizontal tab) ? ;
//  EndOfLine = ? byte 0x0A (newline) ? ;
//
//
// These are the tokens extracted by the scanner (see scanner.h):
//
//  LiteralString = "'" , { ByteCommon | '"' | "`" | "\" } , "'" ;
//  ExecutedString = "`" , { ByteCommon | "'" | '"' | ("\",ByteAny) } , "`" ;
//  InterpretedString = '"' , { ByteCommon | "'" | "\" | ("\",'"') | ("\","`")
//                    | ("\","\") | ExecutedString } , '"' ;
//  NativeString = { ByteNative | ("\",ByteAny) }- ;
//  Space = { " " | Tabulator }- ;
//
//
// These are the nodes of the parsing tree built by the parser (see parser.h).
//
//  StringAtom = { LiteralString | ExecutedString | InterpretedString
//              | NativeString | "=" }- ;
//
//  Command = {Variable,"=",StringAtom,Space}, Application, {Space,Parameter} ;
//  Variable = NativeString ;
//  Application = NativeString ;
//  Parameter = StringAtom ;
//
//  Pipeline = PipeSegment, OptSpace, {"|",OptSpace,PipeSegment,OptSpace} ;
//  PipeSegment = ("(",Script,")") | Command ;
//  OptSpace = Space | ;   (* means "Space or empty product" *)
//
//  Script = OptSpace, {SepP,OptSpace}, Pipeline,
//           { {SepP,OptSpace}-, Pipeline }, {SepP,OptSpace} ;
//  Script = OptSpace , { SepP , OptSpace } ;
//  SepP = ";" | EndOfLine ;
//
//
// All conflicts are solved by choosing the largest possible match.

namespace foomatic_shell {

// This represents a single token extracted by the scanner. All bytes from the
// input that are not a part of LiteralString, ExecutedString, NativeString,
// InterpretedString or Space are represented as token of type kByte.
struct Token {
  enum Type {
    kLiteralString,
    kExecutedString,
    kInterpretedString,
    kNativeString,
    kSpace,
    kByte,
    kEOF
  } type;
  // For |type|=k*String, the range below points directly to the string
  // content (without ', " or `).
  // For |type|=kSpace, the range corresponds to the longest possible
  // sequence of spaces and tabulators.
  // For |type|=kByte, the range points to exactly one character.
  // For |type|=kEOF, the range points to the end iterator.
  std::string::const_iterator begin;
  std::string::const_iterator end;
  std::string value;
};

// Represents StringAtom node.
struct StringAtom {
  std::vector<Token> components;
};

struct VariableAssignment {
  Token variable;
  StringAtom new_value;
};

// Represents Command node.
struct Command {
  std::vector<VariableAssignment> variables_with_values;
  Token application;
  std::vector<StringAtom> parameters;
};

struct Script;

// Represents PipeSegment node. Only one of the fields is set.
struct PipeSegment {
  std::unique_ptr<Command> command;
  std::unique_ptr<Script> script;
};

// Represents Pipeline node.
struct Pipeline {
  std::vector<PipeSegment> segments;
};

// Represents Script node.
struct Script {
  std::vector<Pipeline> pipelines;
};

// Helper function. Returns string value of given StringAtom.
std::string Value(const StringAtom& str);

// Helper functions. Return positions in the executed script corresponding to
// the beginning of an element given as a parameter.
std::string::const_iterator Position(const PipeSegment& segment);
std::string::const_iterator Position(const Command& cmd);
std::string::const_iterator Position(const Script& script);

// Helper function. Builds an error message containing full script. |source| is
// a script and |position| is a position in this script where the error
// occurred. |msg| contains an error message. The function returns a complete
// error message.
std::string CreateErrorLog(const std::string& source,
                           std::string::const_iterator position,
                           const std::string& msg);

}  // namespace foomatic_shell

#endif  // FOOMATIC_SHELL_GRAMMAR_H_
