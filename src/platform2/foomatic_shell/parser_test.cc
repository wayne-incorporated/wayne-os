// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "foomatic_shell/grammar.h"
#include "foomatic_shell/parser.h"
#include "foomatic_shell/scanner.h"

#include <gtest/gtest.h>
#include <string>
#include <utility>
#include <vector>

namespace foomatic_shell {

// Calls CreateRepresentation(...) for each element of the given vector and
// returns single string built from the results according to the following
// pattern: "[result0,result1,result2,...]"
template <typename Element>
std::string CreateRepresentation(const std::vector<Element>& elements) {
  std::string out = "[";
  for (size_t i = 0; i < elements.size(); ++i) {
    if (i > 0)
      out += ",";
    out += CreateRepresentation(elements[i]);
  }
  out.push_back(']');
  return out;
}

// A string representation of StringAtom is its value.
std::string CreateRepresentation(const StringAtom& str) {
  std::string out;
  for (auto& s : str.components) {
    if (s.type == Token::Type::kLiteralString)
      out += std::string(s.begin, s.end);
    else
      out += s.value;
  }
  return out;
}

// A string representation of variable assignment is a name of variable and
// a value of the variable connected by '=' character.
std::string CreateRepresentation(const VariableAssignment& variable) {
  std::string out;
  out = variable.variable.value;
  out += "=";
  out += CreateRepresentation(variable.new_value);
  return out;
}

std::string CreateRepresentation(const Script& script);

// This function returns a string representation of given PipeSegment.
// If the PipeSegment is a Command, its string representation is calculated
// according to the following pattern:
// "{[var0=value0,var1=value1,...],application,[param0,param1,...]}"
std::string CreateRepresentation(const PipeSegment& segment) {
  std::string out;
  if (segment.command) {
    out += "{";
    out += CreateRepresentation(segment.command->variables_with_values);
    out += ",";
    out += segment.command->application.value;
    out += ",";
    out += CreateRepresentation(segment.command->parameters);
    out += "}";
  } else {
    return CreateRepresentation(*segment.script);
  }
  return out;
}

// This function returns a string representation of given Pipeline as a
// sequence of string representations of its segments.
std::string CreateRepresentation(const Pipeline& pipeline) {
  return CreateRepresentation(pipeline.segments);
}

// This function returns a string representation of given Script as a
// sequence of string representations of its pipelines.
std::string CreateRepresentation(const Script& script) {
  return CreateRepresentation(script.pipelines);
}

TEST(Parser, CommandWithParameters) {
  const std::string input =
      "pdftops '9195' 'root' 'split_streams.pdf' '1' "
      "' finishings=3 number-up=1 document=split.pdf' '/cups/tmp/foo-B65TL1'";
  const std::string tree =
      "[[{[],pdftops,[9195,root,split_streams.pdf,1,"
      " finishings=3 number-up=1 document=split.pdf,/cups/tmp/foo-B65TL1]}]]";
  std::vector<Token> tokens;
  Scanner scanner(input);
  ASSERT_TRUE(scanner.ParseWholeInput(&tokens));
  Parser parser(std::move(tokens));
  Script script;
  EXPECT_TRUE(parser.ParseWholeInput(&script));
  EXPECT_EQ(tree, CreateRepresentation(script));
}

TEST(Parser, Pipeline) {
  const std::string input = "ls -h | grep 'XXX' | wc -l; echo \"Done\"; ";
  const std::string tree =
      "[[{[],ls,[-h]},{[],grep,[XXX]},{[],wc,[-l]}],"
      "[{[],echo,[Done]}]]";
  std::vector<Token> tokens;
  Scanner scanner(input);
  ASSERT_TRUE(scanner.ParseWholeInput(&tokens));
  Parser parser(std::move(tokens));
  Script script;
  EXPECT_TRUE(parser.ParseWholeInput(&script));
  EXPECT_EQ(tree, CreateRepresentation(script));
}

TEST(Parser, Subshell) {
  const std::string input =
      "VAR1='xx' VAR=acs'zzz'qq  my_app  -par1 par2'qqq'"
      " ; (echo ttt | tr t T; echo Done) | cat myfile.txt";
  const std::string tree =
      "[[{[VAR1=xx,VAR=acszzzqq],my_app,[-par1,par2qqq]}],"
      "[[[{[],echo,[ttt]},{[],tr,[t,T]}],[{[],echo,[Done]}]],"
      "{[],cat,[myfile.txt]}]]";
  std::vector<Token> tokens;
  Scanner scanner(input);
  ASSERT_TRUE(scanner.ParseWholeInput(&tokens));
  Parser parser(std::move(tokens));
  Script script;
  EXPECT_TRUE(parser.ParseWholeInput(&script));
  EXPECT_EQ(tree, CreateRepresentation(script));
}

}  // namespace foomatic_shell
