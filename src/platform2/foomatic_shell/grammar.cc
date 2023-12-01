// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "foomatic_shell/grammar.h"

#include <base/check.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>

namespace foomatic_shell {

namespace {

// Returns the position of the beginning of given StringAtom.
std::string::const_iterator Position(const StringAtom& str) {
  DCHECK(!str.components.empty());
  return str.components.front().begin;
}

}  // namespace

std::string Value(const StringAtom& str) {
  std::string out;
  for (auto& s : str.components)
    out += s.value;
  return out;
}

std::string::const_iterator Position(const PipeSegment& segment) {
  if (segment.command)
    return Position(*segment.command);
  DCHECK(segment.script != nullptr);
  return Position(*segment.script);
}

std::string::const_iterator Position(const Command& cmd) {
  if (!cmd.variables_with_values.empty())
    return Position(cmd.variables_with_values.front().new_value);
  return cmd.application.begin;
}

std::string::const_iterator Position(const Script& script) {
  DCHECK(!script.pipelines.empty());
  DCHECK(!script.pipelines.front().segments.empty());
  return Position(script.pipelines.front().segments.front());
}

std::string CreateErrorLog(const std::string& source,
                           std::string::const_iterator position,
                           const std::string& msg) {
  std::string out = msg + ". ";
  out += "Error occurred";
  if (position >= source.begin() || position < source.end()) {
    out +=
        " at position " + base::NumberToString(position - source.begin() + 1);
  }
  out += " in the script: \"" + source + "\".";
  return out;
}

}  // namespace foomatic_shell
