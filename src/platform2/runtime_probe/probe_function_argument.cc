// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include "runtime_probe/probe_function.h"
#include "runtime_probe/probe_function_argument.h"

#include <base/logging.h>

namespace runtime_probe {
namespace internal {

#define _DEFINE_PARSE_ARGUMENT(type, GetType)                       \
  template <>                                                       \
  bool ParseArgumentImpl<type>(const base::Value& value, type& out, \
                               std::string& err) {                  \
    if (!value.is_##type()) {                                       \
      std::stringstream ss;                                         \
      ss << "expected " << #type << " but got: " << value;          \
      err = ss.str();                                               \
      return false;                                                 \
    }                                                               \
    out = value.GetType();                                          \
    return true;                                                    \
  }

using std::string;
_DEFINE_PARSE_ARGUMENT(string, GetString);
_DEFINE_PARSE_ARGUMENT(bool, GetBool);
_DEFINE_PARSE_ARGUMENT(double, GetDouble);
_DEFINE_PARSE_ARGUMENT(int, GetInt);

#undef _DEFINE_PARSE_ARGUMENT

template <>
bool ParseArgumentImpl<std::unique_ptr<ProbeFunction>>(
    const base::Value& value,
    std::unique_ptr<ProbeFunction>& out,
    std::string& err) {
  out = ProbeFunction::FromValue(value);
  if (out) {
    return true;
  }
  std::stringstream ss;
  ss << "failed to parse probe function from: " << value;
  err = ss.str();
  return false;
}

}  // namespace internal
}  // namespace runtime_probe
