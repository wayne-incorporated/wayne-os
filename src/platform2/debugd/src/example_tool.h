// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// This is an example of a tool. See </src/example_tool.cc>.

#ifndef DEBUGD_SRC_EXAMPLE_TOOL_H_
#define DEBUGD_SRC_EXAMPLE_TOOL_H_

#include <string>

namespace debugd {

class ExampleTool {
 public:
  ExampleTool() = default;
  ExampleTool(const ExampleTool&) = delete;
  ExampleTool& operator=(const ExampleTool&) = delete;

  ~ExampleTool() = default;

  std::string GetExample();
};

}  // namespace debugd

#endif  // DEBUGD_SRC_EXAMPLE_TOOL_H_
