// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// This is an example of a tool. A tool is the implementation of one or more of
// debugd's dbus methods. The main DebugDaemon class creates a single instance
// of each tool and calls it to answer methods.

#include "debugd/src/example_tool.h"

#include "debugd/src/helper_utils.h"
#include "debugd/src/process_with_output.h"

namespace debugd {

// Tool methods have a similar signature as the generated DBus adaptors.
// Tool methods are generally written in can't-fail style, since
// their output is usually going to be displayed to the user; instead of
// returning a DBus exception, we tend to return a string indicating what went
// wrong.
std::string ExampleTool::GetExample() {
  std::string path;
  if (!GetHelperPath("example", &path))
    return "<path too long>";
  // This whole method is synchronous, so we create a subprocess, let it run to
  // completion, then gather up its output to return it.
  ProcessWithOutput process;
  if (!process.Init())
    return "<process init failed>";
  // If you're going to add switches to a command, have a look at the Process
  // interface; there's support for adding options specifically.
  process.AddArg(path);
  process.AddArg("hello");
  // Run the process to completion. If the process might take a while, you may
  // have to make this asynchronous using .Start().
  if (process.Run() != 0)
    return "<process exited with nonzero status>";
  std::string output;
  process.GetOutput(&output);
  return output;
}

}  // namespace debugd
