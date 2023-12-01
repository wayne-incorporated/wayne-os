// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "debugd/src/network_status_tool.h"

#include "debugd/src/helper_utils.h"
#include "debugd/src/process_with_output.h"

namespace debugd {

std::string NetworkStatusTool::GetNetworkStatus() {
  std::string path;
  if (!GetHelperPath("network_status", &path))
    return "";

  ProcessWithOutput p;
  p.Init();
  p.AddArg(path);
  p.Run();
  std::string out;
  p.GetOutput(&out);
  return out;
}

}  // namespace debugd
