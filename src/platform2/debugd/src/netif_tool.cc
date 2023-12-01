// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "debugd/src/netif_tool.h"

#include "debugd/src/helper_utils.h"
#include "debugd/src/process_with_output.h"

namespace debugd {

std::string NetifTool::GetInterfaces() {
  std::string path;
  if (!GetHelperPath("netif", &path))
    return "<path too long>";

  ProcessWithOutput p;
  if (!p.Init())
    return "<can't create process>";
  p.AddArg(path);
  p.Run();
  std::string out;
  p.GetOutput(&out);
  return out;
}

}  // namespace debugd
