// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DEBUGD_SRC_PERFETTO_TOOL_H_
#define DEBUGD_SRC_PERFETTO_TOOL_H_

#include <memory>
#include <optional>
#include <string>

#include "debugd/src/process_with_output.h"

namespace debugd {

class PerfettoTool {
 public:
  PerfettoTool();
  ~PerfettoTool();
  PerfettoTool(const PerfettoTool&) = delete;
  PerfettoTool& operator=(const PerfettoTool&) = delete;

  // Creates and starts a Perfetto tracing session. Returns nullptr on failure.
  static std::unique_ptr<PerfettoTool> Start();

  // Stops a previously started Perfetto session, returning the collected trace,
  // or std::nullopt on failure.
  std::optional<std::string> Stop();

 private:
  bool Init();
  bool StartImpl();

  ProcessWithOutput perfetto_;
  ProcessWithOutput compressor_;
  std::array<base::ScopedFD, 2> pipe_;
};

}  // namespace debugd

#endif  // DEBUGD_SRC_PERFETTO_TOOL_H_
