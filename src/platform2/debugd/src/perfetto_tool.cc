// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// This tool records a Perfetto trace in feedback reports, for example to assist
// diagnosing tasks with high CPU usage.
//
// Feedback reports contain perf stack samples, which can be useful for figuring
// out aggregate behavior (e.g., what code is hot). In contrast, Perfetto
// records a timeline of events, which can help show how different system
// components are interacting (e.g., what's blocking the processing user input
// events, or how well CPU core scheduling is working).
//
// Running the Perfetto profiler adds a small amount of CPU overhead, but
// this can be easily filtered out of the perf stack samples by ignoring
// samples from the traced and traced_probes processes. Including this data
// also increases the uploaded size of feedback reports by about 10-30%,
// depending on system activity.
//
// TODO(skyostil): Enable stack sampling support in Perfetto so that we no
// longer need to run the perf tool in parallel.

#include "debugd/src/perfetto_tool.h"
#include <fcntl.h>
#include <unistd.h>

#include "base/logging.h"
#include "base/posix/eintr_wrapper.h"

namespace debugd {

PerfettoTool::PerfettoTool() = default;
PerfettoTool::~PerfettoTool() = default;

bool PerfettoTool::Init() {
  int pipe_fds[2];
  if (HANDLE_EINTR(pipe2(pipe_fds, O_CLOEXEC)) != 0)
    return false;
  pipe_[0].reset(pipe_fds[0]);
  pipe_[1].reset(pipe_fds[1]);

  perfetto_.SandboxAs("debugd", "traced-consumer");
  perfetto_.AllowAccessRootMountNamespace();
  if (!perfetto_.Init())
    return false;
  perfetto_.AddArg("/usr/bin/perfetto");
  perfetto_.AddArg("-c");
  perfetto_.AddArg("/usr/share/debugd/perfetto_feedback_config.textproto");
  perfetto_.AddArg("--txt");
  perfetto_.AddArg("-o");
  perfetto_.AddArg("-");
  perfetto_.set_separate_stderr(true);
  perfetto_.BindFd(pipe_[1].get(), STDOUT_FILENO);

  if (!compressor_.Init())
    return false;
  compressor_.AddArg("/usr/bin/zstd");
  compressor_.AddArg("-qc");
  compressor_.set_separate_stderr(true);
  compressor_.BindFd(pipe_[0].get(), STDIN_FILENO);
  return true;
}

bool PerfettoTool::StartImpl() {
  bool ok = perfetto_.Start() && compressor_.Start();
  pipe_[0].reset();
  pipe_[1].reset();
  return ok;
}

// static
std::unique_ptr<PerfettoTool> PerfettoTool::Start() {
  auto tool = std::make_unique<PerfettoTool>();
  if (!tool->Init() || !tool->StartImpl()) {
    LOG(ERROR) << "Failed to start Perfetto";
    return nullptr;
  }
  return tool;
}

std::optional<std::string> PerfettoTool::Stop() {
  std::string trace;
  bool ok = perfetto_.Wait() == EXIT_SUCCESS;
  ok &= compressor_.Wait() == EXIT_SUCCESS;
  if (ok && compressor_.GetOutput(&trace)) {
    return trace;
  }

  std::string error;
  if (!perfetto_.GetError(&error) || error.empty()) {
    compressor_.GetError(&error);
  }
  LOG(ERROR) << "Failed to record Perfetto trace: " << error;
  return std::nullopt;
}

}  // namespace debugd
