// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DEBUGD_SRC_PERF_TOOL_H_
#define DEBUGD_SRC_PERF_TOOL_H_

#include <sys/utsname.h>

#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <base/files/file_util.h>
#include <base/files/scoped_file.h>
#include <brillo/asynchronous_signal_handler.h>
#include <brillo/errors/error.h>
#include <brillo/process/process_reaper.h>

#include "debugd/src/sandboxed_process.h"

namespace debugd {

enum PerfSubcommand {
  PERF_COMMAND_RECORD,
  PERF_COMMAND_STAT,
  PERF_COMMAND_MEM,
  PERF_COMMAND_UNSUPPORTED,
};

bool ValidateQuipperArguments(const std::vector<std::string>& qp_args,
                              PerfSubcommand& subcommand,
                              brillo::ErrorPtr* error);

class PerfTool {
 public:
  PerfTool();
  PerfTool(const PerfTool&) = delete;
  PerfTool& operator=(const PerfTool&) = delete;

  ~PerfTool() = default;

  // Runs the perf tool with the request command for |duration_secs| seconds
  // and returns either a perf_data or perf_stat protobuf in serialized form.
  bool GetPerfOutput(uint32_t duration_secs,
                     const std::vector<std::string>& perf_args,
                     std::vector<uint8_t>* perf_data,
                     std::vector<uint8_t>* perf_stat,
                     int32_t* status,
                     brillo::ErrorPtr* error);

  // Runs the perf tool with the request command for |duration_secs| seconds
  // and returns either a perf_data or perf_stat protobuf in serialized form
  // over the passed stdout_fd file descriptor, or nothing if there was an
  // error. |session_id| is returned to the client to optionally stop the perf
  // tool before it runs for the full duration.
  bool GetPerfOutputFd(uint32_t duration_secs,
                       const std::vector<std::string>& perf_args,
                       const base::ScopedFD& stdout_fd,
                       uint64_t* session_id,
                       brillo::ErrorPtr* error);

  // Stops the perf tool that was previously launched using GetPerfOutputFd()
  // and gathers perf output right away.
  bool StopPerf(uint64_t session_id, brillo::ErrorPtr* error);

  // Runs the perf tool with the given |quipper_args| and returns either a
  // perf_data or perf_stat protobuf in serialized form over the passed
  // |stdout_fd| file descriptor, or nothing if there was an error. |session_id|
  // is returned to the client to optionally stop the perf tool before it runs
  // for the full duration.
  // If |disable_cpu_idle| is true, this will temporarily disable all CPUs from
  // entering the idle states while running the perf command.
  bool GetPerfOutputV2(const std::vector<std::string>& quipper_args,
                       bool disable_cpu_idle,
                       const base::ScopedFD& stdout_fd,
                       uint64_t* session_id,
                       brillo::ErrorPtr* error);

 private:
  inline bool perf_running() const { return quipper_process_ != nullptr; }
  void OnQuipperProcessExited(const siginfo_t& siginfo);

  // Change the proper strobbing settings before starting ETM collection.
  // TODO(b/209861754): remove this when we have implemented a preset for
  // strobbing.
  void EtmStrobbingSettings();

  std::optional<uint64_t> profiler_session_id_;
  std::unique_ptr<SandboxedProcess> quipper_process_;
  base::ScopedFD quipper_process_output_fd_;
  brillo::AsynchronousSignalHandler signal_handler_;
  brillo::ProcessReaper process_reaper_;
  bool etm_available;
};

}  // namespace debugd

#endif  // DEBUGD_SRC_PERF_TOOL_H_
