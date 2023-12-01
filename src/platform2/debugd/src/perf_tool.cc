// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "debugd/src/perf_tool.h"

#include <signal.h>
#include <sys/types.h>
#include <unistd.h>

#include <map>
#include <utility>

#include <base/check.h>
#include <base/check_op.h>
#include <base/functional/bind.h>
#include <base/json/json_reader.h>
#include <base/json/json_writer.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/stringprintf.h>
#include <base/time/time.h>
#include <base/values.h>
#include <brillo/files/file_util.h>

#include "debugd/src/error_utils.h"
#include "debugd/src/helpers/scheduler_configuration_utils.h"
#include "debugd/src/process_with_output.h"

namespace debugd {

namespace {

const char kUnsupportedPerfToolErrorName[] =
    "org.chromium.debugd.error.UnsupportedPerfTool";
const char kProcessErrorName[] = "org.chromium.debugd.error.RunProcess";
const char kStopProcessErrorName[] = "org.chromium.debugd.error.StopProcess";
const char kInvalidPerfArgumentErrorName[] =
    "org.chromium.debugd.error.InvalidPerfArgument";

const char kArgsError[] =
    "perf_args must begin with {\"perf\", \"record\"}, "
    " {\"perf\", \"stat\"}, or {\"perf\", \"mem\"}";

// Location of quipper on ChromeOS.
const char kQuipperLocation[] = "/usr/bin/quipper";

// Location of the file which contains the range of online CPU numbers.
const char kCpuTopologyLocation[] = "/sys/devices/system/cpu/online";
// Pattern of the directories that contain information about the idle state of
// a CPU on the system.
const char kCpuIdleStatePathPattern[] =
    "/sys/devices/system/cpu/cpu%s/cpuidle/state%d/disable";
// Location of the file debugd uses to write the cpuidle states.
constexpr char kCpuIdleStateMapLocation[] =
    "/run/debugd/perf_tool/cpuidle_states";
// Boundaries for validate cpuidle states file.
constexpr int kMaxCpuNumber = 1000;
constexpr int kMaxStateNumber = 10;
// Location of the default ETM strobbing settings in configfs.

const char kStrobbingSettingPathPattern[] =
    "/sys/kernel/config/cs-syscfg/features/strobing/params/%s/value";
const int kStrobbingWindow = 512;
const int kStrobbingPeriod = 10000;

enum class OptionType {
  Boolean,  // Has no value.
  Value,    // Uses another argument.
};

// All quipper options and whether they are blocked in the debugd perf_tool.
const std::map<std::string, OptionType> kQuipperOptions = {
    {"--duration", OptionType::Value},
    // Blocked, quipper figures out the full path of perf on its own.
    // {"--perf_path", OptionType::Value},
    // Blocked, perf_tool always return via stdout.
    // {"--output_file", OptionType::Value},
    {"--run_inject", OptionType::Boolean},
    {"--inject_args", OptionType::Value},
};

// Returns one of the above enums given an vector of perf arguments, starting
// with "perf" itself in |args[0]|.
PerfSubcommand GetPerfSubcommandType(std::string command) {
  if (command == "record")
    return PERF_COMMAND_RECORD;
  if (command == "stat")
    return PERF_COMMAND_STAT;
  if (command == "mem")
    return PERF_COMMAND_MEM;
  return PERF_COMMAND_UNSUPPORTED;
}

void AddQuipperArguments(brillo::Process* process,
                         const uint32_t duration_secs,
                         const std::vector<std::string>& perf_args) {
  process->AddArg(kQuipperLocation);
  if (duration_secs > 0) {
    process->AddArg(base::StringPrintf("%u", duration_secs));
  }
  for (const auto& arg : perf_args) {
    process->AddArg(arg);
  }
}

// Parse |all_cpu_states| to get a series of CPU numbers and states to
// construct cpuidle state paths and write the value either in the json
// object or "1" if |disable|. It also performs validation when
// not |disable| (restoring).
//
// The |all_cpu_states| is in json format and simplified and meant to be read
// by tools. For example, given the entry
//
//  "3": {
//     "2": "1",
//  },
//
// it will write "1" to /sys/devices/system/cpu/cpu3/cpuidle/state2/disable.
bool WriteCpuIdleStates(const base::Value::Dict& all_cpu_states,
                        bool disable = false) {
  if (!disable && all_cpu_states.size() > kMaxCpuNumber) {
    LOG(ERROR) << "Malformed cpuidle states format";
    return false;
  }
  bool completed = true;

  for (auto all_states : all_cpu_states) {
    int cpu;
    if (!disable && !base::StringToInt(all_states.first, &cpu)) {
      LOG(ERROR) << "Expecting a CPU number, found " << all_states.first;
      return false;
    }
    if (!disable && !all_states.second.is_dict()) {
      LOG(ERROR) << "Expecting a dictionary for cpuidle";
      return false;
    }
    if (!disable && all_states.second.GetDict().size() > kMaxStateNumber) {
      LOG(ERROR) << "Too many states for cpuidle";
      return false;
    }
    for (auto state_pair : all_states.second.GetDict()) {
      int state;
      if (!base::StringToInt(state_pair.first, &state)) {
        LOG(ERROR) << "State is not a number: " << state_pair.first;
        return false;
      }
      base::FilePath path(base::StringPrintf(kCpuIdleStatePathPattern,
                                             all_states.first.c_str(), state));
      if (base::PathExists(path)) {
        std::string v = "1";
        if (!disable)
          v = state_pair.second.GetString();
        if (!base::WriteFile(path, v)) {
          PLOG(ERROR) << "Failed to write to " << path;
          completed = false;
        }
      }
    }
  }
  if (!completed)
    LOG(ERROR) << "Not all cpuidle states are written";
  return completed;
}

// Disable the cpuidle states for all online CPUs and save the previous
// disable status in a temporary state file. It returns false when any error
// occurs or it finds a prior dirty state file that is not cleaned up.
bool DisableCpuIdleStates() {
  base::FilePath cpuidle_states_path(kCpuIdleStateMapLocation);
  if (base::PathExists(cpuidle_states_path)) {
    LOG(ERROR) << "The cpuidle states are disabled already.";
    return false;
  }
  std::string cpu_range;
  if (!base::ReadFileToString(base::FilePath(kCpuTopologyLocation),
                              &cpu_range)) {
    PLOG(ERROR) << "File listing online CPU range missing.";
    return false;
  }

  std::vector<std::string> cpu_nums;
  if (!SchedulerConfigurationUtils::ParseCPUNumbers(cpu_range, &cpu_nums)) {
    PLOG(ERROR) << "Failed to parse CPU range: " << cpu_range << ".";
    return false;
  }

  base::Value::Dict all_cpu_states;
  for (const auto& cpu : cpu_nums) {
    base::Value::Dict all_states;
    for (int state = 0;; ++state) {
      const auto disable_file = base::FilePath(
          base::StringPrintf(kCpuIdleStatePathPattern, cpu.c_str(), state));
      if (!base::PathExists(disable_file))
        break;

      std::string disable_state;
      base::ReadFileToString(disable_file, &disable_state);
      all_states.Set(base::NumberToString(state),
                     base::CollapseWhitespaceASCII(disable_state, true));
    }
    all_cpu_states.Set(cpu, std::move(all_states));
  }
  std::string json;
  base::JSONWriter::Write(all_cpu_states, &json);
  if (!base::WriteFile(cpuidle_states_path, json.c_str())) {
    PLOG(ERROR) << "Failed to save all cpuidle states";
    return false;
  }
  if (!WriteCpuIdleStates(all_cpu_states, true)) {
    PLOG(ERROR) << "Failed to write cpuidle states";
    return false;
  }
  return true;
}

// Restore the cpuidle states based on the previously saved log file.
// It will try to validate the file's content and also delete the file
// before returning.
void RestoreCpuIdleStates() {
  base::FilePath cpuidle_states_map(kCpuIdleStateMapLocation);
  std::string json;
  if (!base::PathExists(cpuidle_states_map))
    return;
  if (!base::ReadFileToString(cpuidle_states_map, &json)) {
    PLOG(ERROR) << "Failed to read cpuidle states from: "
                << kCpuIdleStateMapLocation;
    return;
  }
  std::optional<base::Value> all_cpu_states = base::JSONReader::Read(json);
  if (all_cpu_states.has_value() && all_cpu_states->is_dict())
    WriteCpuIdleStates(all_cpu_states->GetDict());
  brillo::DeleteFile(cpuidle_states_map);
}

}  // namespace

bool ValidateQuipperArguments(const std::vector<std::string>& qp_args,
                              PerfSubcommand& subcommand,
                              brillo::ErrorPtr* error) {
  for (auto args_iter = qp_args.begin(); args_iter != qp_args.end();
       ++args_iter) {
    if (*args_iter == "--") {
      ++args_iter;
      if (args_iter == qp_args.end()) {
        DEBUGD_ADD_ERROR(error, kUnsupportedPerfToolErrorName, kArgsError);
        return false;
      }

      subcommand = GetPerfSubcommandType(*args_iter);
      if (subcommand == PERF_COMMAND_UNSUPPORTED) {
        DEBUGD_ADD_ERROR(error, kUnsupportedPerfToolErrorName, kArgsError);
        return false;
      }

      return true;
    }

    const auto& it = kQuipperOptions.find(*args_iter);
    if (it == kQuipperOptions.end()) {
      DEBUGD_ADD_ERROR_FMT(error, kInvalidPerfArgumentErrorName,
                           "option %s is not allowed", args_iter->c_str());
      return false;
    }

    if (it->second == OptionType::Value) {
      ++args_iter;
      if (args_iter == qp_args.end()) {
        DEBUGD_ADD_ERROR_FMT(error, kInvalidPerfArgumentErrorName,
                             "option %s needs a following value",
                             args_iter->c_str());
        return false;
      }
    }
  }
  DEBUGD_ADD_ERROR(error, kUnsupportedPerfToolErrorName, kArgsError);
  return false;
}

PerfTool::PerfTool() {
  signal_handler_.Init();
  process_reaper_.Register(&signal_handler_);
  RestoreCpuIdleStates();
  EtmStrobbingSettings();
}

bool PerfTool::GetPerfOutputV2(const std::vector<std::string>& quipper_args,
                               bool disable_cpu_idle,
                               const base::ScopedFD& stdout_fd,
                               uint64_t* session_id,
                               brillo::ErrorPtr* error) {
  PerfSubcommand subcommand;
  if (!ValidateQuipperArguments(quipper_args, subcommand, error))
    return false;  // DEBUGD_ADD_ERROR is already called.

  if (perf_running()) {
    // Do not run multiple sessions at the same time. Attempt to start another
    // profiler session using this method yields a DBus error. Note that
    // starting another session using GetPerfOutput() will still succeed.
    DEBUGD_ADD_ERROR(error, kProcessErrorName, "Existing perf tool running.");
    return false;
  }

  if (disable_cpu_idle) {
    if (!DisableCpuIdleStates()) {
      DEBUGD_ADD_ERROR(error, kProcessErrorName,
                       "Failed to disable CPU idle states");
      return false;
    }
  }

  DCHECK(!profiler_session_id_);

  auto quipper_process = std::make_unique<SandboxedProcess>();
  quipper_process->SandboxAs("root", "root");
  if (!quipper_process->Init()) {
    DEBUGD_ADD_ERROR(error, kProcessErrorName,
                     "Process initialization failure.");
    return false;
  }

  AddQuipperArguments(quipper_process.get(), 0, quipper_args);
  quipper_process->BindFd(stdout_fd.get(), 1);

  if (!quipper_process->Start()) {
    DEBUGD_ADD_ERROR(error, kProcessErrorName, "Process start failure.");
    return false;
  }
  quipper_process_ = std::move(quipper_process);
  DCHECK_GT(quipper_process_->pid(), 0);

  process_reaper_.WatchForChild(
      FROM_HERE, quipper_process_->pid(),
      base::BindOnce(&PerfTool::OnQuipperProcessExited,
                     base::Unretained(this)));

  // When GetPerfOutputV2() is used to run the perf tool, the user will read
  // from the read end of |stdout_fd| until the write end is closed.  At that
  // point, it may make another call to GetPerfOutputFd() and expect that will
  // start another perf run. |stdout_fd| will be closed when the last process
  // holding it exits, which is minijail0 in this case. However, the kernel
  // closes fds before signaling process exit. Therefore, it's possible for
  // |stdout_fd| to be closed and the user tries to run another
  // GetPerfOutputFd() before we're signaled of the process exit. To mitigate
  // this, hold on to a dup() of |stdout_fd| until we're signaled that the
  // process has exited. This guarantees that the caller can make a new
  // GetPerfOutputFd() call when it finishes reading the output.
  quipper_process_output_fd_.reset(dup(stdout_fd.get()));
  DCHECK(quipper_process_output_fd_.is_valid());

  // Generate an opaque, pseudo-unique, session ID using time and process ID.
  profiler_session_id_ = *session_id =
      static_cast<uint64_t>(base::Time::Now().ToTimeT()) << 32 |
      (quipper_process_->pid() & 0xffffffff);

  return true;
}

bool PerfTool::GetPerfOutput(uint32_t duration_secs,
                             const std::vector<std::string>& perf_args,
                             std::vector<uint8_t>* perf_data,
                             std::vector<uint8_t>* perf_stat,
                             int32_t* status,
                             brillo::ErrorPtr* error) {
  PerfSubcommand subcommand;
  if (duration_secs > 0) {  // legacy option style
    if (perf_args.size() < 2) {
      DEBUGD_ADD_ERROR(error, kUnsupportedPerfToolErrorName, kArgsError);
      return false;
    }
    subcommand = GetPerfSubcommandType(perf_args[1]);
    if (perf_args[0] != "perf" || subcommand == PERF_COMMAND_UNSUPPORTED) {
      DEBUGD_ADD_ERROR(error, kUnsupportedPerfToolErrorName, kArgsError);
      return false;
    }
  } else if (!ValidateQuipperArguments(perf_args, subcommand, error)) {
    return false;  // DEBUGD_ADD_ERROR is already called.
  }

  // This whole method is synchronous, so we create a subprocess, let it run to
  // completion, then gather up its output to return it.
  ProcessWithOutput process;
  process.SandboxAs("root", "root");
  if (!process.Init()) {
    DEBUGD_ADD_ERROR(error, kProcessErrorName,
                     "Process initialization failure.");
    return false;
  }

  AddQuipperArguments(&process, duration_secs, perf_args);

  std::string output_string;
  *status = process.Run();
  if (*status != 0) {
    output_string =
        base::StringPrintf("<process exited with status: %d>", *status);
  } else {
    process.GetOutput(&output_string);
  }

  switch (subcommand) {
    case PERF_COMMAND_RECORD:
    case PERF_COMMAND_MEM:
      perf_data->assign(output_string.begin(), output_string.end());
      break;
    case PERF_COMMAND_STAT:
      perf_stat->assign(output_string.begin(), output_string.end());
      break;
    default:
      // Discard the output.
      break;
  }

  return true;
}

void PerfTool::OnQuipperProcessExited(const siginfo_t& siginfo) {
  // Called after SIGCHLD has been received from the signalfd file descriptor.
  // Wait() for the child process wont' block. It'll just reap the zombie child
  // process.
  quipper_process_->Wait();
  quipper_process_ = nullptr;
  quipper_process_output_fd_.reset();

  profiler_session_id_.reset();

  RestoreCpuIdleStates();
}

bool PerfTool::GetPerfOutputFd(uint32_t duration_secs,
                               const std::vector<std::string>& perf_args,
                               const base::ScopedFD& stdout_fd,
                               uint64_t* session_id,
                               brillo::ErrorPtr* error) {
  PerfSubcommand subcommand;
  if (duration_secs > 0) {  // legacy option style
    if (perf_args.size() < 2) {
      DEBUGD_ADD_ERROR(error, kUnsupportedPerfToolErrorName, kArgsError);
      return false;
    }
    subcommand = GetPerfSubcommandType(perf_args[1]);
    if (perf_args[0] != "perf" || subcommand == PERF_COMMAND_UNSUPPORTED) {
      DEBUGD_ADD_ERROR(error, kUnsupportedPerfToolErrorName, kArgsError);
      return false;
    }
  } else if (!ValidateQuipperArguments(perf_args, subcommand, error)) {
    return false;  // DEBUGD_ADD_ERROR is already called.
  }

  if (perf_running()) {
    // Do not run multiple sessions at the same time. Attempt to start another
    // profiler session using this method yields a DBus error. Note that
    // starting another session using GetPerfOutput() will still succeed.
    DEBUGD_ADD_ERROR(error, kProcessErrorName, "Existing perf tool running.");
    return false;
  }

  DCHECK(!profiler_session_id_);

  auto quipper_process = std::make_unique<SandboxedProcess>();
  quipper_process->SandboxAs("root", "root");
  if (!quipper_process->Init()) {
    DEBUGD_ADD_ERROR(error, kProcessErrorName,
                     "Process initialization failure.");
    return false;
  }

  AddQuipperArguments(quipper_process.get(), duration_secs, perf_args);
  quipper_process->BindFd(stdout_fd.get(), 1);

  if (!quipper_process->Start()) {
    DEBUGD_ADD_ERROR(error, kProcessErrorName, "Process start failure.");
    return false;
  }
  quipper_process_ = std::move(quipper_process);
  DCHECK_GT(quipper_process_->pid(), 0);

  process_reaper_.WatchForChild(
      FROM_HERE, quipper_process_->pid(),
      base::BindOnce(&PerfTool::OnQuipperProcessExited,
                     base::Unretained(this)));

  // When GetPerfOutputFd() is used to run the perf tool, the user will read
  // from the read end of |stdout_fd| until the write end is closed.  At that
  // point, it may make another call to GetPerfOutputFd() and expect that will
  // start another perf run. |stdout_fd| will be closed when the last process
  // holding it exits, which is minijail0 in this case. However, the kernel
  // closes fds before signaling process exit. Therefore, it's possible for
  // |stdout_fd| to be closed and the user tries to run another
  // GetPerfOutputFd() before we're signaled of the process exit. To mitigate
  // this, hold on to a dup() of |stdout_fd| until we're signaled that the
  // process has exited. This guarantees that the caller can make a new
  // GetPerfOutputFd() call when it finishes reading the output.
  quipper_process_output_fd_.reset(dup(stdout_fd.get()));
  DCHECK(quipper_process_output_fd_.is_valid());

  // Generate an opaque, pseudo-unique, session ID using time and process ID.
  profiler_session_id_ = *session_id =
      static_cast<uint64_t>(base::Time::Now().ToTimeT()) << 32 |
      (quipper_process_->pid() & 0xffffffff);

  return true;
}

bool PerfTool::StopPerf(uint64_t session_id, brillo::ErrorPtr* error) {
  if (!profiler_session_id_) {
    DEBUGD_ADD_ERROR(error, kStopProcessErrorName, "Perf tool not started");
    return false;
  }

  if (profiler_session_id_ != session_id) {
    // Session ID mismatch: return a failure without affecting the existing
    // profiler session.
    DEBUGD_ADD_ERROR(error, kStopProcessErrorName,
                     "Invalid profile session id.");
    return false;
  }

  // Stop by sending SIGINT to the profiler session. The sandboxed quipper
  // process will be reaped in OnQuipperProcessExited().
  if (quipper_process_) {
    DCHECK_GT(quipper_process_->pid(), 0);
    if (kill(quipper_process_->pid(), SIGINT) != 0) {
      PLOG(WARNING) << "Failed to stop the profiler session.";
    }
  }

  return true;
}

void PerfTool::EtmStrobbingSettings() {
  const base::FilePath window_path = base::FilePath(
      base::StringPrintf(kStrobbingSettingPathPattern, "window"));
  const base::FilePath period_path = base::FilePath(
      base::StringPrintf(kStrobbingSettingPathPattern, "period"));
  if (!base::PathExists(window_path) || !base::PathExists(period_path))
    return;

  std::string ws, ps;
  base::ReadFileToString(window_path, &ws);
  base::ReadFileToString(period_path, &ps);
  int window, period;
  base::HexStringToInt(ws, &window);
  base::HexStringToInt(ps, &period);
  if (window != kStrobbingWindow) {
    base::WriteFile(window_path, std::to_string(kStrobbingWindow));
    VLOG(1) << "ETM Strobbing window set to " << kStrobbingWindow;
  }
  if (period != kStrobbingPeriod) {
    base::WriteFile(period_path, std::to_string(kStrobbingPeriod));
    VLOG(1) << "ETM Strobbing period set to " << kStrobbingPeriod;
  }
  etm_available = true;
}

}  // namespace debugd
