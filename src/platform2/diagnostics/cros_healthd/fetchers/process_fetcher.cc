// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/cros_healthd/fetchers/process_fetcher.h"

#include <unistd.h>

#include <cstdint>
#include <limits>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include <base/check.h>
#include <base/files/file_enumerator.h>
#include <base/files/file_path.h>
#include <base/functional/bind.h>
#include <base/numerics/safe_conversions.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_split.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>
#include <re2/re2.h>

#include "diagnostics/base/file_utils.h"
#include "diagnostics/cros_healthd/utils/error_utils.h"
#include "diagnostics/cros_healthd/utils/procfs_utils.h"
#include "diagnostics/mojom/public/cros_healthd_probe.mojom.h"

namespace diagnostics {

namespace {

namespace mojom = ::ash::cros_healthd::mojom;

// Regex used to parse a process's statm file.
constexpr char kProcessStatmFileRegex[] =
    R"((\d+)\s+(\d+)\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+)";
// Regex used to parse procfs's uptime file.
constexpr char kUptimeFileRegex[] = R"(([.\d]+)\s+[.\d]+)";
// Regex used to parse the process's Uid field in the status file.
constexpr char kUidStatusRegex[] = R"(Uid:\s*(\d+)\s+\d+\s+\d+\s+\d+)";
// Regex used to parse a process's I/O file.
constexpr char kProcessIOFileRegex[] =
    R"(rchar:\s+(\d+)\nwchar:\s+(\d+)\nsyscr:\s+(\d+)\nsyscw:\s+(\d+)\nread)"
    R"(_bytes:\s+(\d+)\nwrite_bytes:\s+(\d+)\ncancelled_write_bytes:\s+(\d+))";

// Converts the raw process state read from procfs to a mojom::ProcessState.
// If the conversion is successful, returns std::nullopt and sets
// |mojo_state_out| to the converted value. If the conversion fails,
// |mojo_state_out| is invalid and an appropriate error is returned.
std::optional<mojom::ProbeErrorPtr> GetProcessState(
    base::StringPiece raw_state, mojom::ProcessState* mojo_state_out) {
  DCHECK(mojo_state_out);
  // See https://man7.org/linux/man-pages/man5/proc.5.html for allowable raw
  // state values.
  if (raw_state == "R") {
    *mojo_state_out = mojom::ProcessState::kRunning;
  } else if (raw_state == "S") {
    *mojo_state_out = mojom::ProcessState::kSleeping;
  } else if (raw_state == "D") {
    *mojo_state_out = mojom::ProcessState::kWaiting;
  } else if (raw_state == "Z") {
    *mojo_state_out = mojom::ProcessState::kZombie;
  } else if (raw_state == "T") {
    *mojo_state_out = mojom::ProcessState::kStopped;
  } else if (raw_state == "t") {
    *mojo_state_out = mojom::ProcessState::kTracingStop;
  } else if (raw_state == "X") {
    *mojo_state_out = mojom::ProcessState::kDead;
  } else if (raw_state == "I") {
    *mojo_state_out = mojom::ProcessState::kIdle;
  } else {
    return CreateAndLogProbeError(
        mojom::ErrorType::kParseError,
        "Undefined process state: " + std::string(raw_state));
  }

  return std::nullopt;
}

// Converts |str| to a signed, 8-bit integer. If the conversion is successful,
// returns std::nullopt and sets |int_out| to the converted value. If the
// conversion fails, |int_out| is invalid and an appropriate error is returned.
std::optional<mojom::ProbeErrorPtr> GetInt8FromString(base::StringPiece str,
                                                      int8_t* int_out) {
  DCHECK(int_out);

  int full_size_int;
  if (!base::StringToInt(str, &full_size_int)) {
    return CreateAndLogProbeError(
        mojom::ErrorType::kParseError,
        "Failed to convert " + std::string(str) + " to int.");
  }

  if (full_size_int > std::numeric_limits<int8_t>::max()) {
    return CreateAndLogProbeError(
        mojom::ErrorType::kParseError,
        "Integer too large for int8_t: " + base::NumberToString(full_size_int));
  }

  *int_out = static_cast<int8_t>(full_size_int);

  return std::nullopt;
}

std::optional<mojom::ProbeErrorPtr> ParseIOContents(
    std::string io_content, mojom::ProcessInfoPtr& process_info) {
  std::string bytes_read_str;
  std::string bytes_written_str;
  std::string read_system_calls_str;
  std::string write_system_calls_str;
  std::string physical_bytes_read_str;
  std::string physical_bytes_written_str;
  std::string cancelled_bytes_written_str;
  if (!RE2::FullMatch(io_content, kProcessIOFileRegex, &bytes_read_str,
                      &bytes_written_str, &read_system_calls_str,
                      &write_system_calls_str, &physical_bytes_read_str,
                      &physical_bytes_written_str,
                      &cancelled_bytes_written_str)) {
    return CreateAndLogProbeError(mojom::ErrorType::kParseError,
                                  "Failed to parse process IO file");
  }

  if (!base::StringToUint64(bytes_read_str, &process_info->bytes_read)) {
    return CreateAndLogProbeError(
        mojom::ErrorType::kParseError,
        "Failed to convert bytes_read to uint64_t: " + bytes_read_str);
  }

  if (!base::StringToUint64(bytes_written_str, &process_info->bytes_written)) {
    return CreateAndLogProbeError(
        mojom::ErrorType::kParseError,
        "Failed to convert bytes_written to uint64_t: " + bytes_written_str);
  }

  if (!base::StringToUint64(read_system_calls_str,
                            &process_info->read_system_calls)) {
    return CreateAndLogProbeError(
        mojom::ErrorType::kParseError,
        "Failed to convert read_system_calls to uint64_t: " +
            read_system_calls_str);
  }

  if (!base::StringToUint64(write_system_calls_str,
                            &process_info->write_system_calls)) {
    return CreateAndLogProbeError(
        mojom::ErrorType::kParseError,
        "Failed to convert write_system_calls to uint64_t: " +
            write_system_calls_str);
  }

  if (!base::StringToUint64(physical_bytes_read_str,
                            &process_info->physical_bytes_read)) {
    return CreateAndLogProbeError(
        mojom::ErrorType::kParseError,
        "Failed to convert physical_bytes_read to uint64_t: " +
            physical_bytes_read_str);
  }

  if (!base::StringToUint64(physical_bytes_written_str,
                            &process_info->physical_bytes_written)) {
    return CreateAndLogProbeError(
        mojom::ErrorType::kParseError,
        "Failed to convert physical_bytes_written to uint64_t: " +
            physical_bytes_written_str);
  }

  if (!base::StringToUint64(cancelled_bytes_written_str,
                            &process_info->cancelled_bytes_written)) {
    return CreateAndLogProbeError(
        mojom::ErrorType::kParseError,
        "Failed to convert cancelled_bytes_written to uint64_t: " +
            cancelled_bytes_written_str);
  }
  return std::nullopt;
}

void FinishFetchingProcessInfo(
    base::OnceCallback<void(mojom::ProcessResultPtr)> callback,
    uint32_t process_id,
    mojom::ProcessInfo process_info,
    const base::flat_map<uint32_t, std::string>& io_contents) {
  if (io_contents.empty() || !io_contents.contains(process_id)) {
    std::move(callback).Run(mojom::ProcessResult::NewError(
        CreateAndLogProbeError(mojom::ErrorType::kFileReadError,
                               "Failed to read process IO file")));
    return;
  }

  mojom::ProcessInfoPtr process_info_ptr = process_info.Clone();
  auto error = ParseIOContents(io_contents.at(process_id), process_info_ptr);
  if (error.has_value()) {
    std::move(callback).Run(mojom::ProcessResult::NewError(error->Clone()));
    return;
  } else {
    std::move(callback).Run(
        mojom::ProcessResult::NewProcessInfo(std::move(process_info_ptr)));
    return;
  }
}

void FinishFetchingMultipleProcessInfo(
    base::OnceCallback<void(mojom::MultipleProcessResultPtr)> callback,
    const bool ignore_single_process_error,
    std::vector<std::pair<uint32_t, mojom::ProcessInfoPtr>>
        multiple_process_info,
    std::vector<std::pair<uint32_t, mojom::ProbeErrorPtr>> errors,
    const base::flat_map<uint32_t, std::string>& all_io_contents) {
  for (auto it = multiple_process_info.begin();
       it != multiple_process_info.end();) {
    uint32_t pid = it->first;
    if (!all_io_contents.contains(pid)) {
      if (!ignore_single_process_error) {
        errors.push_back(
            {pid, CreateAndLogProbeError(mojom::ErrorType::kFileReadError,
                                         "Failed to read process IO file")});
      }
      it = multiple_process_info.erase(it);
      continue;
    }
    auto error = ParseIOContents(all_io_contents.at(pid), it->second);
    if (error.has_value()) {
      if (!ignore_single_process_error) {
        errors.push_back({pid, error->Clone()});
      }
      it = multiple_process_info.erase(it);
      continue;
    }
    ++it;
  }

  mojom::MultipleProcessResultPtr multiple_process_result =
      mojom::MultipleProcessResult::New(
          base::flat_map<uint32_t, mojom::ProcessInfoPtr>{
              std::move(multiple_process_info)},
          base::flat_map<uint32_t, mojom::ProbeErrorPtr>{std::move(errors)});
  std::move(callback).Run(std::move(multiple_process_result));

  return;
}

}  // namespace

ProcessFetcher::ProcessFetcher(Context* context, const base::FilePath& root_dir)
    : BaseFetcher(context), root_dir_(root_dir) {}

void ProcessFetcher::FetchProcessInfo(
    uint32_t process_id,
    base::OnceCallback<void(mojom::ProcessResultPtr)> callback) {
  mojom::ProcessInfo process_info;
  auto error = GetProcessInfo(process_id, &process_info);
  if (error.has_value()) {
    std::move(callback).Run(
        mojom::ProcessResult::NewError(std::move(error.value())));
    return;
  }

  context_->executor()->GetProcessIOContents(
      {base::checked_cast<uint32_t>(process_id)},
      base::BindOnce(&FinishFetchingProcessInfo, std::move(callback),
                     std::move(process_id), std::move(process_info)));
}

void ProcessFetcher::FetchMultipleProcessInfo(
    const std::optional<std::vector<uint32_t>>& input_process_ids,
    const bool ignore_single_process_error,
    base::OnceCallback<void(mojom::MultipleProcessResultPtr)> callback) {
  std::vector<std::pair<uint32_t, mojom::ProcessInfoPtr>> process_infos;
  std::vector<std::pair<uint32_t, mojom::ProbeErrorPtr>> errors;
  std::set<uint32_t> process_ids;
  if (!input_process_ids.has_value()) {
    base::FileEnumerator enumerator(root_dir_.Append("proc"), false,
                                    base::FileEnumerator::DIRECTORIES);
    for (base::FilePath proc_path = enumerator.Next(); !proc_path.empty();
         proc_path = enumerator.Next()) {
      uint32_t process_id;
      if (base::StringToUint(proc_path.BaseName().value(), &process_id)) {
        process_ids.insert(process_id);
      }
    }
  } else {
    for (const auto& input_process_id : *input_process_ids) {
      process_ids.insert(input_process_id);
    }
  }

  for (auto it = process_ids.begin(); it != process_ids.end();) {
    mojom::ProcessInfo process_info;
    uint32_t process_id = *it;
    auto error = GetProcessInfo(process_id, &process_info);
    if (error.has_value()) {
      if (!ignore_single_process_error) {
        errors.push_back({process_id, error->Clone()});
      }
      it = process_ids.erase(it);
    } else {
      process_infos.push_back({process_id, process_info.Clone()});
      ++it;
    }
  }

  context_->executor()->GetProcessIOContents(
      {process_ids.begin(), process_ids.end()},
      base::BindOnce(&FinishFetchingMultipleProcessInfo, std::move(callback),
                     ignore_single_process_error, std::move(process_infos),
                     std::move(errors)));
}

std::optional<mojom::ProbeErrorPtr> ProcessFetcher::GetProcessInfo(
    uint32_t pid, mojom::ProcessInfo* process_info) {
  base::FilePath proc_pid_dir = GetProcProcessDirectoryPath(root_dir_, pid);

  // Number of ticks after system boot that the process started.
  uint64_t start_time_ticks;
  auto error = ParseProcPidStat(
      &process_info->state, &process_info->priority, &process_info->nice,
      &start_time_ticks, &process_info->name, &process_info->parent_process_id,
      &process_info->process_group_id, &process_info->threads,
      &process_info->process_id, proc_pid_dir);
  if (error.has_value()) {
    return error;
  }

  error = CalculateProcessUptime(start_time_ticks, &process_info->uptime_ticks);
  if (error.has_value()) {
    return error;
  }

  error = ParseProcPidStatm(&process_info->total_memory_kib,
                            &process_info->resident_memory_kib,
                            &process_info->free_memory_kib, proc_pid_dir);
  if (error.has_value()) {
    return error;
  }

  uid_t user_id;
  error = GetProcessUid(&user_id, proc_pid_dir);
  if (error.has_value()) {
    return error;
  }

  process_info->user_id = static_cast<uint32_t>(user_id);
  if (!ReadAndTrimString(proc_pid_dir, kProcessCmdlineFile,
                         &process_info->command)) {
    return CreateAndLogProbeError(
        mojom::ErrorType::kFileReadError,
        "Failed to read " + proc_pid_dir.Append(kProcessCmdlineFile).value());
  }

  // In "/proc/{PID}/cmdline", the arguments are separated by 0x00, we need
  // to replace them by space for better output.
  for (auto& ch : process_info->command) {
    if (ch == '\0') {
      ch = ' ';
    }
  }
  base::TrimWhitespaceASCII(process_info->command, base::TRIM_ALL,
                            &process_info->command);

  return std::nullopt;
}

std::optional<mojom::ProbeErrorPtr> ProcessFetcher::ParseProcPidStat(
    mojom::ProcessState* state,
    int8_t* priority,
    int8_t* nice,
    uint64_t* start_time_ticks,
    std::optional<std::string>* name,
    uint32_t* parent_process_id,
    uint32_t* process_group_id,
    uint32_t* threads,
    uint32_t* process_id,
    base::FilePath proc_pid_dir) {
  // Note that start_time_ticks, name, parent_process_id, process_group_id,
  // threads, process_id are the only pointers actually dereferenced in this
  // function. The helper functions which set |state|, |priority| and |nice| are
  // responsible for checking the validity of those three pointers.
  DCHECK(start_time_ticks);
  DCHECK(name);
  DCHECK(parent_process_id);
  DCHECK(process_group_id);
  DCHECK(threads);
  DCHECK(process_id);

  std::string stat_contents;
  const base::FilePath kProcPidStatFile = proc_pid_dir.Append(kProcessStatFile);
  if (!ReadAndTrimString(proc_pid_dir, kProcessStatFile, &stat_contents)) {
    return CreateAndLogProbeError(mojom::ErrorType::kFileReadError,
                                  "Failed to read " + kProcPidStatFile.value());
  }

  std::vector<base::StringPiece> stat_tokens =
      base::SplitStringPiece(stat_contents, base::kWhitespaceASCII,
                             base::KEEP_WHITESPACE, base::SPLIT_WANT_NONEMPTY);

  if (stat_tokens.size() <= ProcPidStatIndices::kMaxValue) {
    return CreateAndLogProbeError(
        mojom::ErrorType::kParseError,
        "Failed to tokenize " + kProcPidStatFile.value());
  }

  auto error = GetProcessState(stat_tokens[ProcPidStatIndices::kState], state);
  if (error.has_value())
    return error;

  error =
      GetInt8FromString(stat_tokens[ProcPidStatIndices::kPriority], priority);
  if (error.has_value())
    return error;

  error = GetInt8FromString(stat_tokens[ProcPidStatIndices::kNice], nice);
  if (error.has_value())
    return error;

  base::StringPiece start_time_str =
      stat_tokens[ProcPidStatIndices::kStartTime];
  if (!base::StringToUint64(start_time_str, start_time_ticks)) {
    return CreateAndLogProbeError(mojom::ErrorType::kParseError,
                                  "Failed to convert starttime to uint64: " +
                                      std::string(start_time_str));
  }

  base::StringPiece process_id_str =
      stat_tokens[ProcPidStatIndices::kProcessID];
  if (!base::StringToUint(process_id_str, process_id)) {
    return CreateAndLogProbeError(mojom::ErrorType::kParseError,
                                  "Failed to convert process id to uint32: " +
                                      std::string(process_id_str));
  }

  // In "/proc/{PID}/stat", the filename of the executable is displayed in
  // parentheses, we need to remove them to get original value.
  std::string name_str = std::string(stat_tokens[ProcPidStatIndices::kName]);
  name_str = name_str.substr(1, name_str.size() - 2);
  *name = std::optional<std::string>(name_str);

  base::StringPiece parent_process_id_str =
      stat_tokens[ProcPidStatIndices::kParentProcessID];
  if (!base::StringToUint(parent_process_id_str, parent_process_id)) {
    return CreateAndLogProbeError(
        mojom::ErrorType::kParseError,
        "Failed to convert parent process id to uint32: " +
            std::string(parent_process_id_str));
  }

  base::StringPiece process_group_id_str =
      stat_tokens[ProcPidStatIndices::kProcessGroupID];
  if (!base::StringToUint(process_group_id_str, process_group_id)) {
    return CreateAndLogProbeError(
        mojom::ErrorType::kParseError,
        "Failed to convert process group id to uint32: " +
            std::string(process_group_id_str));
  }

  base::StringPiece threads_str = stat_tokens[ProcPidStatIndices::kThreads];
  if (!base::StringToUint(threads_str, threads)) {
    return CreateAndLogProbeError(
        mojom::ErrorType::kParseError,
        "Failed to convert threads to uint32: " + std::string(threads_str));
  }

  return std::nullopt;
}

std::optional<mojom::ProbeErrorPtr> ProcessFetcher::ParseProcPidStatm(
    uint32_t* total_memory_kib,
    uint32_t* resident_memory_kib,
    uint32_t* free_memory_kib,
    base::FilePath proc_pid_dir) {
  DCHECK(total_memory_kib);
  DCHECK(resident_memory_kib);
  DCHECK(free_memory_kib);

  std::string statm_contents;
  if (!ReadAndTrimString(proc_pid_dir, kProcessStatmFile, &statm_contents)) {
    return CreateAndLogProbeError(
        mojom::ErrorType::kFileReadError,
        "Failed to read " + proc_pid_dir.Append(kProcessStatmFile).value());
  }

  std::string total_memory_pages_str;
  std::string resident_memory_pages_str;
  if (!RE2::FullMatch(statm_contents, kProcessStatmFileRegex,
                      &total_memory_pages_str, &resident_memory_pages_str)) {
    return CreateAndLogProbeError(
        mojom::ErrorType::kParseError,
        "Failed to parse process's statm file: " + statm_contents);
  }

  uint32_t total_memory_pages;
  if (!base::StringToUint(total_memory_pages_str, &total_memory_pages)) {
    return CreateAndLogProbeError(
        mojom::ErrorType::kParseError,
        "Failed to convert total memory to uint32_t: " +
            total_memory_pages_str);
  }

  uint32_t resident_memory_pages;
  if (!base::StringToUint(resident_memory_pages_str, &resident_memory_pages)) {
    return CreateAndLogProbeError(
        mojom::ErrorType::kParseError,
        "Failed to convert resident memory to uint32_t: " +
            resident_memory_pages_str);
  }

  if (resident_memory_pages > total_memory_pages) {
    return CreateAndLogProbeError(
        mojom::ErrorType::kParseError,
        base::StringPrintf("Process's resident memory (%u pages) higher than "
                           "total memory (%u pages).",
                           resident_memory_pages, total_memory_pages));
  }

  const auto kPageSizeInBytes = sysconf(_SC_PAGESIZE);
  if (kPageSizeInBytes == -1) {
    return CreateAndLogProbeError(mojom::ErrorType::kSystemUtilityError,
                                  "Failed to run sysconf(_SC_PAGESIZE).");
  }

  const auto kPageSizeInKiB = kPageSizeInBytes / 1024;

  *total_memory_kib =
      static_cast<uint32_t>(total_memory_pages * kPageSizeInKiB);
  *resident_memory_kib =
      static_cast<uint32_t>(resident_memory_pages * kPageSizeInKiB);
  *free_memory_kib = static_cast<uint32_t>(
      (total_memory_pages - resident_memory_pages) * kPageSizeInKiB);

  return std::nullopt;
}

std::optional<mojom::ProbeErrorPtr> ProcessFetcher::CalculateProcessUptime(
    uint64_t start_time_ticks, uint64_t* process_uptime_ticks) {
  DCHECK(process_uptime_ticks);

  std::string uptime_contents;
  base::FilePath uptime_path = GetProcUptimePath(root_dir_);
  if (!ReadAndTrimString(uptime_path, &uptime_contents)) {
    return CreateAndLogProbeError(mojom::ErrorType::kFileReadError,
                                  "Failed to read " + uptime_path.value());
  }

  std::string system_uptime_str;
  if (!RE2::FullMatch(uptime_contents, kUptimeFileRegex, &system_uptime_str)) {
    return CreateAndLogProbeError(
        mojom::ErrorType::kParseError,
        "Failed to parse uptime file: " + uptime_contents);
  }

  double system_uptime_seconds;
  if (!base::StringToDouble(system_uptime_str, &system_uptime_seconds)) {
    return CreateAndLogProbeError(
        mojom::ErrorType::kParseError,
        "Failed to convert system uptime to double: " + system_uptime_str);
  }

  const auto kClockTicksPerSecond = sysconf(_SC_CLK_TCK);
  if (kClockTicksPerSecond == -1) {
    return CreateAndLogProbeError(mojom::ErrorType::kSystemUtilityError,
                                  "Failed to run sysconf(_SC_CLK_TCK).");
  }

  *process_uptime_ticks =
      static_cast<uint64_t>(system_uptime_seconds *
                            static_cast<double>(kClockTicksPerSecond)) -
      start_time_ticks;
  return std::nullopt;
}

std::optional<mojom::ProbeErrorPtr> ProcessFetcher::GetProcessUid(
    uid_t* user_id, base::FilePath proc_pid_dir) {
  DCHECK(user_id);

  std::string status_contents;
  if (!ReadAndTrimString(proc_pid_dir, kProcessStatusFile, &status_contents)) {
    return CreateAndLogProbeError(
        mojom::ErrorType::kFileReadError,
        "Failed to read " + proc_pid_dir.Append(kProcessStatusFile).value());
  }

  std::vector<std::string> status_lines = base::SplitString(
      status_contents, "\n", base::TRIM_WHITESPACE, base::SPLIT_WANT_NONEMPTY);

  bool uid_key_found = false;
  std::string uid_str;
  for (const auto& line : status_lines) {
    if (!RE2::FullMatch(line, kUidStatusRegex, &uid_str))
      continue;

    unsigned int user_id_uint;
    if (!base::StringToUint(uid_str, &user_id_uint)) {
      return CreateAndLogProbeError(
          mojom::ErrorType::kParseError,
          "Failed to convert Uid to uint: " + uid_str);
    }

    *user_id = static_cast<uid_t>(user_id_uint);

    uid_key_found = true;
    break;
  }

  if (!uid_key_found) {
    return CreateAndLogProbeError(mojom::ErrorType::kParseError,
                                  "Failed to find Uid key.");
  }

  return std::nullopt;
}

}  // namespace diagnostics
