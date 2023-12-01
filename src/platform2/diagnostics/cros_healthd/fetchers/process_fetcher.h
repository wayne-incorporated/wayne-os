// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_FETCHERS_PROCESS_FETCHER_H_
#define DIAGNOSTICS_CROS_HEALTHD_FETCHERS_PROCESS_FETCHER_H_

#include <sys/types.h>

#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <base/files/file_path.h>
#include <base/functional/callback.h>

#include "diagnostics/cros_healthd/fetchers/base_fetcher.h"
#include "diagnostics/cros_healthd/system/context.h"
#include "diagnostics/mojom/public/cros_healthd_probe.mojom.h"

namespace diagnostics {

// The ProcessFetcher class is responsible for gathering information about a
// particular or multiple/ all processes on the device.
class ProcessFetcher final : public BaseFetcher {
 public:
  // Only override |root_dir| for testing.
  ProcessFetcher(Context* context,
                 const base::FilePath& root_dir = base::FilePath("/"));

  // Returns information about a particular process on the device, or the error
  // that occurred retrieving the information. |process_id| is the PID for the
  // process whose information will be fetched.
  void FetchProcessInfo(
      uint32_t process_id,
      base::OnceCallback<void(ash::cros_healthd::mojom::ProcessResultPtr)>
          callback);

  // Returns information about multiple specified or all processes on the
  // device, and the errors if any occurred and not ignored when retrieving the
  // information. |input_process_ids| is the array of PIDs for the processes
  // whose information will be fetched. |ignore_single_process_error| will
  // enable errors to be ignored when fetching process infos if set to true.
  void FetchMultipleProcessInfo(
      const std::optional<std::vector<uint32_t>>& input_process_ids,
      const bool ignore_single_process_error,
      base::OnceCallback<
          void(ash::cros_healthd::mojom::MultipleProcessResultPtr)> callback);

 private:
  // Collects |process_info| through `ParseProcPidStat`, `ParseProcPidStatm`,
  // `CalculateProcessUptime`, `GetProcessUid` for |pid|.
  std::optional<ash::cros_healthd::mojom::ProbeErrorPtr> GetProcessInfo(
      uint32_t pid, ash::cros_healthd::mojom::ProcessInfo* process_info);
  // Parses relevant fields from /proc/|process_id_|/stat. Returns the first
  // error encountered or std::nullopt if no errors occurred. |priority|,
  // |nice|, |start_time_ticks|, |name|, |parent_process_id|,
  // |process_group_id|, |threads| and |process_id| are only valid if
  // std::nullopt was returned.
  std::optional<ash::cros_healthd::mojom::ProbeErrorPtr> ParseProcPidStat(
      ash::cros_healthd::mojom::ProcessState* state,
      int8_t* priority,
      int8_t* nice,
      uint64_t* start_time_ticks,
      std::optional<std::string>* name,
      uint32_t* parent_process_id,
      uint32_t* process_group_id,
      uint32_t* threads,
      uint32_t* process_id,
      base::FilePath proc_pid_dir);

  // Parses relevant fields from /proc/|process_id_|/statm. Returns the first
  // error encountered or std::nullopt if no errors occurred.
  // |total_memory_kib|, |resident_memory_kib| and |free_memory_kib| are only
  // valid if std::nullopt was returned.
  std::optional<ash::cros_healthd::mojom::ProbeErrorPtr> ParseProcPidStatm(
      uint32_t* total_memory_kib,
      uint32_t* resident_memory_kib,
      uint32_t* free_memory_kib,
      base::FilePath proc_pid_dir);

  // Calculates the uptime of the process in clock ticks using
  // |start_time_ticks|. Returns the first error encountered or std::nullopt if
  // no errors occurred. |process_uptime_ticks| is only valid if std::nullopt
  // was returned.
  std::optional<ash::cros_healthd::mojom::ProbeErrorPtr> CalculateProcessUptime(
      uint64_t start_time_ticks, uint64_t* process_uptime_ticks);

  // Fetches the real user ID of the process. Returns the first error
  // encountered or std::nullopt if no errors occurred. |user_id| is only
  // valid if std::nullopt was returned.
  std::optional<ash::cros_healthd::mojom::ProbeErrorPtr> GetProcessUid(
      uid_t* user_id, base::FilePath proc_pid_dir);

  // File paths read will be relative to |root_dir_|. In production, this should
  // be "/", but it can be overridden for testing.
  const base::FilePath root_dir_;
};

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_FETCHERS_PROCESS_FETCHER_H_
