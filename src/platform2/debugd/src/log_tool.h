// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DEBUGD_SRC_LOG_TOOL_H_
#define DEBUGD_SRC_LOG_TOOL_H_

#include <sys/types.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <unordered_map>
#include <vector>

#include <base/files/file_path.h>
#include <base/files/scoped_file.h>
#include <base/files/scoped_temp_dir.h>
#include <base/memory/ref_counted.h>
#include <base/system/sys_info.h>
#include <base/values.h>
#include <brillo/process/process.h>
#include <cryptohome/proto_bindings/rpc.pb.h>
#include <cryptohome/proto_bindings/UserDataAuth.pb.h>
#include <dbus/bus.h>
#include <user_data_auth-client/user_data_auth/dbus-proxies.h>

#include "base/time/time.h"
#include "debugd/src/log_provider.h"
#include "debugd/src/perf_tool.h"
#include "debugd/src/sandboxed_process.h"

namespace debugd {

class LogTool : public debugd::LogProvider {
 public:
  // The encoding for a particular log.
  enum class Encoding {
    // Tries to see if the log output is valid UTF-8. Outputs it as-is if it is,
    // or base64-encodes it otherwise.
    kAutodetect,

    // Replaces any characters that are not valid UTF-8 encoded with the
    // replacement character.
    kUtf8,

    // base64-encodes the output.
    kBase64,

    // Doesn't apply an encoding. Copies the data as is.
    kBinary,
  };

  class Log {
   public:
    enum LogType { kCommand, kFile, kGlob };

    static constexpr int64_t kDefaultMaxBytes = 512 * 1024;

    Log(LogType type,
        std::string name,
        std::string data,
        std::string user = SandboxedProcess::kDefaultUser,
        std::string group = SandboxedProcess::kDefaultGroup,
        int64_t max_bytes = kDefaultMaxBytes,
        LogTool::Encoding encoding = LogTool::Encoding::kAutodetect,
        bool access_root_mount_ns = false);

    virtual ~Log() = default;

    std::string GetName() const;
    LogType GetType() const;
    LogTool::Encoding GetEncoding() const;
    virtual std::string GetLogData() const;
    int64_t GetMaxBytes() const;

    std::string GetCommandLogData() const;
    std::string GetFileLogData() const;
    std::string GetGlobLogData() const;

    void DisableMinijailForTest();
    // Config and start the child process to collect log. The log data will be
    // saved to the |output_file_name|.
    bool StartToGetLogData(std::unique_ptr<SandboxedProcess>& child_proc,
                           const base::FilePath& output_file_name) const;

   protected:
    Log() = default;  // For testing only.

   private:
    static uid_t UidForUser(const std::string& name);
    static gid_t GidForGroup(const std::string& group);
    static std::string GetFileData(const base::FilePath& path,
                                   int64_t max_bytes,
                                   const std::string& user,
                                   const std::string& group);

    LogType type_;
    std::string name_;
    // For kCommand logs, this is the command to run.
    // For kFile logs, this is the file path to read.
    std::string data_;
    std::string user_;
    std::string group_;
    int64_t max_bytes_;  // passed as arg to 'tail -c'
    LogTool::Encoding encoding_;
    bool access_root_mount_ns_;

    bool minijail_disabled_for_test_ = false;
  };

  // A helper class to collect logs in parallel.
  class ParallelLogCollector {
   public:
    explicit ParallelLogCollector(base::TimeDelta max_wait_time);
    ParallelLogCollector(const ParallelLogCollector&) = delete;
    ParallelLogCollector& operator=(const ParallelLogCollector&) = delete;

    // Starts asynchronous log collection. Each log will be saved to a temp
    // file. Returns false if temp folder creation fails.
    bool StartGetLogs(const std::vector<Log>& log_list);
    // Insert logs collected to the |dict|. Must be called after StartGetLogs().
    // It will wait maximum !timeout_seconds| seconds. The logs which have not
    // finished on time may not be collected.
    void EndGetLogs(base::Value::Dict* dict);

   private:
    void CollectLogs(const std::map<base::FilePath, Log>& filepath_logs,
                     const base::TimeTicks& deadline,
                     const size_t max_parallelism);

    // Specify the maximum number of concurrent tasks.
    const size_t max_parallelism_;
    // The collector is expected to finish before this |deadline_|. Unfinished
    // logs will be skipped.
    base::TimeTicks deadline_;

    // Task controller pid.
    pid_t task_controller_pid_;

    // Track the mapping between the output file name and the Log.
    std::map<base::FilePath, Log> file_log_map_;
    // Log data will be saved to this temp folder.
    base::ScopedTempDir temp_dir_;
  };

  explicit LogTool(scoped_refptr<dbus::Bus> bus, const bool perf_logging);

  ~LogTool() = default;

  using LogMap = std::map<std::string, std::string>;

  // From debugd::LogProvider.
  virtual std::optional<std::string> GetLog(const std::string& name);
  LogMap GetAllLogs();
  LogMap GetAllDebugLogs();
  void GetFeedbackLogsV2(const base::ScopedFD& fd,
                         const std::string& username,
                         PerfTool* perf_tool,
                         const std::vector<int32_t>& requested_logs);
  void GetFeedbackLogsV3(const base::ScopedFD& fd,
                         const std::string& username,
                         PerfTool* perf_tool,
                         const std::vector<int32_t>& requested_logs);
  void BackupArcBugReport(const std::string& username);
  void DeleteArcBugReportBackup(const std::string& username);

  // Returns a representation of |value| with the specified encoding.
  static std::string EncodeString(std::string value, Encoding source_encoding);

 private:
  friend class LogToolTest;

  // For testing only.
  LogTool(scoped_refptr<dbus::Bus> bus,
          std::unique_ptr<org::chromium::CryptohomeMiscInterfaceProxyInterface>
              cryptohome_proxy,
          const std::unique_ptr<LogTool::Log> arc_bug_report_log,
          const base::FilePath& daemon_store_base_dir);
  LogTool(const LogTool&) = delete;
  LogTool& operator=(const LogTool&) = delete;

  void CreateConnectivityReport(bool wait_for_results);

  // Returns the output of arc-bugreport program in ARC.
  // Returns cached output if it is available for this user.
  std::string GetArcBugReport(const std::string& username, bool* is_backup);
  bool IsUserHashValid(const std::string& userhash);

  void GetArcBugReportInDictionary(const std::string& username,
                                   base::Value::Dict* dictionary);

  scoped_refptr<dbus::Bus> bus_;
  std::unique_ptr<org::chromium::CryptohomeMiscInterfaceProxyInterface>
      cryptohome_proxy_;

  bool perf_logging_;

  std::unique_ptr<LogTool::Log> arc_bug_report_log_;

  base::FilePath daemon_store_base_dir_;
  // Set containing userhash of all users for which
  // ARC bug report has been backed up.
  std::set<std::string> arc_bug_report_backups_;
};

std::vector<std::vector<std::string>> GetAllDebugTitlesForTest();

}  // namespace debugd

#endif  // DEBUGD_SRC_LOG_TOOL_H_
