// Copyright 2016 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "debugd/src/oom_adj_tool.h"

#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <memory>

#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/files/scoped_file.h>
#include <base/logging.h>
#include <base/strings/stringprintf.h>
#include <brillo/userdb_utils.h>

#include "debugd/src/process_with_output.h"

namespace debugd {

namespace {

constexpr char kProcfsDirFormat[] = "/proc/%d";
constexpr char kOomScoreAdjFileFormat[] = "/proc/%d/oom_score_adj";
constexpr char kUidMapFileFormat[] = "/proc/%d/uid_map";

// Though uid might be an unsigned int, some system call like setreuid() still
// accepts uid_t as -1 as a special invalid value. I followed the tradition in
// this file.
constexpr uid_t kInvalidUid = static_cast<uid_t>(-1);

uid_t GetUidForUsername(const std::string& user_name) {
  uid_t uid;
  return brillo::userdb::GetUserInfo(user_name, &uid, nullptr) ? uid
                                                               : kInvalidUid;
}

bool IsValidUid(const uid_t uid) {
  return uid != kInvalidUid;
}

// Print and collect errors.
void PrintAndAppendError(std::string* errors, const std::string& new_error) {
  LOG(WARNING) << new_error;
  *errors += new_error + "\n";
}

// A helper class to get process attributes like process owner, etc.
class ProcessHandler {
 public:
  explicit ProcessHandler(const pid_t pid);
  ~ProcessHandler() = default;

  // Get UID of the process |pid_|.
  uid_t GetProcessOwnerUid(std::string* errors);

  // Get UID of root inside the user namespace |pid_| is in.
  uid_t GetUserNamespaceRootUid(std::string* errors);

 private:
  const pid_t pid_;
};

ProcessHandler::ProcessHandler(const pid_t pid) : pid_(pid) {}

uid_t ProcessHandler::GetProcessOwnerUid(std::string* errors) {
  std::string procfs_entry = base::StringPrintf(kProcfsDirFormat, pid_);
  base::ScopedFD procfs_fd(open(procfs_entry.c_str(), O_RDONLY | O_DIRECTORY));
  if (!procfs_fd.is_valid()) {
    PrintAndAppendError(
        errors,
        base::StringPrintf("Failed to open procfs entry of process %d", pid_));
    return kInvalidUid;
  }

  struct stat statbuf;
  if (fstat(procfs_fd.get(), &statbuf) < 0) {
    PrintAndAppendError(
        errors, base::StringPrintf("Failed to get uid of process %d", pid_));
    return kInvalidUid;
  }

  return statbuf.st_uid;
}

uid_t ProcessHandler::GetUserNamespaceRootUid(std::string* errors) {
  base::FilePath uid_map_file(base::StringPrintf(kUidMapFileFormat, pid_));
  base::ScopedFILE uid_file(base::OpenFile(uid_map_file, "r"));
  if (!uid_file) {
    PrintAndAppendError(
        errors,
        base::StringPrintf("Failed to open uid map file %s for process %d",
                           uid_map_file.value().c_str(), pid_));
    return kInvalidUid;
  }

  uid_t start, map;
  // Each line in the uid_map file specifies a 1-to-1 mapping of a range
  // of contiguous user IDs between two user namespaces. The first two numbers
  // specify the starting user ID in each of the two user namespaces. The
  // third number specifies the length of the mapped range.
  // Assume root user in the user namespace of |pid_| is mapped to the calling
  // user namespace. If not it returns kInvalidUid.
  while (fscanf(uid_file.get(), "%d%d%*d", &start, &map) == 2) {
    // Returns mapping of UID 0 = root.
    if (start == 0)
      return map;
  }
  return kInvalidUid;
}

// Batch set oom_score_adj for a list of processes. Only Chrome tabs and
// Android apps are valid target.
class OomScoreSetter {
 public:
  OomScoreSetter()
      : chronos_uid_(GetUidForUsername("chronos")),
        android_root_uid_(GetUidForUsername("android-root")) {}
  ~OomScoreSetter() = default;

  // Entry point.
  std::string Set(const std::map<pid_t, int32_t>& scores);

 private:
  // Sets oom_score_adj for one process.
  void SetOne(const pid_t pid, const int32_t score, std::string* errors);

  // Whether it's valid to alter OOM score of the given process |pid_|.
  bool IsValidOwner(const pid_t pid, std::string* errors);

  const uid_t chronos_uid_;
  const uid_t android_root_uid_;
};

std::string OomScoreSetter::Set(const std::map<pid_t, int32_t>& scores) {
  VLOG(2) << "UID of chronos: " << chronos_uid_;
  VLOG(2) << "UID of android-root: " << android_root_uid_;

  std::string errors;
  for (const auto& entry : scores) {
    const pid_t& pid = entry.first;
    const int32_t& score = entry.second;
    VLOG(2) << "Setting OOM score " << score << " for process " << pid;

    SetOne(pid, score, &errors);
  }
  return errors;
}

void OomScoreSetter::SetOne(const pid_t pid,
                            const int32_t score,
                            std::string* errors) {
  if (!IsValidOwner(pid, errors)) {
    PrintAndAppendError(
        errors,
        base::StringPrintf("Invalid pid %d, operation not allowed", pid));
    return;
  }

  std::string score_str = std::to_string(score);
  const size_t len = score_str.length();
  base::FilePath oom_file(base::StringPrintf(kOomScoreAdjFileFormat, pid));
  ssize_t bytes_written = base::WriteFile(oom_file, score_str.c_str(), len);

  std::string write_error;
  if (bytes_written < 0) {
    write_error = strerror(errno);
  } else if ((size_t)bytes_written != len) {
    write_error = base::StringPrintf("%zd instead of %zu bytes written",
                                     bytes_written, len);
  }

  if (!write_error.empty()) {
    PrintAndAppendError(
        errors,
        base::StringPrintf("Write %d to %s failed: %s", score,
                           oom_file.value().c_str(), write_error.c_str()));
  }
}

// Returns true if
// 1. The process is owned by "chronos", or
// 2. The process is created in a user namespace where root is "android-root".
bool OomScoreSetter::IsValidOwner(const pid_t pid, std::string* errors) {
  ProcessHandler handler(pid);

  uid_t process_owner_uid = handler.GetProcessOwnerUid(errors);
  VLOG(2) << "Owner of " << pid << ": " << process_owner_uid;
  if (IsValidUid(process_owner_uid) && process_owner_uid == chronos_uid_)
    return true;

  uid_t namespace_root_uid = handler.GetUserNamespaceRootUid(errors);
  VLOG(2) << "Root of the user namespace " << pid
          << " is in: " << namespace_root_uid;
  if (IsValidUid(namespace_root_uid) && namespace_root_uid == android_root_uid_)
    return true;

  return false;
}

}  // namespace

std::string OomAdjTool::Set(const std::map<pid_t, int32_t>& scores) {
  OomScoreSetter setter;
  return setter.Set(scores);
}

}  // namespace debugd
