// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "secanomalyd/processes.h"

#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>

#include <algorithm>
#include <cstddef>
#include <cstdio>
#include <optional>
#include <string>

#include <absl/cleanup/cleanup.h>
#include <base/files/file_path.h>
#include <base/files/file_enumerator.h>
#include <base/files/file_util.h>
#include <base/files/scoped_file.h>
#include <base/logging.h>
#include <base/posix/eintr_wrapper.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_piece_forward.h>
#include <base/strings/string_split.h>
#include <base/strings/string_tokenizer.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>
#include <re2/re2.h>

#include <brillo/process/process.h>

namespace secanomalyd {

namespace {
constexpr char kInitExecutable[] = "/sbin/init";
const base::FilePath kProcPathBase("/proc");
constexpr char kProcSubdirPattern[] = "[0-9]*";
const base::FilePath kProcStatusFile("status");
const base::FilePath kProcCmdlineFile("cmdline");
const base::FilePath kProcNsPidPath("ns/pid");
const base::FilePath kProcNsMntPath("ns/mnt");
static constexpr LazyRE2 kProcNsPattern = {R"([a-z]+:\[(\d+)\])"};
constexpr char kSecCompModeDisabled[] = "0";
// SECCOMP_MODE_STRICT is 1.
// SECCOMP_MODE_FILTER is 2.

// Reads a file under a directory, given the FD for the directory. This is
// useful for when the OS reuses a PID, in which case the underlying FD becomes
// invalidated and the process is skipped.
static bool ReadFileRelativeToDirFD(const int dir_fd,
                                    const base::FilePath& filename,
                                    std::string* content_ptr) {
  int fd = HANDLE_EINTR(openat(dir_fd, filename.value().c_str(), O_RDONLY));
  if (fd == -1) {
    PLOG(ERROR) << "openat(" << filename << ") failed";
    return false;
  }

  absl::Cleanup close_file = [=] {
    if (close(fd) == -1)
      PLOG(ERROR) << "Failed to close file " << filename;
  };

  FILE* fs = fdopen(fd, "r");
  if (!fs) {
    PLOG(ERROR) << "Failed to obtain FD for " << filename << " file";
    return false;
  }

  if (!base::ReadStreamToString(fs, content_ptr)) {
    LOG(ERROR) << "ReadStreamToString failed on " << filename;
    return false;
  }
  return true;
}

// Kernel arg and env lists use '\0' to delimit elements.
static std::string SafeTransFromArgvEnvp(const std::string cmdline) {
  std::string res;
  base::StringTokenizer t(cmdline, std::string("\0", 1));
  while (t.GetNext()) {
    res.append(base::StringPrintf("%s ", t.token().c_str()));
  }
  if (res.length() > 0) {
    res.pop_back();
  }
  return res;
}

static ino_t GetNsFromPath(const base::FilePath& ns_symlink_path) {
  // *_ns_symlink are not actually pathlike. E.g: "mnt:[4026531840]".
  base::FilePath ns_symlink;
  std::string ns_string;
  ino_t ns;
  if (!base::ReadSymbolicLink(ns_symlink_path, &ns_symlink) ||
      !RE2::FullMatch(ns_symlink.value(), *kProcNsPattern, &ns_string) ||
      !base::StringToUint64(ns_string, &ns)) {
    return 0;
  }
  return ns;
}

}  // namespace

MaybeProcEntry ProcEntry::CreateFromPath(const base::FilePath& pid_path) {
  // ProcEntry attributes.
  pid_t pid;
  ino_t pidns = 0, mntns = 0;
  std::string comm, args;
  SandboxStatus sandbox_status;
  sandbox_status.reset();

  // Fail if we cannot parse a PID from the supplied path.
  if (!base::StringToInt(pid_path.BaseName().value(), &pid)) {
    LOG(ERROR) << "Could not parse a PID from path " << pid_path;
    return std::nullopt;
  }

  DIR* pid_dir_ptr = opendir(pid_path.value().c_str());
  if (!pid_dir_ptr) {
    PLOG(ERROR) << "opendir(" << pid_path << ") failed";
    return std::nullopt;
  }

  absl::Cleanup close_dir = [=] {
    if (closedir(pid_dir_ptr) == -1)
      PLOG(ERROR) << "Failed to close dir " << pid_path;
  };

  int pid_dir_fd = HANDLE_EINTR(dirfd(pid_dir_ptr));
  if (pid_dir_fd == -1) {
    LOG(ERROR) << "Failed to obtain FD for " << pid_path;
    return std::nullopt;
  }

  // Fail if we cannot read the status file, since just a PID is not useful.
  std::string status_file_content;
  if (!ReadFileRelativeToDirFD(pid_dir_fd, kProcStatusFile,
                               &status_file_content)) {
    return std::nullopt;
  }

  // The /proc/pid/status file follows this format:
  // Attribute:\tValue\nAttribute:\tValue\n...
  // In cases where an attribute has several values, each value is separated
  // with a tab: Attribute:\tValue1\tValue2\tValue3\n...
  // See https://man7.org/linux/man-pages/man5/proc.5.html for the list of
  // attributes in this file.
  // In our case we parse the values of `Name`, `NoNewPrivs` and `Seccomp`.
  base::StringTokenizer t(status_file_content, "\n");
  while (t.GetNext()) {
    base::StringPiece line = t.token_piece();
    if (base::StartsWith(line, "Name:")) {
      comm = std::string(line.substr(line.rfind("\t") + 1));
    }
    if (base::StartsWith(line, "NoNewPrivs:") &&
        line.substr(line.rfind("\t") + 1) == "1")
      // For more information on no new privs see
      // https://www.kernel.org/doc/html/v4.19/userspace-api/no_new_privs.html
      sandbox_status.set(kNoNewPrivsBit);
    if (base::StartsWith(line, "Seccomp:") &&
        line.substr(line.rfind("\t") + 1) != kSecCompModeDisabled)
      sandbox_status.set(kSecCompBit);
  }

  // Fail if we cannot read the status file, since just a PID is not useful.
  std::string cmdline_file_content;
  if (ReadFileRelativeToDirFD(pid_dir_fd, kProcCmdlineFile,
                              &cmdline_file_content)) {
    // Reads the rest of the process files before processing any content.

    if (cmdline_file_content.empty()) {
      // If there are no args, we set `args` to be be the command name, but
      // enclosed in square brackets. This is to follow the `ps` convention, and
      // to avoid having empty lines in the list of processes in crash reports.
      args = base::StringPrintf("[%s]", comm.c_str());
    } else {
      args = SafeTransFromArgvEnvp(cmdline_file_content);
    }
  }

  pidns = GetNsFromPath(pid_path.Append(kProcNsPidPath));
  mntns = GetNsFromPath(pid_path.Append(kProcNsMntPath));

  return ProcEntry(pid, pidns, mntns, comm, args, sandbox_status);
}

MaybeProcEntries ReadProcesses(ProcessFilter filter) {
  ProcEntries entries;
  std::optional<ino_t> init_pidns = std::nullopt;

  base::FileEnumerator proc_enumerator(kProcPathBase, /*Recursive=*/false,
                                       base::FileEnumerator::DIRECTORIES,
                                       kProcSubdirPattern);
  for (base::FilePath pid_path = proc_enumerator.Next(); !pid_path.empty();
       pid_path = proc_enumerator.Next()) {
    MaybeProcEntry entry = ProcEntry::CreateFromPath(pid_path);
    if (entry.has_value()) {
      if (filter == ProcessFilter::kInitPidNamespaceOnly &&
          entry->args() == std::string(kInitExecutable)) {
        init_pidns = entry->pidns();
        // The init process has been found, add it to the list and continue
        // the loop early.
        entries.push_back(*entry);
        continue;
      }

      // Add the entry to the list if:
      //    -Caller requested all processes, or
      //    -The init process hasn't yet been identified, or
      //    -The init process has been successfully identified, and the PID
      //     namespaces match.
      if (filter == ProcessFilter::kAll || !init_pidns ||
          entry->pidns() == init_pidns.value()) {
        entries.push_back(*entry);
      }
    }
  }

  if (filter == ProcessFilter::kInitPidNamespaceOnly) {
    if (init_pidns) {
      // Remove all processes whose |pidns| does not match init's.
      entries.erase(std::remove_if(entries.begin(), entries.end(),
                                   [init_pidns](const ProcEntry& pe) {
                                     return pe.pidns() != init_pidns.value();
                                   }),
                    entries.end());
    } else {
      LOG(ERROR) << "Failed to find init process";
      return std::nullopt;
    }
  }

  // If we failed to parse any valid processes, return nullopt.
  return entries.empty() ? std::nullopt : MaybeProcEntries(entries);
}

}  // namespace secanomalyd
