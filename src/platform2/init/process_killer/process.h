// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef INIT_PROCESS_KILLER_PROCESS_H_
#define INIT_PROCESS_KILLER_PROCESS_H_

#include <sys/types.h>

#include <string>
#include <utility>
#include <vector>

#include <base/files/file_path.h>
#include <re2/re2.h>

namespace init {

// ActiveMount represents an active mount in the process' mountinfo file.
// ActiveMount only stores the fields necessary to identify whether:
// 1. the mount is active from a source directory.
// 2. the mount on a destination path is still active.
// 3. the mount is keeping a device open.
struct ActiveMount {
  base::FilePath source;
  base::FilePath target;
  std::string device;
};

// OpenFileDescriptor represents the path of a file that is currently held open
// by the process. It is represented by the filepath to the target file that is
// open in the process
struct OpenFileDescriptor {
  base::FilePath path;
};

// ActiveProcess represents a process that is currently active at the time of
// querying. In addition to the standard identifiers (pid, comm), ActiveProcess
// also stores active mounts and open file descriptors seen at the time of
// querying. |in_init_mnt_ns| annotates whether the process resides in the init
// mount namespace or not.
class ActiveProcess {
 public:
  ActiveProcess(pid_t pid,
                bool in_init_mnt_ns,
                const std::string& comm,
                const std::vector<ActiveMount>& mounts,
                const std::vector<OpenFileDescriptor>& file_descriptors);
  bool HasFileOpenOnMount(const re2::RE2& pattern) const;
  bool HasMountOpenFromDevice(const re2::RE2& pattern) const;

  pid_t GetPid() const { return pid_; }
  bool InInitMountNamespace() const { return in_init_mnt_ns_; }

  void LogProcess(const re2::RE2& files_regex,
                  const re2::RE2& mounts_regex) const;

 private:
  pid_t pid_;
  bool in_init_mnt_ns_;
  std::string comm_;
  std::vector<ActiveMount> mounts_;
  std::vector<OpenFileDescriptor> file_descriptors_;
};

}  // namespace init

#endif  // INIT_PROCESS_KILLER_PROCESS_H_
