// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <init/process_killer/process.h>

#include <sys/types.h>

#include <string>
#include <utility>
#include <vector>

#include <base/files/file_path.h>
#include <base/logging.h>
#include <re2/re2.h>

namespace init {

ActiveProcess::ActiveProcess(
    pid_t pid,
    bool in_init_mnt_ns,
    const std::string& comm,
    const std::vector<ActiveMount>& mounts,
    const std::vector<OpenFileDescriptor>& file_descriptors)
    : pid_(pid),
      in_init_mnt_ns_(in_init_mnt_ns),
      comm_(comm),
      mounts_(mounts),
      file_descriptors_(file_descriptors) {}

bool ActiveProcess::HasFileOpenOnMount(const re2::RE2& pattern) const {
  int open_fds =
      std::count_if(file_descriptors_.begin(), file_descriptors_.end(),
                    [&pattern](const OpenFileDescriptor& fd) {
                      return re2::RE2::PartialMatch(fd.path.value(), pattern);
                    });

  return open_fds > 0;
}

bool ActiveProcess::HasMountOpenFromDevice(const re2::RE2& pattern) const {
  int open_mounts = std::count_if(
      mounts_.begin(), mounts_.end(), [&pattern](const ActiveMount& mount) {
        return re2::RE2::PartialMatch(mount.device, pattern);
      });

  return open_mounts > 0;
}

void ActiveProcess::LogProcess(const re2::RE2& files_regex,
                               const re2::RE2& mounts_regex) const {
  bool printed_mounts_header = false;
  bool printed_file_header = false;

  LOG(INFO) << "Process: " << pid_ << "; Comm: " << comm_;

  if (!in_init_mnt_ns_) {
    for (auto& m : mounts_) {
      if (!re2::RE2::PartialMatch(m.device, mounts_regex))
        continue;
      if (!printed_mounts_header) {
        LOG(INFO) << "Matching process Mounts: (Source, Target, Device)";
        printed_mounts_header = true;
      }
      LOG(INFO) << ">> " << m.source << " " << m.target << " " << m.device;
    }
  }

  for (auto& fd : file_descriptors_) {
    if (!re2::RE2::PartialMatch(fd.path.value(), files_regex))
      continue;
    if (!printed_file_header) {
      LOG(INFO) << "Matching open files: (Path)";
      printed_file_header = true;
    }
    LOG(INFO) << ">> " << fd.path;
  }
}

}  // namespace init
