// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "patchpanel/scoped_ns.h"

#include <fcntl.h>
#include <sched.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <string>
#include <utility>

#include <base/logging.h>
#include <base/memory/ptr_util.h>

namespace patchpanel {

std::unique_ptr<ScopedNS> ScopedNS::EnterMountNS(pid_t pid) {
  int nstype = CLONE_NEWNS;
  const std::string current_path = "/proc/self/ns/mnt";
  const std::string target_path = "/proc/" + std::to_string(pid) + "/ns/mnt";
  auto ns = base::WrapUnique(new ScopedNS(nstype, current_path, target_path));
  return ns->valid_ ? std::move(ns) : nullptr;
}

std::unique_ptr<ScopedNS> ScopedNS::EnterNetworkNS(pid_t pid) {
  int nstype = CLONE_NEWNET;
  const std::string current_path = "/proc/self/ns/net";
  const std::string target_path = "/proc/" + std::to_string(pid) + "/ns/net";
  auto ns = base::WrapUnique(new ScopedNS(nstype, current_path, target_path));
  return ns->valid_ ? std::move(ns) : nullptr;
}

std::unique_ptr<ScopedNS> ScopedNS::EnterNetworkNS(
    const std::string& netns_name) {
  int nstype = CLONE_NEWNET;
  const std::string current_path = "/proc/self/ns/net";
  const std::string target_path = "/run/netns/" + netns_name;
  auto ns = base::WrapUnique(new ScopedNS(nstype, current_path, target_path));
  return ns->valid_ ? std::move(ns) : nullptr;
}

ScopedNS::ScopedNS(int nstype,
                   const std::string& current_ns_path,
                   const std::string& target_ns_path)
    : nstype_(nstype), valid_(false) {
  ns_fd_.reset(open(target_ns_path.c_str(), O_RDONLY | O_CLOEXEC));
  if (!ns_fd_.is_valid()) {
    PLOG(ERROR) << "Could not open namespace " << target_ns_path;
    return;
  }
  self_fd_.reset(open(current_ns_path.c_str(), O_RDONLY | O_CLOEXEC));
  if (!self_fd_.is_valid()) {
    PLOG(ERROR) << "Could not open host namespace " << current_ns_path;
    return;
  }
  if (setns(ns_fd_.get(), nstype_) != 0) {
    PLOG(ERROR) << "Could not enter namespace " << target_ns_path;
    return;
  }
  valid_ = true;
}

ScopedNS::~ScopedNS() {
  if (valid_) {
    if (setns(self_fd_.get(), nstype_) != 0)
      PLOG(FATAL) << "Could not re-enter host namespace type " << nstype_;
  }
}

}  // namespace patchpanel
