// Copyright 2016 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "libcontainer/cgroup.h"

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <utility>

#include <base/files/file_util.h>
#include <base/files/scoped_file.h>
#include <base/functional/bind.h>
#include <base/functional/callback.h>
#include <base/functional/callback_helpers.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/stringprintf.h>

namespace libcontainer {

namespace {

Cgroup::CgroupFactory g_cgroup_factory = nullptr;

constexpr const char* kCgroupNames[Cgroup::Type::NUM_TYPES] = {
    "cpu", "cpuacct", "cpuset", "devices", "freezer", "schedtune", "memory"};

base::ScopedFD OpenCgroupFile(const base::FilePath& cgroup_path,
                              base::StringPiece name,
                              bool write) {
  base::FilePath path = cgroup_path.Append(name);
  int flags = write ? O_WRONLY | O_CREAT | O_TRUNC : O_RDONLY;
  // Adding O_NONBLOCK to avoid blocking in case we were tricked into opening a
  // blocking file (e.g. an unopened FIFO or a device).
  flags |= O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC;
  base::ScopedFD fd(HANDLE_EINTR(open(path.value().c_str(), flags, 0664)));
  if (!fd.is_valid())
    return base::ScopedFD();
  // Ensure the opened file is a regular file.
  struct stat st;
  if (fstat(fd.get(), &st) < 0) {
    PLOG(ERROR) << "Failed to fstat " << path.value();
    return base::ScopedFD();
  }
  if (!S_ISREG(st.st_mode)) {
    LOG(ERROR) << path.value() << " is not a regular file";
    return base::ScopedFD();
  }
  // Remove O_NONBLOCK before returning |fd|.
  flags = fcntl(fd.get(), F_GETFL);
  if (flags == -1) {
    PLOG(ERROR) << "Failed to get flags for " << path.value();
    return base::ScopedFD();
  }
  if (fcntl(fd.get(), F_SETFL, flags & ~O_NONBLOCK) < 0) {
    PLOG(ERROR) << "Failed to remove O_NONBLOCK for " << path.value();
    return base::ScopedFD();
  }
  return fd;
}

bool WriteCgroupFile(const base::FilePath& cgroup_path,
                     base::StringPiece name,
                     base::StringPiece str) {
  base::ScopedFD fd = OpenCgroupFile(cgroup_path, name, true);
  if (!fd.is_valid())
    return false;
  if (!base::WriteFileDescriptor(fd.get(), str))
    return false;
  return true;
}

bool WriteCgroupFileInt(const base::FilePath& cgroup_path,
                        base::StringPiece name,
                        const int value) {
  return WriteCgroupFile(cgroup_path, name, base::NumberToString(value));
}

bool CopyCgroupParent(const base::FilePath& cgroup_path,
                      base::StringPiece name) {
  base::ScopedFD dest = OpenCgroupFile(cgroup_path, name, true);
  if (!dest.is_valid())
    return false;

  base::ScopedFD source = OpenCgroupFile(cgroup_path.DirName(), name, false);
  if (!source.is_valid())
    return false;

  base::File infile(std::move(source));
  base::File outfile(std::move(dest));
  return base::CopyFileContents(infile, outfile);
}

std::string GetDeviceString(const int major, const int minor) {
  if (major >= 0 && minor >= 0)
    return base::StringPrintf("%d:%d", major, minor);
  else if (major >= 0)
    return base::StringPrintf("%d:*", major);
  else if (minor >= 0)
    return base::StringPrintf("*:%d", minor);
  else
    return base::StringPrintf("*:*");
}

bool CreateCgroupAsOwner(const base::FilePath& cgroup_path,
                         uid_t cgroup_owner,
                         gid_t cgroup_group) {
  base::ScopedClosureRunner runner;

  // If running as root and the cgroup owner is a user, create the cgroup
  // as that user.
  if (getuid() == 0 && (cgroup_owner != 0 || cgroup_group != 0)) {
    // Ensure that we reset the euid and egid no matter what.
    // TODO(ejcaruso, hidehiko): change to OnceClosure when libchrome is
    // upreved again.
    runner.ReplaceClosure(base::BindOnce(
        [](uid_t euid, gid_t egid) {
          if (seteuid(euid) != 0)
            PLOG(ERROR) << "Failed to reset euid";
          if (setegid(egid) != 0)
            PLOG(ERROR) << "Failed to reset egid";
        },
        geteuid(), getegid()));

    if (setegid(cgroup_group) != 0 || seteuid(cgroup_owner) != 0) {
      PLOG(ERROR) << "Failed to set cgroup owner";
      return false;
    }
  }

  if (mkdir(cgroup_path.value().c_str(), S_IRWXU | S_IRWXG) < 0 &&
      errno != EEXIST) {
    return false;
  }

  return true;
}

bool CopyCpusetParent(const base::FilePath& cgroup_path) {
  // cpuset is special: we need to copy parent's cpus or mems,
  // otherwise we'll start with "empty" cpuset and nothing can
  // run in it/be moved into it.
  //
  // Chromium OS and Android use the legacy noprefix mount option (i.e.
  // no "cpuset." in front of cpus/mems), but we also check for the
  // prefixed files.
  if (!CopyCgroupParent(cgroup_path, "cpus") &&
      !CopyCgroupParent(cgroup_path, "cpuset.cpus")) {
    PLOG(ERROR) << "Failed to copy " << cgroup_path.value()
                << "/cpus from parent";
    return false;
  }

  if (!CopyCgroupParent(cgroup_path, "mems") &&
      !CopyCgroupParent(cgroup_path, "cpuset.mems")) {
    PLOG(ERROR) << "Failed to copy " << cgroup_path.value()
                << "/mems from parent";
    return false;
  }

  return true;
}

bool CheckCgroupAvailable(const base::FilePath& cgroup_root,
                          base::StringPiece cgroup_name) {
  base::FilePath path = cgroup_root.Append(cgroup_name);

  return access(path.value().c_str(), F_OK) == 0;
}

}  // namespace

bool Cgroup::Freeze() {
  return WriteCgroupFile(cgroup_paths_[Type::FREEZER], "freezer.state",
                         "FROZEN\n");
}

bool Cgroup::Thaw() {
  return WriteCgroupFile(cgroup_paths_[Type::FREEZER], "freezer.state",
                         "THAWED\n");
}

bool Cgroup::DenyAllDevices() {
  return WriteCgroupFile(cgroup_paths_[Type::DEVICES], "devices.deny", "a\n");
}

bool Cgroup::AddDevice(bool allow,
                       int major,
                       int minor,
                       bool read,
                       bool write,
                       bool modify,
                       char type) {
  if (type != 'b' && type != 'c' && type != 'a') {
    LOG(ERROR) << "Invalid cgroup type '" << type << "'";
    return false;
  }
  if (!read && !write && !modify) {
    LOG(ERROR) << "Invalid cgroup permissions: at least one of read, write, "
                  "modify should be true";
    return false;
  }

  std::string device_string = GetDeviceString(major, minor);

  // The device file format is:
  // <type, c, b, or a> major:minor rmw
  std::string perm_string =
      base::StringPrintf("%c %s %s%s%s\n", type, device_string.c_str(),
                         read ? "r" : "", write ? "w" : "", modify ? "m" : "");
  return WriteCgroupFile(cgroup_paths_[Type::DEVICES],
                         allow ? "devices.allow" : "devices.deny", perm_string);
}

bool Cgroup::SetCpuShares(int shares) {
  return WriteCgroupFileInt(cgroup_paths_[Type::CPU], "cpu.shares", shares);
}

bool Cgroup::SetCpuQuota(int quota) {
  return WriteCgroupFileInt(cgroup_paths_[Type::CPU], "cpu.cfs_quota_us",
                            quota);
}

bool Cgroup::SetCpuPeriod(int period) {
  return WriteCgroupFileInt(cgroup_paths_[Type::CPU], "cpu.cfs_period_us",
                            period);
}

bool Cgroup::SetCpuRtRuntime(int rt_runtime) {
  return WriteCgroupFileInt(cgroup_paths_[Type::CPU], "cpu.rt_runtime_us",
                            rt_runtime);
}

bool Cgroup::SetCpuRtPeriod(int rt_period) {
  return WriteCgroupFileInt(cgroup_paths_[Type::CPU], "cpu.rt_period_us",
                            rt_period);
}

// static
void Cgroup::SetCgroupFactoryForTesting(CgroupFactory factory) {
  g_cgroup_factory = factory;
}

// static
std::unique_ptr<Cgroup> Cgroup::Create(base::StringPiece name,
                                       const base::FilePath& cgroup_root,
                                       const base::FilePath& cgroup_parent,
                                       uid_t cgroup_owner,
                                       gid_t cgroup_group) {
  if (g_cgroup_factory) {
    return g_cgroup_factory(name, cgroup_root, cgroup_parent, cgroup_owner,
                            cgroup_group);
  }
  std::unique_ptr<Cgroup> cg(new Cgroup());

  for (int32_t i = 0; i < Type::NUM_TYPES; ++i) {
    if (!CheckCgroupAvailable(cgroup_root, kCgroupNames[i])) {
      if (errno == ENOENT)
        continue;
      PLOG(ERROR) << "Cgroup " << kCgroupNames[i] << " not available";
      return nullptr;
    }

    if (!cgroup_parent.empty()) {
      const base::FilePath parent_path =
          cgroup_root.Append(kCgroupNames[i]).Append(cgroup_parent);

      cg->cgroup_paths_[i] = parent_path.Append(name);

      // Try to create the parent cgroup only if it doesn't exist.
      if (!base::DirectoryExists(parent_path)) {
        if (!CreateCgroupAsOwner(parent_path, cgroup_owner, cgroup_group)) {
          PLOG(ERROR) << "Failed to create parent cgroup "
                      << parent_path.value() << " as owner";
          return nullptr;
        }

        if (i == Type::CPUSET && !CopyCpusetParent(parent_path))
          return nullptr;
      }
    } else {
      cg->cgroup_paths_[i] = cgroup_root.Append(kCgroupNames[i]).Append(name);
    }

    if (!CreateCgroupAsOwner(cg->cgroup_paths_[i], cgroup_owner,
                             cgroup_group)) {
      PLOG(ERROR) << "Failed to create cgroup " << cg->cgroup_paths_[i].value()
                  << " as owner";
      return nullptr;
    }

    cg->cgroup_tasks_paths_[i] = cg->cgroup_paths_[i].Append("tasks");

    if (i == Type::CPUSET && !CopyCpusetParent(cg->cgroup_paths_[i]))
      return nullptr;
  }

  cg->name_ = std::string(name);

  return cg;
}

Cgroup::Cgroup() = default;

Cgroup::~Cgroup() {
  for (int32_t i = 0; i < Type::NUM_TYPES; ++i) {
    if (cgroup_paths_[i].empty())
      continue;
    rmdir(cgroup_paths_[i].value().c_str());
  }
}

}  // namespace libcontainer
