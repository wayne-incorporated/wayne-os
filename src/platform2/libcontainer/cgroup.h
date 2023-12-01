// Copyright 2016 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Handles setting basic cgroup properties.  The format of the cgroup files can
// be found in the linux kernel at Documentation/cgroups/.

#ifndef LIBCONTAINER_CGROUP_H_
#define LIBCONTAINER_CGROUP_H_

#include <sys/types.h>

#include <memory>
#include <string>

#include <base/files/file_path.h>
#include <base/functional/callback_forward.h>

namespace libcontainer {

class Cgroup {
 public:
  enum Type : int32_t {
    CPU,
    CPUACCT,
    CPUSET,
    DEVICES,
    FREEZER,
    SCHEDTUNE,
    MEMORY,
    NUM_TYPES,
  };

  static std::unique_ptr<Cgroup> Create(base::StringPiece name,
                                        const base::FilePath& cgroup_root,
                                        const base::FilePath& cgroup_parent,
                                        uid_t cgroup_owner,
                                        gid_t cgroup_group);
  virtual ~Cgroup();

  virtual bool Freeze();
  virtual bool Thaw();
  virtual bool DenyAllDevices();
  virtual bool AddDevice(bool allow,
                         int major,
                         int minor,
                         bool read,
                         bool write,
                         bool modify,
                         char type);
  virtual bool SetCpuShares(int shares);
  virtual bool SetCpuQuota(int quota);
  virtual bool SetCpuPeriod(int period);
  virtual bool SetCpuRtRuntime(int rt_runtime);
  virtual bool SetCpuRtPeriod(int rt_period);

  bool has_tasks_path(int32_t t) const {
    return !cgroup_tasks_paths_[t].empty();
  }

  const base::FilePath& tasks_path(int32_t t) const {
    return cgroup_tasks_paths_[t];
  }

  // TODO(lhchavez): Move to private when we use gtest.
  using CgroupFactory = decltype(&Cgroup::Create);
  static void SetCgroupFactoryForTesting(CgroupFactory factory);

 protected:
  Cgroup();
  Cgroup(const Cgroup&) = delete;
  Cgroup& operator=(const Cgroup&) = delete;

 private:
  std::string name_;
  base::FilePath cgroup_paths_[Type::NUM_TYPES];
  base::FilePath cgroup_tasks_paths_[Type::NUM_TYPES];
};

}  // namespace libcontainer

#endif  // LIBCONTAINER_CGROUP_H_
