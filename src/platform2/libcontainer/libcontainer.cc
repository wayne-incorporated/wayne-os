// Copyright 2016 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <syscall.h>
#include <unistd.h>

#include <algorithm>
#include <map>
#include <memory>
#include <ostream>
#include <set>
#include <sstream>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/files/scoped_file.h>
#include <base/functional/bind.h>
#include <base/functional/callback_helpers.h>
#include <base/logging.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>
#include <libminijail.h>
#include <scoped_minijail.h>

#include "libcontainer/cgroup.h"
#include "libcontainer/config.h"
#include "libcontainer/libcontainer.h"
#include "libcontainer/libcontainer_util.h"

#define QUOTE(s) ('"' + std::string(s) + '"')

// Not available in sys/prctl.h yet, but supported on some kernels.
#ifndef PR_SET_CORE_SCHED
#define PR_SET_CORE_SCHED 0x200
#endif

namespace {

using libcontainer::DeviceMapperDetach;
using libcontainer::DeviceMapperSetup;
using libcontainer::GetUsernsOutsideId;
using libcontainer::Loopdev;
using libcontainer::LoopdevDetach;
using libcontainer::LoopdevSetup;
using libcontainer::MakeDir;
using libcontainer::MountExternal;
using libcontainer::TouchFile;

constexpr size_t kMaxRlimits = 32;  // Linux defines 15 at the time of writing.

struct Mount {
  std::string name;
  base::FilePath source;
  base::FilePath destination;
  std::string type;
  std::string data;
  std::string verity;
  int flags;
  int uid;
  int gid;
  int mode;

  // True if mount should happen in new vfs ns.
  bool mount_in_ns;

  // True if target should be created if it doesn't exist.
  bool create;

  // True if target should be mounted via loopback.
  bool loopback;
};

struct Device {
  // 'c' or 'b' for char or block
  char type;
  base::FilePath path;
  int fs_permissions;
  int major;
  int minor;

  // Copy the major from existing node, ignores |major|.
  bool copy_major;
  // Copy the minor from existing node, ignores |minor|.
  bool copy_minor;
  int uid;
  int gid;
};

struct CgroupDevice {
  bool allow;
  char type;

  // -1 for either major or minor means all.
  int major;
  int minor;

  bool read;
  bool write;
  bool modify;
};

struct CpuCgroup {
  int shares;
  int quota;
  int period;
  int rt_runtime;
  int rt_period;
};

struct Rlimit {
  int type;
  rlim_t cur;
  rlim_t max;
};

}  // namespace

// Structure that configures how the container is run.
struct container_config {
  // Path to the root of the container itself.
  base::FilePath config_root;

  // Path to the root of the container's filesystem.
  base::FilePath rootfs;

  // Flags that will be passed to mount() for the rootfs.
  unsigned long rootfs_mount_flags = 0x0;

  // Path to where the container will be run.
  base::FilePath premounted_runfs;

  // Path to the file where the pid should be written.
  base::FilePath pid_file_path;

  // The program to run and args, e.g. "/sbin/init".
  std::vector<std::string> program_argv;

  // The uid the container will run as.
  uid_t uid = 0;

  // Mapping of UIDs in the container, e.g. "0 100000 1024"
  std::string uid_map;

  // The gid the container will run as.
  gid_t gid = 0;

  // Mapping of GIDs in the container, e.g. "0 100000 1024"
  std::string gid_map;

  // The supplementary gids that attached to the container.
  std::vector<gid_t> additional_gids;

  // Syscall table to use or nullptr if none.
  std::string alt_syscall_table;

  // Filesystems to mount in the new namespace.
  std::vector<Mount> mounts;

  // Namespaces that should be used for the container.
  std::set<std::string> namespaces;

  // Device nodes to create.
  std::vector<Device> devices;

  // Device node cgroup permissions.
  std::vector<CgroupDevice> cgroup_devices;

  // CPU cgroup params.
  CpuCgroup cpu_cgparams;

  // Parent dir for cgroup creation
  base::FilePath cgroup_parent;

  // uid to own the created cgroups
  uid_t cgroup_owner = 0;

  // gid to own the created cgroups
  gid_t cgroup_group = 0;

  // Allow the child process to keep open FDs (for stdin/out/err).
  bool keep_fds_open = false;

  // Array of rlimits for the contained process.
  Rlimit rlimits[kMaxRlimits];

  // The number of elements in `rlimits`.
  int num_rlimits = 0;
  bool use_capmask = false;
  bool use_capmask_ambient = false;
  uint64_t capmask = 0x0;

  // The mask of securebits to skip when restricting caps.
  uint64_t securebits_skip_mask = 0x0;

  // Core Scheduling policy
  bool core_sched = false;

  // Whether the container needs an extra process to be run as init.
  bool do_init = false;

  // The SELinux context name the container will run under.
  std::string selinux_context;

  // A function pointer to be called prior to calling execve(2).
  minijail_hook_t pre_start_hook = nullptr;

  // Parameter that will be passed to pre_start_hook().
  void* pre_start_hook_payload = nullptr;

  // A list of file descriptors to inherit.
  std::vector<int> inherited_fds;

  // A list of hooks that will be called upon minijail reaching various states
  // of execution.
  std::map<minijail_hook_event_t, std::vector<libcontainer::HookCallback>>
      hooks;
};

// Container manipulation
struct container {
  std::unique_ptr<libcontainer::Cgroup> cgroup;
  ScopedMinijail jail;
  pid_t init_pid = -1;
  base::FilePath config_root;
  base::FilePath runfs;
  base::FilePath rundir;
  base::FilePath runfsroot;
  base::FilePath pid_file_path;

  // Mounts made outside of the minijail.
  std::vector<base::FilePath> ext_mounts;
  std::vector<Loopdev> loopdevs;
  std::vector<std::string> device_mappers;
  std::string name;

  std::vector<std::pair<libcontainer::HookState,
                        std::vector<libcontainer::HookCallback>>>
      hook_states;
};

namespace {

std::string GetMountFlagsAsString(int flags) {
#define CHECK_MOUNT_FLAG(flag) \
  do {                         \
    if (flags & flag)          \
      result.push_back(#flag); \
  } while (false)

  std::vector<std::string> result;
  CHECK_MOUNT_FLAG(MS_RDONLY);
  CHECK_MOUNT_FLAG(MS_NOSUID);
  CHECK_MOUNT_FLAG(MS_NODEV);
  CHECK_MOUNT_FLAG(MS_NOEXEC);
  CHECK_MOUNT_FLAG(MS_SYNCHRONOUS);
  CHECK_MOUNT_FLAG(MS_REMOUNT);
  CHECK_MOUNT_FLAG(MS_MANDLOCK);
  CHECK_MOUNT_FLAG(MS_DIRSYNC);
  CHECK_MOUNT_FLAG(MS_NOATIME);
  CHECK_MOUNT_FLAG(MS_NODIRATIME);
  CHECK_MOUNT_FLAG(MS_BIND);
  CHECK_MOUNT_FLAG(MS_MOVE);
  CHECK_MOUNT_FLAG(MS_REC);
  CHECK_MOUNT_FLAG(MS_SILENT);
  CHECK_MOUNT_FLAG(MS_POSIXACL);
  CHECK_MOUNT_FLAG(MS_UNBINDABLE);
  CHECK_MOUNT_FLAG(MS_PRIVATE);
  CHECK_MOUNT_FLAG(MS_SLAVE);
  CHECK_MOUNT_FLAG(MS_SHARED);
  return result.empty() ? "no flags" : base::JoinString(result, " | ");

#undef CHECK_MOUNT_FLAG
}

std::ostream& operator<<(std::ostream& stream, const Mount& mount) {
  stream << "mount:" << std::endl
         << " name: " << QUOTE(mount.name) << std::endl
         << " source: " << QUOTE(mount.source.value()) << std::endl
         << " destination: " << QUOTE(mount.destination.value()) << std::endl
         << " type: " << QUOTE(mount.type) << std::endl
         << " data: " << QUOTE(mount.data) << std::endl
         << " verity: " << QUOTE(mount.verity) << std::endl
         << " flags: 0x" << std::hex << mount.flags << std::dec << " ("
         << GetMountFlagsAsString(mount.flags) << ")" << std::endl
         << " uid: " << mount.uid << std::endl
         << " gid: " << mount.gid << std::endl
         << " mode: 0" << std::oct << mount.mode << std::dec << std::endl
         << " mount_in_ns: " << mount.mount_in_ns << std::endl
         << " create: " << mount.create << std::endl
         << " loopback: " << mount.loopback << std::endl;

  return stream;
}

std::ostream& operator<<(std::ostream& stream, const Device& device) {
  stream << "device:" << std::endl
         << " type: " << device.type << std::endl
         << " path: " << QUOTE(device.path.value()) << std::endl
         << " fs_permissions: 0" << std::oct << device.fs_permissions
         << std::dec << std::endl
         << " major: " << device.major << std::endl
         << " minor: " << device.minor << std::endl
         << " copy_minor: " << device.copy_minor << std::endl
         << " uid: " << device.uid << std::endl
         << " gid: " << device.gid << std::endl;

  return stream;
}

std::ostream& operator<<(std::ostream& stream,
                         const CgroupDevice& cgroup_device) {
  stream << "cgroup_device:" << std::endl
         << " allow: " << cgroup_device.allow << std::endl
         << " type: " << cgroup_device.type << std::endl
         << " major: " << cgroup_device.major << std::endl
         << " minor: " << cgroup_device.minor << std::endl
         << " read: " << cgroup_device.read << std::endl
         << " write: " << cgroup_device.write << std::endl
         << " modify: " << cgroup_device.modify << std::endl;

  return stream;
}

std::ostream& operator<<(std::ostream& stream, const CpuCgroup& cpu_cgroup) {
  stream << "cpu_cgroup:" << std::endl
         << " shares: " << cpu_cgroup.shares << std::endl
         << " quota: " << cpu_cgroup.quota << std::endl
         << " period: " << cpu_cgroup.period << std::endl
         << " rt_runtime: " << cpu_cgroup.rt_runtime << std::endl
         << " rt_period: " << cpu_cgroup.rt_period << std::endl;

  return stream;
}

std::ostream& operator<<(std::ostream& stream, const Rlimit& rlimit) {
  stream << "rlimit:" << std::endl
         << " type: " << rlimit.type << std::endl
         << " cur: " << rlimit.cur << std::endl
         << " max: " << rlimit.max << std::endl;

  return stream;
}

void DumpConfig(std::ostream* stream,
                const container_config* c,
                bool sort_vectors) {
  *stream << "config_root: " << QUOTE(c->config_root.value()) << std::endl
          << "rootfs: " << QUOTE(c->rootfs.value()) << std::endl
          << "rootfs_mount_flags: 0x" << std::hex << c->rootfs_mount_flags
          << std::dec << " (" << GetMountFlagsAsString(c->rootfs_mount_flags)
          << ")" << std::endl
          << "premounted_runfs: " << QUOTE(c->premounted_runfs.value())
          << std::endl
          << "pid_file_path: " << QUOTE(c->pid_file_path.value()) << std::endl
          << "program_argv: size=" << c->program_argv.size() << std::endl;

  for (const std::string& argv : c->program_argv)
    *stream << " " << QUOTE(argv) << std::endl;

  *stream << "uid: " << c->uid << std::endl
          << "uid_map: " << QUOTE(c->uid_map) << std::endl
          << "gid: " << c->gid << std::endl
          << "gid_map: " << QUOTE(c->gid_map) << std::endl
          << "alt_syscall_table: " << QUOTE(c->alt_syscall_table) << std::endl
          << "core_sched:" << (c->core_sched ? "enable" : "disable")
          << std::endl;

  auto mount_sorted = c->mounts;
  if (sort_vectors) {
    std::stable_sort(mount_sorted.begin(), mount_sorted.end(),
                     [](const Mount& lhs, const Mount& rhs) {
                       return std::make_tuple(lhs.destination.value(),
                                              lhs.source.value(), lhs.flags) <
                              std::make_tuple(rhs.destination.value(),
                                              rhs.source.value(), rhs.flags);
                     });
  }
  for (const auto& mount : mount_sorted)
    *stream << mount;

  *stream << "namespaces: size=" << c->namespaces.size() << std::endl;
  for (const std::string& ns : c->namespaces)
    *stream << " " << QUOTE(ns) << std::endl;

  auto devices_sorted = c->devices;
  if (sort_vectors) {
    std::stable_sort(devices_sorted.begin(), devices_sorted.end(),
                     [](const Device& lhs, const Device& rhs) {
                       return lhs.path.value() < rhs.path.value();
                     });
  }
  for (const auto& device : devices_sorted)
    *stream << device;

  auto cgroup_devices_sorted = c->cgroup_devices;
  if (sort_vectors) {
    std::stable_sort(cgroup_devices_sorted.begin(), cgroup_devices_sorted.end(),
                     [](const CgroupDevice& lhs, const CgroupDevice& rhs) {
                       return std::make_tuple(lhs.type, lhs.major, lhs.minor) <
                              std::make_tuple(rhs.type, rhs.major, rhs.minor);
                     });
  }
  for (const auto& cgroup_device : cgroup_devices_sorted)
    *stream << cgroup_device;

  *stream << c->cpu_cgparams
          << "cgroup_parent: " << QUOTE(c->cgroup_parent.value()) << std::endl
          << "cgroup_owner: " << c->cgroup_owner << std::endl
          << "cgroup_group: " << c->cgroup_group << std::endl
          << "keep_fds_open: " << c->keep_fds_open << std::endl;

  *stream << "num_rlimits: " << c->num_rlimits << std::endl;
  for (size_t i = 0; i < c->num_rlimits; ++i)
    *stream << c->rlimits[i];

  *stream << "use_capmask: " << c->use_capmask << std::endl
          << "use_capmask_ambient: " << c->use_capmask_ambient << std::endl
          << "capmask: 0x" << std::hex << c->capmask << std::dec << std::endl
          << "securebits_skip_mask: 0x" << std::hex << c->securebits_skip_mask
          << std::dec << std::endl
          << "do_init: " << c->do_init << std::endl
          << "selinux_context: " << QUOTE(c->selinux_context) << std::endl
          << "pre_start_hook: " << reinterpret_cast<void*>(c->pre_start_hook)
          << std::endl
          << "pre_start_hook_payload: " << c->pre_start_hook_payload
          << std::endl
          << "inherited_fds: size=" << c->inherited_fds.size() << std::endl;

  for (int fd : c->inherited_fds)
    *stream << " " << fd << std::endl;

  *stream << "hooks: size=" << c->hooks.size() << std::endl;
}

// Returns the path for |path_in_container| in the outer namespace.
base::FilePath GetPathInOuterNamespace(
    const base::FilePath& root, const base::FilePath& path_in_container) {
  if (path_in_container.IsAbsolute())
    return base::FilePath(root.value() + path_in_container.value());
  return root.Append(path_in_container);
}

// Make sure the mount target exists in the new rootfs. Create if needed and
// possible.
bool SetupMountDestination(const struct container_config* config,
                           const Mount& mount,
                           const base::FilePath& source,
                           const base::FilePath& dest) {
  struct stat st_buf;
  if (stat(dest.value().c_str(), &st_buf) == 0) {
    // destination exists.
    return true;
  }

  // Try to create the destination. Either make directory or touch a file
  // depending on the source type.
  int uid_userns;
  if (!GetUsernsOutsideId(config->uid_map, mount.uid, &uid_userns))
    return false;
  int gid_userns;
  if (!GetUsernsOutsideId(config->gid_map, mount.gid, &gid_userns))
    return false;

  if (stat(source.value().c_str(), &st_buf) != 0 || S_ISDIR(st_buf.st_mode) ||
      S_ISBLK(st_buf.st_mode)) {
    return MakeDir(dest, uid_userns, gid_userns, mount.mode);
  }

  return TouchFile(dest, uid_userns, gid_userns, mount.mode);
}

// Unmounts anything we mounted in this mount namespace in the opposite order
// that they were mounted.
bool UnmountExternalMounts(struct container* c) {
  bool ret = true;

  for (auto it = c->ext_mounts.rbegin(); it != c->ext_mounts.rend(); ++it) {
    if (umount(it->value().c_str()) != 0) {
      PLOG(ERROR) << "Failed to unmount " << it->value();
      ret = false;
    }
  }
  c->ext_mounts.clear();

  for (auto it = c->loopdevs.rbegin(); it != c->loopdevs.rend(); ++it) {
    if (!LoopdevDetach(&(*it)))
      ret = false;
  }
  c->loopdevs.clear();

  for (auto it = c->device_mappers.rbegin(); it != c->device_mappers.rend();
       ++it) {
    if (!DeviceMapperDetach(*it))
      ret = false;
  }
  c->device_mappers.clear();

  return ret;
}

bool DoContainerMount(struct container* c,
                      const struct container_config* config,
                      const Mount& mount) {
  base::FilePath dest =
      GetPathInOuterNamespace(c->runfsroot, mount.destination);

  // If it's a bind mount relative to rootfs, append source to
  // rootfs path, otherwise source path is absolute.
  base::FilePath source;
  if ((mount.flags & MS_BIND) && !mount.source.IsAbsolute()) {
    source = GetPathInOuterNamespace(c->runfsroot, mount.source);
  } else if (mount.loopback && !mount.source.IsAbsolute() &&
             !c->config_root.empty()) {
    source = GetPathInOuterNamespace(c->config_root, mount.source);
  } else {
    source = mount.source;
  }

  // Only create the destinations for external mounts, minijail will take
  // care of those mounted in the new namespace.
  if (mount.create && !mount.mount_in_ns) {
    if (!SetupMountDestination(config, mount, source, dest))
      return false;
  }
  if (mount.loopback) {
    Loopdev loopdev;
    if (!LoopdevSetup(source, &loopdev))
      return false;

    // Replace the mount source with the loopback device path.
    source = loopdev.path;

    // Save this to cleanup when shutting down.
    c->loopdevs.emplace_back(std::move(loopdev));
  }
  if (!mount.verity.empty()) {
    // Set this device up via dm-verity.
    std::string dm_name;
    base::FilePath dm_source = source;
    if (!DeviceMapperSetup(dm_source, mount.verity, &source, &dm_name))
      return false;

    // Save this to cleanup when shutting down.
    c->device_mappers.push_back(dm_name);
  }
  if (mount.mount_in_ns) {
    // We can mount this with minijail.
    if (minijail_mount_with_data(
            c->jail.get(), source.value().c_str(),
            mount.destination.value().c_str(), mount.type.c_str(), mount.flags,
            mount.data.empty() ? nullptr : mount.data.c_str()) != 0) {
      return false;
    }
  } else {
    // Mount this externally and unmount it on exit.
    if (!MountExternal(source.value(), dest.value(), mount.type, mount.flags,
                       mount.data)) {
      return false;
    }
    // Save this to unmount when shutting down.
    c->ext_mounts.push_back(dest);
  }

  return true;
}

bool DoContainerMounts(struct container* c,
                       const struct container_config* config) {
  UnmountExternalMounts(c);

  // This will run in all the error cases.
  base::ScopedClosureRunner teardown(base::BindOnce(
      base::IgnoreResult(&UnmountExternalMounts), base::Unretained(c)));

  for (const auto& mount : config->mounts) {
    if (!DoContainerMount(c, config, mount))
      return false;
  }

  // The mounts have been done successfully, no need to tear them down anymore.
  teardown.ReplaceClosure(base::DoNothing());

  return true;
}

bool ContainerCreateDevice(const struct container* c,
                           const struct container_config* config,
                           const Device& dev,
                           int major,
                           int minor) {
  mode_t mode = dev.fs_permissions;
  switch (dev.type) {
    case 'b':
      mode |= S_IFBLK;
      break;
    case 'c':
      mode |= S_IFCHR;
      break;
    default:
      return false;
  }

  int uid_userns;
  if (!GetUsernsOutsideId(config->uid_map, dev.uid, &uid_userns))
    return false;
  int gid_userns;
  if (!GetUsernsOutsideId(config->gid_map, dev.gid, &gid_userns))
    return false;

  base::FilePath path = GetPathInOuterNamespace(c->runfsroot, dev.path);
  if (!libcontainer::CreateDirectoryOwnedBy(path.DirName(), 0755, uid_userns,
                                            gid_userns)) {
    PLOG(ERROR) << "Failed to create parent directory for " << path.value();
    return false;
  }
  if (mknod(path.value().c_str(), mode, makedev(major, minor)) != 0 &&
      errno != EEXIST) {
    PLOG(ERROR) << "Failed to mknod " << path.value();
    return false;
  }
  if (chown(path.value().c_str(), uid_userns, gid_userns) != 0) {
    PLOG(ERROR) << "Failed to chown " << path.value();
    return false;
  }
  if (chmod(path.value().c_str(), dev.fs_permissions) != 0) {
    PLOG(ERROR) << "Failed to chmod " << path.value();
    return false;
  }

  return true;
}

bool MountRunfs(struct container* c, const struct container_config* config) {
  {
    std::string runfs_template = base::StringPrintf(
        "%s/%s_XXXXXX", c->rundir.value().c_str(), c->name.c_str());
    // TODO(lhchavez): Replace this with base::CreateTemporaryDirInDir().
    char* runfs_path = mkdtemp(const_cast<char*>(runfs_template.c_str()));
    if (!runfs_path) {
      PLOG(ERROR) << "Failed to mkdtemp in " << c->rundir.value();
      return false;
    }
    c->runfs = base::FilePath(runfs_path);
  }

  int uid_userns;
  if (!GetUsernsOutsideId(config->uid_map, config->uid, &uid_userns))
    return false;
  int gid_userns;
  if (!GetUsernsOutsideId(config->gid_map, config->gid, &gid_userns))
    return false;

  // Make sure the container uid can access the rootfs.
  if (chmod(c->runfs.value().c_str(), 0700) != 0) {
    PLOG(ERROR) << "Failed to chmod " << c->runfs.value();
    return false;
  }
  if (chown(c->runfs.value().c_str(), uid_userns, gid_userns) != 0) {
    PLOG(ERROR) << "Failed to chown " << c->runfs.value();
    return false;
  }

  c->runfsroot = c->runfs.Append("root");

  constexpr mode_t kRootDirMode = 0660;
  if (mkdir(c->runfsroot.value().c_str(), kRootDirMode) != 0) {
    PLOG(ERROR) << "Failed to mkdir " << c->runfsroot.value();
    return false;
  }
  if (chmod(c->runfsroot.value().c_str(), kRootDirMode) != 0) {
    PLOG(ERROR) << "Failed to chmod " << c->runfsroot.value();
    return false;
  }

  if (mount(config->rootfs.value().c_str(), c->runfsroot.value().c_str(), "",
            MS_BIND | (config->rootfs_mount_flags & MS_REC), nullptr) != 0) {
    PLOG(ERROR) << "Failed to bind-mount " << config->rootfs.value();
    return false;
  }

  // MS_BIND ignores any flags passed to it (except MS_REC). We need a
  // second call to mount() to actually set them.
  if (config->rootfs_mount_flags &&
      mount(config->rootfs.value().c_str(), c->runfsroot.value().c_str(), "",
            (config->rootfs_mount_flags & ~MS_REC), nullptr) != 0) {
    PLOG(ERROR) << "Failed to remount " << c->runfsroot.value();
    return false;
  }

  return true;
}

bool CreateDeviceNodes(struct container* c,
                       const struct container_config* config,
                       pid_t container_pid) {
  for (const auto& dev : config->devices) {
    int major = dev.major;
    int minor = dev.minor;

    if (dev.copy_major || dev.copy_minor) {
      struct stat st_buff;
      if (stat(dev.path.value().c_str(), &st_buff) != 0)
        continue;

      if (dev.copy_major)
        major = major(st_buff.st_rdev);
      if (dev.copy_minor)
        minor = minor(st_buff.st_rdev);
    }
    if (major < 0 || minor < 0)
      continue;
    if (!ContainerCreateDevice(c, config, dev, major, minor))
      return false;
  }

  return true;
}

bool DeviceSetup(struct container* c, const struct container_config* config) {
  c->cgroup->DenyAllDevices();

  for (const auto& dev : config->cgroup_devices) {
    if (!c->cgroup->AddDevice(dev.allow, dev.major, dev.minor, dev.read,
                              dev.write, dev.modify, dev.type)) {
      return false;
    }
  }

  for (const auto& loopdev : c->loopdevs) {
    if (!c->cgroup->AddDevice(1, major(loopdev.info.lo_rdevice),
                              minor(loopdev.info.lo_rdevice), 1, 0, 0, 'b')) {
      return false;
    }
  }

  return true;
}

int SetCoreSched(void* payload) {
  int ret = prctl(PR_SET_CORE_SCHED, 1);
  if (ret != 0 && errno != EINVAL) {
    // Bubble error, minijail will abort child process.
    return -errno;
  }
  // Success or unsupported on this kernel, continue.
  return 0;
}

int Setexeccon(void* payload) {
  char* init_domain = reinterpret_cast<char*>(payload);
  pid_t tid = syscall(SYS_gettid);

  if (tid < 0) {
    PLOG(ERROR) << "Failed to gettid";
    return -errno;
  }

  std::string exec_path =
      base::StringPrintf("/proc/self/task/%d/attr/exec", tid);

  base::ScopedFD fd(open(exec_path.c_str(), O_WRONLY | O_CLOEXEC));
  if (!fd.is_valid()) {
    PLOG(ERROR) << "Failed to open " << exec_path;
    return -errno;
  }

  if (!base::WriteFileDescriptor(fd.get(), init_domain)) {
    PLOG(ERROR) << "Failed to write the SELinux label to " << exec_path;
    return -errno;
  }

  return 0;
}

bool ContainerTeardown(struct container* c) {
  UnmountExternalMounts(c);
  if (!c->runfsroot.empty() && !c->runfs.empty()) {
    /* |c->runfsroot| may have been mounted recursively. Thus use
     * MNT_DETACH to "immediately disconnect the filesystem and all
     * filesystems mounted below it from each other and from the
     * mount table". Otherwise one would need to unmount every
     * single dependent mount before unmounting |c->runfsroot|
     * itself.
     */
    if (umount2(c->runfsroot.value().c_str(), MNT_DETACH) != 0) {
      PLOG(ERROR) << "Failed to detach " << c->runfsroot.value();
      return false;
    }
    if (rmdir(c->runfsroot.value().c_str()) != 0) {
      PLOG(ERROR) << "Failed to rmdir " << c->runfsroot.value();
      return false;
    }
    c->runfsroot = base::FilePath();
  }
  if (!c->pid_file_path.empty()) {
    if (unlink(c->pid_file_path.value().c_str()) != 0) {
      PLOG(ERROR) << "Failed to unlink " << c->pid_file_path.value();
      return false;
    }
    c->pid_file_path = base::FilePath();
  }
  if (!c->runfs.empty()) {
    if (rmdir(c->runfs.value().c_str()) != 0) {
      PLOG(ERROR) << "Failed to rmdir " << c->runfs.value();
      return false;
    }
    c->runfs = base::FilePath();
  }
  return true;
}

void CancelContainerStart(struct container* c) {
  if (c->init_pid != -1)
    container_kill(c);
  ContainerTeardown(c);
}

}  // namespace

struct container_config* container_config_create() {
  return new (std::nothrow) struct container_config();
}

void container_config_destroy(struct container_config* c) {
  if (c == nullptr)
    return;
  delete c;
}

int container_config_config_root(struct container_config* c,
                                 const char* config_root) {
  c->config_root = base::FilePath(config_root);
  return 0;
}

const char* container_config_get_config_root(const struct container_config* c) {
  return c->config_root.value().c_str();
}

int container_config_rootfs(struct container_config* c, const char* rootfs) {
  c->rootfs = base::FilePath(rootfs);
  return 0;
}

const char* container_config_get_rootfs(const struct container_config* c) {
  return c->rootfs.value().c_str();
}

void container_config_rootfs_mount_flags(struct container_config* c,
                                         unsigned long rootfs_mount_flags) {
  /* Since we are going to add MS_REMOUNT anyways, add it here so we can
   * simply check against zero later. MS_BIND is also added to avoid
   * re-mounting the original filesystem, since the rootfs is always
   * bind-mounted.
   */
  c->rootfs_mount_flags = MS_REMOUNT | MS_BIND | rootfs_mount_flags;
}

unsigned long container_config_get_rootfs_mount_flags(
    const struct container_config* c) {
  return c->rootfs_mount_flags;
}

int container_config_premounted_runfs(struct container_config* c,
                                      const char* runfs) {
  c->premounted_runfs = base::FilePath(runfs);
  return 0;
}

const char* container_config_get_premounted_runfs(
    const struct container_config* c) {
  return c->premounted_runfs.value().c_str();
}

int container_config_pid_file(struct container_config* c, const char* path) {
  c->pid_file_path = base::FilePath(path);
  return 0;
}

const char* container_config_get_pid_file(const struct container_config* c) {
  return c->pid_file_path.value().c_str();
}

int container_config_program_argv(struct container_config* c,
                                  const char** argv,
                                  size_t num_args) {
  if (num_args < 1) {
    errno = EINVAL;
    return -1;
  }
  c->program_argv.clear();
  c->program_argv.reserve(num_args);
  for (size_t i = 0; i < num_args; ++i)
    c->program_argv.emplace_back(argv[i]);
  return 0;
}

size_t container_config_get_num_program_args(const struct container_config* c) {
  return c->program_argv.size();
}

const char* container_config_get_program_arg(const struct container_config* c,
                                             size_t index) {
  if (index >= c->program_argv.size())
    return nullptr;
  return c->program_argv[index].c_str();
}

void container_config_uid(struct container_config* c, uid_t uid) {
  c->uid = uid;
}

uid_t container_config_get_uid(const struct container_config* c) {
  return c->uid;
}

int container_config_uid_map(struct container_config* c, const char* uid_map) {
  c->uid_map = uid_map;
  return 0;
}

void container_config_gid(struct container_config* c, gid_t gid) {
  c->gid = gid;
}

gid_t container_config_get_gid(const struct container_config* c) {
  return c->gid;
}

int container_config_gid_map(struct container_config* c, const char* gid_map) {
  c->gid_map = gid_map;
  return 0;
}

void container_config_additional_gids(struct container_config* c,
                                      const gid_t* gids,
                                      size_t num_gids) {
  c->additional_gids.assign(gids, gids + num_gids);
}

int container_config_alt_syscall_table(struct container_config* c,
                                       const char* alt_syscall_table) {
  c->alt_syscall_table = alt_syscall_table;
  return 0;
}

int container_config_add_rlimit(struct container_config* c,
                                int type,
                                rlim_t cur,
                                rlim_t max) {
  if (c->num_rlimits >= kMaxRlimits) {
    errno = ENOMEM;
    return -1;
  }
  c->rlimits[c->num_rlimits].type = type;
  c->rlimits[c->num_rlimits].cur = cur;
  c->rlimits[c->num_rlimits].max = max;
  c->num_rlimits++;
  return 0;
}

int container_config_add_mount(struct container_config* c,
                               const char* name,
                               const char* source,
                               const char* destination,
                               const char* type,
                               const char* data,
                               const char* verity,
                               int flags,
                               int uid,
                               int gid,
                               int mode,
                               int mount_in_ns,
                               int create,
                               int loopback) {
  if (name == nullptr || source == nullptr || destination == nullptr ||
      type == nullptr) {
    errno = EINVAL;
    return -1;
  }

  c->mounts.emplace_back(
      Mount{name, base::FilePath(source), base::FilePath(destination), type,
            data ? data : "", verity ? verity : "", flags, uid, gid, mode,
            mount_in_ns != 0, create != 0, loopback != 0});

  return 0;
}

int container_config_add_cgroup_device(struct container_config* c,
                                       int allow,
                                       char type,
                                       int major,
                                       int minor,
                                       int read,
                                       int write,
                                       int modify) {
  c->cgroup_devices.emplace_back(CgroupDevice{
      allow != 0, type, major, minor, read != 0, write != 0, modify != 0});

  return 0;
}

int container_config_add_device(struct container_config* c,
                                char type,
                                const char* path,
                                int fs_permissions,
                                int major,
                                int minor,
                                int copy_major,
                                int copy_minor,
                                int uid,
                                int gid,
                                int read_allowed,
                                int write_allowed,
                                int modify_allowed) {
  if (path == nullptr) {
    errno = EINVAL;
    return -1;
  }
  /* If using a dynamic major/minor number, ensure that major/minor is -1. */
  if ((copy_major && (major != -1)) || (copy_minor && (minor != -1))) {
    errno = EINVAL;
    return -1;
  }

  if (read_allowed || write_allowed || modify_allowed) {
    if (container_config_add_cgroup_device(c, 1, type, major, minor,
                                           read_allowed, write_allowed,
                                           modify_allowed) != 0) {
      errno = ENOMEM;
      return -1;
    }
  }

  c->devices.emplace_back(Device{
      type,
      base::FilePath(path),
      fs_permissions,
      major,
      minor,
      copy_major != 0,
      copy_minor != 0,
      uid,
      gid,
  });

  return 0;
}

int container_config_set_core_sched(struct container_config* c, int enable) {
  c->core_sched = enable;
  return 0;
}

int container_config_set_cpu_shares(struct container_config* c, int shares) {
  /* CPU shares must be 2 or higher. */
  if (shares < 2) {
    errno = EINVAL;
    return -1;
  }

  c->cpu_cgparams.shares = shares;
  return 0;
}

int container_config_set_cpu_cfs_params(struct container_config* c,
                                        int quota,
                                        int period) {
  /*
   * quota could be set higher than period to utilize more than one CPU.
   * quota could also be set as -1 to indicate the cgroup does not adhere
   * to any CPU time restrictions.
   */
  if (quota <= 0 && quota != -1) {
    errno = EINVAL;
    return -1;
  }
  if (period <= 0) {
    errno = EINVAL;
    return -1;
  }

  c->cpu_cgparams.quota = quota;
  c->cpu_cgparams.period = period;
  return 0;
}

int container_config_set_cpu_rt_params(struct container_config* c,
                                       int rt_runtime,
                                       int rt_period) {
  /*
   * rt_runtime could be set as 0 to prevent the cgroup from using
   * realtime CPU.
   */
  if (rt_runtime < 0 || rt_runtime >= rt_period) {
    errno = EINVAL;
    return -1;
  }

  c->cpu_cgparams.rt_runtime = rt_runtime;
  c->cpu_cgparams.rt_period = rt_period;
  return 0;
}

int container_config_get_cpu_shares(struct container_config* c) {
  return c->cpu_cgparams.shares;
}

int container_config_get_cpu_quota(struct container_config* c) {
  return c->cpu_cgparams.quota;
}

int container_config_get_cpu_period(struct container_config* c) {
  return c->cpu_cgparams.period;
}

int container_config_get_cpu_rt_runtime(struct container_config* c) {
  return c->cpu_cgparams.rt_runtime;
}

int container_config_get_cpu_rt_period(struct container_config* c) {
  return c->cpu_cgparams.rt_period;
}

int container_config_set_cgroup_parent(struct container_config* c,
                                       const char* parent,
                                       uid_t cgroup_owner,
                                       gid_t cgroup_group) {
  c->cgroup_owner = cgroup_owner;
  c->cgroup_group = cgroup_group;
  c->cgroup_parent = base::FilePath(parent);
  return 0;
}

const char* container_config_get_cgroup_parent(struct container_config* c) {
  return c->cgroup_parent.value().c_str();
}

int container_config_namespaces(struct container_config* c,
                                const char** namespaces,
                                size_t num_ns) {
  if (num_ns < 1)
    return -EINVAL;
  c->namespaces.clear();
  for (size_t i = 0; i < num_ns; ++i)
    c->namespaces.emplace(namespaces[i]);
  return 0;
}

size_t container_config_get_num_namespaces(const struct container_config* c) {
  return c->namespaces.size();
}

bool container_config_has_namespace(const struct container_config* c,
                                    const char* ns) {
  return c->namespaces.find(ns) != c->namespaces.end();
}

void container_config_keep_fds_open(struct container_config* c) {
  c->keep_fds_open = true;
}

void container_config_set_capmask(struct container_config* c,
                                  uint64_t capmask,
                                  int ambient) {
  c->use_capmask = true;
  c->capmask = capmask;
  c->use_capmask_ambient = ambient;
}

void container_config_set_securebits_skip_mask(struct container_config* c,
                                               uint64_t securebits_skip_mask) {
  c->securebits_skip_mask = securebits_skip_mask;
}

void container_config_set_run_as_init(struct container_config* c,
                                      int run_as_init) {
  c->do_init = !run_as_init;
}

int container_config_set_selinux_context(struct container_config* c,
                                         const char* context) {
  if (!context) {
    errno = EINVAL;
    return -1;
  }
  c->selinux_context = context;
  return 0;
}

void container_config_set_pre_execve_hook(struct container_config* c,
                                          int (*hook)(void*),
                                          void* payload) {
  c->pre_start_hook = hook;
  c->pre_start_hook_payload = payload;
}

void container_config_add_hook(struct container_config* c,
                               minijail_hook_event_t event,
                               libcontainer::HookCallback callback) {
  auto it = c->hooks.insert(
      std::make_pair(event, std::vector<libcontainer::HookCallback>()));
  it.first->second.emplace_back(std::move(callback));
}

int container_config_add_hook(struct container_config* c,
                              minijail_hook_event_t event,
                              const char* filename,
                              const char** argv,
                              size_t num_args,
                              int* pstdin_fd,
                              int* pstdout_fd,
                              int* pstderr_fd) {
  std::vector<std::string> args;
  args.reserve(num_args);
  for (size_t i = 0; i < num_args; ++i)
    args.emplace_back(argv[i]);

  // First element of the array belongs to the parent and the second one belongs
  // to the child.
  base::ScopedFD stdin_fds[2], stdout_fds[2], stderr_fds[2];
  if (pstdin_fd) {
    if (!libcontainer::Pipe2(&stdin_fds[1], &stdin_fds[0], 0))
      return -1;
  }
  if (pstdout_fd) {
    if (!libcontainer::Pipe2(&stdout_fds[0], &stdout_fds[0], 0))
      return -1;
  }
  if (pstderr_fd) {
    if (!libcontainer::Pipe2(&stderr_fds[0], &stderr_fds[0], 0))
      return -1;
  }

  // After this point the call has been successful, so we can now commit to
  // whatever pipes we have opened.
  if (pstdin_fd) {
    *pstdin_fd = stdin_fds[0].release();
    c->inherited_fds.emplace_back(stdin_fds[1].get());
  }
  if (pstdout_fd) {
    *pstdout_fd = stdout_fds[0].release();
    c->inherited_fds.emplace_back(stdout_fds[1].get());
  }
  if (pstderr_fd) {
    *pstderr_fd = stderr_fds[0].release();
    c->inherited_fds.emplace_back(stderr_fds[1].get());
  }
  container_config_add_hook(
      c, event,
      libcontainer::CreateExecveCallback(
          base::FilePath(filename), args, std::move(stdin_fds[1]),
          std::move(stdout_fds[1]), std::move(stderr_fds[1])));
  return 0;
}

int container_config_inherit_fds(struct container_config* c,
                                 const int* inherited_fds,
                                 size_t inherited_fd_count) {
  if (!c->inherited_fds.empty()) {
    errno = EINVAL;
    return -1;
  }
  for (size_t i = 0; i < inherited_fd_count; ++i)
    c->inherited_fds.emplace_back(inherited_fds[i]);
  return 0;
}

struct container* container_new(const char* name, const char* rundir) {
  struct container* c = new (std::nothrow) container();
  if (!c)
    return nullptr;
  c->rundir = base::FilePath(rundir);
  c->name = name;
  return c;
}

void container_destroy(struct container* c) {
  delete c;
}

int container_start(struct container* c, struct container_config* config) {
  if (!c) {
    errno = EINVAL;
    return -1;
  }
  if (!config) {
    errno = EINVAL;
    return -1;
  }
  if (config->program_argv.empty()) {
    errno = EINVAL;
    return -1;
  }

  // This will run in all the error cases.
  base::ScopedClosureRunner teardown(
      base::BindOnce(&CancelContainerStart, base::Unretained(c)));

  if (!config->config_root.empty())
    c->config_root = config->config_root;
  if (!config->premounted_runfs.empty()) {
    c->runfs.clear();
    c->runfsroot = config->premounted_runfs;
  } else {
    if (!MountRunfs(c, config))
      return -1;
  }

  c->jail.reset(minijail_new());
  if (!c->jail) {
    errno = ENOMEM;
    return -1;
  }

  if (!DoContainerMounts(c, config))
    return -1;

  int cgroup_uid;
  if (!GetUsernsOutsideId(config->uid_map, config->cgroup_owner, &cgroup_uid))
    return -1;
  int cgroup_gid;
  if (!GetUsernsOutsideId(config->gid_map, config->cgroup_group, &cgroup_gid))
    return -1;

  c->cgroup = libcontainer::Cgroup::Create(
      c->name, base::FilePath("/sys/fs/cgroup"), config->cgroup_parent,
      cgroup_uid, cgroup_gid);
  if (!c->cgroup)
    return -1;

  // Must be root to modify device cgroup or mknod.
  std::map<minijail_hook_event_t, std::vector<libcontainer::HookCallback>>
      hook_callbacks;
  if (getuid() == 0) {
    if (!config->devices.empty()) {
      // Create the devices in the mount namespace.
      auto it = hook_callbacks.insert(
          std::make_pair(MINIJAIL_HOOK_EVENT_PRE_CHROOT,
                         std::vector<libcontainer::HookCallback>()));
      it.first->second.emplace_back(
          libcontainer::AdaptCallbackToRunInNamespaces(
              base::BindOnce(&CreateDeviceNodes, base::Unretained(c),
                             base::Unretained(config)),
              {CLONE_NEWNS}));
    }
    if (!DeviceSetup(c, config))
      return -1;
  }

  /* Setup CPU cgroup params. */
  if (config->cpu_cgparams.shares) {
    if (!c->cgroup->SetCpuShares(config->cpu_cgparams.shares))
      return -1;
  }
  if (config->cpu_cgparams.period) {
    if (!c->cgroup->SetCpuQuota(config->cpu_cgparams.quota))
      return -1;
    if (!c->cgroup->SetCpuPeriod(config->cpu_cgparams.period))
      return -1;
  }
  if (config->cpu_cgparams.rt_period) {
    if (!c->cgroup->SetCpuRtRuntime(config->cpu_cgparams.rt_runtime))
      return -1;
    if (!c->cgroup->SetCpuRtPeriod(config->cpu_cgparams.rt_period))
      return -1;
  }

  /* Setup and start the container with libminijail. */
  if (!config->pid_file_path.empty())
    c->pid_file_path = config->pid_file_path;
  else if (!c->runfs.empty())
    c->pid_file_path = c->runfs.Append("container.pid");

  if (!c->pid_file_path.empty())
    minijail_write_pid_file(c->jail.get(), c->pid_file_path.value().c_str());
  minijail_forward_signals(c->jail.get());
  minijail_reset_signal_mask(c->jail.get());
  minijail_reset_signal_handlers(c->jail.get());

  /* Setup container namespaces. */
  if (container_config_has_namespace(config, "ipc"))
    minijail_namespace_ipc(c->jail.get());
  if (container_config_has_namespace(config, "mount"))
    minijail_namespace_vfs(c->jail.get());
  if (container_config_has_namespace(config, "network"))
    minijail_namespace_net(c->jail.get());
  if (container_config_has_namespace(config, "pid"))
    minijail_namespace_pids(c->jail.get());

  if (container_config_has_namespace(config, "user")) {
    minijail_namespace_user(c->jail.get());
    if (minijail_uidmap(c->jail.get(), config->uid_map.c_str()) != 0)
      return -1;
    if (minijail_gidmap(c->jail.get(), config->gid_map.c_str()) != 0)
      return -1;
  }

  if (container_config_has_namespace(config, "cgroup"))
    minijail_namespace_cgroups(c->jail.get());

  if (getuid() != 0)
    minijail_namespace_user_disable_setgroups(c->jail.get());

  // Set the UID/GID inside the container if not 0.
  if (!GetUsernsOutsideId(config->uid_map, config->uid, nullptr))
    return -1;
  else if (config->uid > 0)
    minijail_change_uid(c->jail.get(), config->uid);
  if (!GetUsernsOutsideId(config->gid_map, config->gid, nullptr))
    return -1;
  else if (config->gid > 0)
    minijail_change_gid(c->jail.get(), config->gid);

  // Set the supplementary GIDs inside the container, if specified.
  if (!config->additional_gids.empty()) {
    for (const gid_t additional_gid : config->additional_gids) {
      if (!GetUsernsOutsideId(config->gid_map, additional_gid, nullptr))
        return -1;
    }
    minijail_set_supplementary_gids(c->jail.get(),
                                    config->additional_gids.size(),
                                    config->additional_gids.data());
  }

  if (minijail_enter_pivot_root(c->jail.get(), c->runfsroot.value().c_str()) !=
      0) {
    return -1;
  }

  // Add the cgroups configured above.
  for (int32_t i = 0; i < libcontainer::Cgroup::Type::NUM_TYPES; i++) {
    if (c->cgroup->has_tasks_path(i)) {
      if (minijail_add_to_cgroup(
              c->jail.get(), c->cgroup->tasks_path(i).value().c_str()) != 0) {
        return -1;
      }
    }
  }

  if (!config->alt_syscall_table.empty())
    minijail_use_alt_syscall(c->jail.get(), config->alt_syscall_table.c_str());

  if (config->core_sched) {
    if (minijail_add_hook(c->jail.get(), &SetCoreSched, nullptr,
                          MINIJAIL_HOOK_EVENT_PRE_DROP_CAPS) != 0) {
      return -1;
    }
  }

  for (int i = 0; i < config->num_rlimits; i++) {
    const Rlimit& lim = config->rlimits[i];
    if (minijail_rlimit(c->jail.get(), lim.type, lim.cur, lim.max) != 0)
      return -1;
  }

  if (!config->selinux_context.empty()) {
    if (minijail_add_hook(c->jail.get(), &Setexeccon,
                          const_cast<char*>(config->selinux_context.c_str()),
                          MINIJAIL_HOOK_EVENT_PRE_EXECVE) != 0) {
      return -1;
    }
  }

  if (config->pre_start_hook) {
    if (minijail_add_hook(c->jail.get(), config->pre_start_hook,
                          config->pre_start_hook_payload,
                          MINIJAIL_HOOK_EVENT_PRE_EXECVE) != 0) {
      return -1;
    }
  }

  // Now that all pre-requisite hooks are installed, copy the ones in the
  // container_config object in the correct order.
  for (auto& config_hook : config->hooks) {
    auto it = hook_callbacks.insert(std::make_pair(
        config_hook.first, std::vector<libcontainer::HookCallback>()));
    it.first->second.insert(it.first->second.end(),
                            std::make_move_iterator(config_hook.second.begin()),
                            std::make_move_iterator(config_hook.second.end()));
  }

  c->hook_states.clear();
  // Reserve enough memory to hold all the hooks, so that their addresses do not
  // get invalidated by reallocation.
  c->hook_states.reserve(MINIJAIL_HOOK_EVENT_MAX);
  for (minijail_hook_event_t event :
       {MINIJAIL_HOOK_EVENT_PRE_CHROOT, MINIJAIL_HOOK_EVENT_PRE_DROP_CAPS,
        MINIJAIL_HOOK_EVENT_PRE_EXECVE}) {
    const auto& it = hook_callbacks.find(event);
    if (it == hook_callbacks.end())
      continue;
    c->hook_states.emplace_back(
        std::make_pair(libcontainer::HookState(), std::move(it->second)));
    if (!c->hook_states.back().first.InstallHook(c->jail.get(), event))
      return -1;
  }

  for (int fd : config->inherited_fds) {
    if (minijail_preserve_fd(c->jail.get(), fd, fd) != 0)
      return -1;
  }

  /* TODO(dgreid) - remove this once shared mounts are cleaned up. */
  minijail_skip_remount_private(c->jail.get());

  if (!config->keep_fds_open)
    minijail_close_open_fds(c->jail.get());

  if (config->use_capmask) {
    minijail_use_caps(c->jail.get(), config->capmask);
    if (config->use_capmask_ambient)
      minijail_set_ambient_caps(c->jail.get());
    if (config->securebits_skip_mask) {
      minijail_skip_setting_securebits(c->jail.get(),
                                       config->securebits_skip_mask);
    }
  }

  if (!config->do_init)
    minijail_run_as_init(c->jail.get());

  std::vector<char*> argv_cstr;
  argv_cstr.reserve(config->program_argv.size() + 1);
  for (const auto& arg : config->program_argv)
    argv_cstr.emplace_back(const_cast<char*>(arg.c_str()));
  argv_cstr.emplace_back(nullptr);

  if (minijail_run_pid_pipes_no_preload(c->jail.get(), argv_cstr[0],
                                        argv_cstr.data(), &c->init_pid, nullptr,
                                        nullptr, nullptr) != 0) {
    return -1;
  }

  // |hook_states| is already sorted in the correct order.
  for (auto& hook_state : c->hook_states) {
    if (!hook_state.first.WaitForHookAndRun(std::move(hook_state.second),
                                            c->init_pid))
      return -1;
  }

  // The container has started successfully, no need to tear it down anymore.
  teardown.ReplaceClosure(base::DoNothing());
  return 0;
}

const char* container_root(struct container* c) {
  return c->runfs.value().c_str();
}

int container_pid(struct container* c) {
  return c->init_pid;
}

int container_wait(struct container* c) {
  int rc;

  do {
    rc = minijail_wait(c->jail.get());
  } while (rc == -EINTR);

  // If the process had already been reaped, still perform teardown.
  if (rc == -ECHILD || rc >= 0) {
    if (!ContainerTeardown(c))
      rc = -errno;
  }
  return rc;
}

int container_kill(struct container* c) {
  if (kill(c->init_pid, SIGKILL) != 0 && errno != ESRCH) {
    PLOG(ERROR) << "Failed to kill " << c->init_pid;
    return -errno;
  }
  return container_wait(c);
}

char* container_config_dump(struct container_config* c, int sort_vectors) {
  std::stringstream out;
  DumpConfig(&out, c, sort_vectors);
  return strdup(out.str().c_str());
}
