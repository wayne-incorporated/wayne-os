// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "vm_tools/maitred/init.h"

#include <errno.h>
#include <fcntl.h>
#include <mntent.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/resource.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

#include <base/check.h>
#include <base/check_op.h>

// These usually need to come after the sys/ includes.
#include <linux/dm-ioctl.h>
#include <linux/loop.h>
#include <linux/vm_sockets.h>

#include <algorithm>
#include <limits>
#include <list>
#include <optional>
#include <set>
#include <utility>
#include <vector>

#include <base/files/file_descriptor_watcher_posix.h>
#include <base/files/file_enumerator.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/files/scoped_file.h>
#include <base/functional/bind.h>
#include <base/functional/callback_helpers.h>
#include <base/location.h>
#include <base/logging.h>
#include <base/memory/ptr_util.h>
#include <base/message_loop/message_pump_type.h>
#include <base/notreached.h>
#include <base/posix/eintr_wrapper.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_piece.h>
#include <base/strings/string_split.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>
#include <base/time/time.h>
#include <brillo/file_utils.h>
#include <chromeos/constants/vm_tools.h>
#include <grpcpp/grpcpp.h>
#include <vm_protos/proto_bindings/vm_crash.grpc.pb.h>

#include "vm_tools/common/spawn_util.h"

using std::string;

namespace vm_tools {
namespace maitred {
namespace {

// Path to the root directory for cgroups.
constexpr char kCgroupRootDir[] = "/sys/fs/cgroup";

// Default value of the PATH environment variable.
constexpr char kDefaultPath[] = "/usr/bin:/usr/sbin:/bin:/sbin";

#if USE_VM_BOREALIS
// Name of the file that specifies the hostname within the VM.
constexpr char kHostnameConfigFile[] = "/etc/hostname";
#endif

// Retry threshould and duration for processes that respawn.  If a process needs
// to be respawned more than kMaxRespawnCount times in the last
// kRespawnWindowSeconds, then it will stop being respawned.
constexpr size_t kMaxRespawnCount = 10;
constexpr base::TimeDelta kRespawnWindowSeconds = base::Seconds(30);

// Number of seconds that we should wait before force-killing processes for
// shutdown.
constexpr base::TimeDelta kShutdownTimeout = base::Seconds(10);

// Number of seconds that we should wait for tremplin to attempt to gracefully
// shut down containers.
constexpr base::TimeDelta kTremplinShutdownTimeout = base::Seconds(2);

// Maximum number of bytes to capture from a single spawned process.
constexpr size_t kMaxOutputCaptureSize = 65536;

// Mounts that must be created on boot.
constexpr struct {
  const char* source;
  const char* target;
  const char* fstype;
  unsigned long flags;  // NOLINT(runtime/int)
  const void* data;
  bool failure_is_fatal;  // Abort if this mount fails.
} mounts[] = {
    {
        .source = "proc",
        .target = "/proc",
        .fstype = "proc",
        .flags = MS_NOSUID | MS_NODEV | MS_NOEXEC,
        .data = nullptr,
        .failure_is_fatal = true,
    },
    {
        .source = "sys",
        .target = "/sys",
        .fstype = "sysfs",
        .flags = MS_NOSUID | MS_NODEV | MS_NOEXEC,
        .data = nullptr,
        .failure_is_fatal = true,
    },
    {
        // For borealis mount as exec because some apps require it.
        .source = "tmp",
        .target = "/tmp",
        .fstype = "tmpfs",
        .flags = MS_NOSUID |
#if !USE_VM_BOREALIS
                 MS_NOEXEC |
#endif
                 MS_NODEV,
        .data = nullptr,
        .failure_is_fatal = true,
    },
    {
        .source = "tmpfs",
        .target = "/mnt/external",
        .fstype = "tmpfs",
        .flags = MS_NOSUID | MS_NODEV | MS_NOEXEC,
        .data = "mode=0755",
        .failure_is_fatal = true,
    },
    {
        .source = "run",
        .target = "/run",
        .fstype = "tmpfs",
        .flags = MS_NOSUID | MS_NODEV | MS_NOEXEC,
        .data = "mode=0755",
        .failure_is_fatal = true,
    },
    {
        .source = "shmfs",
        .target = "/dev/shm",
        .fstype = "tmpfs",
        .flags = MS_NOSUID | MS_NODEV | MS_NOEXEC,
        .data = nullptr,
        .failure_is_fatal = true,
    },
    {
        .source = "devpts",
        .target = "/dev/pts",
        .fstype = "devpts",
        .flags = MS_NOSUID | MS_NOEXEC,
        .data = "gid=5,mode=0620,ptmxmode=666",
        .failure_is_fatal = true,
    },
#if !USE_VM_BOREALIS
    {
        .source = "var",
        .target = "/var",
        .fstype = "tmpfs",
        .flags = MS_NOSUID | MS_NODEV | MS_NOEXEC,
        .data = "mode=0755",
        .failure_is_fatal = true,
    },
#endif
    {
        .source = "none",
        .target = kCgroupRootDir,
        .fstype = "tmpfs",
        .flags = MS_NOSUID | MS_NODEV | MS_NOEXEC,
        .data = "mode=0755",
        .failure_is_fatal = true,
    },
    {
        .source = "cgroup",
        .target = "/sys/fs/cgroup/blkio",
        .fstype = "cgroup",
        .flags = MS_NOSUID | MS_NODEV | MS_NOEXEC,
        .data = "blkio",
        .failure_is_fatal = false,
    },
    {
        .source = "cgroup",
        .target = "/sys/fs/cgroup/cpu,cpuacct",
        .fstype = "cgroup",
        .flags = MS_NOSUID | MS_NODEV | MS_NOEXEC,
        .data = "cpu,cpuacct",
        .failure_is_fatal = true,
    },
    {
        .source = "cgroup",
        .target = "/sys/fs/cgroup/cpuset",
        .fstype = "cgroup",
        .flags = MS_NOSUID | MS_NODEV | MS_NOEXEC,
        .data = "cpuset",
        .failure_is_fatal = true,
    },
    {
        .source = "cgroup",
        .target = "/sys/fs/cgroup/devices",
        .fstype = "cgroup",
        .flags = MS_NOSUID | MS_NODEV | MS_NOEXEC,
        .data = "devices",
        .failure_is_fatal = true,
    },
    {
        .source = "cgroup",
        .target = "/sys/fs/cgroup/freezer",
        .fstype = "cgroup",
        .flags = MS_NOSUID | MS_NODEV | MS_NOEXEC,
        .data = "freezer",
        .failure_is_fatal = true,
    },
    {
        .source = "cgroup",
        .target = "/sys/fs/cgroup/hugetlb",
        .fstype = "cgroup",
        .flags = MS_NOSUID | MS_NODEV | MS_NOEXEC,
        .data = "hugetlb",
        .failure_is_fatal = false,
    },
    {
        .source = "cgroup",
        .target = "/sys/fs/cgroup/memory",
        .fstype = "cgroup",
        .flags = MS_NOSUID | MS_NODEV | MS_NOEXEC,
        .data = "memory",
        .failure_is_fatal = false,
    },
    {
        .source = "cgroup",
        .target = "/sys/fs/cgroup/net_cls,net_prio",
        .fstype = "cgroup",
        .flags = MS_NOSUID | MS_NODEV | MS_NOEXEC,
        .data = "net_cls,net_prio",
        .failure_is_fatal = false,
    },
    {
        .source = "cgroup",
        .target = "/sys/fs/cgroup/perf_event",
        .fstype = "cgroup",
        .flags = MS_NOSUID | MS_NODEV | MS_NOEXEC,
        .data = "perf_event",
        .failure_is_fatal = false,
    },
    {
        .source = "cgroup",
        .target = "/sys/fs/cgroup/pids",
        .fstype = "cgroup",
        .flags = MS_NOSUID | MS_NODEV | MS_NOEXEC,
        .data = "pids",
        .failure_is_fatal = false,
    },
    {
        .source = "cgroup",
        .target = "/sys/fs/cgroup/systemd",
        .fstype = "cgroup",
        .flags = MS_NOSUID | MS_NODEV | MS_NOEXEC,
        .data = "none,name=systemd",
        .failure_is_fatal = false,
    },
};

// Symlinks to be created on boot. It's done after all mounts have completed.
constexpr struct {
  const char* source;
  const char* target;
} symlinks[] = {
    {
        .source = "/sys/fs/cgroup/cpu,cpuacct",
        .target = "/sys/fs/cgroup/cpu",
    },
    {
        .source = "/sys/fs/cgroup/cpu,cpuacct",
        .target = "/sys/fs/cgroup/cpuacct",
    },
    {
        .source = "/sys/fs/cgroup/net_cls,net_prio",
        .target = "/sys/fs/cgroup/net_cls",
    },
    {
        .source = "/sys/fs/cgroup/net_cls,net_prio",
        .target = "/sys/fs/cgroup/net_prio",
    },
};

// Directories to be created on boot.  These are created only after all the
// mounts have completed.
constexpr struct {
  const char* path;
  mode_t mode;
} boot_dirs[] = {
    {
        .path = "/run/lock",
        .mode = 01777,
    },
    {
        .path = "/run/sshd",
        .mode = 01777,
    },
    {
        .path = "/run/tokens",
        .mode = 01777,
    },
#if !USE_VM_BOREALIS
    {
        .path = "/var/cache",
        .mode = 0755,
    },
    {
        .path = "/var/db",
        .mode = 0755,
    },
    {
        .path = "/var/empty",
        .mode = 0755,
    },
    {
        .path = "/var/log",
        .mode = 0755,
    },
    {
        .path = "/var/spool",
        .mode = 0755,
    },
    {
        .path = "/var/lib",
        .mode = 0755,
    },
    {
        .path = "/var/lib/lxc",
        .mode = 0755,
    },
    {
        .path = "/var/lib/lxc/rootfs",
        .mode = 0755,
    },
    {
        .path = "/var/lib/lxcfs",
        .mode = 0755,
    },
    {
        .path = "/var/lib/misc",
        .mode = 0755,
    },
#endif
};

// Overlay mounts to be created on boot.
constexpr struct {
  const char* target;
  const char* lower_dir;
  const char* upper_dir;
  const char* work_dir;
} overlays[] = {
// TODO(b/286177860): Use overlay /etc for Borealis once Borealis kernel has
// overlayfs.
// sludge kernel does not have overlayfs.
#if !(USE_VM_BOREALIS || USE_VM_SLUDGE)
    {
        .target = "/etc",
        .lower_dir = "/etc",
        .upper_dir = "/run/etc/upper",
        .work_dir = "/run/etc/work",
    },
#endif
};

// These limits are based on suggestions from lxd doc/production-setup.md.
constexpr struct {
  uint8_t resource_type;
  rlimit limit;
} resource_limits[] = {
    {
        .resource_type = RLIMIT_NOFILE,
        .limit = {.rlim_cur = 1048576, .rlim_max = 1048576},
    },
    {
        .resource_type = RLIMIT_MEMLOCK,
        .limit = {.rlim_cur = RLIM_INFINITY, .rlim_max = RLIM_INFINITY},
    },
};

constexpr struct {
  const char* path;
  const char* value;
} sysctl_limits[] = {
    {
        .path = "/proc/sys/fs/inotify/max_queued_events",
        .value = "1048576",
    },
    {
        .path = "/proc/sys/fs/inotify/max_user_instances",
        .value = "1048576",
    },
    {
        .path = "/proc/sys/fs/inotify/max_user_watches",
        .value = "1048576",
    },
    {
        .path = "/proc/sys/vm/max_map_count",
        .value = "262144",
    },
    {
        .path = "/proc/sys/net/core/rmem_max",
        .value = "2097152",
    },
};

// Waits for all the processes in |pids| to exit.  Returns when all processes
// have exited or when |deadline| is reached, whichever happens first.
void WaitForChildren(std::set<pid_t> pids, base::Time deadline) {
  sigset_t mask;
  sigemptyset(&mask);
  sigaddset(&mask, SIGCHLD);

  while (!pids.empty()) {
    // First reap any child processes that have already exited.
    while (true) {
      pid_t child = waitpid(-1, nullptr, WNOHANG);
      if (child < 0 && errno != ECHILD) {
        PLOG(ERROR) << "Failed to wait for child processes";
        return;
      }

      if (child <= 0) {
        // Either there are no more children or they have not exited yet.
        break;
      }

      pids.erase(child);
    }

    // We will not find out about all child processes.  For example some
    // processes might set up custom SIGTERM handlers and then try to handle
    // the termination of their own children, in which case we would not find
    // out about those processes here.
    for (auto iter = pids.begin(); iter != pids.end();) {
      // If the process still exists then leave it in the set.  kill() with a
      // signal value of 0 is explicitly documented as a way to check for the
      // existence of a given process.
      if (kill(*iter, 0) == 0) {
        ++iter;
        continue;
      }

      // If the process has already exited, then remove it from the set.
      DCHECK_EQ(errno, ESRCH);
      iter = pids.erase(iter);
    }

    // If there are no processes left then exit early.  Otherwise we will block
    // for the full timeout duration in the sigtimedwait below.
    if (pids.empty()) {
      return;
    }

    // Check the deadline.
    base::Time now = base::Time::Now();
    if (now >= deadline) {
      return;
    }

    // Wait for more processes to exit.
    struct timespec ts = (deadline - now).ToTimeSpec();
    int ret = sigtimedwait(&mask, nullptr, &ts);
    if (ret == SIGCHLD) {
      // One or more child processes have exited.
      continue;
    }

    if (ret < 0 && errno == EAGAIN) {
      // Deadline expired.
      return;
    }

    if (ret < 0) {
      PLOG(WARNING) << "Unable to wait for processes to exit";
    } else {
      LOG(WARNING) << "Unexpected return value from sigtimedwait(): "
                   << strsignal(ret);
    }
  }

  // Control should never reach here.
  NOTREACHED();
}

// Cached pid of this process.  Starting from version 2.24, glibc stopped
// caching the pid of the current process since the cache interacts in weird
// ways with certain clone() and unshare() flags.  This value is only checked
// and set in ShouldKillProcess().
static pid_t cached_pid = 0;

// Returns true if it is safe to kill |process| either with a SIGTERM or a
// SIGKILL.  |path| must be the path to the process directory in /proc.
bool ShouldKillProcess(pid_t process, const base::FilePath& path) {
  if (cached_pid == 0) {
    cached_pid = getpid();
  }

  if (process == 1 || process == cached_pid) {
    // Probably not a good idea to kill ourselves.
    return false;
  }

  // Get the process's UID.
  uid_t uid = -1;
  string status;
  if (!base::ReadFileToString(path.Append("status"), &status)) {
    PLOG(WARNING) << "Failed to read status for process " << process;

    // Don't send a signal to this process just to be on the safe side.
    return false;
  }

  for (const auto& line : base::SplitStringPiece(
           status, "\n", base::TRIM_WHITESPACE, base::SPLIT_WANT_NONEMPTY)) {
    if (!base::StartsWith(line, "Uid:")) {
      continue;
    }

    std::vector<base::StringPiece> tokens = base::SplitStringPiece(
        line, base::kWhitespaceASCII, base::TRIM_WHITESPACE,
        base::SPLIT_WANT_NONEMPTY);
    DCHECK_EQ(tokens.size(), 5);
    if (!base::StringToUint(tokens[1], &uid)) {
      LOG(WARNING) << "Failed to parse uid (" << tokens[1] << ") for process "
                   << process;
      return false;
    }

    break;
  }

  DCHECK_NE(uid, -1);
  if (uid != 0) {
    // All non-root processes can be killed.
    return true;
  }

  // Check if this is a kernel process.
  char buf;
  if (readlink(path.Append("exe").value().c_str(), &buf, sizeof(buf)) < 0 &&
      errno == ENOENT) {
    // Kernel processes have no executable.
    return false;
  }

  return true;
}

// Broadcast the signal |signo| to all processes.  |signo| must be either
// SIGTERM or SIGKILL.  If |pids| is not nullptr, then it is filled with the
// pids of the processes to which |signo| was successfully sent.
void BroadcastSignal(int signo, std::set<pid_t>* pids) {
  DCHECK(signo == SIGTERM || signo == SIGKILL);

  // We are about to walk the process tree.  Pause all processes so that new
  // processes don't appear or disappear while we're walking the tree.
  // Additionally, pausing all the processes here means that we don't end up
  // with unnecessary thrashing in the system.  For example, consider a
  // pipeline of programs:
  //
  //     cmd1 | cmd2 | cmd3 | cmd4
  //
  // If cmd2 gets killed first, cmd3 might wake up from its read because its
  // pipe is now closed and might end up doing some extra work even though we
  // are going to be killing it very soon as well.  Pausing all processes
  // avoids this problem and ensures that the signal is delivered atomically to
  // all processes.
  if (kill(-1, SIGSTOP) < 0 && errno != ESRCH) {
    PLOG(WARNING) << "Unable to send SIGSTOP to all processes.  System "
                  << "thrashing may occur";
  }

  base::FileEnumerator enumerator(base::FilePath("/proc"),
                                  false /* recursive */,
                                  base::FileEnumerator::DIRECTORIES);
  for (base::FilePath path = enumerator.Next(); !path.empty();
       path = enumerator.Next()) {
    pid_t process;
    if (!base::StringToInt(path.BaseName().value(), &process)) {
      // Ignore anything that doesn't look like a pid.
      continue;
    }

    if (!ShouldKillProcess(process, path)) {
      continue;
    }

    if (kill(process, signo) < 0) {
      PLOG(ERROR) << "Failed to send " << strsignal(signo) << " to process "
                  << process;
      continue;
    }

    // Now that we've sent the signal to the process wake it up.  This way we
    // avoid a thundering herd problem if all the processes wake up at the same
    // time later.
    if (kill(process, SIGCONT) < 0 && errno != ESRCH) {
      // It's possible the process is already gone (for example if signo was
      // SIGKILL).  Only log an error if it's not that case.
      PLOG(WARNING) << "Failed to wake up process " << process;
    }

    if (pids) {
      pids->insert(process);
    }
  }

  // Now restart any programs that may still be hanging around.  There shouldn't
  // actually be any but just in case one of the attempts to send SIGCONT
  // earlier failed we can try one more time here.
  if (kill(-1, SIGCONT) < 0 && errno != ESRCH) {
    PLOG(WARNING) << "Unable to send SIGCONT to all processes.  Some "
                  << "processes may still be frozen";
  }
}

// Detaches all loopback devices.
void DetachLoopback() {
  LOG(INFO) << "Detaching loopback devices";

  const base::FilePath kDev("/dev");

  base::FileEnumerator enumerator(
      base::FilePath("/sys/block"), false /*recursive*/,
      base::FileEnumerator::FILES | base::FileEnumerator::SHOW_SYM_LINKS,
      "loop*" /*pattern*/);
  for (base::FilePath path = enumerator.Next(); !path.empty();
       path = enumerator.Next()) {
    const base::FilePath backing_file =
        path.Append("loop").Append("backing_file");
    if (!base::PathExists(backing_file)) {
      continue;
    }

    const base::FilePath dev_path = kDev.Append(path.BaseName());

    LOG(INFO) << "Detaching " << dev_path.value();

    base::ScopedFD loopdev(open(dev_path.value().c_str(), O_RDWR | O_CLOEXEC));
    if (!loopdev.is_valid()) {
      PLOG(ERROR) << "Unable to open " << dev_path.value();
      continue;
    }

    if (ioctl(loopdev.get(), LOOP_CLR_FD, 0) != 0) {
      PLOG(ERROR) << "Failed to remove backing file for /dev/"
                  << path.BaseName().value();
    }
  }
}

// Removes all device mapper devices.
void RemoveDevMapper() {
  LOG(INFO) << "Removing device mapper devices";

  const base::FilePath kDMControl("/dev/mapper/control");

  base::ScopedFD dm_control(
      open(kDMControl.value().c_str(), O_RDWR | O_CLOEXEC));
  if (!dm_control.is_valid()) {
    PLOG(ERROR) << "Failed to open " << kDMControl.value();
    return;
  }

  struct dm_ioctl param = {
      // clang-format off
      .version = {
          DM_VERSION_MAJOR,
          DM_VERSION_MINOR,
          DM_VERSION_PATCHLEVEL,
      },
      // clang-format on
      .data_size = sizeof(struct dm_ioctl),
      .data_start = sizeof(struct dm_ioctl),
      .flags = DM_DEFERRED_REMOVE,
  };
  if (ioctl(dm_control.get(), DM_REMOVE_ALL, &param) != 0) {
    PLOG(ERROR) << "Failed to remove device mapper devices";
  }
}

// Returns true if |mount_point| should not be unmounted even during the
// shutdown sequence.
bool IsProtectedMount(const string& mount_point) {
  const char* const kProtectedMounts[] = {
      "/dev",
      "/proc",
      "/sys",
  };

  if (mount_point == "/") {
    return true;
  }

  for (const char* mount : kProtectedMounts) {
    if (mount == mount_point ||
        base::FilePath(mount).IsParent(base::FilePath(mount_point))) {
      return true;
    }
  }

  return false;
}

// Unmounts all non-essential filesystems.
void UnmountFilesystems() {
  LOG(INFO) << "Unmounting filesystems";

  base::ScopedFILE mountinfo(fopen("/proc/self/mounts", "r"));
  if (!mountinfo) {
    PLOG(ERROR) << "Failed to open /proc/self/mounts";
    return;
  }

  // Parse all the mounts into a vector since we need to unmount them in
  // reverse order.
  std::vector<string> mount_points;
  char buf[1024 + 4];
  struct mntent entry;
  while (getmntent_r(mountinfo.get(), &entry, buf, sizeof(buf)) != nullptr) {
    mount_points.emplace_back(entry.mnt_dir);
  }

  for (auto iter = mount_points.rbegin(), end = mount_points.rend();
       iter != end; ++iter) {
    if (IsProtectedMount(*iter)) {
      continue;
    }

    LOG(INFO) << "Unmounting " << *iter;
    if (umount(iter->c_str()) != 0) {
      PLOG(ERROR) << "Failed to unmount " << *iter;
    }
  }
}

}  // namespace

string ParseHostname(const string& etc_hostname_contents) {
  for (const auto& line : base::SplitStringPiece(etc_hostname_contents, "\n",
                                                 base::TRIM_WHITESPACE,
                                                 base::SPLIT_WANT_NONEMPTY)) {
    if (line[0] != '#') {
      return string(line);
    }
  }
  return {};
}

class Init::Worker {
 public:
  // Relevant information about processes launched by this process.
  struct ChildInfo {
    std::vector<string> argv;
    std::map<string, string> env;
    bool respawn;
    bool use_console;
    bool wait_for_exit;

    std::list<base::Time> spawn_times;

    std::optional<base::OnceCallback<void(ProcessStatus, int)>> exit_cb;
  };

  Worker()
      : crash_listener_(grpc::CreateChannel(
            base::StringPrintf(
                "vsock:%u:%u", VMADDR_CID_HOST, vm_tools::kCrashListenerPort),
            grpc::InsecureChannelCredentials())) {}
  Worker(const Worker&) = delete;
  Worker& operator=(const Worker&) = delete;

  ~Worker() = default;

  // Start the worker.  This will set up a signalfd for receiving SIGCHLD
  // events.
  void Start();

  // Actually spawns a child process.  Waits until it receives confirmation from
  // the child that the requested program was actually started and fills in
  // |launch_info| with information about the process.  Additionally if
  // |info.wait_for_exit| is true, then waits until the child process exits or
  // is killed before returning.
  void Spawn(struct ChildInfo info, int semfd, ProcessLaunchInfo* launch_info);

  // Shuts down the system.  First broadcasts SIGTERM to all processes and
  // waits for those processes to exit up to a deadline.  Then kills any
  // remaining processes with SIGKILL.  |notify_fd| must be an eventfd, which
  // is notified after all processes are killed.
  void Shutdown(int notify_fd);

  // Finds the pid of a process with |name|. Returns 0 if such a process doesn't
  // exist.
  pid_t FindProcessByName(const string& name);

 private:
  // Called when |signal_fd_| becomes readable.
  void OnSignalReadable();

  // File descriptor on which we will receive SIGCHLD events.
  base::ScopedFD signal_fd_;
  std::unique_ptr<base::FileDescriptorWatcher::Controller> watcher_;

  vm_tools::cicerone::CrashListener::Stub crash_listener_;

  // Information about processes launched by this process.
  std::map<pid_t, ChildInfo> children_;

  // File descriptor for "/dev/console".
  // This is used for spawned processes when |use_console| is true.
  base::ScopedFD console_fd_;
};

void Init::Worker::Start() {
  sigset_t mask;
  sigemptyset(&mask);
  sigaddset(&mask, SIGCHLD);

  // Block SIGCHLD so that we can get it via the signalfd.
  if (sigprocmask(SIG_BLOCK, &mask, nullptr) != 0) {
    PLOG(ERROR) << "Failed to block SIGCHLD";
  }

  signal_fd_.reset(signalfd(-1, &mask, SFD_CLOEXEC | SFD_NONBLOCK));
  PCHECK(signal_fd_.is_valid()) << "Unable to create signal fd";

  watcher_ = base::FileDescriptorWatcher::WatchReadable(
      signal_fd_.get(), base::BindRepeating(&Init::Worker::OnSignalReadable,
                                            base::Unretained(this)));
  CHECK(watcher_) << "Failed to watch SIGCHLD file descriptor";

  console_fd_.reset(open("/dev/console", O_RDWR | O_NOCTTY));
  PCHECK(console_fd_.is_valid()) << "Failed to open /dev/console";
}

static void SignalSpawnComplete(int semfd) {
  if (semfd != -1) {
    uint64_t done = 1;
    ssize_t count = write(semfd, &done, sizeof(done));
    DCHECK_EQ(count, sizeof(done));
  }
}

// Read up to |max_size| bytes from |fd| into |contents|.
// Returns true on success and false on error (including truncation).
static bool ReadFDToStringWithMaxSize(int fd,
                                      std::string* contents,
                                      size_t max_size) {
  DCHECK(contents);

  bool success = true;
  size_t buf_used = 0;
  std::string buf;
  buf.resize(max_size);

  // Keep reading output until read() returns EOF or an error
  // or we run out of space in the buffer.
  while (buf_used < max_size) {
    ssize_t num_bytes = read(fd, &buf[buf_used], max_size - buf_used);
    if (num_bytes <= 0) {
      success = false;
      break;
    }

    buf_used += num_bytes;
  }

  contents->swap(buf);
  contents->resize(buf_used);

  return success;
}

void Init::Worker::Spawn(struct ChildInfo info,
                         int semfd,
                         ProcessLaunchInfo* launch_info) {
  DCHECK_GT(info.argv.size(), 0);
  DCHECK(launch_info);

  bool capture_output = info.wait_for_exit && !info.use_console;

  int pipe_fds[2] = {-1, -1};
  if (capture_output) {
    if (pipe(pipe_fds) != 0) {
      PLOG(ERROR) << "Failed to create pipe";
      launch_info->status = ProcessStatus::FAILED;
      SignalSpawnComplete(semfd);
      return;
    }
  }

  base::ScopedFD output_read_fd(pipe_fds[0]);
  base::ScopedFD output_write_fd(pipe_fds[1]);

  // Block all signals before forking to prevent signals from arriving in the
  // child.
  sigset_t mask, omask;
  sigfillset(&mask);
  sigprocmask(SIG_BLOCK, &mask, &omask);

  int stdio_fds[3] = {-1, -1, -1};
  if (info.use_console) {
    for (auto& fd : stdio_fds) {
      fd = console_fd_.get();
    }
  }

  if (capture_output) {
    stdio_fds[STDOUT_FILENO] = output_write_fd.get();
  }

  pid_t pid = -1;
  bool spawned = vm_tools::Spawn(info.argv, info.env, "" /* working_dir */,
                                 stdio_fds, &pid);

  if (capture_output) {
    // Close the writable end of the pipe in the parent.
    output_write_fd.reset();
  }

  if (!spawned) {
    LOG(ERROR) << "Failed to spawn child process";
    launch_info->status = ProcessStatus::FAILED;
  } else if (info.wait_for_exit) {
    if (capture_output) {
      launch_info->output_truncated = !ReadFDToStringWithMaxSize(
          output_read_fd.get(), &launch_info->output, kMaxOutputCaptureSize);
    }

    int status = 0;
    pid_t child = waitpid(pid, &status, 0);
    DCHECK_EQ(child, pid);

    if (WIFEXITED(status)) {
      launch_info->status = ProcessStatus::EXITED;
      launch_info->code = WEXITSTATUS(status);
    } else if (WIFSIGNALED(status)) {
      launch_info->status = ProcessStatus::SIGNALED;
      launch_info->code = WTERMSIG(status);
    } else {
      launch_info->status = ProcessStatus::UNKNOWN;
    }
  } else {
    info.spawn_times.emplace_back(base::Time::Now());

    // result is a pair<iterator, bool>.
    auto result = children_.emplace(pid, std::move(info));
    DCHECK(result.second);

    launch_info->status = ProcessStatus::LAUNCHED;
  }

  SignalSpawnComplete(semfd);

  // Restore the signal mask.
  sigprocmask(SIG_SETMASK, &omask, nullptr);
}

void Init::Worker::Shutdown(int notify_fd) {
  DCHECK_NE(notify_fd, -1);

  // Stop watching for SIGCHLD.  We will do it manually here.
  watcher_.reset();
  signal_fd_.reset();

  // First send SIGPWR to tremplin, if it is running. This runs "poweroff"
  // in every container, which is necessary to work around the version
  // of systemd in stretch that hangs after receiving SIGRTMIN + 3.
  pid_t tremplin_pid = FindProcessByName("tremplin");
  if (tremplin_pid != 0 && kill(tremplin_pid, SIGPWR) == 0) {
    WaitForChildren({tremplin_pid},
                    base::Time::Now() + kTremplinShutdownTimeout);
  }

  // Second, send SIGPWR to lxd, if it is running.  This will cause lxd to shut
  // down all running containers in parallel.
  pid_t lxd_pid = FindProcessByName("lxd");
  if (lxd_pid != 0 && kill(lxd_pid, SIGPWR) == 0) {
    WaitForChildren({lxd_pid}, base::Time::Now() + kShutdownTimeout);
  }

  // Now send SIGTERM to all remaining processes.
  std::set<pid_t> pids;
  BroadcastSignal(SIGTERM, &pids);

  // Wait for those processes to terminate.
  WaitForChildren(std::move(pids), base::Time::Now() + kShutdownTimeout);

  // Kill anything left with SIGKILL.
  BroadcastSignal(SIGKILL, nullptr);

  // Detach loopback devices.
  DetachLoopback();

  // Remove any device-mapper devices.
  RemoveDevMapper();

  // Unmount all non-essential file systems.
  UnmountFilesystems();

  // Final sync to flush anything left.
  sync();

  // Signal the waiter.
  uint64_t done = 1;
  if (write(notify_fd, &done, sizeof(done)) != sizeof(done)) {
    PLOG(ERROR) << "Failed to wake up shutdown waiter";
  }
}

void Init::Worker::OnSignalReadable() {
  // Pull information about the signal sender out of the fd to ack the signal.
  struct signalfd_siginfo siginfo;
  if (HANDLE_EINTR(read(signal_fd_.get(), &siginfo, sizeof(siginfo))) !=
      sizeof(siginfo)) {
    PLOG(ERROR) << "Failed to read from signalfd";
    return;
  }
  DCHECK_EQ(siginfo.ssi_signo, SIGCHLD);

  // We can't just rely on the information in the siginfo structure because
  // more than one child may have exited but only one SIGCHLD will be
  // generated.
  while (true) {
    int status;
    pid_t pid = waitpid(-1, &status, WNOHANG);
    if (pid <= 0) {
      if (pid == -1) {
        PLOG(ERROR) << "Unable to reap child processes";
      }
      break;
    }

    // See if this is a process we launched.
    struct ChildInfo info = {};
    auto iter = children_.find(pid);
    if (iter != children_.end()) {
      info = std::move(iter->second);
      children_.erase(iter);
    }

    ProcessStatus proc_status = ProcessStatus::UNKNOWN;
    int code = -1;
    if (WIFEXITED(status)) {
      LOG(INFO) << (info.argv.size() == 0 ? "<unknown process>"
                                          : info.argv[0].c_str())
                << " (" << pid << ") exited with status "
                << WEXITSTATUS(status);
      proc_status = ProcessStatus::EXITED;
      code = WEXITSTATUS(status);
    } else if (WIFSIGNALED(status)) {
      LOG(INFO) << (info.argv.size() == 0 ? "<unknown process>"
                                          : info.argv[0].c_str())
                << " (" << pid << ") killed by signal " << WTERMSIG(status)
                << (WCOREDUMP(status) ? " (core dumped)" : "");
      proc_status = ProcessStatus::SIGNALED;
      code = WTERMSIG(status);
    } else {
      LOG(WARNING) << "Unknown exit status " << status << " for process "
                   << pid;
    }

    if (info.exit_cb) {
      std::move(info.exit_cb).value().Run(proc_status, code);
    }

    if (!info.respawn) {
      continue;
    }

    // Notify the host that a persistent process has failed.
    {
      grpc::ClientContext ctx;
      vm_tools::EmptyMessage empty;
      vm_tools::cicerone::FailureReport failure_report;
      // Cicerone expects bare service names (no path).
      failure_report.set_failed_process(
          base::FilePath(info.argv.front()).BaseName().value());
      grpc::Status status =
          crash_listener_.SendFailureReport(&ctx, failure_report, &empty);
      if (!status.ok()) {
        LOG(ERROR) << "Failed to report failure of service \""
                   << failure_report.failed_process()
                   << "\": " << status.error_message() << ", error code "
                   << status.error_code();
      }
    }

    // The process needs to be respawned.  First remove any spawn times older
    // than the respawn counter window.
    base::Time now = base::Time::Now();
    while (info.spawn_times.size() > 0 &&
           now - info.spawn_times.front() > kRespawnWindowSeconds) {
      info.spawn_times.pop_front();
    }

    // Check if the process has respawned too often.
    if (info.spawn_times.size() >= kMaxRespawnCount) {
      LOG(WARNING) << info.argv[0] << " respawning too frequently; stopped";
      continue;
    }

    // Respawn the process.
    LOG(INFO) << "Restarting " << info.argv[0];
    string app(info.argv[0]);

    Init::ProcessLaunchInfo launch_info;
    Spawn(std::move(info), -1, &launch_info);
    switch (launch_info.status) {
      case ProcessStatus::UNKNOWN:
        LOG(WARNING) << app << " has unknown status";
        break;
      case ProcessStatus::EXITED:
        LOG(WARNING) << app << " unexpectedly exited with status "
                     << launch_info.code << ";  stopped";
        break;
      case ProcessStatus::SIGNALED:
        LOG(WARNING) << app << " unexpectedly killed by signal "
                     << launch_info.code << "; stopped";
        break;
      case ProcessStatus::LAUNCHED:
        LOG(INFO) << app << " restarted";
        break;
      case ProcessStatus::FAILED:
        LOG(ERROR) << "Failed to start " << app;
        break;
    }
  }
}

pid_t Init::Worker::FindProcessByName(const string& name) {
  for (const auto& pair : children_) {
    const ChildInfo& info = pair.second;
    if (info.argv[0] == name) {
      return pair.first;
    }
  }

  return 0;
}

Init::Init(bool maitred_is_pid1) : maitred_is_pid1_{maitred_is_pid1} {}

std::unique_ptr<Init> Init::Create(bool maitred_is_pid1) {
  auto init = base::WrapUnique<Init>(new Init(maitred_is_pid1));

  if (!init->Setup()) {
    init.reset();
  }

  return init;
}

Init::~Init() {
  if (worker_) {
    // worker_ is created after worker_thread_ is started so we don't need to
    // check if it is running.
    worker_thread_.task_runner()->DeleteSoon(FROM_HERE, worker_.release());
  }
}

bool Init::Spawn(
    std::vector<string> argv,
    std::map<string, string> env,
    bool respawn,
    bool use_console,
    bool wait_for_exit,
    ProcessLaunchInfo* launch_info,
    std::optional<base::OnceCallback<void(ProcessStatus, int)>> exit_cb) {
  CHECK(!argv.empty());
  CHECK(!(respawn && wait_for_exit));
  CHECK(launch_info);

  if (!worker_) {
    // If there's no worker then we are currently in the process of shutting
    // down.
    return false;
  }

  struct Worker::ChildInfo info = {.argv = std::move(argv),
                                   .env = std::move(env),
                                   .respawn = respawn,
                                   .use_console = use_console,
                                   .wait_for_exit = wait_for_exit,
                                   .exit_cb = std::move(exit_cb)};

  // Create a semaphore that we will use to wait for the worker thread to launch
  // the process and fill in the the ProcessLaunchInfo struct with the result.
  base::ScopedFD sem(eventfd(0 /*initval*/, EFD_CLOEXEC | EFD_SEMAPHORE));
  if (!sem.is_valid()) {
    PLOG(ERROR) << "Failed to create semaphore eventfd";
    return false;
  }

  bool ret = worker_thread_.task_runner()->PostTask(
      FROM_HERE, base::BindOnce(&Worker::Spawn, base::Unretained(worker_.get()),
                                std::move(info), sem.get(), launch_info));
  if (!ret) {
    return false;
  }

  uint64_t done = 0;
  ssize_t count = HANDLE_EINTR(read(sem.get(), &done, sizeof(done)));
  DCHECK_EQ(count, sizeof(done));
  DCHECK_EQ(done, 1);

  return true;
}

void Init::Shutdown() {
  base::ScopedFD notify_fd(eventfd(0 /*initval*/, EFD_CLOEXEC | EFD_SEMAPHORE));
  if (!notify_fd.is_valid()) {
    PLOG(ERROR) << "Failed to create eventfd";
    return;
  }

  bool ret = worker_thread_.task_runner()->PostTask(
      FROM_HERE,
      base::BindOnce(&Worker::Shutdown, base::Unretained(worker_.get()),
                     notify_fd.get()));
  if (!ret) {
    LOG(ERROR) << "Failed to post task to worker thread";
    return;
  }

  uint64_t done = 0;
  if (read(notify_fd.get(), &done, sizeof(done)) != sizeof(done)) {
    PLOG(ERROR) << "Failed to read from eventfd";
    return;
  }
  DCHECK_EQ(done, 1);
}

bool Init::SetupResourceLimit() {
  // Setup rlimit.
  for (const auto& rlimit : resource_limits) {
    if (setrlimit(rlimit.resource_type, &rlimit.limit) != 0) {
      PLOG(ERROR) << "Failed to set limit for resouce type: "
                  << rlimit.resource_type;
      return false;
    }
  }

  // Setup sysctl limits.
  for (const auto& syslimit : sysctl_limits) {
    base::ScopedFD sysctl_node(open(syslimit.path, O_RDWR | O_CLOEXEC));

    if (!sysctl_node.is_valid()) {
      PLOG(ERROR) << "Unable to open sysctl node: " << syslimit.path;
      return false;
    }

    ssize_t count =
        write(sysctl_node.get(), syslimit.value, strlen(syslimit.value));
    if (count != strlen(syslimit.value)) {
      PLOG(ERROR) << "Faile to write sysctl node: " << syslimit.path;
      return false;
    }
  }
  return true;
}

bool Init::Setup() {
  // Set the umask properly or the directory modes will not work.
  umask(0000);

  if (maitred_is_pid1_) {
    for (const auto& mt : mounts) {
      if (mkdir(mt.target, 0755) != 0 && errno != EEXIST) {
        PLOG(ERROR) << "Failed to create " << mt.target;
        if (mt.failure_is_fatal)
          return false;
      }

      if (mount(mt.source, mt.target, mt.fstype, mt.flags, mt.data) != 0) {
        rmdir(mt.target);
        PLOG(ERROR) << "Failed to mount " << mt.target;
        if (mt.failure_is_fatal)
          return false;
      }
    }

    // Setup the resource limits.
    if (!SetupResourceLimit()) {
      return false;
    }

    // Create all the symlinks
    for (const auto& sl : symlinks) {
      if (symlink(sl.source, sl.target) != 0) {
        PLOG(ERROR) << "Failed to create symlink: source " << sl.source
                    << ", target " << sl.target;
        return false;
      }
    }

    // Create all the directories.
    for (const auto& dir : boot_dirs) {
      if (mkdir(dir.path, dir.mode) != 0 && errno != EEXIST) {
        PLOG(ERROR) << "Failed to create " << dir.path;
        return false;
      }
    }

    for (const auto& overlay : overlays) {
      if (!brillo::MkdirRecursively(base::FilePath(overlay.upper_dir), 0755)
               .is_valid()) {
        PLOG(ERROR) << "Failed to create " << overlay.upper_dir;
        return false;
      }

      if (!brillo::MkdirRecursively(base::FilePath(overlay.work_dir), 0755)
               .is_valid()) {
        PLOG(ERROR) << "Failed to create " << overlay.work_dir;
        return false;
      }

      string options = base::StringPrintf("lowerdir=%s,upperdir=%s,workdir=%s",
                                          overlay.lower_dir, overlay.upper_dir,
                                          overlay.work_dir);
      if (mount("overlay", overlay.target, "overlay", 0, options.c_str())) {
        PLOG(ERROR) << "Failed to mount overlay " << overlay.target;
        return false;
      }
    }

    // Enable hierarchial memory accounting for LXD.
    base::FilePath use_hierarchy = base::FilePath(kCgroupRootDir)
                                       .Append("memory")
                                       .Append("memory.use_hierarchy");
    if (base::WriteFile(use_hierarchy, "1", 1) != 1) {
      PLOG(ERROR) << "Failed to set use_hierarchy to 1 on memory cgroup";
      return false;
    }

    // Maitred becomes the session leader if PID1.
    if (setsid() == -1) {
      PLOG(ERROR) << "Failed to become session leader";
      return false;
    }

    // Set the controlling terminal.
    if (ioctl(STDIN_FILENO, TIOCSCTTY, 1) != 0) {
      PLOG(ERROR) << "Failed to set controlling terminal";
      return false;
    }

    // Setup up PATH.
    if (clearenv() != 0) {
      PLOG(ERROR) << "Failed to clear environment";
      return false;
    }
    if (setenv("PATH", kDefaultPath, 1 /*overwrite*/) != 0) {
      PLOG(ERROR) << "Failed to set PATH";
      return false;
    }
  }

#if USE_VM_BOREALIS
  // Set hostname
  string hostnameconfig;
  if (base::ReadFileToString(base::FilePath(kHostnameConfigFile),
                             &hostnameconfig)) {
    string hostname(ParseHostname(hostnameconfig));
    if (hostname.empty()) {
      LOG(WARNING) << "No valid hostname in " << kHostnameConfigFile
                   << "; will not set hostname";
    } else if (sethostname(hostname.c_str(), hostname.size()) != 0) {
      PLOG(ERROR) << "sethostname() failed";
    }
  } else {
    PLOG(WARNING) << "Failed to read " << kHostnameConfigFile
                  << "; will not set hostname";
  }
#endif

  // Block SIGCHLD here because we want to handle it in the worker thread.
  sigset_t mask;
  sigemptyset(&mask);
  sigaddset(&mask, SIGCHLD);
  if (sigprocmask(SIG_BLOCK, &mask, nullptr) != 0) {
    PLOG(ERROR) << "Failed to block SIGCHLD";
    return false;
  }

  // Start the worker.
  if (!worker_thread_.StartWithOptions(
          base::Thread::Options(base::MessagePumpType::IO, 0 /*stack_size*/))) {
    LOG(ERROR) << "Failed to start worker thread";
    return false;
  }

  worker_ = std::make_unique<Worker>();
  bool ret = worker_thread_.task_runner()->PostTask(
      FROM_HERE,
      base::BindOnce(&Worker::Start, base::Unretained(worker_.get())));
  if (!ret) {
    LOG(ERROR) << "Failed to post task to worker thread";
    return false;
  }

  // Applications that should be started for every VM.
  struct {
    const char* doc;
    std::vector<string> argv;
    std::map<string, string> env;
    bool respawn;
    bool use_console;
    bool wait_for_exit;
  } startup_applications[] = {
      {
          .doc = "system log collector",
          .argv = {"vm_syslog"},
          .env = {},
          .respawn = true,
          .use_console = false,
          .wait_for_exit = false,
      },
      {
          .doc = "vsock remote shell daemon",
          .argv = {"vshd"},
          .env = {},
          .respawn = true,
          .use_console = false,
          .wait_for_exit = false,
      },
  };

  // Spawn all the startup applications.
  for (auto& app : startup_applications) {
    CHECK(!app.argv.empty());

    LOG(INFO) << "Starting " << app.doc;

    ProcessLaunchInfo info;
    if (!Spawn(std::move(app.argv), std::move(app.env), app.respawn,
               app.use_console, app.wait_for_exit, &info)) {
      LOG(ERROR) << "Unable to launch " << app.doc;
      continue;
    }

    switch (info.status) {
      case ProcessStatus::UNKNOWN:
        LOG(WARNING) << app.doc << " has unknown status";
        break;
      case ProcessStatus::EXITED:
        LOG(INFO) << app.doc << " exited with status " << info.code;
        break;
      case ProcessStatus::SIGNALED:
        LOG(INFO) << app.doc << " killed by signal " << info.code;
        break;
      case ProcessStatus::LAUNCHED:
        LOG(INFO) << app.doc << " started";
        break;
      case ProcessStatus::FAILED:
        LOG(ERROR) << "Failed to start " << app.doc;
        break;
    }
  }

  return true;
}

}  // namespace maitred
}  // namespace vm_tools
