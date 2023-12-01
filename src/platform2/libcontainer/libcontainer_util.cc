// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "libcontainer/libcontainer_util.h"

#include <errno.h>
#include <fcntl.h>
#if USE_device_mapper
#include <libdevmapper.h>
#endif
#include <linux/loop.h>
#include <sched.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <memory>
#include <utility>
#include <vector>

#include <base/files/file_util.h>
#include <base/files/scoped_file.h>
#include <base/functional/bind.h>
#include <base/functional/callback_helpers.h>
#include <base/logging.h>
#include <base/posix/eintr_wrapper.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_split.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>

// New cgroup namespace might not be in linux-headers yet.
#ifndef CLONE_NEWCGROUP
#define CLONE_NEWCGROUP 0x02000000
#endif

namespace libcontainer {

namespace {

constexpr char kLoopdevCtlPath[] = "/dev/loop-control";
#if USE_device_mapper
constexpr char kDevMapperPath[] = "/dev/mapper/";
#endif

// Gets the namespace name for |nstype|.
std::string GetNamespaceNameForType(int nstype) {
  switch (nstype) {
    case CLONE_NEWCGROUP:
      return "cgroup";
    case CLONE_NEWIPC:
      return "ipc";
    case CLONE_NEWNET:
      return "net";
    case CLONE_NEWNS:
      return "mnt";
    case CLONE_NEWPID:
      return "pid";
    case CLONE_NEWUSER:
      return "user";
    case CLONE_NEWUTS:
      return "uts";
  }
  return std::string();
}

// Helper function that runs |callback| in all the namespaces identified by
// |nstypes|.
bool RunInNamespacesHelper(HookCallback callback,
                           std::vector<int> nstypes,
                           pid_t container_pid) {
  pid_t child = fork();
  if (child < 0) {
    PLOG(ERROR) << "Failed to fork()";
    return false;
  }

  if (child == 0) {
    for (const int nstype : nstypes) {
      std::string nstype_name = GetNamespaceNameForType(nstype);
      if (nstype_name.empty()) {
        LOG(ERROR) << "Invalid namespace type " << nstype;
        _exit(-1);
      }
      base::FilePath ns_path = base::FilePath(base::StringPrintf(
          "/proc/%d/ns/%s", container_pid, nstype_name.c_str()));
      base::ScopedFD ns_fd(open(ns_path.value().c_str(), O_RDONLY));
      if (!ns_fd.is_valid()) {
        PLOG(ERROR) << "Failed to open " << ns_path.value();
        _exit(-1);
      }
      if (setns(ns_fd.get(), nstype)) {
        PLOG(ERROR) << "Failed to enter PID " << container_pid << "'s "
                    << nstype_name << " namespace";
        _exit(-1);
      }
    }

    // Preserve normal POSIX semantics of calling exit(2) with 0 for success and
    // non-zero for failure.
    _exit(std::move(callback).Run(container_pid) ? 0 : 1);
  }

  int status;
  if (HANDLE_EINTR(waitpid(child, &status, 0)) < 0) {
    PLOG(ERROR) << "Failed to wait for callback";
    return false;
  }
  if (!WIFEXITED(status)) {
    LOG(ERROR) << "Callback terminated abnormally: " << std::hex << status;
    return false;
  }
  return static_cast<int8_t>(WEXITSTATUS(status)) == 0;
}

// Helper function that runs a program execve(2)-style.
bool ExecveCallbackHelper(base::FilePath filename,
                          std::vector<std::string> args,
                          base::ScopedFD stdin_fd,
                          base::ScopedFD stdout_fd,
                          base::ScopedFD stderr_fd,
                          pid_t container_pid) {
  pid_t child = fork();
  if (child < 0) {
    PLOG(ERROR) << "Failed to fork()";
    return false;
  }

  if (child == 0) {
    if (stdin_fd.is_valid()) {
      if (dup2(stdin_fd.get(), STDIN_FILENO) == -1) {
        PLOG(ERROR) << "Failed to dup2() stdin fd";
        _exit(-1);
      }
    }
    if (stdout_fd.is_valid()) {
      if (dup2(stdout_fd.get(), STDOUT_FILENO) == -1) {
        PLOG(ERROR) << "Failed to dup2() stdout fd";
        _exit(-1);
      }
    }
    if (stderr_fd.is_valid()) {
      if (dup2(stderr_fd.get(), STDERR_FILENO) == -1) {
        PLOG(ERROR) << "Failed to dup2() stderr fd";
        _exit(-1);
      }
    }

    std::string pid_str = base::NumberToString(container_pid);
    std::vector<const char*> argv;
    argv.reserve(args.size() + 1);
    for (const auto& arg : args) {
      if (arg == "$PID") {
        argv.emplace_back(pid_str.c_str());
        continue;
      }
      argv.emplace_back(arg.c_str());
    }
    argv.emplace_back(nullptr);

    execve(filename.value().c_str(), const_cast<char**>(argv.data()), environ);

    // Only happens when execve(2) fails.
    _exit(-1);
  }

  int status;
  if (HANDLE_EINTR(waitpid(child, &status, 0)) < 0) {
    PLOG(ERROR) << "Failed to wait for hook";
    return false;
  }
  if (!WIFEXITED(status)) {
    LOG(ERROR) << "Hook terminated abnormally: " << std::hex << status;
    return false;
  }
  return static_cast<int8_t>(WEXITSTATUS(status)) == 0;
}

// Immediately removes the loop device from the system.
void RemoveLoopDevice(int control_fd, int32_t device) {
  if (ioctl(control_fd, LOOP_CTL_REMOVE, device) < 0)
    PLOG(ERROR) << "Failed to free /dev/loop" << device;
}

}  // namespace

WaitablePipe::WaitablePipe() {
  if (pipe2(pipe_fds, O_CLOEXEC) < 0)
    PLOG(FATAL) << "Failed to create pipe";
}

WaitablePipe::~WaitablePipe() {
  if (pipe_fds[0] != -1)
    close(pipe_fds[0]);
  if (pipe_fds[1] != -1)
    close(pipe_fds[1]);
}

WaitablePipe::WaitablePipe(WaitablePipe&& other) {
  pipe_fds[0] = pipe_fds[1] = -1;
  std::swap(pipe_fds, other.pipe_fds);
}

void WaitablePipe::Wait() {
  char buf;

  close(pipe_fds[1]);
  HANDLE_EINTR(read(pipe_fds[0], &buf, sizeof(buf)));
  close(pipe_fds[0]);

  pipe_fds[0] = pipe_fds[1] = -1;
}

void WaitablePipe::Signal() {
  close(pipe_fds[0]);
  close(pipe_fds[1]);

  pipe_fds[0] = pipe_fds[1] = -1;
}

HookState::HookState() = default;
HookState::~HookState() = default;

HookState::HookState(HookState&& state) = default;

bool HookState::InstallHook(struct minijail* j, minijail_hook_event_t event) {
  if (installed_) {
    LOG(ERROR) << "Failed to install hook: already installed";
    return false;
  }

  // All these fds will be closed in WaitHook in the child process.
  for (size_t i = 0; i < 2; ++i) {
    if (minijail_preserve_fd(j, reached_pipe_.pipe_fds[i],
                             reached_pipe_.pipe_fds[i]) != 0) {
      LOG(ERROR) << "Failed to preserve reached pipe FDs to install hook";
      return false;
    }
    if (minijail_preserve_fd(j, ready_pipe_.pipe_fds[i],
                             ready_pipe_.pipe_fds[i]) != 0) {
      LOG(ERROR) << "Failed to preserve ready pipe FDs to install hook";
      return false;
    }
  }

  if (minijail_add_hook(j, &HookState::WaitHook, this, event) != 0) {
    LOG(ERROR) << "Failed to add hook";
    return false;
  }

  installed_ = true;
  return true;
}

bool HookState::WaitForHookAndRun(std::vector<HookCallback> callbacks,
                                  pid_t container_pid) {
  if (!installed_) {
    LOG(ERROR) << "Failed to wait for hook: not installed";
    return false;
  }
  reached_pipe_.Wait();

  for (auto& callback : callbacks) {
    bool success = std::move(callback).Run(container_pid);
    if (!success)
      return false;
  }

  ready_pipe_.Signal();
  return true;
}

// static
int HookState::WaitHook(void* payload) {
  HookState* self = reinterpret_cast<HookState*>(payload);

  self->reached_pipe_.Signal();
  self->ready_pipe_.Wait();

  return 0;
}

bool GetUsernsOutsideId(const std::string& map, int id, int* id_out) {
  if (map.empty()) {
    if (id_out)
      *id_out = id;
    return true;
  }

  std::string map_copy = map;
  base::StringPiece map_piece(map_copy);

  for (const auto& mapping : base::SplitStringPiece(
           map_piece, ",", base::KEEP_WHITESPACE, base::SPLIT_WANT_ALL)) {
    std::vector<base::StringPiece> tokens = base::SplitStringPiece(
        mapping, " ", base::TRIM_WHITESPACE, base::SPLIT_WANT_NONEMPTY);

    if (tokens.size() != 3) {
      LOG(ERROR) << "Malformed ugid mapping: '" << mapping << "'";
      return false;
    }

    uint32_t inside, outside, length;
    if (!base::StringToUint(tokens[0], &inside) ||
        !base::StringToUint(tokens[1], &outside) ||
        !base::StringToUint(tokens[2], &length)) {
      LOG(ERROR) << "Malformed ugid mapping: '" << mapping << "'";
      return false;
    }

    if (id >= inside && id <= (inside + length)) {
      if (id_out)
        *id_out = (id - inside) + outside;
      return true;
    }
  }
  VLOG(1) << "ugid " << id << " not found in mapping";

  return false;
}

bool MakeDir(const base::FilePath& path, int uid, int gid, int mode) {
  if (mkdir(path.value().c_str(), mode)) {
    PLOG(ERROR) << "Failed to mkdir " << path.value();
    return false;
  }
  if (chmod(path.value().c_str(), mode)) {
    PLOG(ERROR) << "Failed to chmod " << path.value();
    return false;
  }
  if (chown(path.value().c_str(), uid, gid)) {
    PLOG(ERROR) << "Failed to chown " << path.value();
    return false;
  }
  return true;
}

bool TouchFile(const base::FilePath& path, int uid, int gid, int mode) {
  base::ScopedFD fd(open(path.value().c_str(), O_RDWR | O_CREAT, mode));
  if (!fd.is_valid()) {
    PLOG(ERROR) << "Failed to create " << path.value();
    return false;
  }
  if (fchown(fd.get(), uid, gid)) {
    PLOG(ERROR) << "Failed to chown " << path.value();
    return false;
  }
  return true;
}

bool LoopdevSetup(const base::FilePath& source, Loopdev* loopdev_out) {
  base::ScopedFD source_fd(open(source.value().c_str(), O_RDONLY | O_CLOEXEC));
  if (!source_fd.is_valid()) {
    PLOG(ERROR) << "Failed to open " << source.value();
    return false;
  }

  base::ScopedFD control_fd(
      open(kLoopdevCtlPath, O_RDWR | O_NOFOLLOW | O_CLOEXEC));
  if (!control_fd.is_valid()) {
    PLOG(ERROR) << "Failed to open " << source.value();
    return false;
  }

  while (true) {
    int num = ioctl(control_fd.get(), LOOP_CTL_GET_FREE);
    if (num < 0) {
      PLOG(ERROR) << "Failed to open " << source.value();
      return false;
    }

    // Cleanup in case the setup fails. This frees |num| altogether.
    base::ScopedClosureRunner loop_device_cleanup(
        base::BindOnce(&RemoveLoopDevice, control_fd.get(), num));

    base::FilePath loopdev_path(base::StringPrintf("/dev/loop%i", num));
    base::ScopedFD loop_fd(
        open(loopdev_path.value().c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC));
    if (!loop_fd.is_valid()) {
      PLOG(ERROR) << "Failed to open " << loopdev_path.value();
      return false;
    }

    if (ioctl(loop_fd.get(), LOOP_SET_FD, source_fd.get()) < 0) {
      if (errno != EBUSY) {
        PLOG(ERROR) << "Failed to ioctl(LOOP_SET_FD) " << loopdev_path.value();
        return false;
      }
      continue;
    }

    // Set the autoclear flag on the loop device, which will release it when
    // there are no more references to it.
    struct loop_info64 loop_info = {};
    if (ioctl(loop_fd.get(), LOOP_GET_STATUS64, &loop_info) < 0) {
      PLOG(ERROR) << "Failed to ioctl(LOOP_GET_STATUS64) "
                  << loopdev_path.value();
      return false;
    }
    loop_info.lo_flags |= LO_FLAGS_AUTOCLEAR;
    if (ioctl(loop_fd.get(), LOOP_SET_STATUS64, &loop_info) < 0) {
      PLOG(ERROR) << "Failed to ioctl(LOOP_SET_STATUS64, LO_FLAGS_AUTOCLEAR) "
                  << loopdev_path.value();
      return false;
    }

    loop_device_cleanup.ReplaceClosure(base::DoNothing());
    loopdev_out->path = loopdev_path;
    loopdev_out->fd = std::move(loop_fd);
    loopdev_out->info = loop_info;
    break;
  }

  return true;
}

bool LoopdevDetach(Loopdev* loopdev) {
  if (ioctl(loopdev->fd.get(), LOOP_CLR_FD) < 0) {
    PLOG(ERROR) << "Failed to ioctl(LOOP_CLR_FD) for " << loopdev->path.value();
    return false;
  }

  return true;
}

bool DeviceMapperSetup(const base::FilePath& source,
                       const std::string& verity_cmdline,
                       base::FilePath* dm_path_out,
                       std::string* dm_name_out) {
#if USE_device_mapper
  // Normalize the name into something unique-esque.
  std::string dm_name =
      base::StringPrintf("cros-containers-%s", source.value().c_str());
  base::ReplaceChars(dm_name, "/", "_", &dm_name);

  // Get the /dev path for the higher levels to mount.
  base::FilePath dm_path = base::FilePath(kDevMapperPath).Append(dm_name);

  // Insert the source path in the verity command line.
  std::string verity = verity_cmdline;
  base::ReplaceSubstringsAfterOffset(&verity, 0, "@DEV@", source.value());

  // Extract the first three parameters for dm-verity settings.
  char ttype[20];
  unsigned long long start, size;
  int n;
  if (sscanf(verity.c_str(), "%llu %llu %10s %n", &start, &size, ttype, &n) !=
      3) {
    PLOG(ERROR) << "Malformed verity string " << verity;
    return false;
  }

  /* Finally create the device mapper. */
  std::unique_ptr<struct dm_task, decltype(&dm_task_destroy)> dmt(
      dm_task_create(DM_DEVICE_CREATE), &dm_task_destroy);
  if (dmt == nullptr) {
    PLOG(ERROR) << "Failed to dm_task_create() for " << source.value();
    return false;
  }

  if (dm_task_set_name(dmt.get(), dm_name.c_str()) != 0) {
    PLOG(ERROR) << "Failed to dm_task_set_name() for " << source.value();
    return false;
  }

  if (dm_task_set_ro(dmt.get()) != 0) {
    PLOG(ERROR) << "Failed to dm_task_set_ro() for " << source.value();
    return false;
  }

  if (dm_task_add_target(dmt.get(), start, size, ttype, verity.c_str() + n) !=
      0) {
    PLOG(ERROR) << "Failed to dm_task_add_target() for " << source.value();
    return false;
  }

  uint32_t cookie = 0;
  if (dm_task_set_cookie(dmt.get(), &cookie, 0) != 0) {
    PLOG(ERROR) << "Failed to dm_task_set_cookie() for " << source.value();
    return false;
  }

  if (dm_task_run(dmt.get()) != 0) {
    PLOG(ERROR) << "Failed to dm_task_run() for " << source.value();
    return false;
  }

  /* Make sure the node exists before we continue. */
  dm_udev_wait(cookie);

  *dm_path_out = dm_path;
  *dm_name_out = dm_name;
#endif
  return true;
}

// Tear down the device mapper target.
bool DeviceMapperDetach(const std::string& dm_name) {
#if USE_device_mapper
  struct dm_task* dmt = dm_task_create(DM_DEVICE_REMOVE);
  if (dmt == nullptr) {
    PLOG(ERROR) << "Failed to dm_task_run() for " << dm_name;
    return false;
  }

  base::ScopedClosureRunner teardown(base::BindOnce(
      base::IgnoreResult(&dm_task_destroy), base::Unretained(dmt)));

  if (dm_task_set_name(dmt, dm_name.c_str()) != 0) {
    PLOG(ERROR) << "Failed to dm_task_set_name() for " << dm_name;
    return false;
  }

  if (dm_task_run(dmt) != 0) {
    PLOG(ERROR) << "Failed to dm_task_run() for " << dm_name;
    return false;
  }
#endif
  return true;
}

bool MountExternal(const std::string& src,
                   const std::string& dest,
                   const std::string& type,
                   unsigned long flags,
                   const std::string& data) {
  bool remount_ro = false;

  // R/O bind mounts have to be remounted since 'bind' and 'ro' can't both be
  // specified in the original bind mount.  Remount R/O after the initial mount.
  if ((flags & MS_BIND) && (flags & MS_RDONLY)) {
    remount_ro = true;
    flags &= ~MS_RDONLY;
  }

  if (mount(src.c_str(), dest.c_str(), type.c_str(), flags,
            data.empty() ? nullptr : data.c_str()) != 0) {
    PLOG(ERROR) << "Failed to mount " << src << " to " << dest;
    return false;
  }

  if (remount_ro) {
    flags |= MS_RDONLY;
    if (mount(src.c_str(), dest.c_str(), nullptr, flags | MS_REMOUNT,
              data.empty() ? nullptr : data.c_str()) != 0) {
      PLOG(ERROR) << "Failed to remount " << src << " to " << dest;
      return false;
    }
  }

  return true;
}

bool Pipe2(base::ScopedFD* read_pipe, base::ScopedFD* write_pipe, int flags) {
  int fds[2];
  if (pipe2(fds, flags) != 0)
    return false;
  read_pipe->reset(fds[0]);
  write_pipe->reset(fds[1]);
  return true;
}

HookCallback CreateExecveCallback(base::FilePath filename,
                                  std::vector<std::string> args,
                                  base::ScopedFD stdin_fd,
                                  base::ScopedFD stdout_fd,
                                  base::ScopedFD stderr_fd) {
  return base::BindOnce(&ExecveCallbackHelper, filename, args,
                        std::move(stdin_fd), std::move(stdout_fd),
                        std::move(stderr_fd));
}

HookCallback AdaptCallbackToRunInNamespaces(HookCallback callback,
                                            std::vector<int> nstypes) {
  return base::BindOnce(&RunInNamespacesHelper, std::move(callback),
                        std::move(nstypes));
}

bool CreateDirectoryOwnedBy(const base::FilePath& full_path,
                            mode_t mode,
                            uid_t uid,
                            gid_t gid) {
  if (base::DirectoryExists(full_path))
    return true;

  // Collect a list of all missing directories.
  base::FilePath last_path = full_path;
  std::vector<base::FilePath> missing_subpaths{full_path};
  for (base::FilePath path = full_path.DirName();
       path != last_path && !base::DirectoryExists(path);
       path = path.DirName()) {
    missing_subpaths.push_back(path);
    last_path = path;
  }

  // Iterate through the missing parents, creating them.
  for (std::vector<base::FilePath>::reverse_iterator i =
           missing_subpaths.rbegin();
       i != missing_subpaths.rend(); ++i) {
    if (mkdir(i->value().c_str(), mode) != 0)
      return false;
    if (chown(i->value().c_str(), uid, gid) != 0)
      return false;
  }
  return true;
}

}  // namespace libcontainer
