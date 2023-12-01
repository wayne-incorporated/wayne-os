// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBCONTAINER_LIBCONTAINER_UTIL_H_
#define LIBCONTAINER_LIBCONTAINER_UTIL_H_

#include <linux/loop.h>

#include <string>
#include <vector>

#include <base/files/file_path.h>
#include <base/files/scoped_file.h>
#include <base/functional/callback_forward.h>
#include <base/logging.h>
#include <libminijail.h>

#include "libcontainer/config.h"
#include "libcontainer/libcontainer.h"

namespace libcontainer {

// WaitablePipe provides a way for one process to wait on another. This only
// uses the read(2) and close(2) syscalls, so it can work even in a restrictive
// environment. Each process must call only one of Wait() and Signal() exactly
// once.
struct WaitablePipe {
  WaitablePipe();
  ~WaitablePipe();

  WaitablePipe(WaitablePipe&&);
  WaitablePipe(const WaitablePipe&) = delete;
  WaitablePipe& operator=(const WaitablePipe&) = delete;

  // Waits for Signal() to be called.
  void Wait();

  // Notifies the process that called Wait() to continue running.
  void Signal();

  int pipe_fds[2];
};

// HookState holds two WaitablePipes so that the container can wait for its
// parent to run prestart hooks just prior to calling execve(2).
class HookState {
 public:
  HookState();
  ~HookState();

  HookState(HookState&& state);
  HookState(const HookState&) = delete;
  HookState& operator=(const HookState&) = delete;

  // Initializes this HookState so that WaitForHookAndRun() can be invoked and
  // waited upon when |j| reaches |event|. Returns true on success.
  bool InstallHook(minijail* j, minijail_hook_event_t event);

  // Waits for the event specified in InstallHook() and invokes |callbacks| in
  // the caller process. Returns true if all callbacks succeeded.
  bool WaitForHookAndRun(std::vector<HookCallback> callbacks,
                         pid_t container_pid);

 private:
  // A function that can be passed to minijail_add_hook() that blocks the
  // process in the container until the parent has finished running whatever
  // operations are needed outside the container. This is not expected to be
  // called directly.
  static int WaitHook(void* payload);

  bool installed_ = false;
  WaitablePipe reached_pipe_;
  WaitablePipe ready_pipe_;
};

// Loopdev represents an active loopback device.
struct Loopdev {
  // The path of the loopback device. e.g. /dev/loop1
  base::FilePath path;

  // An open file descriptor for the loopback device. Has the autoclear flag,
  // such that the kernel will automatically remove it once all references to it
  // are closed.
  base::ScopedFD fd;

  // Information about the loop device.
  struct loop_info64 info;
};

// Given a uid/gid map of "inside1 outside1 length1, ...", and an id inside of
// the user namespace, populate |id_out|. Returns true on success.
bool GetUsernsOutsideId(const std::string& map, int id, int* id_out);

bool MakeDir(const base::FilePath& path, int uid, int gid, int mode);

bool TouchFile(const base::FilePath& path, int uid, int gid, int mode);

// Find a free loop device and attach it.
bool LoopdevSetup(const base::FilePath& source, Loopdev* loopdev_out);

// Detach the specified loop device.
bool LoopdevDetach(Loopdev* loopdev);

// Create a new device mapper target for the source.
bool DeviceMapperSetup(const base::FilePath& source,
                       const std::string& verity_cmdline,
                       base::FilePath* dm_path_out,
                       std::string* dm_name_out);

// Tear down the device mapper target.
bool DeviceMapperDetach(const std::string& dm_name);

// Match mount_one in minijail, mount one mountpoint with
// consideration for combination of MS_BIND/MS_RDONLY flag.
bool MountExternal(const std::string& src,
                   const std::string& dest,
                   const std::string& type,
                   unsigned long flags,
                   const std::string& data);

// Creates a pipe using pipe2(2) and returns both ends as base::ScopedFDs.
bool Pipe2(base::ScopedFD* read_pipe, base::ScopedFD* write_pipe, int flags);

// Creates a callback that will fork(2)+execve(2) the program specified by args.
HookCallback CreateExecveCallback(base::FilePath filename,
                                  std::vector<std::string> args,
                                  base::ScopedFD stdin_fd,
                                  base::ScopedFD stdout_fd,
                                  base::ScopedFD stderr_fd);

// Wraps a callback to be run in a subset of the container's namespaces.
HookCallback AdaptCallbackToRunInNamespaces(HookCallback callback,
                                            std::vector<int> nstypes);

// Similar to base::CreateDirectory, but allows specifying the created
// directories' mode and owner.
bool CreateDirectoryOwnedBy(const base::FilePath& full_path,
                            mode_t mode,
                            uid_t uid,
                            gid_t gid);

}  // namespace libcontainer

#endif  // LIBCONTAINER_LIBCONTAINER_UTIL_H_
