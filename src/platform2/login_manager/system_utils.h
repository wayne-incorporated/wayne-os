// Copyright (c) 2012 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LOGIN_MANAGER_SYSTEM_UTILS_H_
#define LOGIN_MANAGER_SYSTEM_UTILS_H_

#include <stdint.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <string>
#include <vector>

#include <base/files/scoped_temp_dir.h>
#include <base/posix/file_descriptor_shuffle.h>
#include <base/strings/stringprintf.h>
#include <base/time/time.h>
#include <chromeos/dbus/service_constants.h>

#include <scoped_minijail.h>

namespace base {
class FilePath;
}

struct DBusPendingCall;

namespace login_manager {

enum class DevModeState {
  DEV_MODE_OFF,
  DEV_MODE_ON,
  DEV_MODE_UNKNOWN,
};

enum class VmState {
  OUTSIDE_VM,
  INSIDE_VM,
  UNKNOWN,
};

class ScopedDBusPendingCall;

class SystemUtils {
 public:
  SystemUtils() {}
  SystemUtils(const SystemUtils&) = delete;
  SystemUtils& operator=(const SystemUtils&) = delete;

  virtual ~SystemUtils() {}

  // Sends |signal| to |pid|, with uid and euid set to |owner|.
  // NOTE: Your saved UID is kept unchanged.  If you expect to drop and regain
  // root privs, MAKE SURE YOUR suid == 0.
  virtual int kill(pid_t pid, uid_t owner, int signal) = 0;

  // Returns time, in seconds, since the unix epoch.
  virtual time_t time(time_t* t) = 0;

  // Forks a new process.  In the parent, returns child's pid.  In child, 0.
  virtual pid_t fork() = 0;

  // Closes file descriptor |fd|.
  virtual int close(int fd) = 0;

  // Changes working directory to |path|.
  virtual int chdir(const base::FilePath& path) = 0;

  // Creates a new session. It only succeeds if the calling process is not a
  // process group leader. Returns the new session ID on success, or -1 on
  // failure.
  virtual pid_t setsid() = 0;

  // Executes the |exec_file|. |argv| is execution arguments. |argv| shouldn't
  // contain the program. |envp| is set up as the initial environment variables.
  // This function doesn't return on success, so if it returns it's a failure.
  virtual int execve(const base::FilePath& exec_file,
                     const char* const argv[],
                     const char* const envp[]) = 0;

  // Enters a new mount namespace.
  virtual bool EnterNewMountNamespace() = 0;

  // Run an external program and collect its stdout in |output|.
  virtual bool GetAppOutput(const std::vector<std::string>& argv,
                            std::string* output) = 0;

  // Returns the current developer mode.
  virtual DevModeState GetDevModeState() = 0;

  // Returns whether Chrome OS is running inside a Virtual Machine.
  virtual VmState GetVmState() = 0;

  // Returns: true if process group specified by |child_spec| exited,
  //          false if we time out.
  virtual bool ProcessGroupIsGone(pid_t child_spec,
                                  base::TimeDelta timeout) = 0;

  // Returns: true if process specified by |child_spec| exited,
  //          false if we time out.
  virtual bool ProcessIsGone(pid_t child_spec, base::TimeDelta timeout) = 0;

  // Returns PID of child process if we reap a child process within timeout, 0
  // if we time out or -1 if we fail. |status_out| is set only if we reap a
  // child process. Note unlike ProcessGroupIsGone, it only reaps at most one
  // child per call. waitpid() will always be called at least once (i.e. even
  // if |timeout| is zero).
  virtual pid_t Wait(pid_t child_spec,
                     base::TimeDelta timeout,
                     int* status_out) = 0;

  virtual bool EnsureAndReturnSafeFileSize(const base::FilePath& file,
                                           int32_t* file_size_32) = 0;

  // Returns whether a file exists.
  virtual bool Exists(const base::FilePath& file) = 0;

  // Returns whether a directory exists.
  virtual bool DirectoryExists(const base::FilePath& dir) = 0;

  // Creates a directory.
  virtual bool CreateDir(const base::FilePath& dir) = 0;

  // Enumerates files in |root_path|. The order of results is not guaranteed.
  // |file_type| is a bit mask of FileType defined in
  // base/files/file_enumerator.h. |root_path| will be prepended to returned
  // paths.
  virtual bool EnumerateFiles(const base::FilePath& root_path,
                              int file_type,
                              std::vector<base::FilePath>* out_files) = 0;

  // Generates a guaranteed-unique filename in a write-only temp dir.
  // Returns false upon failure.
  virtual bool GetUniqueFilenameInWriteOnlyTempDir(
      base::FilePath* temp_file_path) = 0;

  // Removes a file.
  virtual bool RemoveFile(const base::FilePath& filename) = 0;

  // Atomically writes the given buffer into the file, overwriting any
  // data that was previously there.  Returns true upon success, false
  // otherwise.
  virtual bool AtomicFileWrite(const base::FilePath& filename,
                               const std::string& data) = 0;

  // Returns the amount of free disk space in bytes for the filesystem
  // containing |path|.
  virtual int64_t AmountOfFreeDiskSpace(const base::FilePath& path) = 0;

  // Gets the matching group ID for a user ID, as well as supplementary groups.
  virtual bool GetGidAndGroups(uid_t uid,
                               gid_t* out_gid,
                               std::vector<gid_t>* out_groups) = 0;

  // Reads file content from file at |path| into string at |str_out|.
  virtual bool ReadFileToString(const base::FilePath& path,
                                std::string* str_out) = 0;

  // Writes string |data| to file at |path|.
  virtual bool WriteStringToFile(const base::FilePath& path,
                                 const std::string& data) = 0;

  // Changes blocked signals. |how| takes one of |SIG_BLOCK|, |SIG_UNBLOCK|, and
  // |SIG_SETMASK|. See man page of sigprocmask(2) for more details. |signals|
  // contains all signals to operate on.
  virtual bool ChangeBlockedSignals(int how,
                                    const std::vector<int>& signals) = 0;

  // Runs command specified in |argv| in a separate process and wait until it
  // it finishes. Returns true if the process is up, false otherwise.
  // |exit_code_out| is set only when this function returns true.
  virtual bool LaunchAndWait(const std::vector<std::string>& argv,
                             int* exit_code_out) = 0;

  // Runs command |args[0]| with arguments |args| and environment |env_vars| in
  // a restricted runtime specified by |jail|.
  // Does *not* take ownership of |jail|.
  // Returns true if the process was successfully launched and sandboxed.
  virtual bool RunInMinijail(const ScopedMinijail& jail,
                             const std::vector<std::string>& args,
                             const std::vector<std::string>& env_vars,
                             pid_t* pchild_pid) = 0;
};

}  // namespace login_manager

#endif  // LOGIN_MANAGER_SYSTEM_UTILS_H_
