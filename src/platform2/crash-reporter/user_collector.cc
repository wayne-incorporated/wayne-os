// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "crash-reporter/user_collector.h"

#include <bits/wordsize.h>
#include <elf.h>
#include <fcntl.h>
#include <stdint.h>

#include <unordered_set>
#include <utility>
#include <vector>

#include <base/check.h>
#include <base/files/file_enumerator.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/posix/eintr_wrapper.h>
#include <base/containers/contains.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_piece.h>
#include <base/strings/string_split.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>
#include <brillo/process/process.h>

#include "crash-reporter/constants.h"
#include "crash-reporter/paths.h"
#include "crash-reporter/user_collector_base.h"
#include "crash-reporter/util.h"
#include "crash-reporter/vm_support.h"

using base::FilePath;
using base::StringPrintf;

namespace {

// The length of a process name stored in the kernel. Appears on our command
// line and also in /proc/[pid] places. See PR_SET_NAME in
// http://www.kernel.org/doc/man-pages/online/pages/man2/prctl.2.html and also
// TASK_COMM_LEN. Both of those say "16 bytes" which includes the terminating
// nul byte; the strlen is 15 characters.
constexpr int kKernelProcessNameLength = 15;

// This procfs file is used to cause kernel core file writing to
// instead pipe the core file into a user space process.  See
// core(5) man page.
const char kCorePatternFile[] = "/proc/sys/kernel/core_pattern";
const char kCorePipeLimitFile[] = "/proc/sys/kernel/core_pipe_limit";
// Set core_pipe_limit to 4 so that we can catch a few unrelated concurrent
// crashes, but finite to avoid infinitely recursing on crash handling.
const char kCorePipeLimit[] = "4";
const char kCoreToMinidumpConverterPath[] = "/usr/bin/core2md";

const char kFilterPath[] = "/opt/google/crash-reporter/filter";

// Core pattern lock file: only exists on linux-3.18 and earlier.
const char kCorePatternLockFile[] = "/proc/sys/kernel/lock_core_pattern";

// Filename we touch in our state directory when we get enabled.
constexpr char kCrashHandlingEnabledFlagFile[] = "crash-handling-enabled";

// The name of the main chrome executable. Currently, both lacros and ash use
// the same executable name.
constexpr char kChromeExecName[] = "chrome";

// The crash key used by Chrome to record its process type (browser, renderer,
// gpu-process, etc). Must match the key of the |ptype_key| variable inside
// InitializeCrashpadImpl() in
// https://source.chromium.org/chromium/chromium/src/+/main:components/crash/core/app/crashpad.cc
constexpr char kChromeProcessTypeKey[] = "ptype";

// The value of ptype for Chrome's browser process.  Must match the value of
// |ptype_key| if browser_process is true inside InitializeCrashpadImpl() in
// https://source.chromium.org/chromium/chromium/src/+/main:components/crash/core/app/crashpad.cc
constexpr char kChromeProcessTypeBrowserValue[] = "browser";

// Returns true if the given executable name matches that of Chrome.  This
// includes checks for threads that Chrome has renamed.
bool IsChromeExecName(const std::string& exec);

// This is needed for kernels older than linux-4.4. Once we drop support for
// older kernels (upgrading or going EOL), we can drop this logic.
bool LockCorePattern() {
  base::FilePath core_pattern_lock_file(kCorePatternLockFile);

  // Core pattern lock was only added for kernel versions before 4.4.
  if (!base::PathExists(core_pattern_lock_file)) {
    VLOG(1) << "No core pattern lock available";
    return true;
  }

  if (util::IsDeveloperImage()) {
    LOG(INFO) << "Developer image -- leaving core pattern unlocked";
    return true;
  }

  if (base::WriteFile(core_pattern_lock_file, "1", 1) != 1) {
    PLOG(ERROR) << "Failed to lock core pattern";
    return false;
  }

  return true;
}

// Given an exec name like "chrome", return the string we'd get in |exec| if
// we're getting the exec name from the kernel. Matches the string manipulation
// in UserCollectorBase::HandleCrash.
std::string ExecNameToSuppliedName(base::StringPiece name) {
  // When checking a kernel-supplied name, it should be truncated to 15 chars.
  return "supplied_" + std::string(name.data(), 0, kKernelProcessNameLength);
}

#if !USE_FORCE_BREAKPAD
// |status_file| is the path to a /proc/<pid>/status file. Returns true if the
// process described by the status file is (a) the crashpad handled program and
// (b) a child of |desired_parent|.
bool IsACrashpadChildOf(const base::FilePath& status_file,
                        pid_t desired_parent) {
  std::string status_contents;
  // Don't log error messages on failures reading or parsing the files;
  // processes may go away in between the time we scan the directory and the
  // time we try to read the status file. That's expected and we'll generate a
  // lot of log-spam if we write a message on each failure.
  if (!base::ReadFileToString(status_file, &status_contents)) {
    VPLOG(3) << "Failed to read " << status_file.value();
    return false;
  }

  bool has_correct_parent = false;
  bool is_crashpad = false;
  base::StringPairs pairs;
  if (!base::SplitStringIntoKeyValuePairs(status_contents, ':', '\n', &pairs)) {
    VLOG(3) << "Failed to convert " << status_file.value();
    return false;
  }
  for (const auto& key_value : pairs) {
    if (key_value.first == "PPid") {
      std::string value;
      int ppid;
      base::TrimWhitespaceASCII(key_value.second, base::TRIM_ALL, &value);
      if (base::StringToInt(value, &ppid) && ppid == desired_parent) {
        has_correct_parent = true;
      } else {
        return false;  // No need to continue looking at this process's
                       // status file; it's a child of a different process.
      }
    } else if (key_value.first == "Name") {
      // Names in status are truncated to 15 characters. (TASK_COMM_LEN is 16
      // and one byte is used for the terminating nul internally.)
      constexpr base::StringPiece kCrashpadName(
          base::StringPiece("chrome_crashpad_handler")
              .substr(0, kKernelProcessNameLength));
      std::string value;
      base::TrimWhitespaceASCII(key_value.second, base::TRIM_ALL, &value);
      if (value == kCrashpadName) {
        is_crashpad = true;
      } else {
        return false;  // No need to continue looking at this process's
                       // status file; it's not crashpad.
      }
    }

    if (is_crashpad && has_correct_parent) {
      return true;
    }
  }

  VLOG(3) << status_file.value() << " didn't have Name and PPid";
  return false;
}
#endif  // !USE_FORCE_BREAKPAD
}  // namespace

UserCollector::UserCollector()
    : UserCollectorBase("user", kUseNormalCrashDirectorySelectionMethod),
      core_pattern_file_(kCorePatternFile),
      core_pipe_limit_file_(kCorePipeLimitFile),
      filter_path_(kFilterPath),
      handling_early_chrome_crash_(false),
      core2md_failure_(false) {}

void UserCollector::Initialize(const std::string& our_path,
                               bool core2md_failure,
                               bool directory_failure,
                               bool early) {
  UserCollectorBase::Initialize(directory_failure, early);
  our_path_ = our_path;
  core2md_failure_ = core2md_failure;
}

UserCollector::~UserCollector() {}

void UserCollector::FinishCrash(const base::FilePath& meta_path,
                                const std::string& exec_name,
                                const std::string& payload_name) {
  VmSupport* vm_support = VmSupport::Get();
  if (vm_support)
    vm_support->AddMetadata(this);

  UserCollectorBase::FinishCrash(meta_path, exec_name, payload_name);

  if (vm_support)
    vm_support->FinishCrash(meta_path);
}

// Return the string that should be used for the kernel's core_pattern file.
// Note that if you change the format of the enabled pattern, you'll probably
// also need to change the UserCollectorBase::ParseCrashAttributes function, the
// user_collector_test.cc unittest, the logging_UserCrash.py autotest,
// and the platform.UserCrash tast test.
std::string UserCollector::GetPattern(bool enabled, bool early) const {
  if (enabled) {
    // Combine the crash attributes into one parameter to try to reduce
    // the size of the invocation line for crash_reporter, since the kernel
    // has a fixed-sized (128B) buffer for it (before parameter expansion).
    // Note that the kernel does not support quoted arguments in core_pattern.
    return StringPrintf("|%s %s--user=%%P:%%s:%%u:%%g:%%f", our_path_.c_str(),
                        early ? "--early --log_to_stderr " : "");
  } else {
    return "core";
  }
}

bool UserCollector::SetUpInternal(bool enabled, bool early) {
  CHECK(initialized_);
  LOG(INFO) << (enabled ? "Enabling" : "Disabling") << " user crash handling";

  if (base::WriteFile(FilePath(core_pipe_limit_file_), kCorePipeLimit,
                      strlen(kCorePipeLimit)) !=
      static_cast<int>(strlen(kCorePipeLimit))) {
    PLOG(ERROR) << "Unable to write " << core_pipe_limit_file_;
    return false;
  }
  std::string pattern = GetPattern(enabled, early);
  if (base::WriteFile(FilePath(core_pattern_file_), pattern.c_str(),
                      pattern.length()) != static_cast<int>(pattern.length())) {
    int saved_errno = errno;
    // If the core pattern is locked and we try to reset the |core_pattern|
    // while disabling |user_collector| or resetting it to what it already was,
    // expect failure here with an EPERM.
    bool ignore_error = false;
    if (errno == EPERM && base::PathExists(FilePath(kCorePatternLockFile))) {
      std::string actual_contents;
      if (!base::ReadFileToString(FilePath(core_pattern_file_),
                                  &actual_contents)) {
        PLOG(ERROR) << "Failed to read " << core_pattern_file_;
        actual_contents.clear();
      }
      if (!enabled || base::TrimWhitespaceASCII(
                          actual_contents, base::TRIM_TRAILING) == pattern) {
        ignore_error = true;
        LOG(WARNING) << "Failed to write to locked core pattern; ignoring";
      }
    }
    if (!ignore_error) {
      LOG(ERROR) << "Unable to write " << core_pattern_file_ << ": "
                 << strerror(saved_errno);
      return false;
    }
  }

  // Attempt to lock down |core_pattern|: this only works for kernels older than
  // linux-3.18.
  if (enabled && !early && !LockCorePattern()) {
    LOG(ERROR) << "Failed to lock core pattern on a supported device";
    return false;
  }

  // Set up the base crash processing dir for future users.
  const FilePath dir = GetCrashProcessingDir();

  // First nuke all existing content.  This will take care of deleting any
  // existing paths (files, symlinks, dirs, etc...) for us.
  if (!base::DeletePathRecursively(dir))
    PLOG(WARNING) << "Cleanup of directory failed: " << dir.value();

  // This will create the directory with 0700 mode.  Since init is run as root,
  // root will own these too.
  if (!base::CreateDirectory(dir)) {
    PLOG(ERROR) << "Creating directory failed: " << dir.value();
    return false;
  }

  // Write out a flag file for testing to indicate we have started correctly.
  char data[] = "enabled";
  size_t write_len = sizeof(data) - 1;
  if (base::WriteFile(base::FilePath(crash_reporter_state_path_)
                          .Append(kCrashHandlingEnabledFlagFile),
                      data, write_len) != write_len) {
    PLOG(WARNING) << "Unable to create flag file for crash reporter enabled";
  }

  return true;
}

bool UserCollector::CopyOffProcFiles(pid_t pid, const FilePath& container_dir) {
  FilePath process_path = GetProcessPath(pid);
  if (!base::PathExists(process_path)) {
    LOG(ERROR) << "Path " << process_path.value() << " does not exist";
    return false;
  }

  // NB: We can't (yet) use brillo::SafeFD here because it does not support
  // reading /proc files (it sometimes truncates them).
  // TODO(b/216739198): Use SafeFD.
  int processpath_fd;
  if (!ValidatePathAndOpen(process_path, &processpath_fd)) {
    LOG(ERROR) << "Failed to open process path dir: " << process_path.value();
    return false;
  }
  base::ScopedFD scoped_processpath_fd(processpath_fd);

  int containerpath_fd;
  if (!ValidatePathAndOpen(container_dir, &containerpath_fd)) {
    LOG(ERROR) << "Failed to open container dir:" << container_dir.value();
    return false;
  }
  base::ScopedFD scoped_containerpath_fd(containerpath_fd);

  static const char* const kProcFiles[] = {"auxv", "cmdline", "environ",
                                           "maps", "status",  "syscall"};
  for (const auto& proc_file : kProcFiles) {
    int source_fd = HANDLE_EINTR(
        openat(processpath_fd, proc_file, O_RDONLY | O_CLOEXEC | O_NOFOLLOW));
    if (source_fd < 0) {
      PLOG(ERROR) << "Failed to open " << process_path << "/" << proc_file;
      return false;
    }
    base::File source(source_fd);

    int dest_fd = HANDLE_EINTR(
        openat(containerpath_fd, proc_file,
               O_CREAT | O_WRONLY | O_TRUNC | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
               constants::kSystemCrashFilesMode));
    if (dest_fd < 0) {
      PLOG(ERROR) << "Failed to open " << container_dir << "/" << proc_file;
      return false;
    }
    base::File dest(dest_fd);

    if (!base::CopyFileContents(source, dest)) {
      LOG(ERROR) << "Failed to copy " << proc_file;
      return false;
    }
  }
  return true;
}

bool UserCollector::ValidateProcFiles(const FilePath& container_dir) const {
  // Check if the maps file is empty, which could be due to the crashed
  // process being reaped by the kernel before finishing a core dump.
  int64_t file_size = 0;
  if (!base::GetFileSize(container_dir.Append("maps"), &file_size)) {
    PLOG(ERROR) << "Could not get the size of maps file";
    return false;
  }
  if (file_size == 0) {
    LOG(ERROR) << "maps file is empty";
    return false;
  }
  return true;
}

UserCollector::ErrorType UserCollector::ValidateCoreFile(
    const FilePath& core_path) const {
  int fd = HANDLE_EINTR(open(core_path.value().c_str(), O_RDONLY));
  if (fd < 0) {
    PLOG(ERROR) << "Could not open core file " << core_path.value();
    return kErrorReadCoreData;
  }

  char e_ident[EI_NIDENT];
  bool read_ok = base::ReadFromFD(fd, e_ident, sizeof(e_ident));
  IGNORE_EINTR(close(fd));
  if (!read_ok) {
    LOG(ERROR) << "Could not read header of core file";
    return kErrorInvalidCoreFile;
  }

  if (e_ident[EI_MAG0] != ELFMAG0 || e_ident[EI_MAG1] != ELFMAG1 ||
      e_ident[EI_MAG2] != ELFMAG2 || e_ident[EI_MAG3] != ELFMAG3) {
    LOG(ERROR) << "Invalid core file";
    return kErrorInvalidCoreFile;
  }

#if __WORDSIZE == 64
  // TODO(benchan, mkrebs): Remove this check once core2md can
  // handles both 32-bit and 64-bit ELF on a 64-bit platform.
  if (e_ident[EI_CLASS] == ELFCLASS32) {
    LOG(ERROR) << "Conversion of 32-bit core file on 64-bit platform is "
               << "currently not supported";
    return kErrorUnsupported32BitCoreFile;
  }
#endif

  return kErrorNone;
}

bool UserCollector::CopyStdinToCoreFile(const base::FilePath& core_path) {
  return CopyPipeToCoreFile(STDIN_FILENO, core_path);
}

bool UserCollector::CopyPipeToCoreFile(int input_fd,
                                       const base::FilePath& core_path) {
  // We need to write to an actual file here for core2md.
  // If we're in memfd mode, fail out.
  if (crash_sending_mode_ == kCrashLoopSendingMode) {
    LOG(ERROR) << "Cannot call CopyFdToNewFile in kCrashLoopSendingMode";
    return false;
  }

  if (handling_early_chrome_crash_) {
    int max_core_size = kMaxChromeCoreSize;
    if (util::UseLooseCoreSizeForChromeCrashEarly()) {
      max_core_size = kMaxChromeCoreSizeLoose;
    }

    // See comments for kMaxChromeCoreSize in the header for why we do this.
    std::optional<int> res =
        CopyFirstNBytesOfFdToNewFile(input_fd, core_path, max_core_size);
    if (!res) {
      LOG(ERROR) << "Could not write core file " << core_path.value();
      if (!base::DeleteFile(core_path)) {
        LOG(ERROR) << "And could not delete the core file either";
      }
      return false;
    }

    // Check that we wrote out the entire core file. Partial core files aren't
    // going to usable.
    if (res.value() < max_core_size) {
      return true;
    }

    // If res.value() == max_core_size, then we can only tell if we wrote
    // out all the input by trying to read one more byte and seeing if we were
    // at EOF.
    char n_plus_one_byte;
    if (read(input_fd, &n_plus_one_byte, 1) == 0) {
      // Core was exactly max_core_size.
      return true;
    }

    LOG(ERROR) << "Core file too big; write aborted";
    if (!base::DeleteFile(core_path)) {
      LOG(ERROR) << "And could not delete partial core file afterwards";
    }
    return false;
  }

  // We don't directly create a ScopedFD with input_fd because the
  // destructor would close() that file descriptor. In non-test-scenarios,
  // input_fd is stdin and we don't want to close stdin.
  base::ScopedFD input_fd_copy(dup(input_fd));
  if (!input_fd_copy.is_valid()) {
    return false;
  }
  if (CopyFdToNewFile(std::move(input_fd_copy), core_path)) {
    return true;
  }

  PLOG(ERROR) << "Could not write core file " << core_path.value();
  // If the file system was full, make sure we remove any remnants.
  if (!base::DeleteFile(core_path)) {
    LOG(ERROR) << "And could not delete the core file either";
  }
  return false;
}

bool UserCollector::RunCoreToMinidump(const FilePath& core_path,
                                      const FilePath& procfs_directory,
                                      const FilePath& minidump_path,
                                      const FilePath& temp_directory) {
  FilePath output_path = temp_directory.Append("output");
  brillo::ProcessImpl core2md;
  core2md.RedirectOutput(output_path.value());
  core2md.AddArg(kCoreToMinidumpConverterPath);
  core2md.AddArg(core_path.value());
  core2md.AddArg(procfs_directory.value());

  if (!core2md_failure_) {
    core2md.AddArg(minidump_path.value());
  } else {
    // To test how core2md errors are propagaged, cause an error
    // by forgetting a required argument.
  }

  int errorlevel = core2md.Run();

  std::string output;
  base::ReadFileToString(output_path, &output);
  if (errorlevel != 0) {
    LOG(ERROR) << "Problem during " << kCoreToMinidumpConverterPath
               << " [result=" << errorlevel << "]: " << output;
    return false;
  }

  // Change the minidump to be not-world-readable. chmod will change permissions
  // on symlinks. Use fchmod instead.
  base::ScopedFD minidump(
      open(minidump_path.value().c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC));
  if (!minidump.is_valid()) {
    PLOG(ERROR) << "Could not open minidump file: " << minidump_path.value();
    return false;
  }
  if (fchmod(minidump.get(), constants::kSystemCrashFilesMode) < 0) {
    PLOG(ERROR) << "Couldn't chmod minidump file: " << minidump_path.value();
    return false;
  }
  return true;
}

bool UserCollector::RunFilter(pid_t pid) {
  int mode;
  int exec_mode = base::FILE_PERMISSION_EXECUTE_BY_USER |
                  base::FILE_PERMISSION_EXECUTE_BY_GROUP |
                  base::FILE_PERMISSION_EXECUTE_BY_OTHERS;
  if (!base::GetPosixFilePermissions(base::FilePath(filter_path_), &mode) ||
      (mode & exec_mode) != exec_mode) {
    // Filter does not exist or is not executable.
    return true;
  }

  brillo::ProcessImpl filter;
  filter.AddArg(filter_path_);
  filter.AddArg(StringPrintf("%d", pid));

  return filter.Run() == 0;
}

bool UserCollector::ShouldCaptureEarlyChromeCrash(const std::string& exec,
                                                  pid_t pid) {
  // Rules:
  //   1. Only the main browser process needs to be captured this way. Crashpad
  //      can capture very early crashes in subprocesses.
  //   2. Only capture if the process does not have a child process named
  //      "chrome_crashpad_handler". Once this process exists, crashpad should
  //      be capturing the crash.
  //   3. Don't capture on boards with USE flag force_breakpad. We can't tell if
  //      breakpad is initialized from the outside.
  //   4. If the process has been up for more than 10 seconds, don't capture.
  //      Long-running processes will have cores which are larger than
  //      kMaxChromeCoreSize, and the lack of a chrome_crashpad_handler probably
  //      indicates we're trying to shutdown, not start up.
#if USE_FORCE_BREAKPAD
  return false;  // Doesn't meet rule #3.
#else
  if (exec != kChromeExecName &&
      exec != ExecNameToSuppliedName(kChromeExecName)) {
    return false;  // Doesn't meet rule #1.
  }

  base::FilePath process_path = GetProcessPath(pid);
  base::FilePath cmdline_path(process_path.Append("cmdline"));
  std::string cmdline;
  if (!base::ReadFileToString(cmdline_path, &cmdline)) {
    LOG(WARNING) << "Could not read " << cmdline_path.value();
    return false;  // Can't tell if it meets rule #1.
  }

  // https://man7.org/linux/man-pages/man5/proc.5.html says the command line
  // arguments are separated by '\0's. But  When Chrome's processes spawn and
  // override their cmdlines, they can end up with spaces between the args
  // instead of the expected \0s. Check both ways.
  for (char separator :
       {kNormalCmdlineSeparator, kChromeSubprocessCmdlineSeparator}) {
    std::vector<base::StringPiece> argv = base::SplitStringPiece(
        cmdline, std::string(1, separator), base::TRIM_WHITESPACE,
        base::SPLIT_WANT_NONEMPTY);

    for (base::StringPiece arg : argv) {
      if (base::StartsWith(arg, "--type=")) {
        return false;  // Not the browser process. Doesn't meet rule #1.
      }
    }
  }

  // Check uptime before checking for a child crashpad process. The uptime
  // check requires far fewer system calls and will usually return false.
  base::TimeDelta current_uptime;
  base::TimeDelta process_start_uptime;
  constexpr base::TimeDelta kMaxProcessAge = base::Seconds(10);
  if (!GetUptime(&current_uptime) ||
      !GetUptimeAtProcessStart(pid, &process_start_uptime) ||
      (current_uptime - process_start_uptime) > kMaxProcessAge) {
    return false;  // Doesn't meet rule #4.
  }

  // Enumerate all /proc/<pid>/status files to look for one that's a child of
  // the crashed process and which is a crashpad handler.
  base::FileEnumerator status_files(
      paths::Get("/proc"), true /*recursive*/, base::FileEnumerator::FILES,
      "status", base::FileEnumerator::FolderSearchPolicy::ALL,
      base::FileEnumerator::ErrorPolicy::IGNORE_ERRORS);
  for (base::FilePath status_file = status_files.Next(); !status_file.empty();
       status_file = status_files.Next()) {
    if (IsACrashpadChildOf(status_file, pid)) {
      return false;  // Doesn't meet rule #2.
    }
  }

  return true;
#endif  // !USE_FORCE_BREAKPAD
}

// static
const char* UserCollector::GuessChromeProductName(
    const base::FilePath& exec_directory) {
  if (exec_directory.empty()) {
    // Guess Chrome_ChromeOS for lack of a better choice.
    LOG(WARNING) << "Exectuable directory not known; assuming ash";
    return constants::kProductNameChromeAsh;
  }

  const base::FilePath kAshChromeDirectory(paths::Get("/opt/google/chrome"));
  if (kAshChromeDirectory == exec_directory) {
    return constants::kProductNameChromeAsh;
  }

  // Lacros can be in several different directories. Sometimes it runs from
  // rootfs, sometimes from stateful. Just look for the "lacros" string.
  if (exec_directory.value().find("lacros") != std::string::npos) {
    return constants::kProductNameChromeLacros;
  }

  LOG(WARNING) << exec_directory.value()
               << " does not match Ash or Lacros paths";
  // Guess Chrome_ChromeOS for lack of a better choice.
  return constants::kProductNameChromeAsh;
}

void UserCollector::BeginHandlingCrash(pid_t pid,
                                       const std::string& exec,
                                       const base::FilePath& exec_directory) {
  // Check for early Chrome crashes; if this is an early Chrome crash, start
  // the special handling. Don't use the special handling if
  // ShouldHandleChromeCrashes() returns true, because that indicates we want to
  // use the normal handling code path for Chrome crashes.
  if (!ShouldHandleChromeCrashes() && IsChromeExecName(exec) &&
      ShouldCaptureEarlyChromeCrash(exec, pid)) {
    handling_early_chrome_crash_ = true;
    // Change product name to Chrome_ChromeOS or Chrome_Lacros.
    std::string product_key = GuessChromeProductName(exec_directory);
    AddCrashMetaUploadData(constants::kUploadDataKeyProductKey, product_key);
    AddCrashMetaUploadData("early_chrome_crash", "true");

    // Add the "ptype=browser" normally added by InitializeCrashpadImpl(). Since
    // we reject any process with a "--type" flag, this should always be a
    // browser process.
    AddCrashMetaUploadData(kChromeProcessTypeKey,
                           kChromeProcessTypeBrowserValue);
    // Get the Chrome version if we can, so that the crashes show up correctly
    // on the "crashes in the latest dev release" dashboards.
    base::FilePath chrome_metadata_path =
        exec_directory.Append("metadata.json");
    if (std::optional<std::string> version_maybe =
            util::ExtractChromeVersionFromMetadata(chrome_metadata_path);
        version_maybe) {
      AddCrashMetaUploadData("ver", *version_maybe);
    }

    // TODO(b/234500620): We should also check for crash-loop mode and activate
    // it here if appropriate. Otherwise we risk losing crashes if there's an
    // early crash loading a user's profile info.

    LOG(INFO) << "Activating early Chrome crash mode for " << product_key;
  }
}

bool UserCollector::ShouldDump(pid_t pid,
                               bool handle_chrome_crashes,
                               const std::string& exec,
                               std::string* reason) {
  reason->clear();

  // Treat Chrome crashes as if the user opted-out.  We stop counting Chrome
  // crashes towards user crashes, so user crashes really mean non-Chrome
  // user-space crashes.
  if (!handle_chrome_crashes && !handling_early_chrome_crash_ &&
      IsChromeExecName(exec)) {
    // anomaly_detector's CrashReporterParser looks for this message; don't
    // change it without updating the regex.
    *reason =
        "ignoring call by kernel - chrome crash; "
        "waiting for chrome to call us directly";
    return false;
  }

  if (!RunFilter(pid)) {
    *reason = "filtered out";
    return false;
  }

  return UserCollectorBase::ShouldDump(pid, reason);
}

bool UserCollector::ShouldDump(pid_t pid,
                               uid_t,
                               const std::string& exec,
                               std::string* reason) {
  return ShouldDump(pid, ShouldHandleChromeCrashes(), exec, reason);
}

UserCollector::ErrorType UserCollector::ConvertCoreToMinidump(
    pid_t pid,
    const FilePath& container_dir,
    const FilePath& core_path,
    const FilePath& minidump_path) {
  // If proc files are unusable, we continue to read the core file from stdin,
  // but only skip the core-to-minidump conversion, so that we may still use
  // the core file for debugging.
  bool proc_files_usable =
      CopyOffProcFiles(pid, container_dir) && ValidateProcFiles(container_dir);

  if (!CopyStdinToCoreFile(core_path)) {
    return kErrorReadCoreData;
  }

  if (!proc_files_usable) {
    LOG(INFO) << "Skipped converting core file to minidump due to "
              << "unusable proc files";
    return kErrorUnusableProcFiles;
  }

  ErrorType error = ValidateCoreFile(core_path);
  if (error != kErrorNone) {
    return error;
  }

  if (!RunCoreToMinidump(core_path,
                         container_dir,  // procfs directory
                         minidump_path,
                         container_dir)) {  // temporary directory
    return kErrorCore2MinidumpConversion;
  }

  return kErrorNone;
}

namespace {

bool IsChromeExecName(const std::string& exec) {
  static const char* const kChromeNames[] = {
      kChromeExecName,
      // These are additional thread names seen in http://crash/
      "MediaPipeline",
      // These come from the use of base::PlatformThread::SetName() directly
      "CrBrowserMain", "CrRendererMain", "CrUtilityMain", "CrPPAPIMain",
      "CrPPAPIBrokerMain", "CrPluginMain", "CrWorkerMain", "CrGpuMain",
      "BrokerEvent", "CrVideoRenderer", "CrShutdownDetector", "UsbEventHandler",
      "CrNaClMain", "CrServiceMain",
      // These thread names come from the use of base::Thread
      "Gamepad polling thread", "Chrome_InProcGpuThread",
      "Chrome_DragDropThread", "Renderer::FILE", "VC manager",
      "VideoCaptureModuleImpl", "JavaBridge", "VideoCaptureManagerThread",
      "Geolocation", "Geolocation_wifi_provider",
      "Device orientation polling thread", "Chrome_InProcRendererThread",
      "NetworkChangeNotifier", "Watchdog", "inotify_reader",
      "cf_iexplore_background_thread", "BrowserWatchdog",
      "Chrome_HistoryThread", "Chrome_SyncThread", "Chrome_ShellDialogThread",
      "Printing_Worker", "Chrome_SafeBrowsingThread", "SimpleDBThread",
      "D-Bus thread", "AudioThread", "NullAudioThread", "V4L2Thread",
      "ChromotingClientDecodeThread", "Profiling_Flush", "worker_thread_ticker",
      "AudioMixerAlsa", "AudioMixerCras", "FakeAudioRecordingThread",
      "CaptureThread", "Chrome_WebSocketproxyThread", "ProcessWatcherThread",
      "Chrome_CameraThread", "import_thread", "NaCl_IOThread",
      "Chrome_CloudPrintJobPrintThread", "Chrome_CloudPrintProxyCoreThread",
      "DaemonControllerFileIO", "ChromotingMainThread",
      "ChromotingEncodeThread", "ChromotingDesktopThread", "ChromotingIOThread",
      "ChromotingFileIOThread", "Chrome_libJingle_WorkerThread",
      "Chrome_ChildIOThread", "GLHelperThread", "RemotingHostPlugin",
      // "PAC thread #%d",  // not easy to check because of "%d"
      "Chrome_DBThread", "Chrome_WebKitThread", "Chrome_FileThread",
      "Chrome_FileUserBlockingThread", "Chrome_ProcessLauncherThread",
      "Chrome_CacheThread", "Chrome_IOThread", "Cache Thread", "File Thread",
      "ServiceProcess_IO", "ServiceProcess_File", "extension_crash_uploader",
      "gpu-process_crash_uploader", "plugin_crash_uploader",
      "renderer_crash_uploader",
      // These come from the use of webkit_glue::WebThreadImpl
      "Compositor", "Browser Compositor",
      // "WorkerPool/%d",  // not easy to check because of "%d"
      // These come from the use of base::Watchdog
      "Startup watchdog thread Watchdog", "Shutdown watchdog thread Watchdog",
      // These come from the use of AudioDeviceThread::Start
      "AudioDevice", "AudioInputDevice", "AudioOutputDevice",
      // These come from the use of MessageLoopFactory::GetMessageLoop
      "GpuVideoDecoder", "RtcVideoDecoderThread", "PipelineThread",
      "AudioDecoderThread", "VideoDecoderThread",
      // These come from the use of MessageLoopFactory::GetMessageLoopProxy
      "CaptureVideoDecoderThread", "CaptureVideoDecoder",
      // These come from the use of base::SimpleThread
      "LocalInputMonitor/%d",  // "%d" gets lopped off for kernel-supplied
      // These come from the use of base::DelegateSimpleThread
      "ipc_channel_nacl reader thread/%d", "plugin_audio_input_thread/%d",
      "plugin_audio_thread/%d",
      // These come from the use of base::SequencedWorkerPool
      "BrowserBlockingWorker%d/%d",  // "%d" gets lopped off for kernel-supplied
  };
  static std::unordered_set<std::string> chrome_names;

  // Initialize a set of chrome names, for efficient lookup
  if (chrome_names.empty()) {
    for (std::string check_name : kChromeNames) {
      chrome_names.insert(check_name);
      chrome_names.insert(ExecNameToSuppliedName(check_name));
    }
  }

  return base::Contains(chrome_names, exec);
}

}  // namespace
