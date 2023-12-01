// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "crash-reporter/crash_collector.h"

#include <dirent.h>
#include <fcntl.h>  // For file creation modes.
#include <inttypes.h>
#include <linux/limits.h>  // PATH_MAX
#include <sys/mman.h>      // for memfd_create
#include <sys/types.h>     // for mode_t and gid_t.
#include <sys/utsname.h>   // For uname.
#include <sys/wait.h>      // For waitpid.
#include <unistd.h>        // For execv and fork.

#include <ctime>
#include <map>
#include <optional>
#include <set>
#include <utility>
#include <vector>

#include <base/check.h>
#include <base/check_op.h>
#include <base/files/file_enumerator.h>
#include <base/files/file_util.h>
#include <base/files/scoped_file.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/notreached.h>
#include <base/posix/eintr_wrapper.h>
#include <base/ranges/algorithm.h>
#include <base/rand_util.h>
#include <base/run_loop.h>
#include <base/scoped_clear_last_error.h>
#include <base/strings/strcat.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_split.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>
#include <base/task/single_thread_task_runner.h>
#include <brillo/key_value_store.h>
#include <brillo/process/process.h>
#include <brillo/syslog_logging.h>
#include <brillo/userdb_utils.h>
#include <debugd/dbus-constants.h>
#include <policy/device_policy_impl.h>
#include <re2/re2.h>
#include <redaction_tool/redaction_tool.h>
#include <zlib.h>

#include "base/files/file_path.h"
#include "crash-reporter/constants.h"
#include "crash-reporter/paths.h"
#include "crash-reporter/util.h"

namespace {

const char kCollectChromeFile[] =
    "/mnt/stateful_partition/etc/collect_chrome_crashes";
const char kDefaultLogConfig[] = "/etc/crash_reporter_logs.conf";
const char kDefaultUserName[] = "chronos";
const char kShellPath[] = "/bin/sh";
const char kCollectorNameKey[] = "collector";
const char kDaemonStoreKey[] = "using_daemon_store";
const char kEarlyCrashKey[] = "is_early_boot";
const char kChannelKey[] = "channel";
// These should be kept in sync with variations::kNumExperimentsKey and
// variations::kExperimentListKey in the chromium repo.
const char kVariationsKey[] = "variations";
const char kNumExperimentsKey[] = "num-experiments";
// Arbitrarily say we won't accept more than 1MiB for the variations file
const int64_t kArbitraryMaxVariationsSize = 1 << 20;

// Key of the lsb-release entry containing the OS version.
const char kLsbOsVersionKey[] = "CHROMEOS_RELEASE_VERSION";

// Key of the lsb-release entry containing the OS milestone.
const char kLsbOsMilestoneKey[] = "CHROMEOS_RELEASE_CHROME_MILESTONE";

// Key of the lsb-release entry containing the OS description.
const char kLsbOsDescriptionKey[] = "CHROMEOS_RELEASE_DESCRIPTION";

// Key of the lsb-release entry containing the channel.
const char kLsbChannelKey[] = "CHROMEOS_RELEASE_TRACK";

// Environment variable set by minijail that includes the path to a seccomp
// policy if one is defined.
constexpr char kEnvSeccompPolicyPath[] = "SECCOMP_POLICY_PATH=";

#if !USE_KVM_GUEST
// Directory mode of the user crash spool directory.
// This is SGID so that files created in it are also accessible to the group.
const mode_t kUserCrashPathMode = 02770;

// Directory mode of the daemon store spool directory.  This has the sticky bit
// set to prevent different crash collectors from messing with each others
// files.
const mode_t kDaemonStoreCrashPathMode = 03770;
#endif

// Directory mode of the system crash spool directory.
// This is SGID so that files created in it are also accessible to the group.
const mode_t kSystemCrashDirectoryMode = 02770;

// Directory mode of the run time state directory.
// Since we place flag files in here for checking by tests, we make it readable.
constexpr mode_t kSystemRunStateDirectoryMode = 0755;

// Directory mode of /var/lib/crash_reporter.
constexpr mode_t kCrashReporterStateDirectoryMode = 0700;

constexpr gid_t kRootGroup = 0;

// Directory mode of /run/metrics/external/crash-reporter. Anyone in "metrics"
// group can read/write, and not readable by any other user.
constexpr mode_t kSystemRunMetricsFlagMode = 0770;

// Buffer size for reading a log into memory.
constexpr size_t kMaxLogSize = 1024 * 1024;

// Limit how many processes we walk back up.  This avoids any possible races
// and loops, and we probably don't need that many in the first place.
constexpr size_t kMaxParentProcessLogs = 8;

const char kCollectionErrorSignature[] = "crash_reporter-user-collection";

#define NCG(x) "(?:" x ")"
#define OPT_NCG(x) NCG(x) "?"
#define DEC_OCTET NCG("1[0-9][0-9]|2[0-4][0-9]|25[0-5]|[1-9][0-9]|[0-9]")
#define IPV4ADDRESS DEC_OCTET "\\." DEC_OCTET "\\." DEC_OCTET "\\." DEC_OCTET
#define HEXDIG "[0-9a-f]"
#define H16 NCG(HEXDIG) "{1,4}"
#define LS32 NCG(H16 ":" H16 "|" IPV4ADDRESS)
#define WB "\\b"
// clang-format off
#define IPV6ADDRESS "(?i)(" NCG( \
                                          WB NCG(H16 ":") "{6}" LS32 WB "|" \
                                        "::" NCG(H16 ":") "{5}" LS32 WB "|" \
  /* NOLINTNEXTLINE(whitespace/parens) */ \
  OPT_NCG( WB                      H16) "::" NCG(H16 ":") "{4}" LS32 WB "|" \
  /* NOLINTNEXTLINE(whitespace/parens) */ \
  OPT_NCG( WB NCG(H16 ":") "{0,1}" H16) "::" NCG(H16 ":") "{3}" LS32 WB "|" \
  /* NOLINTNEXTLINE(whitespace/parens) */ \
  OPT_NCG( WB NCG(H16 ":") "{0,2}" H16) "::" NCG(H16 ":") "{2}" LS32 WB "|" \
  /* NOLINTNEXTLINE(whitespace/parens) */ \
  OPT_NCG( WB NCG(H16 ":") "{0,3}" H16) "::" NCG(H16 ":")       LS32 WB "|" \
  /* NOLINTNEXTLINE(whitespace/parens) */ \
  OPT_NCG( WB NCG(H16 ":") "{0,4}" H16) "::"                    LS32 WB "|" \
  /* NOLINTNEXTLINE(whitespace/parens) */ \
  OPT_NCG( WB NCG(H16 ":") "{0,5}" H16) "::"                    H16  WB "|" \
  /* NOLINTNEXTLINE(whitespace/parens) */ \
  OPT_NCG( WB NCG(H16 ":") "{0,6}" H16) "::") ")"
// clang-format on

}  // namespace

const char* const CrashCollector::kUnknownValue = "unknown";

// Maximum crash reports per crash spool directory.  Note that this is
// a separate maximum from the maximum rate at which we upload these
// diagnostics.  The higher this rate is, the more space we allow for
// core files, minidumps, and kcrash logs, and equivalently the more
// processor and I/O bandwidth we dedicate to handling these crashes when
// many occur at once.  Also note that if core files are configured to
// be left on the file system, we stop adding crashes when either the
// number of core files or minidumps reaches this number.
const int CrashCollector::kMaxCrashDirectorySize = 32;

// metrics user for creating /run/metrics/external/crash-reporter.
constexpr char kMetricsUserName[] = "metrics";

// metrics group for creating /run/metrics/external/crash-reporter.
constexpr char kMetricsGroupName[] = "metrics";

// CrosEventEnum for crash reports.
constexpr char kReportCountEnum[] = "Crash.Collector.CollectionCount";

using base::FileEnumerator;
using base::FilePath;
using base::StringPrintf;

bool ValidatePathAndOpen(const FilePath& dir, int* outfd) {
  std::vector<std::string> components = dir.GetComponents();
  int parentfd = AT_FDCWD;

  for (const auto& component : components) {
    int dirfd = openat(parentfd, component.c_str(),
                       O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW | O_PATH);
    if (dirfd < 0) {
      PLOG(ERROR) << "Unable to access crash path: " << dir.value() << " ("
                  << component << ")";
      if (parentfd != AT_FDCWD)
        close(parentfd);
      return false;
    }
    if (parentfd != AT_FDCWD)
      close(parentfd);
    parentfd = dirfd;
  }
  *outfd = parentfd;
  return true;
}

void ExtractEnvironmentVars(const std::string& contents,
                            std::ostringstream* stream) {
  // SplitString is used instead of base::SplitStringIntoKeyValuePairs because
  // base::SplitStringIntoKeyValuePairs fails when there are two delimiters in
  // a row which happens in practice.
  std::vector<std::string> environ =
      SplitString(contents, std::string(1, '\0'), base::TRIM_WHITESPACE,
                  base::SPLIT_WANT_NONEMPTY);
  for (const std::string& line : environ) {
    if (base::StartsWith(line, kEnvSeccompPolicyPath)) {
      *stream << line << std::endl;
      break;
    }
  }
}

// Create a directory using the specified mode/user/group, and make sure it
// is actually a directory with the specified permissions.
// static
bool CrashCollector::CreateDirectoryWithSettings(const FilePath& dir,
                                                 mode_t mode,
                                                 uid_t owner,
                                                 gid_t group,
                                                 int* dirfd_out,
                                                 mode_t files_mode) {
  const FilePath parent_dir = dir.DirName();
  const FilePath final_dir = dir.BaseName();

  int parentfd;
  if (!ValidatePathAndOpen(parent_dir, &parentfd)) {
    return false;
  }

  // Now handle the final part of the crash dir.  This one we can initialize.
  // Note: We omit O_CLOEXEC on purpose as children will use it.
  const char* final_dir_str = final_dir.value().c_str();
  int dirfd =
      openat(parentfd, final_dir_str, O_DIRECTORY | O_NOFOLLOW | O_RDONLY);
  if (dirfd < 0) {
    if (errno != ENOENT) {
      // Delete whatever is there.
      if (unlinkat(parentfd, final_dir_str, 0) < 0) {
        PLOG(ERROR) << "Unable to clean up crash path: " << dir.value();
        close(parentfd);
        return false;
      }
    }

    // It doesn't exist, so create it!  We'll recheck the mode below.
    if (mkdirat(parentfd, final_dir_str, mode) < 0) {
      if (errno != EEXIST) {
        PLOG(ERROR) << "Unable to create crash directory: " << dir.value();
        close(parentfd);
        return false;
      }
    }

    // Try once more before we give up.
    // Note: We omit O_CLOEXEC on purpose as children will use it.
    dirfd =
        openat(parentfd, final_dir_str, O_DIRECTORY | O_NOFOLLOW | O_RDONLY);
    if (dirfd < 0) {
      PLOG(ERROR) << "Unable to open crash directory: " << dir.value();
      close(parentfd);
      return false;
    }
  }
  close(parentfd);

  // Make sure the ownership/permissions are correct in case they got reset.
  // We stat it to avoid pointless metadata updates in the common case.
  struct stat st;
  if (fstat(dirfd, &st) < 0) {
    PLOG(ERROR) << "Unable to stat crash path: " << dir.value();
    close(dirfd);
    return false;
  }

  // Change the ownership before we change the mode.
  if (st.st_uid != owner || st.st_gid != group) {
    if (fchown(dirfd, owner, group)) {
      PLOG(ERROR) << "Unable to chown crash directory: " << dir.value();
      close(dirfd);
      return false;
    }
  }

  // Update the mode bits.
  if ((st.st_mode & 07777) != mode) {
    if (fchmod(dirfd, mode)) {
      PLOG(ERROR) << "Unable to chmod crash directory: " << dir.value();
      close(dirfd);
      return false;
    }
  }

  if (files_mode) {
    FileEnumerator files(dir, /*recursive=*/true,
                         FileEnumerator::FILES | FileEnumerator::DIRECTORIES |
                             FileEnumerator::SHOW_SYM_LINKS);
    for (FilePath name = files.Next(); !name.empty(); name = files.Next()) {
      const base::stat_wrapper_t st = files.GetInfo().stat();
      const FilePath subdir_path = name.DirName();
      const FilePath file = name.BaseName();

      mode_t desired_mode = files.GetInfo().IsDirectory() ? mode : files_mode;

      if (st.st_uid != owner || st.st_gid != group ||
          (st.st_mode & 07777) != desired_mode) {
        // Something needs to change, so open the file.
        int subdir_fd;
        if (subdir_path == dir) {
          subdir_fd = dirfd;
        } else {
          if (!ValidatePathAndOpen(subdir_path, &subdir_fd)) {
            close(dirfd);
            return false;
          }
        }

        int file_fd =
            openat(subdir_fd, file.value().c_str(), O_NOFOLLOW | O_RDONLY);
        if (file_fd < 0) {
          PLOG(ERROR) << "Unable to open subfile: " << name.value();
          if (subdir_fd != dirfd) {
            close(subdir_fd);
          }
          close(dirfd);
          return false;
        }

        if (subdir_fd != dirfd) {
          close(subdir_fd);
        }

        if (st.st_uid != owner || st.st_gid != group) {
          if (fchown(file_fd, owner, group)) {
            PLOG(ERROR) << "Unable to chown crash file: " << name.value();
            close(file_fd);
            close(dirfd);
            return false;
          }
        }
        if ((st.st_mode & 07777) != desired_mode) {
          if (fchmod(file_fd, desired_mode)) {
            PLOG(ERROR) << "Unable to chmod crash file: " << name.value();
            close(file_fd);
            close(dirfd);
            return false;
          }
        }

        close(file_fd);
      }
    }
  }

  if (dirfd_out)
    *dirfd_out = dirfd;
  else
    close(dirfd);
  return true;
}

bool CarefullyReadFileToStringWithMaxSize(const base::FilePath& path,
                                          int64_t max_size,
                                          std::string* contents) {
  const FilePath parent_dir = path.DirName();
  const FilePath file = path.BaseName();

  int parentfd;
  if (!ValidatePathAndOpen(parent_dir, &parentfd)) {
    LOG(ERROR) << "Failed to open parent dir ";
    return false;
  }
  base::ScopedFD scoped_parentfd(parentfd);
  int fd = HANDLE_EINTR(openat(parentfd, file.value().c_str(),
                               O_RDONLY | O_CLOEXEC | O_NOFOLLOW));
  if (fd < 0) {
    PLOG(ERROR) << "Failed to open " << file.value();
    return false;
  }

  base::File f(fd);
  base::File::Info info;
  if (!f.GetInfo(&info)) {
    PLOG(ERROR) << "Failed to get file info";
    return false;
  }
  int64_t size = info.size;
  if (size > max_size) {
    LOG(ERROR) << path.value() << " is too large (" << size
               << " bytes, wanted at most " << max_size << ")";
    return false;
  }

  std::vector<uint8_t> data(size);
  // Then, read the file in to memory.
  if (!f.ReadAtCurrentPosAndCheck(data)) {
    PLOG(ERROR) << "Failed to read variant file";
    return false;
  }
  contents->append(data.begin(), data.end());

  return true;
}

CrashCollector::CrashCollector(const std::string& collector_name,
                               const std::string& tag)
    : CrashCollector(collector_name,
                     kUseNormalCrashDirectorySelectionMethod,
                     kNormalCrashSendMode,
                     tag) {}

CrashCollector::CrashCollector(
    const std::string& collector_name,
    CrashDirectorySelectionMethod crash_directory_selection_method,
    CrashSendingMode crash_sending_mode,
    const std::string& tag)
    : collector_name_(collector_name),
      lsb_release_(FilePath(paths::kEtcDirectory).Append(paths::kLsbRelease)),
      system_crash_path_(paths::kSystemCrashDirectory),
      crash_reporter_state_path_(paths::kCrashReporterStateDirectory),
      log_config_path_(kDefaultLogConfig),
      max_log_size_(kMaxLogSize),
      device_policy_loaded_(false),
      device_policy_(std::make_unique<policy::DevicePolicyImpl>()),
      crash_directory_selection_method_(crash_directory_selection_method),
      crash_sending_mode_(crash_sending_mode),
      force_daemon_store_(std::nullopt),
      is_finished_(false),
      bytes_written_(0),
      tag_(tag) {
  AddCrashMetaUploadData(kCollectorNameKey, collector_name);
  if (crash_sending_mode_ == kCrashLoopSendingMode) {
    AddCrashMetaUploadData(constants::kCrashLoopModeKey, "true");
  }
  metrics_lib_ = std::make_unique<MetricsLibrary>();
}

CrashCollector::~CrashCollector() {
  if (bus_)
    bus_->ShutdownAndBlock();
}

void CrashCollector::Initialize(bool early) {
  // For early boot crash collectors, /var and /home will not be accessible.
  // Instead, collect the crashes into /run.
  if (early) {
    early_ = true;
    AddCrashMetaUploadData(kEarlyCrashKey, "true");
    system_crash_path_ = base::FilePath(paths::kSystemRunCrashDirectory);
  }
}

bool CrashCollector::TrySetUpDBus() {
  if (bus_)
    return true;

  dbus::Bus::Options options;
  options.bus_type = dbus::Bus::SYSTEM;

  bus_ = new dbus::Bus(options);
  if (!bus_->Connect()) {
    return false;
  }

  session_manager_proxy_.reset(
      new org::chromium::SessionManagerInterfaceProxy(bus_));

  debugd_proxy_.reset(new org::chromium::debugdProxy(bus_));
  return true;
}

void CrashCollector::SetUpDBus() {
  CHECK(TrySetUpDBus());
}

bool CrashCollector::InMemoryFileExists(const base::FilePath& filename) const {
  base::FilePath base_name = filename.BaseName();
  for (const auto& in_memory_file : in_memory_files_) {
    if (std::get<0>(in_memory_file) == base_name.value()) {
      return true;
    }
  }
  return false;
}

base::ScopedFD CrashCollector::GetNewFileHandle(
    const base::FilePath& filename) {
  DCHECK(!is_finished_);
  int fd = -1;
  // Note: Getting the c_str() before calling open or memfd_create ensures that
  // PLOG works correctly -- there won't be intervening standard library calls
  // between the open / memfd_create and PLOG which could overwrite errno.
  std::string filename_string;
  const char* filename_cstr;
  switch (crash_sending_mode_) {
    case kNormalCrashSendMode:
      filename_string = filename.value();
      filename_cstr = filename_string.c_str();
      // The O_NOFOLLOW is redundant with O_CREAT|O_EXCL, but doesn't hurt.
      fd = HANDLE_EINTR(
          open(filename_cstr,
               O_CREAT | O_WRONLY | O_TRUNC | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
               constants::kSystemCrashFilesMode));
      if (fd < 0) {
        PLOG(ERROR) << "Could not open " << filename_cstr;
      }
      break;
    case kCrashLoopSendingMode:
      filename_string = filename.BaseName().value();
      filename_cstr = filename_string.c_str();
      fd = memfd_create(filename_cstr, MFD_CLOEXEC);
      if (fd < 0) {
        PLOG(ERROR) << "Could not memfd_create " << filename_cstr;
      }
      break;
    default:
      NOTREACHED();
  }
  return base::ScopedFD(fd);
}

int CrashCollector::WriteNewFile(const FilePath& filename,
                                 base::StringPiece data) {
  base::ScopedFD fd = GetNewFileHandle(filename);
  if (!fd.is_valid()) {
    PLOG(ERROR) << "WriteNewFile: Cannot open " << filename.value();
    return -1;
  }

  if (!base::WriteFileDescriptor(fd.get(), data)) {
    PLOG(ERROR) << "WriteNewFile: Cannot write " << filename.value();
    base::ScopedClearLastError restore_error;
    fd.reset();
    return -1;
  }

  if (crash_sending_mode_ == kCrashLoopSendingMode) {
    if (InMemoryFileExists(filename)) {
      LOG(ERROR)
          << "Duplicate file names not allowed in crash loop sending mode: "
          << filename.value();
      errno = EEXIST;
      return -1;
    }
    in_memory_files_.emplace_back(filename.BaseName().value(), std::move(fd));
  }

  int size = data.size();
  bytes_written_ += size;
  return size;
}

bool CrashCollector::CopyFdToNewFile(base::ScopedFD source_fd,
                                     const base::FilePath& target_path) {
  base::File source = base::File(std::move(source_fd));
  base::ScopedFD target_fd = GetNewFileHandle(target_path);
  if (!target_fd.is_valid()) {
    return false;
  }
  base::File target = base::File(std::move(target_fd));
  return base::CopyFileContents(source, target);
}

std::optional<int> CrashCollector::CopyFirstNBytesOfFdToNewFile(
    int source_pipe_fd, const base::FilePath& target_path, int bytes_to_copy) {
  int bytes_written = 0;
  base::ScopedFD target_fd = GetNewFileHandle(target_path);
  if (!target_fd.is_valid()) {
    return std::nullopt;
  }

  while (bytes_to_copy > bytes_written) {
    // splice() allows us to ask the kernel to transfer the data directly from
    // the pipe (normally STDIN) to disk, without passing through our userspace.
    // In the best case, this is a zero-copy operation where the kernel just
    // transfers ownership of the memory pages from the input pipe to the
    // output. This is considerably more efficient than having us read the pipe
    // to a buffer and then write the buffer.
    ssize_t res = splice(source_pipe_fd, /*off_in=*/nullptr, target_fd.get(),
                         /*off_out=*/nullptr,
                         /*length=*/bytes_to_copy - bytes_written, /*flags=*/0);
    if (res == 0) {
      // man page: "A return value of 0 means end of input."
      return bytes_written;
    }

    if (res < 0) {
      PLOG(ERROR) << "splice failed: ";
      return std::nullopt;
    }

    bytes_written += res;
  }

  return bytes_written;
}

base::ScopedFD CrashCollector::OpenNewCompressedFileForWriting(
    const base::FilePath& filename, gzFile* compressed_output) {
  DCHECK_EQ(filename.FinalExtension(), ".gz")
      << filename.value() << " must end in .gz";
  base::ScopedFD fd = GetNewFileHandle(filename);
  if (!fd.is_valid()) {
    LOG(ERROR) << "Failed to open " << filename.value();
    return fd;
  }
  // No way to stop gzclose_w from closing the file descriptor, but we need a
  // copy to send to debugd if crash_sending_mode_ == kCrashLoopSendingMode, so
  // duplicate first. We don't *need* a duplicate for kNormalCrashSendMode, but
  // it makes the bytes_written_-updating code easier below, so we duplicate in
  // both crash sending modes.
  base::ScopedFD fd_dup(dup(fd.get()));
  if (!fd_dup.is_valid()) {
    PLOG(ERROR) << "Failed to dup file descriptor";
    return fd_dup;
  }

  *compressed_output = gzdopen(fd.get(), "wba");
  if (*compressed_output == nullptr) {
    LOG(ERROR) << "Failed to gzip " << filename.value();
    return base::ScopedFD();
  }

  // zlib now owns the file descriptor; we must not close it past this point.
  // Note that if gzdopen fails, we are still responsible for closing the file,
  // so we can't just put the release() call inside gzdopen().
  (void)fd.release();

  return fd_dup;
}

bool CrashCollector::WriteCompressedFile(gzFile compressed_output,
                                         const char* data,
                                         size_t bytes) {
  // Allow for partial writes
  ssize_t bytes_written_per_read = 0;
  do {
    int result = gzwrite(compressed_output, &data[bytes_written_per_read],
                         bytes - bytes_written_per_read);
    if (result < 0) {
      int saved_errno = errno;
      int errnum = 0;
      const char* error_msg = gzerror(compressed_output, &errnum);
      if (errnum == Z_ERRNO) {
        LOG(ERROR) << "gzwrite failed with file system error: "
                   << strerror(saved_errno);
      } else {
        LOG(ERROR) << "gzwrite failed: error code " << errnum << ", error msg: "
                   << (error_msg == nullptr ? "None" : error_msg);
      }
      gzclose_w(compressed_output);
      return false;
    }
    bytes_written_per_read += result;
  } while (bytes_written_per_read < bytes);
  return true;
}

bool CrashCollector::CloseCompressedFileAndUpdateStats(
    gzFile compressed_output,
    base::ScopedFD fd_dup,
    const base::FilePath& filename) {
  int result = gzclose_w(compressed_output);
  if (result != Z_OK) {
    LOG(ERROR) << "gzclose_w failed with error code " << result;
    return false;
  }

  struct stat compressed_output_stats;
  if (fstat(fd_dup.get(), &compressed_output_stats) < 0) {
    PLOG(WARNING) << "Failed to fstat compressed file";
    // Make sure st_size is set so we don't add junk to bytes_written.
    compressed_output_stats.st_size = 0;
  }

  if (crash_sending_mode_ == kCrashLoopSendingMode) {
    if (InMemoryFileExists(filename)) {
      LOG(ERROR)
          << "Duplicate file names not allowed in crash loop sending mode: "
          << filename.value();
      return false;
    }
    in_memory_files_.emplace_back(filename.BaseName().value(),
                                  std::move(fd_dup));
  }
  bytes_written_ += compressed_output_stats.st_size;
  return true;
}

bool CrashCollector::CopyFdToNewCompressedFile(
    base::ScopedFD source_fd, const base::FilePath& target_path) {
  static constexpr size_t kBufferSize = 32768;
  std::vector<char> buffer(kBufferSize);
  base::File source = base::File(std::move(source_fd));
  base::ScopedFD fd_dup;
  gzFile compressed_output;

  fd_dup = OpenNewCompressedFileForWriting(target_path, &compressed_output);
  if (!fd_dup.is_valid())
    return false;

  ssize_t bytes_read;

  do {
    bytes_read = source.ReadAtCurrentPos(buffer.data(), buffer.size());
    if (bytes_read < 0) {
      gzclose_w(compressed_output);
      return false;
    }
    if (!WriteCompressedFile(compressed_output, buffer.data(), bytes_read))
      return false;
  } while (bytes_read > 0);

  return CloseCompressedFileAndUpdateStats(compressed_output, std::move(fd_dup),
                                           target_path);
}

bool CrashCollector::WriteNewCompressedFile(const FilePath& filename,
                                            const char* data,
                                            size_t size) {
  base::ScopedFD fd_dup;
  gzFile compressed_output;

  fd_dup = OpenNewCompressedFileForWriting(filename, &compressed_output);
  if (!fd_dup.is_valid())
    return false;

  if (!WriteCompressedFile(compressed_output, data, size))
    return false;

  return CloseCompressedFileAndUpdateStats(compressed_output, std::move(fd_dup),
                                           filename);
}

bool CrashCollector::RemoveNewFile(const base::FilePath& file_name) {
  switch (crash_sending_mode_) {
    case kNormalCrashSendMode: {
      if (!base::PathExists(file_name)) {
        return false;
      }
      int64_t file_size = 0;
      if (base::GetFileSize(file_name, &file_size)) {
        bytes_written_ -= file_size;
      }
      return base::DeleteFile(file_name);
    }
    case kCrashLoopSendingMode: {
      auto it = base::ranges::find(
          in_memory_files_, file_name.BaseName().value(),
          [](const auto& elem) { return std::get<0>(elem); });
      if (it == in_memory_files_.end()) {
        return false;
      }
      struct stat file_stat;
      if (fstat(std::get<1>(*it).get(), &file_stat) == 0) {
        bytes_written_ -= file_stat.st_size;
      }
      // Resources for memfd_create files are automatically released once
      // the last file descriptor is closed, and this will close what should
      // be the last file descriptor, so we are effectively deleting the
      // file by erasing the vector entry.
      in_memory_files_.erase(it);
      return true;
    }
    default:
      NOTREACHED();
      return false;
  }
}

std::string CrashCollector::Sanitize(const std::string& name) {
  // Make sure the sanitized name does not include any periods.
  // The logic in crash_sender relies on this.
  std::string result = name;
  for (size_t i = 0; i < name.size(); ++i) {
    if (!isalnum(result[i]) && result[i] != '_')
      result[i] = '_';
  }
  return result;
}

void CrashCollector::StripSensitiveData(std::string* contents) {
  redaction::RedactionTool redactor(nullptr);
  *contents = redactor.Redact(*contents);
}

std::string CrashCollector::FormatDumpBasename(const std::string& exec_name,
                                               time_t timestamp,
                                               pid_t pid) {
  struct tm tm;
  gmtime_r(&timestamp, &tm);
  std::string sanitized_exec_name = Sanitize(exec_name);
  // Add a random 5-digit number to reduce the chance of filename collisions.
  int rand = base::RandGenerator(100'000);
  return StringPrintf("%s.%04d%02d%02d.%02d%02d%02d.%05d.%d",
                      sanitized_exec_name.c_str(), tm.tm_year + 1900,
                      tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min,
                      tm.tm_sec, rand, pid);
}

FilePath CrashCollector::GetCrashPath(const FilePath& crash_directory,
                                      const std::string& basename,
                                      const std::string& extension) {
  return crash_directory.Append(
      StringPrintf("%s.%s", basename.c_str(), extension.c_str()));
}

bool CrashCollector::GetUserCrashDirectoriesOld(
    std::vector<FilePath>* directories, bool use_daemon_store) {
  SetUpDBus();
  if (use_daemon_store) {
    return util::GetDaemonStoreCrashDirectories(session_manager_proxy_.get(),
                                                directories);
  } else {
    return util::GetUserCrashDirectories(session_manager_proxy_.get(),
                                         directories);
  }
}

FilePath CrashCollector::GetUserCrashDirectoryOld(bool use_daemon_store) {
  FilePath user_directory = FilePath(paths::kFallbackUserCrashDirectory);
  // When testing, store crashes in the fallback crash directory; otherwise, the
  // test framework can't get to them after logging the user out. We don't so
  // this when using the daemon-store crash directory because crash_reporter
  // won't be able to write to the fallback directory.
  if ((util::IsTestImage() || ShouldHandleChromeCrashes()) &&
      !use_daemon_store) {
    return user_directory;
  }
  // In this multiprofile world, there is no one-specific user dir anymore.
  // Ask the session manager for the active ones, then just run with the
  // first result we get back.
  std::vector<FilePath> directories;
  if (!GetUserCrashDirectoriesOld(&directories, use_daemon_store) ||
      directories.empty()) {
    LOG(ERROR) << "Could not get user crash directories, using default.";
    return user_directory;
  }

  user_directory = directories[0];
  return user_directory;
}

std::optional<FilePath> CrashCollector::GetUserCrashDirectoryNew() {
  if (util::IsTestImage() || ShouldHandleChromeCrashes()) {
    // When testing, store crashes in the fallback crash directory
    // (/var/spool/crash or /home/chronos/crash); otherwise,
    // the test framework can't get to them after logging the user out.
    return std::nullopt;
  }
  // In this multiprofile world, there is no one-specific user dir anymore.
  // Ask the session manager for the active ones, then just run with the
  // first result we get back.
  std::vector<FilePath> directories;
  SetUpDBus();
  if (!util::GetDaemonStoreCrashDirectories(session_manager_proxy_.get(),
                                            &directories) ||
      directories.empty()) {
    LOG(ERROR) << "Could not get user crash directories";
    return std::nullopt;
  }

  return directories[0];
}

bool CrashCollector::UseDaemonStore() {
  if (force_daemon_store_.has_value()) {
    LOG(WARNING) << "force_daemon_store_ is " << force_daemon_store_.value()
                 << ". Returning that.";
    return force_daemon_store_.value();
  }

  if (early_) {
    // When early in boot, daemon-store isn't available, so don't try it.
    return false;
  }
  return true;
}

std::optional<FilePath> CrashCollector::GetCrashDirectoryInfoOld(
    uid_t process_euid,
    uid_t default_user_id,
    mode_t* mode,
    uid_t* directory_owner,
    gid_t* directory_group) {
  // User crashes should go into the cryptohome, since they may contain PII.
  // For system crashes, and crashes in the VM, there may not be a cryptohome
  // mounted, so we use the system crash path.
#if !USE_KVM_GUEST
  if (process_euid == default_user_id ||
      crash_directory_selection_method_ == kAlwaysUseUserCrashDirectory ||
      crash_directory_selection_method_ == kAlwaysUseDaemonStore) {
    if (crash_directory_selection_method_ == kAlwaysUseDaemonStore) {
      *mode = kDaemonStoreCrashPathMode;
      if (!brillo::userdb::GetGroupInfo(constants::kCrashName,
                                        directory_owner)) {
        PLOG(ERROR) << "Couldn't look up user " << constants::kCrashName;
        return std::nullopt;
      }
    } else {
      *mode = kUserCrashPathMode;
      *directory_owner = default_user_id;
    }
    if (!brillo::userdb::GetGroupInfo(constants::kCrashUserGroupName,
                                      directory_group)) {
      PLOG(ERROR) << "Couldn't look up group "
                  << constants::kCrashUserGroupName;
      return std::nullopt;
    }
    return GetUserCrashDirectoryOld(crash_directory_selection_method_ ==
                                    kAlwaysUseDaemonStore);
  }
#endif  // !USE_KVM_GUEST
  *mode = kSystemCrashDirectoryMode;
  *directory_owner = constants::kRootUid;
  if (!brillo::userdb::GetGroupInfo(constants::kCrashGroupName,
                                    directory_group)) {
    PLOG(ERROR) << "Couldn't look up group " << constants::kCrashGroupName;
    return std::nullopt;
  }
  return system_crash_path_;
}

std::optional<FilePath> CrashCollector::GetCrashDirectoryInfoNew(
    uid_t process_euid,
    uid_t default_user_id,
    mode_t* mode,
    uid_t* directory_owner,
    gid_t* directory_group) {
  // Crashes that happen while a user is logged-in should go into the
  // cryptohome, since they may contain PII.
  // For crashes that occur when no one is logged in, or test device
  // crashes:
  // * For user crashes, we use /home/chronos/crash, as the cryptohome is
  //   unavailable and we don't have access to /var/spool/crash.
  // * For system crashes, we use the system crash path.
  // For crashes that occur during integration tests of the crash reporter
  // system itself, we use regular (non-test-device) behavior.
#if USE_KVM_GUEST
  // In the VM, there is no cryptohome or /home/chronos, so we'll fall back to
  // the system crash directory after the #if.
#else
  if (crash_directory_selection_method_ != kAlwaysUseSystemCrashDirectory) {
    *mode = kDaemonStoreCrashPathMode;
    if (!brillo::userdb::GetGroupInfo(constants::kCrashName, directory_owner)) {
      PLOG(ERROR) << "Couldn't look up user " << constants::kCrashName;
      return std::nullopt;
    }
    if (!brillo::userdb::GetGroupInfo(constants::kCrashUserGroupName,
                                      directory_group)) {
      PLOG(ERROR) << "Couldn't look up group "
                  << constants::kCrashUserGroupName;
      return std::nullopt;
    }
    std::optional<FilePath> maybe_path = GetUserCrashDirectoryNew();
    if (maybe_path) {
      return maybe_path;
    }
  }

  if (crash_directory_selection_method_ == kAlwaysUseDaemonStore) {
    LOG(ERROR) << "Using daemon-store failed but daemon-store was required";
    return std::nullopt;
  }

  // Otherwise, we can't use daemon store, so try the fallback directory if
  // appropriate.
  if (process_euid == default_user_id ||
      crash_directory_selection_method_ == kAlwaysUseUserCrashDirectory) {
    if (!brillo::userdb::GetGroupInfo(constants::kCrashUserGroupName,
                                      directory_group)) {
      PLOG(ERROR) << "Couldn't look up group "
                  << constants::kCrashUserGroupName;
      return std::nullopt;
    }
    *mode = kUserCrashPathMode;
    *directory_owner = default_user_id;

    // Fall back to /home/chronos/crash
    return paths::Get(paths::kFallbackUserCrashDirectory);
  }
#endif  // USE_KVM_GUEST
  // Otherwise, no one is logged in and crash_reporter is running as something
  // other than chronos, so fall back to the system directory.
  *mode = kSystemCrashDirectoryMode;
  *directory_owner = constants::kRootUid;
  if (!brillo::userdb::GetGroupInfo(constants::kCrashGroupName,
                                    directory_group)) {
    PLOG(ERROR) << "Couldn't look up group " << constants::kCrashGroupName;
    return std::nullopt;
  }
  return system_crash_path_;
}

bool CrashCollector::GetCreatedCrashDirectoryByEuid(uid_t euid,
                                                    FilePath* crash_directory,
                                                    bool* out_of_capacity) {
  if (out_of_capacity)
    *out_of_capacity = false;

  // In crash loop mode, we don't actually need a crash directory, so don't
  // bother creating one.
  if (crash_sending_mode_ == kCrashLoopSendingMode) {
    crash_directory->clear();
    return true;
  }

  // For testing.
  if (!forced_crash_directory_.empty()) {
    *crash_directory = forced_crash_directory_;
    return true;
  }

  uid_t default_user_id;
  if (!brillo::userdb::GetUserInfo(kDefaultUserName, &default_user_id,
                                   nullptr)) {
    LOG(ERROR) << "Could not find default user info";
    return false;
  }

  mode_t directory_mode;
  uid_t directory_owner;
  gid_t directory_group;
  std::optional<base::FilePath> maybe_path;
  // Roll a die to decide whether to attempt using daemon-store. Even if this
  // comes up as true, we might not use daemon-store (for example if the user is
  // logged out, or we otherwise fail to get the daemon-store directory)
  // TODO(b/186659673): Validate daemon-store usage and always use it.
  if (UseDaemonStore()) {
    AddCrashMetaUploadData(kDaemonStoreKey, "true");
    maybe_path =
        GetCrashDirectoryInfoNew(euid, default_user_id, &directory_mode,
                                 &directory_owner, &directory_group);
  } else {
    AddCrashMetaUploadData(kDaemonStoreKey, "false");
    maybe_path =
        GetCrashDirectoryInfoOld(euid, default_user_id, &directory_mode,
                                 &directory_owner, &directory_group);
  }
  if (!maybe_path) {
    return false;
  }
  base::FilePath full_path = *maybe_path;

  // Note: We "leak" dirfd to children so the /proc symlink below stays valid
  // in their own context.  We can't pass other /proc paths as they might not
  // be accessible in the children (when dropping privs), and we don't want to
  // pass the direct path in the filesystem as it'd be subject to TOCTOU.
  int dirfd;
  if (!CreateDirectoryWithSettings(full_path, directory_mode, directory_owner,
                                   directory_group, &dirfd)) {
    LOG(ERROR) << "CreateDirectory failed";
    return false;
  }

  // Have all the rest of the tools access the directory by file handle.  This
  // avoids any TOCTOU races in case the underlying dir is changed on us.
  const FilePath crash_dir_procfd =
      FilePath("/proc/self/fd").Append(std::to_string(dirfd));
  LOG(INFO) << "Accessing crash dir '" << full_path.value()
            << "' via symlinked handle '" << crash_dir_procfd.value() << "'";

  if (!CheckHasCapacity(crash_dir_procfd, full_path.value())) {
    if (out_of_capacity)
      *out_of_capacity = true;
    return false;
  }

  *crash_directory = crash_dir_procfd;
  return true;
}

// static
FilePath CrashCollector::GetProcessPath(pid_t pid) {
  return paths::Get(StringPrintf("/proc/%d", pid));
}

void CrashCollector::set_current_uptime_for_test(base::TimeDelta uptime) {
  override_uptime_for_testing_ = std::make_unique<base::TimeDelta>(uptime);
}

bool CrashCollector::GetUptime(base::TimeDelta* uptime) {
  if (override_uptime_for_testing_) {
    *uptime = *override_uptime_for_testing_;
    return true;
  }
  timespec boot_time;
  if (clock_gettime(CLOCK_BOOTTIME, &boot_time) != 0) {
    PLOG(ERROR) << "Failed to get boot time.";
    return false;
  }

  *uptime =
      base::Seconds(boot_time.tv_sec) + base::Nanoseconds(boot_time.tv_nsec);
  return true;
}

// static
bool CrashCollector::GetUptimeAtProcessStart(pid_t pid,
                                             base::TimeDelta* uptime) {
  std::string stat;
  if (!base::ReadFileToString(GetProcessPath(pid).Append("stat"), &stat)) {
    PLOG(ERROR) << "Failed to read process status.";
    return false;
  }

  uint64_t ticks;
  if (!ParseProcessTicksFromStat(stat, &ticks)) {
    LOG(ERROR) << "Failed to parse process status: " << stat;
    return false;
  }

  *uptime = base::Seconds(static_cast<double>(ticks) / sysconf(_SC_CLK_TCK));

  return true;
}

bool CrashCollector::GetExecutableBaseNameAndDirectoryFromPid(
    pid_t pid, std::string* base_name, base::FilePath* exec_directory) {
  FilePath target;
  FilePath process_path = GetProcessPath(pid);
  FilePath exe_path = process_path.Append("exe");
  if (!base::ReadSymbolicLink(exe_path, &target)) {
    LOG(INFO) << "ReadSymbolicLink failed - Path " << process_path.value()
              << " DirectoryExists: " << base::DirectoryExists(process_path);
    // Try to further diagnose exe readlink failure cause.
    struct stat buf;
    int stat_result = stat(exe_path.value().c_str(), &buf);
    int saved_errno = errno;
    if (stat_result < 0) {
      LOG(INFO) << "stat " << exe_path.value() << " failed: " << stat_result
                << " " << saved_errno;
    } else {
      LOG(INFO) << "stat " << exe_path.value()
                << " succeeded: st_mode=" << buf.st_mode;
    }
    return false;
  }
  *base_name = target.BaseName().value();
  *exec_directory = target.DirName();
  return true;
}

// Return true if the given crash directory has not already reached
// maximum capacity.
bool CrashCollector::CheckHasCapacity(const FilePath& crash_directory,
                                      const std::string& display_path) {
  DIR* dir = opendir(crash_directory.value().c_str());
  if (!dir) {
    PLOG(ERROR) << "Unable to open directory to check capacity: "
                << crash_directory.value();
    return false;
  }
  struct dirent* ent;
  bool full = false;
  std::set<std::string> basenames;
  // readdir_r is deprecated from glibc and we need to use readdir instead.
  // readdir is safe for glibc because it guarantees readdir is thread safe,
  // and atm we aren't supporting other C libraries
  while ((ent = readdir(dir))) {
    // Only count crash reports.  Ignore all other supplemental files.
    // We define "crash reports" as .meta, .dmp, .js_stack, or .core files.
    // This does mean that we ignore random files that might accumulate but
    // didn't come from us, but not a lot we can do about that.  Our crash
    // sender process should clean up unknown files independently.
    const base::FilePath filename(ent->d_name);
    const std::string ext = filename.FinalExtension();
    if (ext != ".core" && ext != constants::kMinidumpExtensionWithDot &&
        ext != ".meta" && ext != constants::kJavaScriptStackExtensionWithDot)
      continue;

    // Track the basenames as our unique identifiers.  When the core/dmp files
    // are part of a single report, this will count them as one report.
    const std::string basename = filename.RemoveFinalExtension().value();
    basenames.insert(basename);

    if (basenames.size() >= static_cast<size_t>(kMaxCrashDirectorySize)) {
      LOG(WARNING) << "Crash directory " << display_path
                   << " already full with " << kMaxCrashDirectorySize
                   << " pending reports";
      full = true;
      break;
    }
  }
  closedir(dir);
  return !full;
}

bool CrashCollector::CheckHasCapacity(const FilePath& crash_directory) {
  return CheckHasCapacity(crash_directory, crash_directory.value());
}

bool CrashCollector::GetLogContents(const FilePath& config_path,
                                    const std::string& exec_name,
                                    const FilePath& output_file) {
  return GetMultipleLogContents(config_path, {exec_name}, output_file);
}

bool CrashCollector::GetMultipleLogContents(
    const FilePath& config_path,
    const std::vector<std::string>& exec_names,
    const FilePath& output_file) {
  brillo::KeyValueStore store;
  if (!store.Load(config_path)) {
    LOG(WARNING) << "Unable to read log configuration file "
                 << config_path.value();
    return false;
  }

  std::string collated_log_contents;
  for (auto exec_name : exec_names) {
    std::string command;
    if (!store.GetString(exec_name, &command)) {
      LOG(WARNING) << "exec name '" << exec_name << "' not found in log file";
      continue;
    }

    FilePath raw_output_file;
    if (!base::CreateTemporaryFile(&raw_output_file)) {
      PLOG(WARNING) << "Failed to create temporary file for raw log output.";
      continue;
    }

    brillo::ProcessImpl diag_process;
    diag_process.AddArg(kShellPath);
    diag_process.AddStringOption("-c", command);
    diag_process.RedirectOutput(raw_output_file.value());

    const int result = diag_process.Run();

    std::string log_contents;
    const bool fully_read = base::ReadFileToStringWithMaxSize(
        raw_output_file, &log_contents, max_log_size_);
    base::DeleteFile(raw_output_file);

    if (!fully_read) {
      if (log_contents.empty()) {
        LOG(WARNING) << "Failed to read raw log contents.";
        continue;
      }
      // If ReadFileToStringWithMaxSize returned false and log_contents is
      // non-empty, this means the log is larger than max_log_size_.
      LOG(WARNING) << "Log is larger than " << max_log_size_
                   << " bytes. Truncating.";
      log_contents.append("\n<TRUNCATED>\n");
    }

    // If the registered command failed, we include any (partial) output it
    // might have produced to improve crash reports.  But make a note of the
    // failure.
    if (result != 0) {
      const std::string warning = StringPrintf(
          "\nLog command \"%s\" exited with %i\n", command.c_str(), result);
      log_contents.append(warning);
      LOG(WARNING) << warning;
    }

    collated_log_contents.append(log_contents);
  }

  if (collated_log_contents.empty())
    return false;

  return WriteLogContents(collated_log_contents, output_file);
}

bool CrashCollector::WriteLogContents(std::string& log_contents,
                                      const base::FilePath& output_file) {
  // Don't accidentally leak sensitive data.
  StripSensitiveData(&log_contents);

  if (output_file.FinalExtension() == ".gz") {
    if (!WriteNewCompressedFile(output_file, log_contents.data(),
                                log_contents.size())) {
      LOG(WARNING) << "Error writing compressed sanitized log to "
                   << output_file.value();
      return false;
    }
  } else {
    if (WriteNewFile(output_file, log_contents) !=
        static_cast<int>(log_contents.length())) {
      PLOG(WARNING) << "Error writing sanitized log to " << output_file.value();
      return false;
    }
  }

  return true;
}

bool CrashCollector::GetProcessTree(pid_t pid,
                                    const base::FilePath& output_file) {
  std::ostringstream stream;

  // Grab a limited number of parent process details.
  for (size_t depth = 0; depth < kMaxParentProcessLogs; ++depth) {
    std::string contents;

    stream << "### Process " << pid << std::endl;

    const FilePath proc_path = GetProcessPath(pid);
    const FilePath status_path = proc_path.Append("status");

    // Read the command line and append it to the log.
    if (!base::ReadFileToString(proc_path.Append("cmdline"), &contents))
      break;
    base::ReplaceChars(contents, std::string(1, '\0'), " ", &contents);
    stream << "cmdline: " << contents << std::endl;

    // Read the status file and append it to the log.
    if (!base::ReadFileToString(proc_path.Append("status"), &contents))
      break;
    stream << contents;

    // Include values of interest from the environment.
    if (!base::ReadFileToString(proc_path.Append("environ"), &contents))
      break;
    ExtractEnvironmentVars(contents, &stream);
    stream << std::endl;

    // Pull out the parent pid from the status file.  The line will look like:
    // PPid:\t1234
    base::StringPairs pairs;
    if (!base::SplitStringIntoKeyValuePairs(contents, ':', '\n', &pairs))
      break;
    pid = 0;
    for (const auto& key_value : pairs) {
      if (key_value.first == "PPid") {
        std::string value;
        int ppid;

        // Parse the parent pid.  Set it only if it's valid.
        base::TrimWhitespaceASCII(key_value.second, base::TRIM_ALL, &value);
        if (base::StringToInt(value, &ppid))
          pid = ppid;
        break;
      }
    }
    // If we couldn't find the parent pid, break out.
    if (pid == 0)
      break;
  }

  // Always do this after log collection is "finished" so we don't accidentally
  // leak data.
  std::string log = stream.str();
  StripSensitiveData(&log);

  if (WriteNewFile(output_file, log) != static_cast<int>(log.size())) {
    PLOG(WARNING) << "Error writing sanitized PStree to "
                  << output_file.value();
    return false;
  }

  return true;
}

void CrashCollector::AddCrashMetaData(const std::string& key,
                                      const std::string& value) {
  if (key.empty()) {
    LOG(ERROR) << "Cannot use empty key";
    return;
  }

  std::string sanitized_key;
  for (char c : key) {
    if (!(base::IsAsciiAlpha(c) || base::IsAsciiDigit(c) || c == '_' ||
          c == '-' || c == '.')) {
      // Replace invalid characters with '_'
      c = '_';
    }
    sanitized_key.push_back(c);
  }

  std::string sanitized_value;
  for (char c : value) {
    if (c == '\n') {
      // append a literal '\n' to indicate to users that there was a newline
      // here, but do not use an actual newline, since brillo's KeyValueStore
      // parser cannot handle unescaped newlines, and downstream systems might
      // also have trouble with them.
      sanitized_value.append("\\n");
    } else {
      sanitized_value.push_back(c);
    }
  }
  extra_metadata_.append(
      StringPrintf("%s=%s\n", sanitized_key.c_str(), sanitized_value.c_str()));
}

void CrashCollector::AddCrashMetaUploadFile(const std::string& key,
                                            const std::string& path) {
  if (!path.empty()) {
    if (path.find('/') != std::string::npos) {
      LOG(ERROR) << "Upload files must be basenames only: " << path;
      return;
    }
    AddCrashMetaData(constants::kUploadFilePrefix + key, path);
  }
}

void CrashCollector::AddCrashMetaUploadData(const std::string& key,
                                            const std::string& value) {
  if (!value.empty())
    AddCrashMetaData(constants::kUploadVarPrefix + key, value);
}

void CrashCollector::AddCrashMetaUploadText(const std::string& key,
                                            const std::string& path) {
  if (!path.empty()) {
    if (path.find('/') != std::string::npos) {
      LOG(ERROR) << "Upload files must be basenames only: " << path;
      return;
    }
    AddCrashMetaData(constants::kUploadTextPrefix + key, path);
  }
}

std::string CrashCollector::GetLsbReleaseValue(const std::string& key) const {
  std::vector<base::FilePath> directories = {lsb_release_.DirName()};
  if (use_saved_lsb_) {
    directories.insert(directories.begin(), crash_reporter_state_path_);
  }

  std::string value;
  if (util::GetCachedKeyValue(lsb_release_.BaseName(), key, directories,
                              &value)) {
    return value;
  }
  return kUnknownValue;
}

std::string CrashCollector::GetOsVersion() const {
  return GetLsbReleaseValue(kLsbOsVersionKey);
}

std::string CrashCollector::GetOsMilestone() const {
  return GetLsbReleaseValue(kLsbOsMilestoneKey);
}

std::string CrashCollector::GetOsDescription() const {
  return GetLsbReleaseValue(kLsbOsDescriptionKey);
}

std::string CrashCollector::GetChannel() const {
  // gives a string with "-channel" suffix, e.g. "testimage-channel",
  // "stable-channel", "beta-channel", "dev-channel", "canary-channel".
  std::string channel = GetLsbReleaseValue(kLsbChannelKey);

  // strip the "-channel" suffix.
  channel = channel.substr(0, channel.find("-"));

  if (channel == "testimage") {
    return "test";
  }

  return channel;
}

std::string CrashCollector::GetProductVersion() const {
  return GetOsVersion();
}

std::string CrashCollector::GetKernelName() const {
  struct utsname buf;
  if (!test_kernel_name_.empty())
    return test_kernel_name_;

  if (uname(&buf))
    return kUnknownValue;

  return buf.sysname;
}

std::string CrashCollector::GetKernelVersion() const {
  struct utsname buf;
  if (!test_kernel_version_.empty())
    return test_kernel_version_;

  if (uname(&buf))
    return kUnknownValue;

  // 3.8.11 #1 SMP Wed Aug 22 02:18:30 PDT 2018
  return StringPrintf("%s %s", buf.release, buf.version);
}

std::optional<bool> CrashCollector::IsEnterpriseEnrolled() {
  DCHECK(device_policy_);
  if (!device_policy_loaded_) {
    if (!device_policy_->LoadPolicy(/*delete_invalid_files=*/false)) {
      LOG(ERROR) << "Failed to load device policy";
      return std::nullopt;
    }
    device_policy_loaded_ = true;
  }

  return device_policy_->IsEnterpriseEnrolled();
}

// Callback for CallMethodWithErrorCallback(). Discards the response pointer
// and just calls |callback|.
static void IgnoreResponsePointer(base::OnceCallback<void()> callback,
                                  dbus::Response*) {
  std::move(callback).Run();
}

// Error callback for CallMethodWithErrorCallback(). Discards the error pointer
// and just calls |callback|.
static void IgnoreErrorResponsePointer(base::OnceCallback<void()> callback,
                                       dbus::ErrorResponse*) {
  // We set the timeout to 0, so of course we time out before we get a response.
  // 99% of the time, the ErrorResponse is just "NoReply". Don't spam the error
  // log with that information, just discard the error response.
  std::move(callback).Run();
}

// TODO(b/285611845): Add full logic to stub implementation.
CrashCollector::ComputedCrashSeverity CrashCollector::ComputeSeverity(
    const std::string& exec_name) {
  return CrashCollector::ComputedCrashSeverity{
      .crash_severity = CrashSeverity::kUnspecified,
      .product_group = Product::kUnspecified,
  };
}

void CrashCollector::FinishCrash(const FilePath& meta_path,
                                 const std::string& exec_name,
                                 const std::string& payload_name) {
  DCHECK(!is_finished_);

  // All files are relative to the metadata, so reject anything else.
  if (payload_name.find('/') != std::string::npos) {
    LOG(ERROR) << "Upload files must be basenames only: " << payload_name;
    return;
  }

  const FilePath payload_path = meta_path.DirName().Append(payload_name);

  LOG(INFO) << "Finishing crash. Meta file: " << meta_path.value();

  if (!AddVariations()) {
    LOG(ERROR) << "Failed to add variations to report";
  }

  const std::string product_version = GetProductVersion();
  std::string product_version_info =
      StringPrintf("ver=%s\n", product_version.c_str());

  const std::string milestone = GetOsMilestone();
  const std::string description = GetOsDescription();
  // TODO(b/270434087): Use timestamp of old lsb-release?
  base::Time os_timestamp = util::GetOsTimestamp();
  std::string os_timestamp_str;
  if (!os_timestamp.is_null()) {
    os_timestamp_str =
        StringPrintf("os_millis=%" PRId64 "\n",
                     (os_timestamp - base::Time::UnixEpoch()).InMilliseconds());
  }

  // Populate the channel (if not already populated--chrome will first attempt
  // to populate this).
  if (extra_metadata_.find("upload_var_channel") == std::string::npos) {
    AddCrashMetaUploadData(kChannelKey, GetChannel());
  }

  std::string lsb_release_info = StringPrintf(
      "upload_var_lsb-release=%s\n"
      "upload_var_cros_milestone=%s\n"
      "%s",
      description.c_str(), milestone.c_str(), os_timestamp_str.c_str());

  const std::string kernel_name = GetKernelName();
  const std::string kernel_version = GetKernelVersion();
  std::string kernel_info = StringPrintf(
      "upload_var_osName=%s\n"
      "upload_var_osVersion=%s\n",
      kernel_name.c_str(), kernel_version.c_str());

  std::string version_info =
      product_version_info + lsb_release_info + kernel_info;

  std::optional<bool> is_enterprise_enrolled = IsEnterpriseEnrolled();
  if (is_enterprise_enrolled.has_value()) {
    AddCrashMetaUploadData("is-enterprise-enrolled",
                           *is_enterprise_enrolled ? "true" : "false");
  }

  std::string in_progress_test;
  if (base::ReadFileToString(paths::GetAt(paths::kSystemRunStateDirectory,
                                          paths::kInProgressTestName),
                             &in_progress_test)) {
    AddCrashMetaUploadData("in_progress_integration_test", in_progress_test);
  }

  std::string exec_name_line;
  if (!exec_name.empty()) {
    exec_name_line = base::StrCat({"exec_name=", exec_name, "\n"});
  }

  base::Time now = test_clock_ ? test_clock_->Now() : base::Time::Now();
  int64_t now_millis = (now - base::Time::UnixEpoch()).InMilliseconds();
  std::string meta_data =
      StringPrintf("%supload_var_reportTimeMillis=%" PRId64
                   "\n"
                   "%s"
                   "%s"
                   "payload=%s\n"
                   "done=1\n",
                   extra_metadata_.c_str(), now_millis, exec_name_line.c_str(),
                   version_info.c_str(), payload_name.c_str());
  // We must use WriteNewFile instead of base::WriteFile as we
  // do not want to write with root access to a symlink that an attacker
  // might have created.
  if (WriteNewFile(meta_path, meta_data) < 0) {
    PLOG(ERROR) << "Unable to write meta " << meta_path.value();
  }

  // Record report created metric in UMA.
  // TODO(b/270732207): Remove deadlock risk.
  metrics_lib_->SendCrosEventToUMA(kReportCountEnum);

  if (crash_sending_mode_ == kCrashLoopSendingMode) {
    SetUpDBus();

    // We'd like to call debugd_proxy_->UploadSingleCrash here; that seems like
    // the simplest method. However, calling debugd_proxy_->UploadSingleCrash
    // with a timeout of zero will spam the error log with messages about timing
    // out and not receiving a response. Going through
    // CallMethodWithErrorCallback avoids the error messages, but it does mean
    // we need a RunLoop.
    base::RunLoop run_loop;
    auto quit_closure = run_loop.QuitClosure();
    dbus::MethodCall method_call(debugd::kDebugdInterface,
                                 debugd::kUploadSingleCrash);
    dbus::MessageWriter writer(&method_call);

    // Append the file list.
    brillo::dbus_utils::DBusParamWriter::Append(&writer,
                                                std::move(in_memory_files_));
    // Append a true value for `consent_already_checked_by_crash_reporter`.
    brillo::dbus_utils::DBusParamWriter::Append(&writer, true);

    debugd_proxy_->GetObjectProxy()->CallMethodWithErrorCallback(
        &method_call, 0 /*timeout_ms*/,
        base::BindOnce(IgnoreResponsePointer, quit_closure),
        base::BindOnce(IgnoreErrorResponsePointer, quit_closure));
    run_loop.Run();
  }

  is_finished_ = true;
}

bool CrashCollector::ShouldHandleChromeCrashes() {
  // If we're testing crash reporter itself, we don't want to allow an
  // override for chrome crashes.  And, let's be conservative and only
  // allow an override for developer images.
  if (!util::IsCrashTestInProgress() && util::IsDeveloperImage()) {
    // Check if there's an override to indicate we should indeed collect
    // chrome crashes.  This allows the crashes to still be tracked when
    // they occur in integration tests.  See "crosbug.com/17987".
    if (base::PathExists(FilePath(kCollectChromeFile)))
      return true;
  }
  // We default to ignoring chrome crashes.
  return false;
}

bool CrashCollector::InitializeSystemCrashDirectories(bool early) {
  if (!CreateDirectoryWithSettings(FilePath(paths::kSystemRunStateDirectory),
                                   kSystemRunStateDirectoryMode,
                                   constants::kRootUid, kRootGroup, nullptr))
    return false;

  if (early) {
    if (!CreateDirectoryWithSettings(FilePath(paths::kSystemRunCrashDirectory),
                                     kSystemRunStateDirectoryMode,
                                     constants::kRootUid, kRootGroup, nullptr))
      return false;
  } else {
    gid_t directory_group;
    if (!brillo::userdb::GetGroupInfo(constants::kCrashGroupName,
                                      &directory_group)) {
      PLOG(ERROR) << "Group " << constants::kCrashGroupName << " doesn't exist";
      return false;
    }
    if (!CreateDirectoryWithSettings(
            FilePath(paths::kSystemCrashDirectory), kSystemCrashDirectoryMode,
            constants::kRootUid, directory_group, nullptr,
            /*files_mode=*/constants::kSystemCrashFilesMode))
      return false;

    if (!CreateDirectoryWithSettings(
            FilePath(paths::kCrashReporterStateDirectory),
            kCrashReporterStateDirectoryMode, constants::kRootUid, kRootGroup,
            nullptr))
      return false;
  }

  return true;
}

bool CrashCollector::InitializeSystemMetricsDirectories() {
  uid_t metrics_user_id;
  gid_t metrics_group_id;

  if (!brillo::userdb::GetUserInfo(kMetricsUserName, &metrics_user_id,
                                   &metrics_group_id)) {
    PLOG(ERROR) << "Could not find user " << kMetricsUserName;
    return false;
  }

  if (!brillo::userdb::GetGroupInfo(kMetricsGroupName, &metrics_group_id)) {
    PLOG(ERROR) << "Could not find group " << kMetricsGroupName;
    return false;
  }

  FilePath metrics_flag_directory(paths::kSystemRunMetricsFlagDirectory);
  FilePath metrics_external_dir = metrics_flag_directory.DirName();
  FilePath metrics_dir = metrics_external_dir.DirName();

  // Ensure /run/metrics directory exists.
  if (!CreateDirectoryWithSettings(metrics_dir, kSystemRunMetricsFlagMode,
                                   metrics_user_id, metrics_group_id, nullptr))
    return false;

  // Ensure metrics/external exists.
  if (!CreateDirectoryWithSettings(metrics_external_dir,
                                   kSystemRunMetricsFlagMode, metrics_user_id,
                                   metrics_group_id, nullptr))
    return false;

  // Create final crash-reporter flag directory.
  if (!CreateDirectoryWithSettings(metrics_flag_directory,
                                   kSystemRunMetricsFlagMode, metrics_user_id,
                                   metrics_group_id, nullptr))
    return false;

  return true;
}

// static
bool CrashCollector::ParseProcessTicksFromStat(base::StringPiece stat,
                                               uint64_t* ticks) {
  // Skip "pid" and "comm" fields. See format in proc(5).
  const auto pos = stat.find_last_of(')');
  if (pos == base::StringPiece::npos)
    return false;

  stat.remove_prefix(pos + 1);
  const auto fields = base::SplitStringPiece(stat, " ", base::TRIM_WHITESPACE,
                                             base::SPLIT_WANT_NONEMPTY);

  constexpr size_t kStartTimePos = 19;
  return fields.size() > kStartTimePos &&
         base::StringToUint64(fields[kStartTimePos], ticks);
}

bool CrashCollector::AddVariations() {
  std::vector<FilePath> directories;
  if (extra_metadata_.find(kVariationsKey) != std::string::npos) {
    // Don't add variations a second time if something (e.g. chrome) already
    // did.
    return true;
  }

  FilePath home_directory;
  // In this multiprofile world, there is no one-specific user dir anymore.
  // Ask the session manager for the active ones, then just run with the
  // first result we get back.
  if (!TrySetUpDBus() || !session_manager_proxy_ ||
      !util::GetUserHomeDirectories(session_manager_proxy_.get(),
                                    &directories) ||
      directories.empty()) {
    LOG(ERROR) << "Could not get user home directories, using default.";
    home_directory = paths::Get(paths::kFallbackToHomeDir);
  } else {
    home_directory = directories[0];
  }

  std::string contents;
  // TODO(mutexlox): When anomaly-detector invokes crash_reporter it cannot read
  // this file as it's in the user's home dir. Get the info to anomaly-detector
  // some other way.
  base::FilePath to_read = home_directory.Append(paths::kVariationsListFile);
  if (!CarefullyReadFileToStringWithMaxSize(
          to_read, kArbitraryMaxVariationsSize, &contents)) {
    LOG(ERROR) << "Couldn't read " << to_read.value();
    return false;
  }
  // Validate the variations file in case a user overwrote it.
  brillo::KeyValueStore variant_store;
  if (!variant_store.LoadFromString(contents)) {
    LOG(ERROR) << "Failed to load contents " << contents;
    return false;
  }
  std::string num_exp;
  if (!variant_store.GetString(kNumExperimentsKey, &num_exp)) {
    LOG(ERROR) << "Failed to get value for " << kNumExperimentsKey
               << " from contents " << contents;
    return false;
  }
  std::string variations;
  if (!variant_store.GetString(kVariationsKey, &variations)) {
    LOG(ERROR) << "Failed to get value for " << kVariationsKey
               << " from contents " << contents;
    return false;
  }
  AddCrashMetaUploadData(kVariationsKey, variations);
  AddCrashMetaUploadData(kNumExperimentsKey, num_exp);
  return true;
}

void CrashCollector::EnqueueCollectionErrorLog(ErrorType error_type,
                                               const std::string& orig_exec) {
  LOG(INFO) << "Writing conversion problems as separate crash report.";

  const std::string exec = "crash_reporter_failure";
  // We use a distinct basename to avoid having to deal with any possible files
  // that the collector may have started to write before failing.
  const std::string basename =
      FormatDumpBasename(exec, time(nullptr), getpid());

  // Get rid of the existing metadata, since we're now writing info about
  // errors *pertaining to collection* rather than the original program.
  extra_metadata_.clear();
  AddCrashMetaUploadData(kCollectorNameKey, exec);
  // Record the original collector name for analytics purposes. (e.g. to see
  // if one collector fails more often than others.)
  AddCrashMetaUploadData("orig_collector", collector_name_);
  AddCrashMetaUploadData("orig_exec", orig_exec);

  FilePath crash_path;
  if (!GetCreatedCrashDirectoryByEuid(0, &crash_path, nullptr)) {
    LOG(ERROR) << "Could not even get log directory; out of space?";
    return;
  }

  std::string type = GetErrorTypeSignature(error_type);
  AddCrashMetaData("sig", base::StrCat({kCollectionErrorSignature, "_", type}));
  AddCrashMetaData("error_type", type);
  FilePath log_path = GetCrashPath(crash_path, basename, "log");

  std::string error_log = brillo::GetLog();
  // We must use WriteNewFile instead of base::WriteFile as we do
  // not want to write with root access to a symlink that an attacker
  // might have created.
  if (WriteNewFile(log_path, error_log) < 0) {
    LOG(ERROR) << "Error writing new file " << log_path.value();
    return;
  }

  // If we fail to get this log, still try to proceed (the other log could be
  // useful on its own).
  FilePath ps_log_path = GetCrashPath(crash_path, basename, "pslog");
  if (GetLogContents(FilePath(log_config_path_), kCollectionErrorSignature,
                     ps_log_path)) {
    AddCrashMetaUploadFile("pslog", ps_log_path.BaseName().value());
  } else {
    LOG(ERROR) << "Failed getting collection error log contents for "
               << kCollectionErrorSignature;
  }

  FilePath meta_path = GetCrashPath(crash_path, basename, "meta");
  FinishCrash(meta_path, exec, log_path.BaseName().value());
}

void CrashCollector::LogCrash(const std::string& message,
                              const std::string& reason) const {
  LOG(WARNING) << '[' << tag_ << "] " << message << " (" << reason << ')';
}

std::string CrashCollector::GetErrorTypeSignature(ErrorType error_type) const {
  switch (error_type) {
    case kErrorSystemIssue:
      return "system-issue";
    case kErrorReadCoreData:
      return "read-core-data";
    case kErrorUnusableProcFiles:
      return "unusable-proc-files";
    case kErrorInvalidCoreFile:
      return "invalid-core-file";
    case kErrorUnsupported32BitCoreFile:
      return "unsupported-32bit-core-file";
    case kErrorCore2MinidumpConversion:
      return "core2md-conversion";
    default:
      return "";
  }
}
