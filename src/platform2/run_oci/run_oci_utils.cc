// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "run_oci/run_oci_utils.h"

#include <fcntl.h>
#include <mntent.h>
#include <stdio.h>
#include <sys/capability.h>
#include <sys/epoll.h>
#include <sys/mount.h>
#include <sys/signal.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <iterator>
#include <string>
#include <tuple>
#include <type_traits>
#include <utility>

#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/strings/string_piece.h>
#include <base/strings/string_split.h>
#include <base/strings/string_util.h>
#include <brillo/key_value_store.h>
#include <brillo/syslog_logging.h>
#include <libminijail.h>
#include <libmount/libmount.h>

// Avoid including syslog.h because it interacts badly with base::logging.
extern "C" void syslog(int priority, const char* format, ...);

namespace run_oci {

namespace {

// We avoid using LOG_* because they interacts badly with base::logging, which
// re-defines LOG_* and causes all sorts of confusion.
constexpr int kSyslogLogWarningPriority = 4;
constexpr int kSyslogLogInfoPriority = 6;

// Creates a pipe where the read end of it is made to be close-on-exec and the
// write end of it is associated with one of the well-known stdio FDs (e.g.
// STDOUT_FILENO/STDERR_FILENO).
bool CreateStdioPipe(base::ScopedFD* pipe_read_fd, int stdio_fd) {
  base::ScopedFD pipe_write_fd;

  if (!Pipe(pipe_read_fd, &pipe_write_fd, O_CLOEXEC)) {
    PLOG(ERROR) << "Failed to create pipe for " << stdio_fd;
    return false;
  }

  if (pipe_write_fd.get() == stdio_fd) {
    // The write fd is already the correct fd number, but it needs to have the
    // close-on-exec flag cleared.
    if (fcntl(pipe_write_fd.get(), F_SETFD, 0) == -1) {
      PLOG(ERROR) << "Failed to set FD_CLOEXEC on read end of pipe for "
                  << stdio_fd;
      return false;
    }
    // Finally, release it so that it is not closed upon returning.
    std::ignore = pipe_write_fd.release();
  } else {
    if (dup2(pipe_write_fd.get(), stdio_fd) == -1) {
      PLOG(ERROR) << "Failed to redirect stdio for " << stdio_fd;
      return false;
    }
  }

  return true;
}

bool IsTestImage() {
  brillo::KeyValueStore store;
  std::string channel;
  if (!store.Load(base::FilePath("/etc/lsb-release"))) {
    LOG(WARNING) << "Failed to parse /etc/lsb-release, assuming non-test image";
    return false;
  }

  if (!store.GetString("CHROMEOS_RELEASE_TRACK", &channel)) {
    LOG(WARNING) << "Couldn't find release track an /etc/lsb-release, assuming "
                    "non-test image";
    return false;
  }

  return base::StartsWith(channel, "test", base::CompareCase::SENSITIVE);
}

}  // namespace

SyslogStdioAdapter::SyslogStdioAdapter(base::Process child)
    : child_(std::move(child)) {}

SyslogStdioAdapter::~SyslogStdioAdapter() {
  if (!child_.Terminate(0 /* exit_code */, true /* wait */))
    LOG(ERROR) << "Failed to terminate logger process";
}

std::unique_ptr<SyslogStdioAdapter> SyslogStdioAdapter::Create() {
  base::ScopedFD stdout_pipe_read_fd, stderr_pipe_read_fd;

  if (!CreateStdioPipe(&stdout_pipe_read_fd, STDOUT_FILENO))
    return nullptr;
  if (!CreateStdioPipe(&stderr_pipe_read_fd, STDERR_FILENO))
    return nullptr;

  // Redirect all minijail logs to avoid them appearing in multiple places.
  minijail_log_to_fd(STDOUT_FILENO, kSyslogLogInfoPriority);

  brillo::SetLogFlags(brillo::kLogToSyslog | brillo::kLogHeader);
  logging::SetLogItems(false /* pid */, false /* tid */, false /* timestamp */,
                       false /* tick_count */);

  pid_t child = fork();
  if (child == -1) {
    PLOG(ERROR) << "Failed to fork";
    return nullptr;
  }

  if (child == 0) {
    close(STDOUT_FILENO);
    close(STDERR_FILENO);
    SyslogStdioAdapter::RunLoop(std::move(stdout_pipe_read_fd),
                                std::move(stderr_pipe_read_fd));
    _exit(1);
  }

  return std::unique_ptr<SyslogStdioAdapter>(
      new SyslogStdioAdapter(base::Process(child)));
}

// static
void SyslogStdioAdapter::RunLoop(base::ScopedFD stdout_fd,
                                 base::ScopedFD stderr_fd) {
  base::ScopedFD epollfd(epoll_create(1 /*arbitrary, ignored by kernel*/));
  if (!epollfd.is_valid()) {
    PLOG(ERROR) << "Failed to open epoll fd";
    return;
  }

  struct EpollDescriptor {
    base::ScopedFD* fd;
    const char* name;
    int priority;
  } epoll_descriptors[2] = {{&stdout_fd, "stdout", kSyslogLogInfoPriority},
                            {&stderr_fd, "stderr", kSyslogLogWarningPriority}};
  for (auto& descriptor : epoll_descriptors) {
    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.ptr = &descriptor;
    if (epoll_ctl(epollfd.get(), EPOLL_CTL_ADD, descriptor.fd->get(), &ev) ==
        -1) {
      PLOG(ERROR) << "Failed to register " << descriptor.name;
      return;
    }
  }

  char buffer[4096];
  struct epoll_event events[std::size(epoll_descriptors)];
  while (true) {
    int nfds =
        HANDLE_EINTR(epoll_wait(epollfd.get(), events, std::size(events), -1));
    if (nfds == -1) {
      PLOG(ERROR) << "Failed to epoll_wait";
      return;
    }

    for (int i = 0; i < nfds; i++) {
      EpollDescriptor* descriptor =
          reinterpret_cast<EpollDescriptor*>(events[i].data.ptr);
      ssize_t bytes =
          HANDLE_EINTR(read(descriptor->fd->get(), buffer, sizeof(buffer)));
      if (bytes <= 0) {
        PLOG(ERROR) << "Failed to read from " << descriptor->name;
        epoll_ctl(epollfd.get(), EPOLL_CTL_DEL, descriptor->fd->get(), nullptr);
        descriptor->fd->reset();
        continue;
      }
      if (bytes == 0) {
        LOG(ERROR) << descriptor->name << " was closed";
        epoll_ctl(epollfd.get(), EPOLL_CTL_DEL, descriptor->fd->get(), nullptr);
        descriptor->fd->reset();
        continue;
      }

      // This assumes that the writer's output is buffered and flushed on a
      // line-by-line basis. This is true in practice and requires much simpler
      // code, but may lead to lines that straddle a buffer size or partial
      // lines that are output using raw write(2) syscalls being split across
      // two read(2) syscalls.
      base::StringPiece lines(buffer, bytes);
      for (const auto& line : base::SplitString(
               lines, "\n", base::KEEP_WHITESPACE, base::SPLIT_WANT_NONEMPTY)) {
        syslog(descriptor->priority, "[%s] %s", descriptor->name, line.data());
      }
    }
  }
}

bool Mountpoint::operator==(const Mountpoint& other) const {
  return path == other.path && mountflags == other.mountflags &&
         data_string == other.data_string;
}

std::string ParseMountOptions(const std::vector<std::string>& options,
                              int* mount_flags_out,
                              int* negated_mount_flags_out,
                              int* bind_flags_out,
                              int* mount_propagation_flags_out,
                              bool* loopback_out,
                              std::string* verity_options) {
  std::string option_string_out;
  *mount_flags_out = 0;
  *negated_mount_flags_out = 0;
  *bind_flags_out = 0;
  *mount_propagation_flags_out = 0;
  *loopback_out = false;

  const struct libmnt_optmap* linux_option_map =
      mnt_get_builtin_optmap(MNT_LINUX_MAP);

  constexpr int kMountPropagationFlagsMask =
      MS_PRIVATE | MS_SLAVE | MS_SHARED | MS_UNBINDABLE;

  for (const auto& option : options) {
    const struct libmnt_optmap* map_entry = nullptr;

    for (const struct libmnt_optmap* it = linux_option_map; it->name; ++it) {
      if (option == it->name && it->id) {
        map_entry = it;
        break;
      }
    }

    if (map_entry) {
      // This is a known flag name.
      if (map_entry->id & MS_BIND) {
        *bind_flags_out |= map_entry->id;
      } else if (map_entry->id & kMountPropagationFlagsMask) {
        *mount_propagation_flags_out |= map_entry->id;
      } else if (map_entry->mask & MNT_INVERT) {
        *negated_mount_flags_out |= map_entry->id;
      } else {
        *mount_flags_out |= map_entry->id;
      }
    } else if (option == "loop") {
      *loopback_out = true;
    } else if (base::StartsWith(option, "dm=", base::CompareCase::SENSITIVE)) {
      *verity_options = option.substr(3, std::string::npos);
    } else {
      // Unknown options get appended to the string passed to mount data.
      if (!option_string_out.empty())
        option_string_out += ",";
      option_string_out += option;
    }
  }

  return option_string_out;
}

std::vector<Mountpoint> GetMountpointsUnder(
    const base::FilePath& root, const base::FilePath& procSelfMountsPath) {
  base::ScopedFILE mountinfo(fopen(procSelfMountsPath.value().c_str(), "r"));
  if (!mountinfo) {
    PLOG(ERROR) << "Failed to open " << procSelfMountsPath.value();
    return std::vector<Mountpoint>();
  }

  struct mntent mount_entry;

  std::string line;
  char buffer[1024];
  std::vector<Mountpoint> mountpoints;
  while (getmntent_r(mountinfo.get(), &mount_entry, buffer, sizeof(buffer))) {
    // Only return paths that are under |root|.
    const std::string path = mount_entry.mnt_dir;
    if (path.compare(0, root.value().size(), root.value()) != 0)
      continue;

    int mount_flags, negated_mount_flags, bind_mount_flags,
        mount_propagation_flags;
    bool loopback;
    std::string verity_options;
    std::string options = ParseMountOptions(
        base::SplitString(mount_entry.mnt_opts, ",", base::TRIM_WHITESPACE,
                          base::SPLIT_WANT_NONEMPTY),
        &mount_flags, &negated_mount_flags, &bind_mount_flags,
        &mount_propagation_flags, &loopback, &verity_options);
    mountpoints.emplace_back(
        Mountpoint{base::FilePath(path), mount_flags, options});
  }

  return mountpoints;
}

bool HasCapSysAdmin() {
  if (!CAP_IS_SUPPORTED(CAP_SYS_ADMIN))
    return false;

  std::unique_ptr<std::remove_pointer_t<cap_t>, decltype(&cap_free)> caps(
      cap_get_proc(), &cap_free);
  if (!caps) {
    PLOG(ERROR) << "Failed to get process' capabilities";
    return false;
  }

  cap_flag_value_t cap_value;
  if (cap_get_flag(caps.get(), CAP_SYS_ADMIN, CAP_EFFECTIVE, &cap_value) != 0) {
    PLOG(ERROR) << "Failed to get the value of CAP_SYS_ADMIN";
    return false;
  }
  return cap_value == CAP_SET;
}

bool RedirectLoggingAndStdio(const base::FilePath& log_file) {
  base::ScopedFD log_fd(HANDLE_EINTR(
      open(log_file.value().c_str(), O_CREAT | O_WRONLY | O_APPEND, 0644)));
  if (!log_fd.is_valid()) {
    PLOG(ERROR) << "Failed to open log file '" << log_file.value() << "'";
    return false;
  }
  // Redirecting stdout/stderr for the hooks' benefit.
  if (dup2(log_fd.get(), STDOUT_FILENO) == -1) {
    PLOG(ERROR) << "Failed to redirect stdout";
    return false;
  }
  if (dup2(log_fd.get(), STDERR_FILENO) == -1) {
    PLOG(ERROR) << "Failed to redirect stderr";
    return false;
  }
  // Redirect all minijail logs to make them easier to find.
  minijail_log_to_fd(STDERR_FILENO, kSyslogLogInfoPriority);

  brillo::SetLogFlags(brillo::kLogHeader | brillo::kLogToStderr);
  logging::SetLogItems(true /* pid */, false /* tid */, true /* timestamp */,
                       false /* tick_count */);
  return true;
}

bool Pipe(base::ScopedFD* read_fd, base::ScopedFD* write_fd, int flags) {
  int pipe_fds[2];
  if (HANDLE_EINTR(pipe2(pipe_fds, flags)) != 0)
    return false;
  read_fd->reset(pipe_fds[0]);
  write_fd->reset(pipe_fds[1]);
  return true;
}

brillo::SafeFD OpenOciConfigSafelyInternal(const base::FilePath& config_path,
                                           bool enable_noexec_check) {
  brillo::SafeFD::SafeFDResult result(
      brillo::SafeFD::Root().first.OpenExistingFile(config_path,
                                                    O_RDONLY | O_CLOEXEC));
  if (brillo::SafeFD::IsError(result.second)) {
    LOG(ERROR) << "Failed to open " << config_path.value() << " with error "
               << static_cast<int>(result.second);
    return brillo::SafeFD();
  }

  brillo::SafeFD fd(std::move(result.first));
  struct statvfs buf;
  if (HANDLE_EINTR(fstatvfs(fd.get(), &buf)) < 0) {
    PLOG(ERROR) << "Failed to statvfs container config: "
                << config_path.value();
    return brillo::SafeFD();
  }

  if (enable_noexec_check && (buf.f_flag & ST_NOEXEC)) {
    LOG(ERROR) << config_path.value() << " is on a noexec filesystem";
    errno = EPERM;
    return brillo::SafeFD();
  }
  return fd;
}

brillo::SafeFD OpenOciConfigSafely(const base::FilePath& config_path) {
  // Don't check the flag on a test image. security.RunOCI relies on configs on
  // a writable partition.
  return OpenOciConfigSafelyInternal(config_path,
                                     !IsTestImage() /* enable_noexec_check */);
}

brillo::SafeFD OpenOciConfigSafelyForTest(const base::FilePath& config_path,
                                          bool enable_noexec_check) {
  return OpenOciConfigSafelyInternal(config_path, enable_noexec_check);
}

}  // namespace run_oci
