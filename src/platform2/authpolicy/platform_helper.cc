// Copyright 2016 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "authpolicy/platform_helper.h"

#include <fcntl.h>
#include <linux/capability.h>
#include <poll.h>
#include <sys/capability.h>
#include <sys/prctl.h>
#include <sysexits.h>
#include <cstdint>

#include <sys/ioctl.h>

#include <algorithm>
#include <vector>

#include <base/check.h>
#include <base/check_op.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/logging.h>

namespace authpolicy {

namespace {

// Size limit on the total number of bytes to read from a pipe.
const size_t kMaxReadSize = 16 * 1024 * 1024;  // 16 MB
// The size of the buffer used to read from a pipe.
const size_t kBufferSize = PIPE_BUF;  // ~4 Kb on my system
// Timeout used for poll()ing pipes.
const int kPollTimeoutMilliseconds = 30000;

// Creates a non-blocking local pipe and returns the read and the write end.
bool CreatePipe(base::ScopedFD* pipe_read_end, base::ScopedFD* pipe_write_end) {
  int pipe_fd[2];
  if (!base::CreateLocalNonBlockingPipe(pipe_fd)) {
    LOG(ERROR) << "Failed to create pipe";
    return false;
  }
  pipe_read_end->reset(pipe_fd[0]);
  pipe_write_end->reset(pipe_fd[1]);
  return true;
}

// Reads up to |kBufferSize| bytes from the file descriptor |src_fd| and appends
// them to |dst_str|. Sets |done| to true iff the whole file was read
// successfully. Might block if |src_fd| is a blocking pipe. Returns false on
// error.
bool ReadPipe(int src_fd, std::string* dst_str, bool* done) {
  *done = false;
  char buffer[kBufferSize];
  const ssize_t bytes_read = HANDLE_EINTR(read(src_fd, buffer, kBufferSize));
  if (bytes_read < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
    PLOG(ERROR) << "read() from fd " << src_fd << " failed";
    return false;
  }
  if (bytes_read == 0)
    *done = true;
  else if (bytes_read > 0)
    dst_str->append(buffer, bytes_read);
  return true;
}

// Splices (copies) as much as possible data from the file descriptor |src_fd|
// to |dst_fd|. Sets |done| to true iff the whole |src_fd| file was spliced
// successfully. Might block if |src_fd| or |dst_fd| are blocking pipes. Returns
// false on error.
bool SplicePipe(int dst_fd, int src_fd, bool* done) {
  *done = false;
  const int flags = SPLICE_F_NONBLOCK | SPLICE_F_MORE | SPLICE_F_MOVE;
  const ssize_t bytes_written =
      HANDLE_EINTR(splice(src_fd, nullptr, dst_fd, nullptr, INT_MAX, flags));
  if (bytes_written < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
    PLOG(ERROR) << "splice() " << src_fd << " failed";
    return false;
  }
  if (bytes_written == 0)
    *done = true;
  return true;
}

// Writes as much as possible from |src_str|, beginning at position |src_pos|,
// to the file descriptor |dst_fd|. Sets |done| to true iff the whole string
// was written successfully. Handles blocking |dst_fd|. Returns false on error.
// On success, increases |src_pos| by the number of bytes written.
bool WritePipe(int dst_fd,
               const std::string& src_str,
               size_t* src_pos,
               bool* done) {
  DCHECK_LE(*src_pos, src_str.size());
  // Writing 0 bytes might not be well defined, so early out in this case.
  if (*src_pos == src_str.size()) {
    *done = true;
    return true;
  }
  *done = false;
  const ssize_t bytes_written = HANDLE_EINTR(
      write(dst_fd, src_str.data() + *src_pos, src_str.size() - *src_pos));
  if (bytes_written < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
    PLOG(ERROR) << "write() to " << dst_fd << " failed";
    return false;
  }
  if (bytes_written > 0) {
    *src_pos += bytes_written;
    DCHECK_LE(*src_pos, src_str.size());
  }
  if (*src_pos == src_str.size())
    *done = true;
  return true;
}

}  // namespace

bool ReadPipeToString(int fd, std::string* out) {
  char buffer[kBufferSize];
  size_t total_read = 0;
  while (total_read < kMaxReadSize) {
    const ssize_t bytes_read = HANDLE_EINTR(
        read(fd, buffer, std::min(kBufferSize, kMaxReadSize - total_read)));
    if (bytes_read < 0)
      return false;
    if (bytes_read == 0)
      return true;
    total_read += bytes_read;
    out->append(buffer, bytes_read);
  }

  // Size limit hit. Do one more read to check if the file size is exactly
  // kMaxReadSize bytes.
  return HANDLE_EINTR(read(fd, buffer, 1)) == 0;
}

base::ScopedFD ReadFileToPipe(const base::FilePath& path) {
  base::ScopedFD pipe_read_end, pipe_write_end;
  if (!authpolicy::CreatePipe(&pipe_read_end, &pipe_write_end))
    return base::ScopedFD();

  bool done = false;
  base::ScopedFD file_fd(open(path.value().c_str(), O_RDONLY | O_NONBLOCK));
  if (!file_fd.is_valid()) {
    PLOG(ERROR) << "Failed to open file '" << path.value() << "'";
    return base::ScopedFD();
  }
  // Splice twice. The first splice reads the whole file, but doesn't set
  // |done|. The second splice sets |done| to true.
  if (!SplicePipe(pipe_write_end.get(), file_fd.get(), &done) ||
      !SplicePipe(pipe_write_end.get(), file_fd.get(), &done)) {
    return base::ScopedFD();
  }
  if (!done) {
    LOG(ERROR) << "Failed to splice the whole pipe in one go";
    return base::ScopedFD();
  }
  return pipe_read_end;
}

bool PerformPipeIo(int stdin_fd,
                   int stdout_fd,
                   int stderr_fd,
                   int input_fd,
                   const std::string& input_str,
                   std::string* stdout,
                   std::string* stderr) {
  // Make sure pipes get closed when exiting the scope.
  base::ScopedFD stdin_scoped_fd(stdin_fd);
  base::ScopedFD stdout_scoped_fd(stdout_fd);
  base::ScopedFD stderr_scoped_fd(stderr_fd);

  size_t input_str_pos = 0;
  bool splicing_input_fd = (input_fd != -1);

  while (stdin_scoped_fd.is_valid() || stdout_scoped_fd.is_valid() ||
         stderr_scoped_fd.is_valid()) {
    // Note that closed files (*_scoped_fd.get() == -1) are ignored.
    const int kIndexStdin = 0, kIndexStdout = 1, kIndexStderr = 2;
    const char* kPipeNames[] = {"stdin", "stdout", "stderr"};
    const int kPollCount = 3;

    struct pollfd poll_fds[kPollCount];
    poll_fds[kIndexStdin] = {stdin_scoped_fd.get(), POLLOUT, 0};
    poll_fds[kIndexStdout] = {stdout_scoped_fd.get(), POLLIN, 0};
    poll_fds[kIndexStderr] = {stderr_scoped_fd.get(), POLLIN, 0};

    const int poll_result =
        HANDLE_EINTR(poll(poll_fds, kPollCount, kPollTimeoutMilliseconds));
    if (poll_result < 0) {
      PLOG(ERROR) << "poll() failed";
      return false;
    }
    // Treat POLLNVAL as an error for all pipes.
    for (int n : {kIndexStdin, kIndexStdout, kIndexStderr}) {
      if ((poll_fds[n].revents & POLLNVAL) == 0)
        continue;
      LOG(ERROR) << "POLLNVAL for " << kPipeNames[n];
      return false;
    }
    // Special case: POLLERR can legitimately happen on the child process'
    // stdin if it already exited. Do not treat that as an error unless
    // there was data the parent process wanted to send to the child
    // process.
    for (int n : {kIndexStdin, kIndexStdout, kIndexStderr}) {
      if ((poll_fds[n].revents & POLLERR) == 0)
        continue;
      if (n == kIndexStdin) {
        if (!splicing_input_fd && input_str.size() == input_str_pos) {
          VLOG(1) << "Ignoring POLLERR for stdin.";
          stdin_scoped_fd.reset();
          continue;
        }

        LOG(ERROR) << "Child process stdin closed due to POLLERR when "
                   << "there was still data to write.";
      }
      LOG(ERROR) << "POLLERR for " << kPipeNames[n];
      return false;
    }

    // Should only happen on timeout. Log a warning here, so we get at least a
    // log if the process is stale.
    if (poll_result == 0)
      LOG(WARNING) << "poll() timed out. Process might be stale.";

    // Read stdout to the stdout string.
    if (stdout_scoped_fd.is_valid() &&
        (poll_fds[kIndexStdout].revents & (POLLIN | POLLHUP))) {
      bool done = false;
      if (!ReadPipe(stdout_scoped_fd.get(), stdout, &done))
        return false;
      else if (done)
        stdout_scoped_fd.reset();
    }

    // Read stderr to the stderr string.
    if (stderr_scoped_fd.is_valid() &&
        (poll_fds[kIndexStderr].revents & (POLLIN | POLLHUP))) {
      bool done = false;
      if (!ReadPipe(stderr_scoped_fd.get(), stderr, &done))
        return false;
      else if (done)
        stderr_scoped_fd.reset();
    }

    if (stdin_scoped_fd.is_valid() && poll_fds[kIndexStdin].revents & POLLOUT) {
      bool done = false;
      if (splicing_input_fd) {
        // Splice input_fd to stdin_scoped_fd.
        if (!SplicePipe(stdin_scoped_fd.get(), input_fd, &done))
          return false;
        else if (done)
          splicing_input_fd = false;
      } else {
        // Write input_str to stdin_scoped_fd.
        if (!WritePipe(stdin_scoped_fd.get(), input_str, &input_str_pos, &done))
          return false;
        else if (done)
          stdin_scoped_fd.reset();
      }
    }

    // Check size limits.
    if (stdout->size() > kMaxReadSize || stderr->size() > kMaxReadSize) {
      LOG(ERROR) << "Hit size limit";
      return false;
    }
  }
  return true;
}

base::ScopedFD DuplicatePipe(int src_fd) {
  base::ScopedFD pipe_read_end, pipe_write_end;
  if (!authpolicy::CreatePipe(&pipe_read_end, &pipe_write_end))
    return base::ScopedFD();

  if (HANDLE_EINTR(
          tee(src_fd, pipe_write_end.get(), INT_MAX, SPLICE_F_NONBLOCK)) <= 0) {
    PLOG(ERROR) << "Failed to duplicate pipe";
    return base::ScopedFD();
  }
  return pipe_read_end;
}

base::ScopedFD WriteStringToPipe(const std::string& str) {
  base::ScopedFD pipe_read_end, pipe_write_end;
  if (!authpolicy::CreatePipe(&pipe_read_end, &pipe_write_end))
    return base::ScopedFD();

  if (!base::WriteFileDescriptor(pipe_write_end.get(), str)) {
    LOG(ERROR) << "Failed to write string to pipe";
    return base::ScopedFD();
  }
  return pipe_read_end;
}

base::ScopedFD WriteStringAndPipeToPipe(const std::string& str, int fd) {
  base::ScopedFD pipe_read_end, pipe_write_end;
  if (!authpolicy::CreatePipe(&pipe_read_end, &pipe_write_end))
    return base::ScopedFD();

  if (!base::WriteFileDescriptor(pipe_write_end.get(), str)) {
    LOG(ERROR) << "Failed to write string to pipe";
    return base::ScopedFD();
  }

  if (HANDLE_EINTR(tee(fd, pipe_write_end.get(), INT_MAX, SPLICE_F_NONBLOCK)) <=
      0) {
    PLOG(ERROR) << "Failed to duplicate pipe";
    return base::ScopedFD();
  }
  return pipe_read_end;
}

uid_t GetEffectiveUserId() {
  return geteuid();
}

bool SetSavedUserAndDropCaps(uid_t saved_uid) {
  // Only set the saved UID, keep the other ones.
  if (setresuid(-1, -1, saved_uid)) {
    PLOG(ERROR) << "setresuid failed";
    return false;
  }

  // Drop capabilities from bounding set.
  if (prctl(PR_CAPBSET_DROP, CAP_SETUID) ||
      prctl(PR_CAPBSET_DROP, CAP_SETPCAP)) {
    PLOG(ERROR) << "Failed to drop caps from bounding set";
    return false;
  }

  // Clear capabilities.
  cap_t caps = cap_get_proc();
  if (!caps || cap_clear_flag(caps, CAP_INHERITABLE) ||
      cap_clear_flag(caps, CAP_EFFECTIVE) ||
      cap_clear_flag(caps, CAP_PERMITTED) || cap_set_proc(caps)) {
    PLOG(ERROR) << "Clearing caps failed";
    return false;
  }

  return true;
}

ScopedSwitchToSavedUid::ScopedSwitchToSavedUid() {
  uid_t real_uid, effective_uid;
  CHECK_EQ(0, getresuid(&real_uid, &effective_uid, &saved_uid_));
  CHECK(real_uid == effective_uid);
  real_and_effective_uid_ = real_uid;
  CHECK_EQ(0, setresuid(saved_uid_, saved_uid_, real_and_effective_uid_));
}

ScopedSwitchToSavedUid::~ScopedSwitchToSavedUid() {
  CHECK_EQ(0, setresuid(real_and_effective_uid_, real_and_effective_uid_,
                        saved_uid_));
}

}  // namespace authpolicy
