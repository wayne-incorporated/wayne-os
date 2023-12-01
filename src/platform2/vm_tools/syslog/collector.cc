// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "vm_tools/syslog/collector.h"

#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <string.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysinfo.h>
#include <sys/un.h>

#include <linux/vm_sockets.h>  // Needs to come after sys/socket.h

#include <string>
#include <utility>

#include <base/check.h>
#include <base/functional/bind.h>
#include <base/functional/callback.h>
#include <base/functional/callback_helpers.h>
#include <base/location.h>
#include <base/logging.h>
#include <base/memory/ptr_util.h>
#include <base/posix/eintr_wrapper.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_piece.h>
#include <base/strings/stringprintf.h>
#include <base/task/single_thread_task_runner.h>
#include <base/time/time.h>
#include <chromeos/scoped_minijail.h>
#include <grpcpp/grpcpp.h>

#include "vm_tools/syslog/forwarder.h"
#include "vm_tools/syslog/parser.h"

using std::string;

namespace pb = google::protobuf;

namespace vm_tools {
namespace syslog {
namespace {

// Maximum size the buffer can reach before logs are immediately flushed.
constexpr size_t kBufferThreshold = 4096;

// Size of the largest syslog record as defined by RFC3164.
constexpr size_t kMaxSyslogRecord = 1024;

// Max number of records we should attempt to read out of the socket at a time.
constexpr int kMaxRecordCount = 11;

const char kProcPath[] = "/proc/self/fd/%d/%s";

}  // namespace

Collector::~Collector() = default;

bool Collector::BindLogSocket(const base::FilePath& name) {
  // Start listening on the syslog socket.
  syslog_fd_.reset(socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0));

  if (!syslog_fd_.is_valid()) {
    PLOG(ERROR) << "Failed to create unix domain socket";
    return false;
  }

  struct sockaddr_un sun = {
      .sun_family = AF_UNIX,
  };

  base::ScopedFD dir_fd;
  std::string short_name;
  if (name.value().size() > sizeof(sun.sun_path)) {
    // If the socket path is too long, we can shorten it by replacing the
    // directory paths with /proc/self/fd/${dir_fd}/socket_name to try and get
    // it under the limit.
    dir_fd.reset(HANDLE_EINTR(open(name.DirName().value().c_str(),
                                   O_PATH | O_DIRECTORY | O_CLOEXEC)));
    if (!dir_fd.is_valid()) {
      PLOG(ERROR) << "Failed to open logging directory";
      return false;
    }

    short_name = base::StringPrintf(kProcPath, dir_fd.get(),
                                    name.BaseName().value().c_str());
  } else {
    short_name = name.value();
  }

  if (short_name.size() > sizeof(sun.sun_path)) {
    LOG(ERROR) << "Socket path too long even after shortening";
    return false;
  }

  // Make sure that any previous socket is cleaned up before attempting to bind
  // to it again.  We don't really care whether the unlink succeeds or not.
  HANDLE_EINTR(unlink(short_name.c_str()));

  strncpy(sun.sun_path, short_name.c_str(), sizeof(sun.sun_path));

  if (bind(syslog_fd_.get(), reinterpret_cast<struct sockaddr*>(&sun),
           sizeof(sun)) != 0) {
    PLOG(ERROR) << "Failed to bind logging socket";
    return false;
  }

  // Give everyone write permissions to the socket.
  if (chmod(sun.sun_path, 0666) != 0) {
    PLOG(ERROR) << "Unable to change permissions for syslog socket";
    return false;
  }
  LOG(INFO) << "Bound socket fd " << syslog_fd_.get() << " at " << name;
  return true;
}

void Collector::SetSyslogFDForTesting(base::ScopedFD syslog_fd) {
  CHECK(syslog_fd.is_valid());
  syslog_fd_ = std::move(syslog_fd);
}

bool Collector::StartWatcher(base::TimeDelta flush_period) {
  syslog_controller_ = base::FileDescriptorWatcher::WatchReadable(
      syslog_fd_.get(), base::BindRepeating(&Collector::OnSyslogReadable,
                                            base::Unretained(this)));
  if (!syslog_controller_) {
    LOG(ERROR) << "Failed to watch syslog file descriptor";
    return false;
  }

  // Start a timer to periodically flush logs.
  timer_.Start(
      FROM_HERE, flush_period,
      base::BindRepeating(&Collector::FlushLogs, weak_factory_.GetWeakPtr()));

  // Start a new log request buffer.
  syslog_request_ = pb::Arena::CreateMessage<vm_tools::LogRequest>(&arena_);
  buffered_size_ = 0;

  // Everything succeeded.
  return true;
}

void Collector::OnSyslogReadable() {
  bool more = true;
  for (int i = 0; i < kMaxRecordCount && more; ++i) {
    more = ReadOneSyslogRecord();

    // Send all buffered records immediately if we've crossed the threshold.
    if (buffered_size_ > kBufferThreshold) {
      FlushLogs();
      timer_.Reset();
    }
  }
}

void Collector::FlushLogs() {
  if (syslog_request_->records_size() <= 0) {
    // Nothing to do.  Just return.
    return;
  }

  if (syslog_request_->records_size() > 0) {
    if (!SendUserLogs()) {
      // Try again later - maybe logs are being rotated.
      return;
    }
  }

  // Reset everything.
  arena_.Reset();
  syslog_request_ = pb::Arena::CreateMessage<vm_tools::LogRequest>(&arena_);
  buffered_size_ = 0;
}

bool Collector::ReadOneSyslogRecord() {
  char buf[kMaxSyslogRecord + 1];
  ssize_t ret =
      HANDLE_EINTR(recv(syslog_fd_.get(), buf, kMaxSyslogRecord, MSG_DONTWAIT));
  if (ret < 0) {
    if (errno != EAGAIN && errno != EWOULDBLOCK) {
      static int log_count = 0;
      PLOG_IF(ERROR, log_count < 10)
          << "Failed to read from syslog socket " << syslog_fd_.get();
      ++log_count;
    }
    return false;
  }

  if (ret == 0) {
    // We didn't read anything but that doesn't necessarily mean there was an
    // error.
    return true;
  }
  // Make sure the buffer is properly terminated.
  buf[ret] = '\0';

  // Attempt to parse the record.
  auto* record = pb::Arena::CreateMessage<vm_tools::LogRecord>(&arena_);
  if (!ParseSyslogRecord(buf, ret, record)) {
    LOG(ERROR) << "Failed to parse syslog record";

    // Return true here because while we failed to parse this message there may
    // still be more messages pending in the kernel buffer.
    return true;
  }

  // We have a valid entry. Update the buffered message count and store the
  // message.
  buffered_size_ += record->ByteSizeLong();

  // Safe because |record| was created by the same Arena that owns
  // |syslog_request_|.
  syslog_request_->add_records()->UnsafeArenaSwap(record);

  return true;
}

}  // namespace syslog
}  // namespace vm_tools
