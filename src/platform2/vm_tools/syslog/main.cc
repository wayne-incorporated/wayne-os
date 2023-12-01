// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <fcntl.h>
#include <sys/socket.h>
#include <sys/uio.h>

#include <memory>
#include <string>

#include <base/at_exit.h>
#include <base/check.h>
#include <base/check_op.h>
#include <base/files/file_descriptor_watcher_posix.h>
#include <base/files/scoped_file.h>
#include <base/logging.h>
#include <base/message_loop/message_pump_type.h>
#include <base/posix/eintr_wrapper.h>
#include <base/run_loop.h>
#include <base/stl_util.h>
#include <base/task/single_thread_task_executor.h>

#include "vm_tools/syslog/guest_collector.h"

using std::string;

namespace {
// Path to logging file.
constexpr char kDevKmsg[] = "/dev/kmsg";

// Prefix inserted before every log message.
constexpr char kLogPrefix[] = "vm_syslog: ";

// File descriptor that points to /dev/kmsg.  Needs to be a global variable
// because logging::LogMessageHandlerFunction is just a function pointer so we
// can't bind any variables to it via base::Bind*.
int g_kmsg_fd = -1;

bool LogToKmsg(logging::LogSeverity severity,
               const char* file,
               int line,
               size_t message_start,
               const string& message) {
  DCHECK_NE(g_kmsg_fd, -1);

  const char* priority = nullptr;
  switch (severity) {
    case logging::LOGGING_VERBOSE:
      priority = "<7>";
      break;
    case logging::LOGGING_INFO:
      priority = "<6>";
      break;
    case logging::LOGGING_WARNING:
      priority = "<4>";
      break;
    case logging::LOGGING_ERROR:
      priority = "<3>";
      break;
    case logging::LOGGING_FATAL:
      priority = "<2>";
      break;
    default:
      priority = "<5>";
      break;
  }

  const struct iovec iovs[] = {
      {
          .iov_base = static_cast<void*>(const_cast<char*>(priority)),
          .iov_len = strlen(priority),
      },
      {
          .iov_base = static_cast<void*>(const_cast<char*>(kLogPrefix)),
          .iov_len = sizeof(kLogPrefix) - 1,
      },
      {
          .iov_base = static_cast<void*>(
              const_cast<char*>(message.c_str() + message_start)),
          .iov_len = message.length() - message_start,
      },
  };

  ssize_t count = 0;
  for (const struct iovec& iov : iovs) {
    count += iov.iov_len;
  }

  ssize_t ret = HANDLE_EINTR(writev(g_kmsg_fd, iovs, std::size(iovs)));

  // Even if the write wasn't successful, we can't log anything here because
  // this _is_ the logging function.  Just return whether the write succeeded.
  return ret == count;
}

}  // namespace

int main(int argc, char** argv) {
  base::AtExitManager at_exit;
  logging::InitLogging(logging::LoggingSettings());

  // Set up logging to /dev/kmsg.
  base::ScopedFD kmsg_fd(open(kDevKmsg, O_WRONLY | O_CLOEXEC));
  PCHECK(kmsg_fd.is_valid()) << "Failed to open " << kDevKmsg;

  g_kmsg_fd = kmsg_fd.get();
  logging::SetLogMessageHandler(LogToKmsg);

  if (argc > 1) {
    LOG(ERROR) << "Unexpected command line arguments";
    return 1;
  }

  base::SingleThreadTaskExecutor task_executor(base::MessagePumpType::IO);
  base::FileDescriptorWatcher watcher(task_executor.task_runner());
  base::RunLoop run_loop;

  std::unique_ptr<vm_tools::syslog::Collector> collector =
      vm_tools::syslog::GuestCollector::Create(run_loop.QuitClosure());
  CHECK(collector);

  run_loop.Run();

  return 0;
}
