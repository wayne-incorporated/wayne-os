// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cros-disks/process.h"

#include <algorithm>
#include <array>
#include <cstdlib>
#include <string>

#include <fcntl.h>
#include <poll.h>
#include <signal.h>

#include <base/check.h>
#include <base/check_op.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/posix/eintr_wrapper.h>
#include <base/process/kill.h>
#include <base/strings/strcat.h>
#include <base/strings/string_split.h>
#include <base/strings/string_util.h>
#include <base/time/time.h>
#include <chromeos/libminijail.h>

#include "cros-disks/quote.h"
#include "cros-disks/sandboxed_init.h"

namespace cros_disks {
namespace {

// Creates a pipe holding the given string and returns a file descriptor to the
// read end of this pipe. If the given string is too big to fit into the pipe's
// buffer, it is truncated.
base::ScopedFD WrapStdIn(const base::StringPiece in) {
  SubprocessPipe p(SubprocessPipe::kParentToChild);

  const int fd = p.parent_fd.get();
  PCHECK(base::SetNonBlocking(fd));
  const ssize_t n =
      HANDLE_EINTR(write(p.parent_fd.get(), in.data(), in.size()));
  if (n < 0) {
    PLOG(ERROR) << "Cannot write to pipe " << fd;
  } else if (n < in.size()) {
    LOG(ERROR) << "Short write to pipe " << fd << ": Wrote " << n
               << " bytes instead of " << in.size() << " bytes";
  }

  return std::move(p.child_fd);
}

}  // namespace

std::ostream& operator<<(std::ostream& out, const Process::ExitCode exit_code) {
  switch (static_cast<int>(exit_code)) {
#define PRINT(s)                  \
  case MINIJAIL_ERR_SIG_BASE + s: \
    return out << #s;
    PRINT(SIGHUP)
    PRINT(SIGINT)
    PRINT(SIGQUIT)
    PRINT(SIGILL)
    PRINT(SIGTRAP)
    PRINT(SIGABRT)
    PRINT(SIGBUS)
    PRINT(SIGFPE)
    PRINT(SIGKILL)
    PRINT(SIGUSR1)
    PRINT(SIGSEGV)
    PRINT(SIGUSR2)
    PRINT(SIGPIPE)
    PRINT(SIGALRM)
    PRINT(SIGTERM)
    PRINT(SIGSTKFLT)
    PRINT(SIGCHLD)
    PRINT(SIGCONT)
    PRINT(SIGSTOP)
    PRINT(SIGTSTP)
    PRINT(SIGTTIN)
    PRINT(SIGTTOU)
    PRINT(SIGURG)
    PRINT(SIGXCPU)
    PRINT(SIGXFSZ)
    PRINT(SIGVTALRM)
    PRINT(SIGPROF)
    PRINT(SIGWINCH)
    PRINT(SIGIO)
    PRINT(SIGPWR)
    PRINT(SIGSYS)
#undef PRINT

#define PRINT(s) \
  case s:        \
    return out << #s;
    PRINT(EXIT_SUCCESS)
    PRINT(EXIT_FAILURE)
    PRINT(MINIJAIL_ERR_NO_ACCESS)
    PRINT(MINIJAIL_ERR_NO_COMMAND)
    PRINT(MINIJAIL_ERR_MOUNT)
    PRINT(MINIJAIL_ERR_PRELOAD)
    PRINT(MINIJAIL_ERR_JAIL)
    PRINT(MINIJAIL_ERR_INIT)
#undef PRINT
  }

  return out << "exit code " << static_cast<int>(exit_code);
}

// static
const pid_t Process::kInvalidProcessId = -1;

Process::Process() = default;
Process::~Process() = default;

void Process::AddArgument(std::string argument) {
  DCHECK(arguments_array_.empty());
  arguments_.push_back(std::move(argument));
  if (arguments_.size() == 1)
    program_name_ = base::FilePath(arguments_.front()).BaseName().value();
}

char* const* Process::GetArguments() {
  if (arguments_array_.empty())
    BuildArgumentsArray();

  return arguments_array_.data();
}

void Process::BuildArgumentsArray() {
  for (std::string& argument : arguments_) {
    arguments_array_.push_back(argument.data());
  }

  arguments_array_.push_back(nullptr);
}

void Process::AddEnvironmentVariable(const base::StringPiece name,
                                     const base::StringPiece value) {
  DCHECK(environment_array_.empty());
  DCHECK(!name.empty());
  std::string s;
  s.reserve(name.size() + value.size() + 1);
  s.append(name.data(), name.size());
  s += '=';
  s.append(value.data(), value.size());
  environment_.push_back(std::move(s));
}

char* const* Process::GetEnvironment() {
  // If there are no extra environment variables, just use the current
  // environment.
  if (environment_.empty()) {
    return environ;
  }

  if (environment_array_.empty()) {
    // Prepare the new environment.
    for (std::string& s : environment_) {
      // TODO(fdegros) Remove const_cast when using C++17
      environment_array_.push_back(const_cast<char*>(s.data()));
    }

    // Append the current environment.
    for (char* const* p = environ; *p; ++p) {
      environment_array_.push_back(*p);
    }

    environment_array_.push_back(nullptr);
  }

  return environment_array_.data();
}

void Process::OnLauncherExit() {
  if (!IsFinished()) {
    LOG(WARNING) << "Spurious call to OnLauncherExit";
    return;
  }

  // By then, |launcher_exit_callback_| should have been called.
  DCHECK(!launcher_exit_callback_);
  launcher_watch_.reset();
}

void Process::SetLauncherExitCallback(LauncherExitCallback callback) {
  DCHECK(!launcher_exit_callback_);
  launcher_exit_callback_ = std::move(callback);
  DCHECK(launcher_exit_callback_);
  DCHECK(!launcher_watch_);
  launcher_watch_ = base::FileDescriptorWatcher::WatchReadable(
      launcher_pipe_.parent_fd.get(),
      base::BindRepeating(&Process::OnLauncherExit, base::Unretained(this)));
  DCHECK(launcher_watch_);
}

bool Process::Start(base::ScopedFD in_fd, base::ScopedFD out_fd) {
  CHECK_EQ(kInvalidProcessId, pid_);
  CHECK(!finished());
  CHECK(!arguments_.empty()) << "No arguments provided";
  LOG(INFO) << "Starting program " << quote(program_name_) << " with arguments "
            << quote(arguments_);
  LOG_IF(INFO, !environment_.empty())
      << "and extra environment " << quote(environment_);
  pid_ = StartImpl(std::move(in_fd), std::move(out_fd));
  return pid_ != kInvalidProcessId;
}

bool Process::Start() {
  base::ScopedFD out_child_fd;

  if (output_callback_) {
    SubprocessPipe out_pipe(SubprocessPipe::kChildToParent);
    PCHECK(base::SetNonBlocking(out_pipe.parent_fd.get()));

    DCHECK(!output_watch_);
    output_watch_ = base::FileDescriptorWatcher::WatchReadable(
        out_pipe.parent_fd.get(),
        base::BindRepeating(&Process::OnOutputAvailable,
                            base::Unretained(this)));
    DCHECK(output_watch_);

    DCHECK(!out_fd_.is_valid());
    out_fd_ = std::move(out_pipe.parent_fd);
    DCHECK(out_fd_.is_valid());

    out_child_fd = std::move(out_pipe.child_fd);
  } else {
    out_child_fd.reset(dup(STDERR_FILENO));
    PCHECK(out_child_fd.is_valid());
  }

  DCHECK(out_child_fd.is_valid());
  return Start(WrapStdIn(input_), std::move(out_child_fd));
}

int Process::Wait() {
  if (finished())
    return exit_code_;

  DCHECK_NE(kInvalidProcessId, pid_);
  exit_code_ = WaitImpl();
  DCHECK(finished());

  if (launcher_exit_callback_)
    std::move(launcher_exit_callback_).Run(exit_code_);

  return exit_code_;
}

bool Process::IsFinished() {
  if (finished())
    return true;

  CHECK_NE(kInvalidProcessId, pid_);
  exit_code_ = WaitNonBlockingImpl();
  if (!finished())
    return false;

  if (launcher_exit_callback_)
    std::move(launcher_exit_callback_).Run(exit_code_);
  return true;
}

void Process::StoreOutputLine(const base::StringPiece line) {
  DCHECK(!line.empty());
  LOG(INFO) << program_name_ << ": " << line;
  captured_output_.emplace_back(line);
  if (output_callback_)
    output_callback_.Run(line);
}

void Process::SplitOutputIntoLines(base::StringPiece data) {
  size_t i;
  while ((i = data.find_first_of('\n')) != base::StringPiece::npos) {
    remaining_.append(data.data(), i);
    data.remove_prefix(i + 1);
    StoreOutputLine(remaining_);
    remaining_.clear();
  }

  remaining_.append(data.data(), data.size());
}

bool Process::CaptureOutput() {
  if (!out_fd_.is_valid())
    return false;

  const int fd = out_fd_.get();

  while (true) {
    char buffer[PIPE_BUF];
    const ssize_t n = read(fd, buffer, PIPE_BUF);

    if (n < 0) {
      // Error reading.
      switch (errno) {
        case EAGAIN:
        case EINTR:
          // Nothing for now, but it's Ok to try again later.
          VPLOG(2) << "Nothing to read from file descriptor " << fd;
          return true;
      }

      PLOG(ERROR) << "Cannot read from file descriptor " << fd;
      FlushOutput();
      return false;
    }

    if (n == 0) {
      // End of stream.
      VLOG(2) << "End of stream from file descriptor " << fd;
      FlushOutput();
      return false;
    }

    VLOG(2) << "Got " << n << " bytes from file descriptor " << fd;
    DCHECK_GT(n, 0);
    DCHECK_LE(n, PIPE_BUF);
    SplitOutputIntoLines(base::StringPiece(buffer, n));
  }
}

bool Process::WaitAndCaptureOutput() {
  if (!out_fd_.is_valid())
    return false;

  const int fd = out_fd_.get();

  struct pollfd pfd {
    fd, POLLIN, 0
  };

  const int ret = poll(&pfd, 1, 100 /* milliseconds */);

  if (ret < 0) {
    // Error.
    PLOG(ERROR) << "Cannot poll file descriptor " << fd;
    CHECK_EQ(errno, EINTR);
    return true;
  }

  if (ret == 0) {
    // Nothing to read because of timeout.
    VLOG(2) << "Nothing to read from file descriptor " << fd;
    return true;
  }

  return CaptureOutput();
}

void Process::FlushOutput() {
  output_watch_.reset();
  out_fd_.reset();

  if (!remaining_.empty()) {
    StoreOutputLine(remaining_);
    remaining_.clear();
  }

  output_callback_.Reset();
}

void Process::OnOutputAvailable() {
  VLOG(1) << "Data available from file descriptor " << out_fd_.get();
  CaptureOutput();
}

int Process::Run() {
  SubprocessPipe out(SubprocessPipe::kChildToParent);
  PCHECK(base::SetNonBlocking(out.parent_fd.get()));
  DCHECK(!out_fd_.is_valid());
  out_fd_ = std::move(out.parent_fd);
  DCHECK(out_fd_.is_valid());

  if (!Start(WrapStdIn(input_), std::move(out.child_fd)))
    return -1;

  VLOG(1) << "Collecting output of program " << quote(program_name_) << "...";

  // Poll process and pipe. Read from pipe when possible.
  while (!IsFinished() && WaitAndCaptureOutput())
    continue;

  // Really wait for process to finish.
  const int exit_code = Wait();

  // Final read from pipe after process finished.
  CaptureOutput();
  FlushOutput();
  VLOG(1) << "Finished collecting output of program " << quote(program_name_);

  if (exit_code == 0) {
    LOG(INFO) << "Program " << quote(program_name_) << " finished successfully";
    return exit_code;
  }

  // Process finished with a non-zero exit code.
  DCHECK_GT(exit_code, 0);

  // Log the captured output, if it hasn't been already logged as it was getting
  // captured.
  if (!LOG_IS_ON(INFO)) {
    for (const std::string& s : captured_output_) {
      LOG(ERROR) << program_name_ << ": " << s;
    }
  }

  LOG(ERROR) << "Program " << quote(program_name_) << " finished with "
             << ExitCode(exit_code);

  return exit_code;
}

}  // namespace cros_disks
