// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "foomatic_shell/process_launcher.h"

#include <errno.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <list>
#include <map>
#include <utility>

#include <base/functional/bind.h>
#include <base/logging.h>
#include <brillo/process/process.h>

namespace foomatic_shell {

namespace {

// Helper structure holding a pointer to brillo::Process or PID of process.
struct Subprocess {
  explicit Subprocess(pid_t pid) : script_pid(pid) {}
  explicit Subprocess(std::unique_ptr<brillo::Process> process)
      : command_process(std::move(process)) {}
  // Exactly one of these two fields is set.
  std::unique_ptr<brillo::Process> command_process;
  pid_t script_pid = -1;
  // The position of the executed fragment of the input script.
  std::string::const_iterator position;
};

// This function is called before calling exec(...) in forked process.
// |vars| contains environment variables to set. In case of an error, the
// function returns false and prints an error message to stderr.
bool PreExecSettings(const std::map<std::string, std::string>& vars) {
  // Set environment variables.
  for (const auto& name_value : vars) {
    if (setenv(name_value.first.c_str(), name_value.second.c_str(), 1)) {
      perror("setenv(...) failed");
      return false;
    }
  }

  // Set soft/hard limit for CPU usage (900 sec / 950 sec).
  const rlimit cpu_limit = {900, 950};
  if (setrlimit(RLIMIT_CPU, &cpu_limit)) {
    perror("setrlimit(RLIMIT_CPU,...) failed");
    return false;
  }

  // Set soft/hard limit for memory (256 MB / 288 MB).
  const rlimit mem_limit = {256 * 1024 * 1024, 288 * 1024 * 1024};
  if (setrlimit(RLIMIT_DATA, &mem_limit)) {
    perror("setrlimit(RLIMIT_DATA,...) failed");
    return false;
  }

  return true;
}

// Prints to the stderr an error message. |source| is a source of the script
// that failed. |position| points to the part of |source| where the error
// occurred. |msg| is an error message. Neither dot nor end-of-line is expected
// at the end of |msg|. If |use_errno| is set the function adds to |msg| a
// string ": " followed by the error message reported by errno.
void PrintMessage(const std::string& source,
                  std::string::const_iterator position,
                  std::string msg,
                  bool use_errno = false) {
  if (use_errno) {
    msg += ": ";
    msg += strerror(errno);
  }
  const std::string out = CreateErrorLog(source, position, msg);
  fprintf(stderr, "%s\n", out.c_str());
}

}  // namespace

// Creates a new process executing the given |command|. |input_fd| and
// |output_fd| are input/output descriptors for the new process. The function
// returns nullptr when error occurs and the process cannot be started.
std::unique_ptr<brillo::Process> ProcessLauncher::StartProcess(
    const Command& command, int input_fd, int output_fd) {
  // Saves to a map all environment variables to set.
  std::map<std::string, std::string> vars;
  for (const auto& assignment : command.variables_with_values)
    vars[assignment.variable.value] = Value(assignment.new_value);

  // Creates and runs the process.
  std::unique_ptr<brillo::Process> process(new brillo::ProcessImpl());
  process->AddArg(command.application.value);
  for (const StringAtom& param : command.parameters)
    process->AddArg(Value(param));
  if (input_fd >= 0)
    process->BindFd(input_fd, 0);
  if (output_fd >= 0)
    process->BindFd(output_fd, 1);
  process->SetCloseUnusedFileDescriptors(true);
  process->SetSearchPath(true);
  process->SetPreExecCallback(base::BindOnce(&PreExecSettings, vars));
  if (!process->Start()) {
    PrintMessage(source_, Position(command), "brillo::Process::Start() failed");
    return nullptr;
  }

  if (verbose_)
    fprintf(stderr, "PROCESS %s STARTED\n", command.application.value.c_str());
  return process;
}

// This function forks a new process and executes |script| in it. |input_fd| and
// |output_fd| are standard input/output streams for the new process. All file
// descriptors > 2 and different than |input_fd| and |output_fd| are closed in
// the forked (child) process. The function returns PID of the forked process or
// -1 in case on an error.
pid_t ProcessLauncher::StartSubshell(const Script& script,
                                     int input_fd,
                                     int output_fd) {
  pid_t pid = fork();
  if (pid == 0) {
    // Inside the child process.
    // Get the maximum number of file descriptor.
    rlimit file_desc_limit;
    if (getrlimit(RLIMIT_NOFILE, &file_desc_limit)) {
      perror("getrlimit(RLIMIT_NOFILE,...) failed");
      return false;
    }
    // Close all unused file descriptors.
    for (int fd = 3; fd < file_desc_limit.rlim_cur; ++fd) {
      if (fd != input_fd && fd != output_fd) {
        // Since this code calls close() on every integer that could
        // possibly be a file descriptor, we expect most of the calls
        // to fail with EBADF, which indicates that the parameter to
        // close() wasn't an open file descriptor to begin with.
        if (close(fd) != 0 && errno != EBADF)
          perror("close(fd) failed");
      }
    }
    // Run |script| and exit.
    const int exit_code = RunScript(script, input_fd, output_fd);
    exit(exit_code);
  }

  // Inside the parent process.
  if (pid < 0) {
    PrintMessage(source_, Position(script), "fork() failed", true);
    return (pid_t)-1;
  }

  if (verbose_)
    fprintf(stderr, "SUBSHELL STARTED\n");
  return pid;
}

// The function runs given |pipeline|. |input_fd| and |output_fd| are
// input/output descriptors for the whole pipeline. In case of an error the
// method returns kShellError. Otherwise, the method returns exit code
// returned by the last command in the pipeline.
int ProcessLauncher::RunPipeline(const Pipeline& pipeline,
                                 int input_fd,
                                 int output_fd) {
  if (verbose_)
    fprintf(stderr, "EXECUTE PIPELINE\n");

  // List of processes created within this pipeline.
  std::list<Subprocess> processes;

  // Iterate over the pipeline and create corresponding processes.
  int next_fd_in = input_fd;
  for (size_t iSegment = 0; iSegment < pipeline.segments.size(); ++iSegment) {
    auto& pipe_segment = pipeline.segments[iSegment];

    // Create a pipe connecting the current segment with the next one.
    const int fd_in = next_fd_in;
    int fd_out;
    if (iSegment == pipeline.segments.size() - 1) {
      // It is the last segment. Instead of creating a new pipe, we just set
      // the output file descriptor to |output_fd|.
      next_fd_in = -1;
      fd_out = output_fd;
    } else {
      // Create a new pipe connecting this segment with the next one.
      int fd[2];
      if (pipe(fd) != 0) {
        PrintMessage(source_, Position(pipe_segment), "pipe(...) failed",
                     true /* use_errno */);
        return kShellError;
      }
      next_fd_in = fd[0];
      fd_out = fd[1];
    }

    // Create a process corresponding to the current segment.
    if (pipe_segment.command) {
      // The current segment is a simple command.
      auto process = StartProcess(*pipe_segment.command, fd_in, fd_out);
      if (process != nullptr) {
        // Success. Save the new process.
        processes.emplace_back(std::move(process));
      } else {
        // Failure. Break the pipeline.
        return kShellError;
      }
    } else {
      // The current segment is a subshell.
      pid_t pid = StartSubshell(*pipe_segment.script, fd_in, fd_out);
      if (pid != (pid_t)-1) {
        // Success. Save the new process.
        processes.emplace_back(pid);
      } else {
        // Failure. Break the pipeline.
        return kShellError;
      }
    }
    processes.back().position = Position(pipe_segment);

    // Close file descriptors.
    if (fd_in != input_fd) {
      if (close(fd_in) != 0)
        perror("close(fd_in) failed");
    }
    if (fd_out != output_fd) {
      if (close(fd_out) != 0)
        perror("close(fd_out) failed");
    }
  }

  // Wait for all the processes to finish.
  int exit_code = 0;
  for (Subprocess& sp : processes) {
    if (sp.command_process) {
      exit_code = sp.command_process->Wait();
      // (|exit_code| == kShellError) means that brillo::Process failed during
      // initialization of the child process.
      if (exit_code == kShellError) {
        PrintMessage(source_, sp.position, "Process failed");
        return kShellError;
      }
      // The process reached the CPU time limit.
      if (exit_code == kProcTimeLimitError) {
        PrintMessage(source_, sp.position, "CPU time limit was reached");
        return kProcTimeLimitError;
      }
    } else {
      if (waitpid(sp.script_pid, &exit_code, 0) == (pid_t)-1) {
        PrintMessage(source_, sp.position, "waitpid(...) failed",
                     true /* use_errno */);
        return kShellError;
      }
      // (|exit_code| == kShellError) means that the subshell failed.
      if (exit_code == kShellError)
        return kShellError;
      // One of children processes reached the CPU time limit.
      if (exit_code == kProcTimeLimitError)
        return kProcTimeLimitError;
    }
    // We ignore the exit_code different than kShellError and
    // kProcTimeLimitError, because the Linux shell behaves this way. The exit
    // code from the last pipeline segment is reported as the exit code for the
    // whole pipeline.
  }

  if (verbose_)
    fprintf(stderr, "PIPELINE COMPLETED SUCCESSFULLY\n");
  return exit_code;
}

int ProcessLauncher::RunScript(const Script& script,
                               int input_fd,
                               int output_fd) {
  for (auto& pipeline : script.pipelines) {
    // Try to execute the given |pipeline|.
    const int exit_code = RunPipeline(pipeline, input_fd, output_fd);

    // We stop execution on the first failing pipeline.
    if (exit_code != 0)
      return exit_code;
  }

  return 0;
}

}  // namespace foomatic_shell
