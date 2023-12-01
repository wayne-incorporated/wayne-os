// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Standalone test that checks to check if the current compiler is optimizing
// out the memory clearing logic used by brillo::SecureBlob. It works by
// calling `secure_blob_test_helper` which sends the memory address of the
// secure blob and synchronizes using event fds so this process can read and
// validate the values in memory.

#include <fcntl.h>
#include <inttypes.h>
#include <sys/eventfd.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cstddef>
#include <cstdio>
#include <cstring>
#include <memory>
#include <string>

#include <base/files/scoped_file.h>
#include <base/logging.h>
#include "brillo/secure_blob_test_helper.h"

constexpr size_t kTestBlobSize = 16;

size_t check_value(const std::array<uint8_t, kTestBlobSize>& value) {
  size_t match_count = 0;
  for (size_t x = 0; x < value.size(); ++x) {
    match_count += value[x] == (x + 1);
  }
  return match_count;
}

size_t count_zeros(const std::array<uint8_t, kTestBlobSize>& value) {
  size_t match_count = 0;
  for (size_t x = 0; x < value.size(); ++x) {
    match_count += value[x] == 0;
  }
  return match_count;
}

int setup_event_fd() {
  int event_fd = eventfd(0, 0);
  if (event_fd < 0) {
    PLOG(ERROR) << "failed to create event-fd";
    return -1;
  }
  return event_fd;
}

class ChildProcessInspector {
 public:
  explicit ChildProcessInspector(pid_t child)
      : errors_(0), mem_path_("/proc/" + std::to_string(child) + "/mem") {}

  std::optional<std::array<uint8_t, kTestBlobSize>> check_memory_location(
      void* to_check) {
    base::ScopedFD mem(open(mem_path_.c_str(), O_RDONLY));
    if (!mem.is_valid()) {
      ++errors_;
      PLOG(ERROR) << "failed to open '" << mem_path_ << "'";
      return {};
    }

    if (lseek(mem.get(), (off_t)to_check, SEEK_SET) < 0) {
      ++errors_;
      PLOG(ERROR) << "failed to seek mem to pointer";
      return {};
    }

    std::array<uint8_t, kTestBlobSize> value;
    if (read(mem.get(), value.data(), value.size()) < 0) {
      ++errors_;
      PLOG(ERROR) << "failed to read mem at pointer";
      return {};
    }
    return {value};
  }

  int errors() { return errors_; }

 private:
  int errors_;
  std::string mem_path_;
};

int main() {
  // Set up eventfds for synchronizing with child process.
  base::ScopedFD child_to_parent(setup_event_fd());
  if (!child_to_parent.is_valid()) {
    return 1;
  }
  base::ScopedFD parent_to_child(setup_event_fd());
  if (!parent_to_child.is_valid()) {
    return 1;
  }

  int child_pipe[2] = {-1, -1};
  if (pipe2(child_pipe, 0) < 0) {
    PLOG(ERROR) << "failed to create pipe for child stdout";
    return 1;
  }
  base::ScopedFD child_stdout_r(child_pipe[0]);
  base::ScopedFD child_stdout_w(child_pipe[1]);

  pid_t child = fork();
  if (child < 0) {
    PLOG(ERROR) << "fork failed";
    return 1;
  }
  if (child == 0) {
    if (dup3(child_stdout_w.get(), 1, 0) < 0) {
      PLOG(ERROR) << "failed to dup child stdout pipe";
      return 1;
    }
    child_stdout_r.reset();
    child_stdout_w.reset();
    char arg0[] = "./secure_blob_test_helper";
    char* args[] = {arg0, strdup(std::to_string(child_to_parent.get()).c_str()),
                    strdup(std::to_string(parent_to_child.get()).c_str()),
                    strdup(std::to_string(kTestBlobSize).c_str()), nullptr};
    return execvp(args[0], args);
  }
  child_stdout_w.reset();

  base::ScopedFILE child_out(fdopen(child_stdout_r.get(), "r"));
  if (child_out == nullptr) {
    PLOG(ERROR) << "failed to get FILE from fd";
    return 1;
  }
  // Discard is ok here because child_out has ownership already.
  (void)child_stdout_r.release();

  int errors = 0;
  int status = 0;
  ChildProcessInspector inspector(child);
  while (true) {
    // Read pointer address.
    void* to_check;
    int scan = fscanf(child_out.get(), "%p", &to_check);
    if (scan == EOF) {
      LOG(INFO) << "child stdout closed";
      break;
    }
    if (scan < 1) {
      PLOG(ERROR) << "failed to read pointer address from child stdout";
      break;
    }

    VLOG(1) << "pre-clear read";
    auto data = inspector.check_memory_location(to_check);
    if (!data) {
      PLOG(ERROR)
          << "failed to read pre-clear memory location from child process";
      break;
    }
    if (check_value(*data) != kTestBlobSize) {
      LOG(ERROR) << "pre-cleared memory doesn't match expected value.";
      ++errors;
    }
    errors += brillo::send_event(parent_to_child.get());

    // Wait for deallocate.
    errors += brillo::wait_for_event(child_to_parent.get());
    VLOG(1) << "post-clear read";
    data = inspector.check_memory_location(to_check);
    if (!data) {
      PLOG(ERROR)
          << "failed to read post-clear memory location from child process";
      break;
    }
    if (count_zeros(*data) != kTestBlobSize) {
      LOG(ERROR) << "post-cleared memory isn't zeroed.";
      ++errors;
    }
    errors += brillo::send_event(parent_to_child.get());
  }
  child_to_parent.reset();
  parent_to_child.reset();

  if (kill(child, SIGINT) < 0 && errno != ESRCH) {
    PLOG(ERROR) << "failed to kill child process";
  }
  pid_t pid = waitpid(child, &status, 0);
  if (pid < 0) {
    PLOG(ERROR) << "failed to wait on child process";
    return 1;
  }
  errors += inspector.errors();
  if (errors) {
    return !!errors;
  }
  if (pid == child) {
    return WEXITSTATUS(status);
  }
  return 0;
}
