// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef P2P_COMMON_TESTUTIL_H_
#define P2P_COMMON_TESTUTIL_H_

#include <signal.h>

#include <string>
#include <vector>

#include <base/files/file_path.h>
#include <base/functional/callback.h>
#include <base/strings/stringprintf.h>
#include <gtest/gtest.h>

namespace p2p {

namespace testutil {

// See chromium:419964 for discussion of why 10 minutes is used.
constexpr int kDefaultMainLoopTimeoutMs = 10 * 60 * 1000;

// This class will call exit() if the object is not destroyed before
// a given timeout. Useful to cancel a test in deadlock when no other
// mechanism is available to detect the deadlock and make the test fail.
class TimeBombAbort {
 public:
  // Configures the TimeBombAbort to call exit() after |timeout_seconds|
  // seconds if the object is not destroyed before. If the timeout is
  // reached, the |message| string will be printed in stderr right before
  // finishing the program. This class uses SIGALRM and should not be used
  // together with sleep(2).
  TimeBombAbort(int timeout_seconds, const char* message);
  TimeBombAbort(const TimeBombAbort&) = delete;
  TimeBombAbort& operator=(const TimeBombAbort&) = delete;

  ~TimeBombAbort();

 private:
  static void TimeoutHandler(int signal);

  struct sigaction previous_;
};

// Utility macro to run the command expressed by the printf()-style string
// |command_format| using the system(3) utility function. Will assert unless
// the command exits normally with exit status |expected_exit_status|.
#define EXPECT_COMMAND(expected_exit_status, command_format, ...)          \
  do {                                                                     \
    int rc =                                                               \
        system(base::StringPrintf(command_format, ##__VA_ARGS__).c_str()); \
    EXPECT_TRUE(WIFEXITED(rc));                                            \
    EXPECT_EQ(WEXITSTATUS(rc), expected_exit_status);                      \
  } while (0);

// Creates a unique and empty directory and returns the
// path. Your code should call TeardownTestDir() when
// you are done with it.
base::FilePath SetupTestDir(const std::string& test_name);

// Deletes all files and sub-directories of the directory given by
// |dir_path|. This should only be called on directories
// previously created by SetupTestDir().
void TeardownTestDir(const base::FilePath& dir_path);

// Runs the default GLib main loop for at most |timeout_msec| or util the
// function |terminate| returns true, wichever happens first. The function
// |terminate| is called before every GLib main loop iteration and its value is
// checked.
void RunGMainLoopUntil(int timeout_msec,
                       base::RepeatingCallback<bool()> terminate);

// Runs the default GLib main loop at most |iterations| times. This
// dispatches all the events that are already waiting in the main loop and
// those that get scheduled as a result of these events being attended.
// Returns the number of iterations the main loop was ran. If there are more
// than |iterations| events to attend, then this function returns |iterations|
// and the remaining events are not dispatched.
int RunGMainLoopMaxIterations(int iterations);

// Utility function to get the size of the file given by |file_name| in
// the directory given by |dir|. If the file does not exist, 0 is
// returned.
size_t FileSize(const base::FilePath& dir, const std::string& file_name);

// Asserts unless the file given by |file_name| in |dir| does not have
// the size given by |expected_size|.
void ExpectFileSize(const base::FilePath& dir,
                    const std::string& file_name,
                    size_t expected_size);

// Sets the expected total file size for the given |filename| file in the
// xattr of it. This is consumed by the connection_delegate to know the total
// file size regardless the current file size.
bool SetExpectedFileSize(const base::FilePath& filename, size_t size);

}  // namespace testutil

}  // namespace p2p

#endif  // P2P_COMMON_TESTUTIL_H_
