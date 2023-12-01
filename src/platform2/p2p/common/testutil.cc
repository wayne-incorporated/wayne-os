// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "p2p/common/testutil.h"

#include <fcntl.h>
#include <glib-object.h>
#include <stdarg.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/xattr.h>

#include <cctype>
#include <cinttypes>
#include <cstdlib>
#include <tuple>

#include <base/check.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <gtest/gtest.h>

using std::string;

using base::FilePath;

namespace p2p {

namespace testutil {

// This is the message to be displayed if the TimeBombAbort timeout is
// reached.
static const char* time_bomb_abort_message_ = NULL;

TimeBombAbort::TimeBombAbort(int timeout_seconds, const char* message) {
  CHECK(time_bomb_abort_message_ == NULL);
  time_bomb_abort_message_ = message;
  // Install the signal handler keeping the previous one.
  struct sigaction time_bomb_action;
  time_bomb_action.sa_flags = 0;
  time_bomb_action.sa_handler = TimeoutHandler;
  sigaction(SIGALRM, &time_bomb_action, &previous_);
  alarm(timeout_seconds);
}

TimeBombAbort::~TimeBombAbort() {
  // Restore the previous sigaction.
  alarm(0);
  sigaction(SIGALRM, &previous_, NULL);
  time_bomb_abort_message_ = NULL;
}

void TimeBombAbort::TimeoutHandler(int signal) {
  // Does a "best-effort" write.
  const char* msg = "\n\nTimeBombAbort::TimeoutHandler reached.\n";
  std::ignore = write(STDERR_FILENO, msg, strlen(msg));
  std::ignore = write(STDERR_FILENO, time_bomb_abort_message_,
                      strlen(time_bomb_abort_message_));
  exit(1);
}

FilePath SetupTestDir(const string& test_name) {
  // Create testing directory
  FilePath ret;
  string dir_name = string("/tmp/p2p-testing-") + test_name + ".XXXXXX";
  char* buf = strdup(dir_name.c_str());
  EXPECT_TRUE(mkdtemp(buf) != NULL);
  ret = FilePath(buf);
  free(buf);
  return ret;
}

void TeardownTestDir(const FilePath& dir_path) {
  // Sanity check
  EXPECT_EQ(0, dir_path.value().find("/tmp/p2p-testing-"));
  EXPECT_COMMAND(0, "rm -rf %s", dir_path.value().c_str());
}

static gboolean RunGMainLoopOnTimeout(gpointer user_data) {
  bool* timeout = static_cast<bool*>(user_data);
  *timeout = true;
  return FALSE;  // Remove timeout source
}

void RunGMainLoopUntil(int timeout_msec,
                       base::RepeatingCallback<bool()> terminate) {
  GMainLoop* loop = g_main_loop_new(NULL, FALSE);
  GMainContext* context = g_main_context_default();

  bool timeout = false;
  guint source_id = g_timeout_add(
      timeout_msec, p2p::testutil::RunGMainLoopOnTimeout, &timeout);

  while (!timeout && (terminate.is_null() || !terminate.Run()))
    g_main_context_iteration(context, TRUE);

  g_source_remove(source_id);
  g_main_loop_unref(loop);
}

int RunGMainLoopMaxIterations(int iterations) {
  int result;
  GMainContext* context = g_main_context_default();
  for (result = 0;
       result < iterations && g_main_context_iteration(context, FALSE);
       result++) {
  }
  return result;
}

size_t FileSize(const FilePath& dir, const string& file_name) {
  struct stat stat_buf;
  FilePath path = dir.Append(file_name);
  if (stat(path.value().c_str(), &stat_buf) != 0) {
    return 0;
  }
  return stat_buf.st_size;
}

void ExpectFileSize(const FilePath& dir,
                    const string& file_name,
                    size_t expected_size) {
  EXPECT_EQ(FileSize(dir, file_name), expected_size);
}

bool SetExpectedFileSize(const FilePath& filename, size_t size) {
  int fd = open(filename.value().c_str(), O_RDWR);
  if (fd == -1)
    return false;

  string decimal_size = base::NumberToString(size);
  if (fsetxattr(fd, "user.cros-p2p-filesize", decimal_size.c_str(),
                decimal_size.size(), 0) != 0) {
    close(fd);
    return false;
  }
  close(fd);
  return true;
}

}  // namespace testutil

}  // namespace p2p
