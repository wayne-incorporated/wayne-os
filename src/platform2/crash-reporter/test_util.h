// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRASH_REPORTER_TEST_UTIL_H_
#define CRASH_REPORTER_TEST_UTIL_H_

#include <map>
#include <string>
#include <vector>

#include <base/files/file_path.h>
#include <base/strings/string_piece.h>
#include <base/time/clock.h>
#include <base/time/time.h>

#include <session_manager/dbus-proxy-mocks.h>

namespace test_util {

constexpr char kFakeClientId[] = "00112233445566778899aabbccddeeff";

// A Clock that advances 10 seconds (by default) on each call, used in tests and
// fuzzers. Unlike a MockClock, it will not fail the test regardless of how many
// times it is or isn't called, and it always eventually reaches any desired
// time. In particular, having an advancing clock in the crash sender code is
// useful because if AcquireLockFileOrDie can't get the lock, the test will
// eventually fail instead of going into an infinite loop.
class AdvancingClock : public base::Clock {
 public:
  // Start clock at GetDefaultTime()
  AdvancingClock();
  // Start clock at GetDefaultTime(). Each call to Now() will advance the
  // clock by |advance_amount|.
  explicit AdvancingClock(base::TimeDelta advance_amount);

  base::Time Now() const override;

 private:
  mutable base::Time time_;
  const base::TimeDelta advance_amount_;
};

void FakeSleep(std::vector<base::TimeDelta>* sleep_times,
               base::TimeDelta duration);

bool CreateClientIdFile();

// Get an assumed "now" for things that mocks out the current time. Always
// returns 2018-04-20 13:53.
base::Time GetDefaultTime();

// Creates a file at |file_path| with |content|, with parent directories.
// Returns true on success. If you want the test function to stop when the file
// creation failed, wrap this function with ASSERT_TRUE().
bool CreateFile(const base::FilePath& file_path, base::StringPiece content);

// Configures |mock| so that RetrieveActiveSessions() returns |sessions|.
void SetActiveSessions(org::chromium::SessionManagerInterfaceProxyMock* mock,
                       const std::map<std::string, std::string>& sessions);

// Returns true if at least one file in this directory matches the pattern.
// found_file_path is not assigned if found_file_path is nullptr.
// Only the first found path is stored into found_file_path.
bool DirectoryHasFileWithPattern(const base::FilePath& directory,
                                 const std::string& pattern,
                                 base::FilePath* found_file_path);

// Returns true if at least one file in this directory matches the |pattern|
// and contains the string |contents|.
bool DirectoryHasFileWithPatternAndContents(const base::FilePath& directory,
                                            const std::string& pattern,
                                            const std::string& contents);

// Return path to an input files used by unit tests.
// use_testdata: Whether to add "testdata/" in front of the filename.
base::FilePath GetTestDataPath(const std::string& name, bool use_testdata);

// Helper function for calling base::TouchFile() concisely for tests.
bool TouchFileHelper(const base::FilePath& file_name, base::Time modified_time);

}  // namespace test_util

#endif  // CRASH_REPORTER_TEST_UTIL_H_
