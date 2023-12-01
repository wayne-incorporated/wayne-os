// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "crash-reporter/test_util.h"

#include <base/check.h>
#include <base/files/file_enumerator.h>
#include <base/files/file_util.h>
#include <gtest/gtest.h>

#include "crash-reporter/crash_sender_paths.h"
#include "crash-reporter/paths.h"

using testing::_;
using testing::Invoke;

namespace test_util {

namespace {

std::map<std::string, std::string>* g_active_sessions;

// Implementation of
// SessionManagerInterfaceProxyMock::RetrieveActiveSessions().
bool RetrieveActiveSessionsImpl(
    std::map<std::string, std::string>* out_sessions,
    brillo::ErrorPtr* error,
    int timeout_ms = dbus::ObjectProxy::TIMEOUT_USE_DEFAULT) {
  DCHECK(g_active_sessions);  // Set in SetActiveSessions().
  *out_sessions = *g_active_sessions;
  return true;
}

}  // namespace

AdvancingClock::AdvancingClock()
    : time_(GetDefaultTime()), advance_amount_(base::Seconds(10)) {}

AdvancingClock::AdvancingClock(base::TimeDelta advance_amount)
    : time_(GetDefaultTime()), advance_amount_(advance_amount) {}

base::Time AdvancingClock::Now() const {
  time_ += advance_amount_;
  return time_;
}

// Fake sleep function that records the requested sleep time.
void FakeSleep(std::vector<base::TimeDelta>* sleep_times,
               base::TimeDelta duration) {
  LOG(INFO) << "FakeSleep(" << duration
            << "); real time: " << base::Time::Now();
  sleep_times->push_back(duration);
}

// Creates the client ID file and stores the fake client ID in it.
bool CreateClientIdFile() {
  return test_util::CreateFile(
      paths::GetAt(paths::kCrashSenderStateDirectory, paths::kClientId),
      kFakeClientId);
}

base::Time GetDefaultTime() {
  base::Time time;
  // Date is basically arbitrary, but far enough back that
  // IsOsTimestampTooOldForUploads (the function with the longest duration in
  // it) would return true for this date. This avoids any possibility of unit
  // tests suddenly failing if someone is (incorrectly) comparing this to the
  // real base::Time::Now().
  CHECK(base::Time::FromUTCString("2018-04-20 13:53", &time));
  return time;
}

bool CreateFile(const base::FilePath& file_path, base::StringPiece content) {
  if (!base::CreateDirectory(file_path.DirName()))
    return false;
  return base::WriteFile(file_path, content.data(), content.size()) ==
         content.size();
}

void SetActiveSessions(org::chromium::SessionManagerInterfaceProxyMock* mock,
                       const std::map<std::string, std::string>& sessions) {
  if (g_active_sessions)
    delete g_active_sessions;
  g_active_sessions = new std::map<std::string, std::string>(sessions);

  EXPECT_CALL(*mock, RetrieveActiveSessions(_, _, _))
      .WillRepeatedly(Invoke(&RetrieveActiveSessionsImpl));
}

bool DirectoryHasFileWithPattern(const base::FilePath& directory,
                                 const std::string& pattern,
                                 base::FilePath* found_file_path) {
  base::FileEnumerator enumerator(
      directory, false, base::FileEnumerator::FileType::FILES, pattern);
  base::FilePath path = enumerator.Next();
  if (!path.empty() && found_file_path)
    *found_file_path = path;
  return !path.empty();
}

bool DirectoryHasFileWithPatternAndContents(const base::FilePath& directory,
                                            const std::string& pattern,
                                            const std::string& contents) {
  base::FileEnumerator enumerator(
      directory, false, base::FileEnumerator::FileType::FILES, pattern);
  for (base::FilePath path = enumerator.Next(); !path.empty();
       path = enumerator.Next()) {
    LOG(INFO) << "Checking " << path.value();
    std::string actual_contents;
    if (!base::ReadFileToString(path, &actual_contents)) {
      LOG(ERROR) << "Failed to read file " << path.value();
      return false;
    }
    std::size_t found = actual_contents.find(contents);
    if (found != std::string::npos) {
      return true;
    }
  }
  return false;
}

base::FilePath GetTestDataPath(const std::string& name, bool use_testdata) {
  base::FilePath src = base::FilePath(getenv("SRC"));
  if (use_testdata) {
    src = src.Append("testdata");
  }
  return src.Append(name);
}

bool TouchFileHelper(const base::FilePath& file_name,
                     base::Time modified_time) {
  return base::TouchFile(file_name, modified_time, modified_time);
}

}  // namespace test_util
