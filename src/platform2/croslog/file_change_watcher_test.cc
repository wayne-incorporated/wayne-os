// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "croslog/file_change_watcher.h"

#include <string>

#include "base/files/file.h"
#include "base/files/file_path.h"
#include "base/files/file_util.h"
#include "base/functional/bind.h"
#include "base/run_loop.h"
#include "base/threading/platform_thread.h"
#include "base/time/time.h"
#include "gtest/gtest.h"

namespace croslog {

class FileChangeWatcherTest : public ::testing::Test,
                              public FileChangeWatcher::Observer {
 public:
  FileChangeWatcherTest() = default;
  FileChangeWatcherTest(const FileChangeWatcherTest&) = delete;
  FileChangeWatcherTest& operator=(const FileChangeWatcherTest&) = delete;

  ~FileChangeWatcherTest() override = default;

  void OnFileContentMaybeChanged() override { counter_++; }
  void OnFileNameMaybeChanged() override {}

  bool WaitForCounterValue(uint32_t target_value) {
    constexpr base::TimeDelta kTinyTimeout = base::Milliseconds(100);
    int max_try = 50;
    while (counter() < target_value) {
      base::PlatformThread::Sleep(kTinyTimeout);
      base::RunLoop().RunUntilIdle();
      if (--max_try == 0)
        return false;
    }
    return true;
  }

  uint32_t counter() const { return counter_; }

 private:
  uint32_t counter_ = 0;
};

TEST_F(FileChangeWatcherTest, FileChange) {
  base::FilePath mount_info;
  std::string test_string = "test";

  FileChangeWatcher* watcher = FileChangeWatcher::GetInstance();

  EXPECT_TRUE(base::CreateTemporaryFile(&mount_info));
  EXPECT_TRUE(watcher->AddWatch(mount_info, this));

  // Open the temporary file and write something twice.
  {
    // Open
    base::File file(mount_info, base::File::FLAG_OPEN | base::File::FLAG_WRITE);
    base::RunLoop().RunUntilIdle();
    EXPECT_EQ(0u, counter());

    // Write
    uint32_t previous_counter = counter();
    EXPECT_EQ(file.WriteAtCurrentPos(test_string.c_str(), test_string.length()),
              test_string.length());
    EXPECT_TRUE(WaitForCounterValue(previous_counter + 1u));

    // Write (append)
    previous_counter = counter();
    EXPECT_EQ(file.WriteAtCurrentPos(test_string.c_str(), test_string.length()),
              test_string.length());
    EXPECT_TRUE(WaitForCounterValue(previous_counter + 1u));

    // Close
    previous_counter = counter();
    file.Close();
    base::RunLoop().RunUntilIdle();
    EXPECT_EQ(previous_counter, counter());
  }

  // Open the temporary file again and append something twice.
  {
    // Open
    uint32_t previous_counter = counter();
    base::File file(mount_info, base::File::FLAG_OPEN | base::File::FLAG_WRITE |
                                    base::File::FLAG_APPEND);
    base::RunLoop().RunUntilIdle();
    EXPECT_EQ(previous_counter, counter());

    // Write (append)
    previous_counter = counter();
    EXPECT_EQ(file.WriteAtCurrentPos(test_string.c_str(), test_string.length()),
              test_string.length());
    EXPECT_TRUE(WaitForCounterValue(previous_counter + 1u));

    // Close
    previous_counter = counter();
    file.Close();
    base::RunLoop().RunUntilIdle();
    EXPECT_EQ(previous_counter, counter());
  }

  watcher->RemoveWatch(mount_info);
}

}  // namespace croslog
