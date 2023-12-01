// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "dlp/fanotify_watcher.h"

#include <memory>
#include <utility>

#include "base/files/file.h"
#include "base/files/file_path.h"
#include "base/files/file_util.h"
#include "base/functional/bind.h"
#include "base/run_loop.h"
#include "base/task/post_task.h"
#include "base/test/task_environment.h"
#include "gtest/gtest.h"

namespace dlp {

namespace {

bool DoOpen(base::FilePath file_path) {
  base::File file(file_path, base::File::FLAG_OPEN | base::File::FLAG_WRITE);
  return file.IsValid();
}

class FileOpenTester {
 public:
  explicit FileOpenTester(base::FilePath file_path) : file_path_(file_path) {}
  ~FileOpenTester() = default;

  bool CanOpen() {
    base::ThreadPool::PostTaskAndReplyWithResult(
        FROM_HERE, {base::MayBlock()}, base::BindOnce(&DoOpen, file_path_),
        base::BindOnce(&FileOpenTester::OnOpenResult, base::Unretained(this)));
    run_loop_.Run();
    return could_open_;
  }

 private:
  void OnOpenResult(bool result) {
    could_open_ = result;
    run_loop_.Quit();
  }

  base::FilePath file_path_;
  base::RunLoop run_loop_;
  bool could_open_ = false;
};

}  // namespace

class FanotifyWatcherTest : public ::testing::Test,
                            public FanotifyWatcher::Delegate {
 public:
  FanotifyWatcherTest() = default;
  FanotifyWatcherTest(const FanotifyWatcherTest&) = delete;
  FanotifyWatcherTest& operator=(const FanotifyWatcherTest&) = delete;
  ~FanotifyWatcherTest() override = default;

  void ProcessFileOpenRequest(
      ino_t inode, int pid, base::OnceCallback<void(bool)> callback) override {
    counter_++;
    std::move(callback).Run(file_open_allowed_);
  }

  uint32_t counter() const { return counter_; }

 protected:
  base::test::TaskEnvironment task_environment_;
  bool file_open_allowed_ = true;

 private:
  uint32_t counter_ = 0;
};

TEST_F(FanotifyWatcherTest, RunAsRoot_FileOpenAllowed) {
  base::FilePath temp_file;
  std::unique_ptr<FanotifyWatcher> watcher =
      std::make_unique<FanotifyWatcher>(this);

  EXPECT_TRUE(base::CreateTemporaryFile(&temp_file));
  watcher->AddWatch(temp_file);

  // Open the temporary file.
  uint32_t old_counter = counter();
  EXPECT_TRUE(FileOpenTester(temp_file).CanOpen());
  EXPECT_GE(counter(), old_counter + 1);
}

TEST_F(FanotifyWatcherTest, RunAsRoot_FileOpenNotAllowed) {
  base::FilePath temp_file;
  std::unique_ptr<FanotifyWatcher> watcher =
      std::make_unique<FanotifyWatcher>(this);

  EXPECT_TRUE(base::CreateTemporaryFile(&temp_file));
  watcher->AddWatch(temp_file);

  file_open_allowed_ = false;

  // Open the temporary file.
  uint32_t old_counter = counter();
  EXPECT_FALSE(FileOpenTester(temp_file).CanOpen());
  EXPECT_GE(counter(), old_counter + 1);
}

}  // namespace dlp
