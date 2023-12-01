// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "p2p/server/file_watcher.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <glib-object.h>
#include <stdarg.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <cctype>
#include <cinttypes>
#include <iostream>
#include <string>
#include <tuple>
#include <vector>

#include <base/command_line.h>
#include <base/files/file_path.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/strings/stringprintf.h>
#include <base/threading/simple_thread.h>
#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include "p2p/common/testutil.h"

using std::vector;

using base::BindRepeating;
using base::FilePath;
using base::Unretained;

using testing::_;
using testing::StrictMock;

using p2p::testutil::kDefaultMainLoopTimeoutMs;
using p2p::testutil::RunGMainLoopUntil;
using p2p::testutil::SetupTestDir;
using p2p::testutil::TeardownTestDir;

namespace p2p {

namespace server {

// ------------------------------------------------------------------------

class FileWatcherListener {
 public:
  explicit FileWatcherListener(FileWatcher* file_watcher) {
    file_watcher->SetChangedCallback(
        BindRepeating(&FileWatcherListener::OnChanged, Unretained(this)));
  }
  FileWatcherListener(const FileWatcherListener&) = delete;
  FileWatcherListener& operator=(const FileWatcherListener&) = delete;

  virtual void OnChanged(const FilePath& file,
                         FileWatcher::EventType event_type) = 0;
};

class MockFileWatcherListener : public FileWatcherListener {
 public:
  explicit MockFileWatcherListener(FileWatcher* file_watcher)
      : FileWatcherListener(file_watcher), num_calls_(0) {
    ON_CALL(*this, OnChanged(_, _))
        .WillByDefault(
            testing::InvokeWithoutArgs(this, &MockFileWatcherListener::OnCall));
  }
  MockFileWatcherListener(const MockFileWatcherListener&) = delete;
  MockFileWatcherListener& operator=(const MockFileWatcherListener&) = delete;

  MOCK_METHOD(void,
              OnChanged,
              (const FilePath&, FileWatcher::EventType),
              (override));

  // NumCallsReached() returns true when the number of calls to |this|
  // is at least |num_calls|. This is used to terminate the GLib main loop
  // excecution and verify the expectations.
  bool NumCallsReached(int num_calls) const { return num_calls_ >= num_calls; }

 private:
  void OnCall() { num_calls_++; }

  int num_calls_;
};

// ------------------------------------------------------------------------

// Check that we detect that files are added - this should result in
// two events, one for the file creation event and one for the
// change event that results in touch(1) updating the timestamp.
TEST(FileWatcher, TouchNonExisting) {
  FilePath testdir = SetupTestDir("filewatcher-touch-non-existing");

  FileWatcher* watcher = FileWatcher::Construct(testdir, ".p2p");

  {
    vector<FilePath> expected_files;
    EXPECT_EQ(watcher->files(), expected_files);
  }

  StrictMock<MockFileWatcherListener> listener(watcher);
  EXPECT_CALL(listener, OnChanged(testdir.Append("file.p2p"),
                                  FileWatcher::EventType::kFileAdded));
  EXPECT_CALL(listener, OnChanged(testdir.Append("file.p2p"),
                                  FileWatcher::EventType::kFileChanged));
  EXPECT_COMMAND(0, "touch %s", testdir.Append("file.p2p").value().c_str());

  // At this point, all the events should be generated, but the directory
  // watcher could be implemented using polling.
  RunGMainLoopUntil(kDefaultMainLoopTimeoutMs,
                    BindRepeating(&MockFileWatcherListener::NumCallsReached,
                                  Unretained(&listener), 2 /* num_calls */));

  {
    vector<FilePath> expected_files;
    expected_files.push_back(testdir.Append("file.p2p"));
    EXPECT_EQ(watcher->files(), expected_files);
  }

  delete watcher;
  TeardownTestDir(testdir);
}

// Check that we detect when a timestamp is updated on an existing
// file that we monitor - this should result in a single event.
TEST(FileWatcher, TouchExisting) {
  FilePath testdir = SetupTestDir("filewatcher-touch-existing");
  EXPECT_COMMAND(0, "touch %s", testdir.Append("existing.p2p").value().c_str());

  FileWatcher* watcher = FileWatcher::Construct(testdir, ".p2p");

  {
    vector<FilePath> expected_files;
    expected_files.push_back(testdir.Append("existing.p2p"));
    EXPECT_EQ(watcher->files(), expected_files);
  }

  StrictMock<MockFileWatcherListener> listener(watcher);
  EXPECT_CALL(listener, OnChanged(testdir.Append("existing.p2p"),
                                  FileWatcher::EventType::kFileChanged));
  EXPECT_COMMAND(0, "touch %s", testdir.Append("existing.p2p").value().c_str());

  RunGMainLoopUntil(kDefaultMainLoopTimeoutMs,
                    BindRepeating(&MockFileWatcherListener::NumCallsReached,
                                  Unretained(&listener), 1 /* num_calls */));

  {
    vector<FilePath> expected_files;
    expected_files.push_back(testdir.Append("existing.p2p"));
    EXPECT_EQ(watcher->files(), expected_files);
  }

  delete watcher;
  TeardownTestDir(testdir);
}

// Check that we detect when a file has been written to.
TEST(FileWatcher, CreateFile) {
  FilePath testdir = SetupTestDir("filewatcher-create-file");

  FileWatcher* watcher = FileWatcher::Construct(testdir, ".p2p");

  {
    vector<FilePath> expected_files;
    EXPECT_EQ(watcher->files(), expected_files);
  }

  StrictMock<MockFileWatcherListener> listener(watcher);
  EXPECT_CALL(listener, OnChanged(testdir.Append("new-file.p2p"),
                                  FileWatcher::EventType::kFileAdded));
  EXPECT_CALL(listener, OnChanged(testdir.Append("new-file.p2p"),
                                  FileWatcher::EventType::kFileChanged));
  EXPECT_COMMAND(0, "dd if=/dev/zero of=%s bs=1000 count=1",
                 testdir.Append("new-file.p2p").value().c_str());

  RunGMainLoopUntil(kDefaultMainLoopTimeoutMs,
                    BindRepeating(&MockFileWatcherListener::NumCallsReached,
                                  Unretained(&listener), 2 /* num_calls */));

  {
    vector<FilePath> expected_files;
    expected_files.push_back(testdir.Append("new-file.p2p"));
    EXPECT_EQ(watcher->files(), expected_files);
  }

  delete watcher;
  TeardownTestDir(testdir);
}

// Check that we detect when data is appended to a file.
TEST(FileWatcher, AppendToFile) {
  FilePath testdir = SetupTestDir("filewatcher-append-to-file");
  EXPECT_COMMAND(0, "touch %s", testdir.Append("existing.p2p").value().c_str());

  FileWatcher* watcher = FileWatcher::Construct(testdir, ".p2p");

  {
    vector<FilePath> expected_files;
    expected_files.push_back(testdir.Append("existing.p2p"));
    EXPECT_EQ(watcher->files(), expected_files);
  }

  StrictMock<MockFileWatcherListener> listener(watcher);
  EXPECT_CALL(listener, OnChanged(testdir.Append("existing.p2p"),
                                  FileWatcher::EventType::kFileChanged));
  EXPECT_COMMAND(0, "echo -n xyz >> %s",
                 testdir.Append("existing.p2p").value().c_str());

  RunGMainLoopUntil(kDefaultMainLoopTimeoutMs,
                    BindRepeating(&MockFileWatcherListener::NumCallsReached,
                                  Unretained(&listener), 1 /* num_calls */));

  {
    vector<FilePath> expected_files;
    expected_files.push_back(testdir.Append("existing.p2p"));
    EXPECT_EQ(watcher->files(), expected_files);
  }

  delete watcher;
  TeardownTestDir(testdir);
}

// Check that we detect when a file is removed - this should result
// in a single event.
TEST(FileWatcher, RemoveFile) {
  FilePath testdir = SetupTestDir("filewatcher-remove-file");
  EXPECT_COMMAND(0, "touch %s", testdir.Append("file.p2p").value().c_str());

  FileWatcher* watcher = FileWatcher::Construct(testdir, ".p2p");

  {
    vector<FilePath> expected_files;
    expected_files.push_back(testdir.Append("file.p2p"));
    EXPECT_EQ(watcher->files(), expected_files);
  }

  StrictMock<MockFileWatcherListener> listener(watcher);
  EXPECT_CALL(listener, OnChanged(testdir.Append("file.p2p"),
                                  FileWatcher::EventType::kFileRemoved));
  EXPECT_COMMAND(0, "rm -f %s", testdir.Append("file.p2p").value().c_str());

  RunGMainLoopUntil(kDefaultMainLoopTimeoutMs,
                    BindRepeating(&MockFileWatcherListener::NumCallsReached,
                                  Unretained(&listener), 1 /* num_calls */));

  {
    vector<FilePath> expected_files;
    EXPECT_EQ(watcher->files(), expected_files);
  }

  delete watcher;
  TeardownTestDir(testdir);
}

// Check that we detect when a file is renamed into what we match - this
// should result in just a single event
TEST(FileWatcher, RenameInto) {
  FilePath testdir = SetupTestDir("filewatcher-rename-into");

  EXPECT_COMMAND(0, "touch %s", testdir.Append("bar.p2p.tmp").value().c_str());

  FileWatcher* watcher = FileWatcher::Construct(testdir, ".p2p");

  {
    vector<FilePath> expected_files;
    EXPECT_EQ(watcher->files(), expected_files);
  }

  StrictMock<MockFileWatcherListener> listener(watcher);
  EXPECT_CALL(listener, OnChanged(testdir.Append("bar.p2p"),
                                  FileWatcher::EventType::kFileAdded));
  EXPECT_COMMAND(0, "dd if=/dev/zero of=%s bs=100 count=10",
                 testdir.Append("bar.p2p.tmp").value().c_str());
  int rc = rename(testdir.Append("bar.p2p.tmp").value().c_str(),
                  testdir.Append("bar.p2p").value().c_str());
  EXPECT_EQ(rc, 0);

  RunGMainLoopUntil(kDefaultMainLoopTimeoutMs,
                    BindRepeating(&MockFileWatcherListener::NumCallsReached,
                                  Unretained(&listener), 1 /* num_calls */));

  {
    vector<FilePath> expected_files;
    expected_files.push_back(testdir.Append("bar.p2p"));
    EXPECT_EQ(watcher->files(), expected_files);
  }

  delete watcher;
  TeardownTestDir(testdir);
}

// Check that we get a Removed event when a file is renamed away
// from what we match
TEST(FileWatcher, RenameAway) {
  FilePath testdir = SetupTestDir("filewatcher-rename-away");

  EXPECT_COMMAND(0, "touch %s", testdir.Append("foo.p2p").value().c_str());

  FileWatcher* watcher = FileWatcher::Construct(testdir, ".p2p");

  {
    vector<FilePath> expected_files;
    expected_files.push_back(testdir.Append("foo.p2p"));
    EXPECT_EQ(watcher->files(), expected_files);
  }

  StrictMock<MockFileWatcherListener> listener(watcher);
  EXPECT_CALL(listener, OnChanged(testdir.Append("foo.p2p"),
                                  FileWatcher::EventType::kFileRemoved));
  int rc = rename(testdir.Append("foo.p2p").value().c_str(),
                  testdir.Append("foo.p2p.tmp").value().c_str());
  EXPECT_EQ(rc, 0);
  RunGMainLoopUntil(kDefaultMainLoopTimeoutMs,
                    BindRepeating(&MockFileWatcherListener::NumCallsReached,
                                  Unretained(&listener), 1 /* num_calls */));

  {
    vector<FilePath> expected_files;
    EXPECT_EQ(watcher->files(), expected_files);
  }

  delete watcher;
  TeardownTestDir(testdir);
}

// Check that it monitoring works even when there are existing files.
TEST(FileWatcher, ExistingFiles) {
  FilePath testdir = SetupTestDir("filewatcher-existing-files");
  EXPECT_COMMAND(0, "touch %s", testdir.Append("1.p2p").value().c_str());
  EXPECT_COMMAND(0, "touch %s", testdir.Append("2.p2p").value().c_str());
  EXPECT_COMMAND(0, "touch %s", testdir.Append("3.p2p").value().c_str());

  FileWatcher* watcher = FileWatcher::Construct(testdir, ".p2p");

  {
    vector<FilePath> expected_files;
    expected_files.push_back(testdir.Append("1.p2p"));
    expected_files.push_back(testdir.Append("2.p2p"));
    expected_files.push_back(testdir.Append("3.p2p"));
    EXPECT_EQ(watcher->files(), expected_files);
  }

  StrictMock<MockFileWatcherListener> listener(watcher);
  EXPECT_CALL(listener, OnChanged(testdir.Append("4.p2p"),
                                  FileWatcher::EventType::kFileAdded));
  EXPECT_CALL(listener, OnChanged(testdir.Append("4.p2p"),
                                  FileWatcher::EventType::kFileChanged));
  EXPECT_COMMAND(0, "touch %s", testdir.Append("4.p2p").value().c_str());

  RunGMainLoopUntil(kDefaultMainLoopTimeoutMs,
                    BindRepeating(&MockFileWatcherListener::NumCallsReached,
                                  Unretained(&listener), 2 /* num_calls */));

  {
    vector<FilePath> expected_files;
    expected_files.push_back(testdir.Append("1.p2p"));
    expected_files.push_back(testdir.Append("2.p2p"));
    expected_files.push_back(testdir.Append("3.p2p"));
    expected_files.push_back(testdir.Append("4.p2p"));
    EXPECT_EQ(watcher->files(), expected_files);
  }

  delete watcher;
  TeardownTestDir(testdir);
}

// Check that activity on non-matching files does not cause any events.
TEST(FileWatcher, ActivityOnNonMatchingFiles) {
  FilePath testdir = SetupTestDir("filewatcher-activity-non-matching");

  FileWatcher* watcher = FileWatcher::Construct(testdir, ".p2p");
  StrictMock<MockFileWatcherListener> listener(watcher);
  EXPECT_COMMAND(0, "touch %s",
                 testdir.Append("non-match.boo").value().c_str());

  // We use a second file to flag the test completion and ensure the event
  // from the non-match.boo file was processed and properly ignored.
  EXPECT_CALL(listener, OnChanged(testdir.Append("match.p2p"),
                                  FileWatcher::EventType::kFileAdded));
  EXPECT_CALL(listener, OnChanged(testdir.Append("match.p2p"),
                                  FileWatcher::EventType::kFileChanged));
  EXPECT_COMMAND(0, "touch %s", testdir.Append("match.p2p").value().c_str());

  RunGMainLoopUntil(kDefaultMainLoopTimeoutMs,
                    BindRepeating(&MockFileWatcherListener::NumCallsReached,
                                  Unretained(&listener), 2 /* num_calls */));
  delete watcher;
  TeardownTestDir(testdir);
}

// ------------------------------------------------------------------------

}  // namespace server

}  // namespace p2p
