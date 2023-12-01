// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "p2p/server/peer_update_manager.h"

#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <string>

#include <base/logging.h>
#include <metrics/metrics_library_mock.h>

#include "p2p/common/testutil.h"
#include "p2p/server/fake_file_watcher.h"
#include "p2p/server/mock_http_server.h"
#include "p2p/server/mock_service_publisher.h"

using testing::_;
using testing::AtLeast;
using testing::StrictMock;

using base::FilePath;

using p2p::testutil::kDefaultMainLoopTimeoutMs;
using p2p::testutil::RunGMainLoopMaxIterations;
using p2p::testutil::SetupTestDir;
using p2p::testutil::TeardownTestDir;

namespace p2p {

namespace server {

// If there are no files present, ensure that we don't publish
// anything and don't start the HTTP server.
TEST(PeerUpdateManager, NoFilesPresent) {
  FilePath testdir = SetupTestDir("no-files-present");

  StrictMock<MockHttpServer> server;
  StrictMock<MockServicePublisher> publisher;
  StrictMock<MetricsLibraryMock> metrics_lib;
  FakeFileWatcher watcher(testdir, ".p2p");

  EXPECT_CALL(server, SetNumConnectionsCallback(_));
  EXPECT_CALL(publisher, files()).Times(AtLeast(0));

  PeerUpdateManager manager(&watcher, &publisher, &server, &metrics_lib);
  manager.Init();

  EXPECT_LT(RunGMainLoopMaxIterations(100), 100);

  TeardownTestDir(testdir);
}

// If there are files present at startup, ensure that we publish them
// and start the HTTP server.
TEST(PeerUpdateManager, FilesPresent) {
  FilePath testdir = SetupTestDir("files-present");

  StrictMock<MockHttpServer> server;
  StrictMock<MockServicePublisher> publisher;
  StrictMock<MetricsLibraryMock> metrics_lib;

  FakeFileWatcher watcher(testdir, ".p2p");
  ASSERT_TRUE(watcher.AddFile(testdir.Append("a.p2p"), 0));
  ASSERT_TRUE(watcher.AddFile(testdir.Append("b.p2p"), 0));
  ASSERT_TRUE(watcher.AddFile(testdir.Append("c.p2p"), 3));

  EXPECT_CALL(server, SetNumConnectionsCallback(_));
  EXPECT_CALL(publisher, files()).Times(AtLeast(0));

  EXPECT_CALL(publisher, AddFile("a", 0));
  EXPECT_CALL(publisher, AddFile("b", 0));
  EXPECT_CALL(publisher, AddFile("c", 3));

  EXPECT_CALL(server, IsRunning()).Times((AtLeast(1)));
  EXPECT_CALL(server, Start());

  // Process all the pending file additions before the manager gets notified.
  EXPECT_LT(RunGMainLoopMaxIterations(100), 100);

  PeerUpdateManager manager(&watcher, &publisher, &server, &metrics_lib);
  manager.Init();

  // Run the main loop to process the manager actions.
  EXPECT_LT(RunGMainLoopMaxIterations(100), 100);

  TeardownTestDir(testdir);
}

// If there are files present at startup and we remove one of them,
// check that the one we remove is subsequently removed from the publisher.
TEST(PeerUpdateManager, RemoveFile) {
  FilePath testdir = SetupTestDir("remove-file");

  StrictMock<MockHttpServer> server;
  StrictMock<MockServicePublisher> publisher;
  StrictMock<MetricsLibraryMock> metrics_lib;

  FakeFileWatcher watcher(testdir, ".p2p");
  ASSERT_TRUE(watcher.AddFile(testdir.Append("a.p2p"), 0));
  ASSERT_TRUE(watcher.AddFile(testdir.Append("b.p2p"), 0));
  ASSERT_TRUE(watcher.AddFile(testdir.Append("c.p2p"), 3));

  EXPECT_CALL(server, SetNumConnectionsCallback(_));
  EXPECT_CALL(publisher, files()).Times(AtLeast(0));

  EXPECT_CALL(publisher, AddFile("a", 0));
  EXPECT_CALL(publisher, AddFile("b", 0));
  EXPECT_CALL(publisher, AddFile("c", 3));
  EXPECT_CALL(publisher, RemoveFile("c"));

  EXPECT_CALL(server, IsRunning()).Times((AtLeast(1)));
  EXPECT_CALL(server, Start());

  // Process all the pending file additions before the manager gets notified.
  EXPECT_LT(RunGMainLoopMaxIterations(100), 100);

  PeerUpdateManager manager(&watcher, &publisher, &server, &metrics_lib);
  manager.Init();

  EXPECT_CALL(metrics_lib, SendToUMA("P2P.Server.FileCount", 2, _, _, _));
  ASSERT_TRUE(watcher.RemoveFile(testdir.Append("c.p2p")));

  EXPECT_LT(RunGMainLoopMaxIterations(100), 100);

  TeardownTestDir(testdir);
}

// If there are files present at startup and we remove all of them,
// check that they're removed and the HTTP server is stopped.
TEST(PeerUpdateManager, RemoveLastFile) {
  FilePath testdir = SetupTestDir("remove-file");

  StrictMock<MockHttpServer> server;
  StrictMock<MockServicePublisher> publisher;
  StrictMock<MetricsLibraryMock> metrics_lib;

  FakeFileWatcher watcher(testdir, ".p2p");
  ASSERT_TRUE(watcher.AddFile(testdir.Append("a.p2p"), 0));
  ASSERT_TRUE(watcher.AddFile(testdir.Append("b.p2p"), 0));

  EXPECT_CALL(server, SetNumConnectionsCallback(_));
  EXPECT_CALL(publisher, files()).Times(AtLeast(0));

  EXPECT_CALL(publisher, AddFile("a", 0));
  EXPECT_CALL(publisher, AddFile("b", 0));
  EXPECT_CALL(publisher, RemoveFile("b"));
  EXPECT_CALL(publisher, RemoveFile("a"));

  EXPECT_CALL(server, IsRunning()).Times((AtLeast(1)));
  EXPECT_CALL(server, Start());
  EXPECT_CALL(server, Stop());

  // Process all the pending file additions before the manager gets notified.
  EXPECT_LT(RunGMainLoopMaxIterations(100), 100);

  PeerUpdateManager manager(&watcher, &publisher, &server, &metrics_lib);
  manager.Init();

  EXPECT_CALL(metrics_lib, SendToUMA("P2P.Server.FileCount", 1, _, _, _));
  EXPECT_CALL(metrics_lib, SendToUMA("P2P.Server.FileCount", 0, _, _, _));

  ASSERT_TRUE(watcher.RemoveFile(testdir.Append("a.p2p")));
  ASSERT_TRUE(watcher.RemoveFile(testdir.Append("b.p2p")));

  // Run the main loop to process the manager actions.
  EXPECT_LT(RunGMainLoopMaxIterations(100), 100);

  TeardownTestDir(testdir);
}

// Check that we propagate number of connections to the publisher.
TEST(PeerUpdateManager, HttpNumConnections) {
  FilePath testdir = SetupTestDir("http-num-connections");

  StrictMock<MockHttpServer> server;
  StrictMock<MockServicePublisher> publisher;
  StrictMock<MetricsLibraryMock> metrics_lib;

  FakeFileWatcher watcher(testdir, ".p2p");
  ASSERT_TRUE(watcher.AddFile(testdir.Append("a.p2p"), 5));

  EXPECT_CALL(server, SetNumConnectionsCallback(_));
  EXPECT_CALL(publisher, files()).Times(AtLeast(0));

  EXPECT_CALL(publisher, AddFile("a", 5));

  EXPECT_CALL(server, IsRunning()).Times((AtLeast(1)));
  EXPECT_CALL(server, Start());

  EXPECT_CALL(publisher, SetNumConnections(1));
  EXPECT_CALL(publisher, SetNumConnections(2));
  EXPECT_CALL(publisher, SetNumConnections(5));
  EXPECT_CALL(publisher, SetNumConnections(0));

  // Process all the pending file additions before the manager gets notified.
  EXPECT_LT(RunGMainLoopMaxIterations(100), 100);

  PeerUpdateManager manager(&watcher, &publisher, &server, &metrics_lib);
  manager.Init();

  server.fake().SetNumConnections(1);
  server.fake().SetNumConnections(2);
  server.fake().SetNumConnections(5);
  server.fake().SetNumConnections(0);

  // Run the main loop to process the manager actions.
  EXPECT_LT(RunGMainLoopMaxIterations(100), 100);

  TeardownTestDir(testdir);
}

}  // namespace server

}  // namespace p2p
