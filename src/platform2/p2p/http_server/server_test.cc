// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "p2p/http_server/server.h"

#include <arpa/inet.h>
#include <fcntl.h>
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
#include <base/notreached.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>
#include <base/synchronization/condition_variable.h>
#include <base/threading/simple_thread.h>
#include <gtest/gtest.h>

#include "p2p/common/constants.h"
#include "p2p/common/server_message.h"
#include "p2p/common/struct_serializer.h"
#include "p2p/common/testutil.h"
#include "p2p/common/util.h"
#include "p2p/http_server/connection_delegate.h"
#include "p2p/http_server/fake_connection_delegate.h"

using std::string;
using std::tuple;
using std::vector;

using base::FilePath;

using p2p::constants::kBytesPerMB;
using p2p::testutil::RunGMainLoopMaxIterations;
using p2p::testutil::RunGMainLoopUntil;
using p2p::testutil::SetupTestDir;
using p2p::testutil::TeardownTestDir;
using p2p::util::P2PServerMessage;
using p2p::util::StructSerializerWatcher;

namespace p2p {

namespace http_server {

static void OnMessageReceivedAppend(const P2PServerMessage& msg,
                                    void* user_data) {
  vector<string>* messages = reinterpret_cast<vector<string>*>(user_data);
  EXPECT_TRUE(ValidP2PServerMessageMagic(msg));
  messages->push_back(ToString(msg));
}

static int ConnectToLocalPort(uint16_t port) {
  int sock = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_TCP);
  if (sock == -1) {
    PLOG(ERROR) << "Creating a client socket()";
    NOTREACHED();
  }

  struct sockaddr_in server_addr;
  memset(reinterpret_cast<char*>(&server_addr), 0, sizeof(server_addr));
  server_addr.sin_family = AF_INET;
  server_addr.sin_port = htons(port);
  server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");

  if (connect(sock, reinterpret_cast<struct sockaddr*>(&server_addr),
              sizeof(server_addr)) == -1) {
    PLOG(ERROR) << "Connecting to localhost:" << port;
    NOTREACHED();
  }
  return sock;
}

// Implements a barrier that blocks until |n| threads call Wait() and then
// releases them all.
class Barrier {
 public:
  explicit Barrier(int n) : n_(n), cond_(&lock_) {}
  Barrier(const Barrier&) = delete;
  Barrier& operator=(const Barrier&) = delete;

  // Wait on the barrier. This function is thread-safe.
  void Wait() {
    lock_.Acquire();
    n_--;
    // Any call to wait after |n_| reaches 0 will not block.
    if (n_ <= 0) {
      cond_.Broadcast();
    } else {
      while (n_ > 0)
        cond_.Wait();
    }
    lock_.Release();
  }

 private:
  int n_;
  base::Lock lock_;
  base::ConditionVariable cond_;
};

TEST(P2PHttpServer, InvalidDirectoryFails) {
  FilePath testdir_path("/path/to/invalid/directory");
  Server server(testdir_path, 0, STDOUT_FILENO,
                FakeConnectionDelegate::Construct);
  EXPECT_FALSE(server.Start());
}

TEST(P2PHttpServer, AlreadyUsedPortFails) {
  FilePath testdir_path = SetupTestDir("reuse-port");
  int dev_null = open("/dev/null", O_RDWR);
  EXPECT_NE(dev_null, -1);

  // Create a server on a port number provided by the kernel.
  Server server1(testdir_path, 0, dev_null, FakeConnectionDelegate::Construct);
  EXPECT_TRUE(server1.Start());
  EXPECT_NE(server1.Port(), 0);

  // Attempt to create a server on the same port must fail.
  Server server2(testdir_path, server1.Port(), dev_null,
                 FakeConnectionDelegate::Construct);
  EXPECT_FALSE(server2.Start());

  // Stop the first server allows the second server to run. This ensures that
  // we are closing the sockets properly on Stop().
  server1.Stop();
  EXPECT_TRUE(server2.Start());
  server2.Stop();

  close(dev_null);
  TeardownTestDir(testdir_path);
}

TEST(P2PHttpServer, ReportServerMessageTest) {
  FilePath testdir_path = SetupTestDir("basic");

  // Redirect the ServerMessage to a pipe to verify the contents.
  // (requires the GLib main loop).
  vector<string> messages;
  int pipefd[2];
  ASSERT_EQ(0, pipe(pipefd));
  StructSerializerWatcher<P2PServerMessage> watch(
      pipefd[0], OnMessageReceivedAppend, reinterpret_cast<void*>(&messages));

  // Bring up the HTTP server.
  Server server(testdir_path, 0, pipefd[1], FakeConnectionDelegate::Construct);
  EXPECT_TRUE(server.Start());

  // Connect and disconnect a client. This doesn't block (at least accepts 1
  // connection).
  int sock = ConnectToLocalPort(server.Port());
  RunGMainLoopMaxIterations(100);
  EXPECT_EQ(0, close(sock));
  RunGMainLoopMaxIterations(100);
  server.Stop();
  RunGMainLoopMaxIterations(100);

  TeardownTestDir(testdir_path);

  // Check the messages reported by the Server.
  ASSERT_EQ(messages.size(), 4);
  EXPECT_TRUE(base::StartsWith(
      messages[0], "{PortNumber: ", base::CompareCase::INSENSITIVE_ASCII));
  EXPECT_EQ(messages[1], "{NumConnections: 1}");
  EXPECT_EQ(messages[2], "{ClientCount: 1}");
  EXPECT_EQ(messages[3], "{NumConnections: 0}");

  EXPECT_EQ(0, close(pipefd[0]));
  EXPECT_EQ(0, close(pipefd[1]));
}

// ------------------------------------------------------------------------

static const int kMultipleTestNumConnections = 5;

class MultipleClientThread : public base::SimpleThread {
 public:
  MultipleClientThread(uint16_t port,
                       int id,
                       ServerInterface* server,
                       Barrier* pre_check,
                       Barrier* post_check)
      : base::SimpleThread("test-multiple", base::SimpleThread::Options()),
        port_(port),
        id_(id),
        server_(server),
        pre_check_(pre_check),
        post_check_(post_check) {}
  MultipleClientThread(const MultipleClientThread&) = delete;
  MultipleClientThread& operator=(const MultipleClientThread&) = delete;

 private:
  void Run() override {
    // Connect to the Server and wait until all the threads reached that point.
    int sock = ConnectToLocalPort(port_);
    ASSERT_NE(-1, sock);

    EXPECT_EQ(5, write(sock, "ping\n", 5));
    char msg[5];
    EXPECT_EQ(5, read(sock, msg, 5));
    EXPECT_EQ(0, memcmp(msg, "pong\n", 5));

    pre_check_->Wait();
    // At this point the server is not handling any request since all the
    // threads passed the pre_check point. We check the test conditions only
    // in one thread (id == 0)
    if (id_ == 0) {
      EXPECT_EQ(server_->NumConnections(), kMultipleTestNumConnections);
    }

    post_check_->Wait();
    // Instruct the server to finish and wait until it closes the socket.
    EXPECT_EQ(5, write(sock, "quit\n", 5));
    EXPECT_EQ(0, read(sock, msg, 1));
    close(sock);
  }

  uint16_t port_;
  int id_;
  ServerInterface* server_;
  Barrier* pre_check_;
  Barrier* post_check_;
};

bool ConnectionsReached(ServerInterface* server, int conns) {
  return server->NumConnections() >= conns;
}

// This test verifies that the Server can handle multiple simultaneous
// connections up to |kMultipleTestNumConnections|.
TEST(P2PHttpServer, MultipleConnections) {
  FilePath testdir_path = SetupTestDir("multiple");
  int dev_null = open("/dev/null", O_RDWR);
  EXPECT_NE(dev_null, -1);

  // Bring up the HTTP server.
  Server server(testdir_path, 0, dev_null, FakeConnectionDelegate::Construct);
  EXPECT_TRUE(server.Start());

  // Start N threads, one for each connection.
  Barrier pre_check(kMultipleTestNumConnections);
  Barrier post_check(kMultipleTestNumConnections);
  vector<MultipleClientThread*> threads;
  for (int n = 0; n < kMultipleTestNumConnections; n++) {
    MultipleClientThread* thread = new MultipleClientThread(
        server.Port(), n, &server, &pre_check, &post_check);
    thread->Start();
    threads.push_back(thread);
  }

  // Run the main loop until all the connections are established. After that,
  // there's no need to run the main loop, all the work is done by the
  // ConnectionDelegate threads.
  RunGMainLoopUntil(30000, base::BindRepeating(&ConnectionsReached, &server,
                                               kMultipleTestNumConnections));

  // Wait for all threads to finish the work.
  for (auto& t : threads) {
    t->Join();
    delete t;
  }
  EXPECT_EQ(server.NumConnections(), 0);

  // Cleanup
  server.Stop();
  close(dev_null);
  TeardownTestDir(testdir_path);
}

}  // namespace http_server

}  // namespace p2p
