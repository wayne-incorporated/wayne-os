// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>
#include <string>
#include <vector>

#include <base/check.h>
#include <base/files/file_path.h>
#include <base/files/scoped_temp_dir.h>
#include <base/logging.h>
#include <base/run_loop.h>
#include <base/task/single_thread_task_executor.h>
#include <base/task/single_thread_task_runner.h>
#include <gtest/gtest.h>

#include "brillo/grpc/async_grpc_server.h"
#include "test_rpcs.grpc.pb.h"  // NOLINT(build/include_directory)

namespace brillo {

namespace {

std::string MakeGrpcUri(const base::FilePath& socket_path) {
  return "unix:" + socket_path.value();
}

}  // namespace

// Simple smoke tests for AsyncGrpcServer.
class AsyncGrpcServerTest : public ::testing::Test {
 public:
  AsyncGrpcServerTest() = default;
  AsyncGrpcServerTest(const AsyncGrpcServerTest&) = delete;
  AsyncGrpcServerTest& operator=(const AsyncGrpcServerTest&) = delete;

  void SetUp() override { ASSERT_TRUE(temp_dir_.CreateUniqueTempDir()); }

  void TearDown() override {
    if (server_) {
      BlockingShutdownServer();
      server_.reset();
    }
  }

  base::FilePath GetTempPath() const { return temp_dir_.GetPath(); }

  void CreateServer(const std::string& service_uri) {
    DCHECK(!server_);
    server_ = std::make_unique<
        AsyncGrpcServer<test_rpcs::ExampleService::AsyncService>>(
        base::SingleThreadTaskRunner::GetCurrentDefault(),
        std::vector<std::string>{service_uri});
  }

  void DestroyServer() {
    DCHECK(server_);
    server_.reset();
  }

  AsyncGrpcServer<test_rpcs::ExampleService::AsyncService>* server() {
    return server_.get();
  }

 private:
  void BlockingShutdownServer() {
    base::RunLoop loop;
    server_->ShutDown(loop.QuitClosure());
    loop.Run();
  }

  base::SingleThreadTaskExecutor task_executor_{base::MessagePumpType::IO};
  base::ScopedTempDir temp_dir_;
  std::unique_ptr<AsyncGrpcServer<test_rpcs::ExampleService::AsyncService>>
      server_;
};

// Test that the server gets successfully started on the given socket file path.
TEST_F(AsyncGrpcServerTest, Basic) {
  CreateServer(MakeGrpcUri(GetTempPath().AppendASCII("testing_socket")));
  EXPECT_TRUE(server()->Start());
}

// Test that the server may be destroyed without using ShutDown() when the
// server has not been started.
TEST_F(AsyncGrpcServerTest, SkippingShutdownWhenNotStarted) {
  CreateServer(MakeGrpcUri(GetTempPath().AppendASCII("testing_socket")));
  DestroyServer();
}

// Test that the server fails to start when the socket file cannot be created
// due to a non-existing directory in the path.
TEST_F(AsyncGrpcServerTest, ErrorUnavailablePath) {
  CreateServer(MakeGrpcUri(GetTempPath()
                               .AppendASCII("non_existing_directory")
                               .AppendASCII("testing_socket")));
  EXPECT_FALSE(server()->Start());
}

// Test that the server may be destroyed without using ShutDown() when the
// server startup failed (the failure is the same as in the ErrorUnavailablePath
// test).
TEST_F(AsyncGrpcServerTest, ErrorUnavailablePathSkippingShutdown) {
  CreateServer(MakeGrpcUri(GetTempPath()
                               .AppendASCII("non_existing_directory")
                               .AppendASCII("testing_socket")));
  EXPECT_FALSE(server()->Start());
  DestroyServer();
}

}  // namespace brillo
