// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// This is an integration test, testing AsyncGrpcClient and AsyncGrpcServer by
// sending messages between instances of the two classes.

#include <memory>
#include <queue>
#include <string>
#include <utility>
#include <vector>

#include <base/check.h>
#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <base/functional/bind.h>
#include <base/functional/callback.h>
#include <base/functional/callback_helpers.h>
#include <base/location.h>
#include <base/run_loop.h>
#include <base/task/single_thread_task_executor.h>
#include <base/task/single_thread_task_runner.h>
#include <gmock/gmock.h>
#include <grpcpp/grpcpp.h>
#include <gtest/gtest.h>

#include "brillo/grpc/async_grpc_client.h"
#include "brillo/grpc/async_grpc_constants.h"
#include "brillo/grpc/async_grpc_server.h"
#include "test_rpcs.grpc.pb.h"  // NOLINT(build/include_directory)

namespace brillo {

namespace {

// A utility for testing incoming RPCs. It exposes a handler callback through
// |GetRpcHandlerCallback|. This can be passed to
// |AsyncGrpcServer::RegisterRpcHandler|.
template <typename RequestType, typename ResponseType>
class PendingIncomingRpcQueue {
 public:
  using HandlerDoneCallback = base::OnceCallback<void(
      grpc::Status status, std::unique_ptr<ResponseType> response)>;
  using RpcHandlerCallback =
      base::RepeatingCallback<void(std::unique_ptr<RequestType> request,
                                   HandlerDoneCallback response_callback)>;

  // Holds information about an RPC that should be handled.
  struct PendingIncomingRpc {
    // The request of this RPC.
    std::unique_ptr<RequestType> request;
    // The callback which must be called to answer this RPC.
    HandlerDoneCallback handler_done_callback;
  };

  PendingIncomingRpcQueue() : weak_ptr_factory_(this) {}
  PendingIncomingRpcQueue(const PendingIncomingRpcQueue&) = delete;
  PendingIncomingRpcQueue& operator=(const PendingIncomingRpcQueue&) = delete;

  ~PendingIncomingRpcQueue() = default;

  // Returns a callback that should be called when an incoming RPC is available.
  RpcHandlerCallback GetRpcHandlerCallback() {
    return base::BindRepeating(&PendingIncomingRpcQueue::HandleRpc,
                               weak_ptr_factory_.GetWeakPtr());
  }

  // Wait until there are |count| pending incoming RPCs of this type.
  void WaitUntilPendingRpcCount(size_t count) {
    while (pending_rpcs_.size() < count) {
      waiting_loop_ = std::make_unique<base::RunLoop>();
      waiting_loop_->Run();
    }
  }

  // Get the IncomingRpcContext for the oldest pending incoming RPC. May only be
  // called if there is at least one pending incoming RPC.
  std::unique_ptr<PendingIncomingRpc> GetOldestPendingRpc() {
    CHECK(!pending_rpcs_.empty());
    auto oldest_pending_rpc = std::move(pending_rpcs_.front());
    pending_rpcs_.pop();
    return oldest_pending_rpc;
  }

 private:
  // This is the actual handler function invoked on incoming RPCs.
  void HandleRpc(std::unique_ptr<RequestType> request,
                 HandlerDoneCallback handler_done_callback) {
    auto incoming_rpc = std::make_unique<PendingIncomingRpc>();
    incoming_rpc->request = std::move(request);
    incoming_rpc->handler_done_callback = std::move(handler_done_callback);
    pending_rpcs_.push(std::move(incoming_rpc));
    if (waiting_loop_)
      waiting_loop_->Quit();
  }

  // Holds information about all RPCs that this |PendingIncomingRpcQueue| was
  // asked to handle, but which have not been retrieved using
  // |GetOldestPendingRpc| yet.
  std::queue<std::unique_ptr<PendingIncomingRpc>> pending_rpcs_;
  // This |RunLoop| is started when waiting for (an) incoming RPC(s) and exited
  // when an RPC comes in.
  std::unique_ptr<base::RunLoop> waiting_loop_;

  base::WeakPtrFactory<PendingIncomingRpcQueue> weak_ptr_factory_;
};

// A utility for testing outgoing RPCs. It gets notified of a response to an
// outgoing RPC through the callback it returns from |MakeWriter|.
template <typename ResponseType>
class RpcReply {
 public:
  using ReplyCallback = base::OnceCallback<void(grpc::Status status,
                                                std::unique_ptr<ResponseType>)>;

  RpcReply() : weak_ptr_factory_(this) {}
  RpcReply(const RpcReply&) = delete;
  RpcReply& operator=(const RpcReply&) = delete;

  ~RpcReply() = default;

  // Returns a callback that should be called when a response to the outgoing
  // RPC is available.
  ReplyCallback MakeWriter() {
    return base::BindOnce(&RpcReply::OnReply, weak_ptr_factory_.GetWeakPtr());
  }

  // Wait until this RPC has a reply.
  void Wait() {
    if (has_reply_)
      return;

    waiting_loop_ = std::make_unique<base::RunLoop>();
    waiting_loop_->Run();
  }

  // Returns true if the reply indicated an error. This may only be called after
  // |Wait| returned.
  bool IsError() const {
    CHECK(has_reply_);
    return !status_.ok();
  }

  // Returns this outgoing RPC's response. This may only be called after
  // |Wait| returned and when |IsError| is false.
  const ResponseType& response() const {
    CHECK(!IsError());
    return *response_;
  }

 private:
  void OnReply(grpc::Status status, std::unique_ptr<ResponseType> response) {
    CHECK(!has_reply_);

    has_reply_ = true;
    response_ = std::move(response);
    status_ = std::move(status);

    if (waiting_loop_)
      waiting_loop_->Quit();
  }

  std::unique_ptr<base::RunLoop> waiting_loop_;
  bool has_reply_ = false;
  grpc::Status status_;
  std::unique_ptr<ResponseType> response_;

  base::WeakPtrFactory<RpcReply> weak_ptr_factory_;
};

// Implementation of test_rpcs.ExampleService that accumulates all RPC calls and
// allows to manually trigger responses to them.
class ManualExampleService final {
 public:
  explicit ManualExampleService(const std::vector<std::string>& server_uris)
      : server_(base::SingleThreadTaskRunner::GetCurrentDefault(),
                server_uris) {
    server_.RegisterHandler(
        &test_rpcs::ExampleService::AsyncService::RequestEmptyRpc,
        pending_empty_rpcs_.GetRpcHandlerCallback());
    server_.RegisterHandler(
        &test_rpcs::ExampleService::AsyncService::RequestEchoIntRpc,
        pending_echo_int_rpcs_.GetRpcHandlerCallback());
    server_.RegisterHandler(
        &test_rpcs::ExampleService::AsyncService::RequestHeavyRpc,
        pending_heavy_rpcs_.GetRpcHandlerCallback());
  }

  ManualExampleService(const ManualExampleService&) = delete;
  ManualExampleService& operator=(const ManualExampleService&) = delete;

  ~ManualExampleService() {
    if (in_shutdown_) {
      // Shutdown was already performed.
      return;
    }
    base::RunLoop run_loop;
    server_.ShutDown(run_loop.QuitClosure());
    run_loop.Run();
  }

  bool Start() { return server_.Start(); }

  void ShutDown(base::OnceClosure on_shutdown) {
    DCHECK(!in_shutdown_);
    in_shutdown_ = true;
    server_.ShutDown(std::move(on_shutdown));
  }

  PendingIncomingRpcQueue<test_rpcs::EmptyRpcRequest,
                          test_rpcs::EmptyRpcResponse>*
  pending_empty_rpcs() {
    return &pending_empty_rpcs_;
  }
  PendingIncomingRpcQueue<test_rpcs::EchoIntRpcRequest,
                          test_rpcs::EchoIntRpcResponse>*
  pending_echo_int_rpcs() {
    return &pending_echo_int_rpcs_;
  }
  PendingIncomingRpcQueue<test_rpcs::HeavyRpcRequest,
                          test_rpcs::HeavyRpcResponse>*
  pending_heavy_rpcs() {
    return &pending_heavy_rpcs_;
  }

 private:
  AsyncGrpcServer<test_rpcs::ExampleService::AsyncService> server_;
  bool in_shutdown_ = false;
  PendingIncomingRpcQueue<test_rpcs::EmptyRpcRequest,
                          test_rpcs::EmptyRpcResponse>
      pending_empty_rpcs_;
  PendingIncomingRpcQueue<test_rpcs::EchoIntRpcRequest,
                          test_rpcs::EchoIntRpcResponse>
      pending_echo_int_rpcs_;
  PendingIncomingRpcQueue<test_rpcs::HeavyRpcRequest,
                          test_rpcs::HeavyRpcResponse>
      pending_heavy_rpcs_;
};

// Implementation of test_rpcs.ExampleService that synchronously replies to the
// requests and triggers self-shutdown after receiving the first RPC call.
class SelfStoppingExampleService final {
 public:
  explicit SelfStoppingExampleService(
      const std::vector<std::string>& server_uris)
      : server_(base::SingleThreadTaskRunner::GetCurrentDefault(),
                server_uris) {
    server_.RegisterHandler(
        &test_rpcs::ExampleService::AsyncService::RequestEmptyRpc,
        base::BindRepeating(&SelfStoppingExampleService::OnEmptyRpc,
                            base::Unretained(this)));
  }

  SelfStoppingExampleService(const SelfStoppingExampleService&) = delete;
  SelfStoppingExampleService& operator=(const SelfStoppingExampleService&) =
      delete;

  ~SelfStoppingExampleService() {
    if (is_any_rpc_received_) {
      // Shut down was already performed on first RPC.
      // The test performing the RPC has the responsibility to wait until
      // shutdown finishes (through set_on_shutdown_callback).
      return;
    }
    base::RunLoop run_loop;
    server_.ShutDown(run_loop.QuitClosure());
    run_loop.Run();
  }

  bool Start() { return server_.Start(); }

  void set_on_shutdown_callback(base::OnceClosure on_shutdown) {
    on_shutdown_ = std::move(on_shutdown);
  }

 private:
  void OnEmptyRpc(std::unique_ptr<test_rpcs::EmptyRpcRequest>,
                  base::OnceCallback<void(
                      grpc::Status status,
                      std::unique_ptr<test_rpcs::EmptyRpcResponse> response)>
                      response_callback) {
    if (!is_any_rpc_received_) {
      is_any_rpc_received_ = true;
      ScheduleSelfShutDown();
    }
    std::move(response_callback)
        .Run(grpc::Status::OK, std::make_unique<test_rpcs::EmptyRpcResponse>());
  }

  void ScheduleSelfShutDown() {
    base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
        FROM_HERE,
        base::BindOnce(
            &AsyncGrpcServer<test_rpcs::ExampleService::AsyncService>::ShutDown,
            base::Unretained(&server_), std::move(on_shutdown_)));
  }

  AsyncGrpcServer<test_rpcs::ExampleService::AsyncService> server_;
  base::OnceClosure on_shutdown_;
  bool is_any_rpc_received_ = false;
};

}  // namespace

// Tests communication between |AsyncGrpcServer| and |AsyncGrpcClient| for the
// test_rpcs::ExampleService::AsyncService interface (defined in
// test_rpcs.proto).
class AsyncGrpcClientServerTest : public ::testing::Test {
 protected:
  AsyncGrpcClientServerTest() = default;
  AsyncGrpcClientServerTest(const AsyncGrpcClientServerTest&) = delete;
  AsyncGrpcClientServerTest& operator=(const AsyncGrpcClientServerTest&) =
      delete;

  void SetUp() override {
    ASSERT_TRUE(tmpdir_.CreateUniqueTempDir());

    // Create a temporary filename that's guaranteed to not exist, but is
    // inside our scoped directory so it'll get deleted later.
    // |tmpfile_| will be used as a unix domain socket to communicate between
    // the server and client used here.
    tmpfile_ = tmpdir_.GetPath().AppendASCII("testsocket");
  }

  ManualExampleService* manual_service() { return manual_service_.get(); }

  // Run an AsyncGrpcServer that accumulates all RPC calls and allows to
  // manually respond to them.
  void StartManualService() {
    manual_service_ = std::make_unique<ManualExampleService>(
        std::vector<std::string>{GetDomainSocketAddress()});
    ASSERT_TRUE(manual_service_->Start());
  }

  // Run an AsyncGrpcServer that shuts down itself after receiving the first RPC
  // call.
  void StartSelfStoppingService() {
    self_stopping_service_ = std::make_unique<SelfStoppingExampleService>(
        std::vector<std::string>{GetDomainSocketAddress()});
    ASSERT_TRUE(self_stopping_service_->Start());
  }

  // Create an AsyncGrpcClient.
  void CreateClient() {
    client_ = std::make_unique<AsyncGrpcClient<test_rpcs::ExampleService>>(
        task_executor_.task_runner(), GetDomainSocketAddress());
  }

  // Create an AsyncGrpcClient using the constructor that takes in a stub.
  void CreateClientConstructorFromStub() {
    grpc::ChannelArguments arguments;
    std::shared_ptr<grpc::Channel> channel = grpc::CreateCustomChannel(
        GetDomainSocketAddress(), grpc::InsecureChannelCredentials(),
        arguments);
    std::unique_ptr<test_rpcs::ExampleService::Stub> stub =
        test_rpcs::ExampleService::NewStub(channel);
    client_ = std::make_unique<AsyncGrpcClient<test_rpcs::ExampleService>>(
        task_executor_.task_runner(), std::move(stub));
  }

  // Create the second AsyncGrpcClient using the same socket, which has to be
  // shutdown by ShutDownSecondClient.
  void CreateSecondClient() {
    client2_ = std::make_unique<AsyncGrpcClient<test_rpcs::ExampleService>>(
        task_executor_.task_runner(), GetDomainSocketAddress());
  }

  // Shutdown the second AsyncGrpcClient.
  void ShutDownSecondClient() {
    base::RunLoop loop;
    client2_->ShutDown(loop.QuitClosure());
    loop.Run();
    // Explicitly delete client before server to avoid gRPC 1.6.1 "magic" 10
    // seconds hangs to delete grpc::CompletionQueue. It affects HeavyRpcData
    // test only.
    // TODO(b/132969701): remove when gRPC won't have hangs bug.
    client2_.reset();
  }

  void RestartManualService() {
    manual_service_.reset();
    StartManualService();
  }

  void TearDown() override {
    // Stop all clients and servers here, before deleting the temp dir that they
    // use.
    if (client2_)
      ShutDownSecondClient();
    if (client_)
      ShutDownClient();
    self_stopping_service_.reset();
    ShutDownManualService();
  }

  void ShutDownManualService() { manual_service_.reset(); }

  base::SingleThreadTaskExecutor task_executor_{base::MessagePumpType::IO};
  std::unique_ptr<ManualExampleService> manual_service_;
  std::unique_ptr<SelfStoppingExampleService> self_stopping_service_;
  std::unique_ptr<AsyncGrpcClient<test_rpcs::ExampleService>> client_;
  std::unique_ptr<AsyncGrpcClient<test_rpcs::ExampleService>> client2_;

 private:
  std::string GetDomainSocketAddress() { return "unix:" + tmpfile_.value(); }

  void ShutDownClient() {
    base::RunLoop loop;
    client_->ShutDown(loop.QuitClosure());
    loop.Run();
    // Explicitly delete client before server to avoid gRPC 1.6.1 "magic" 10
    // seconds hangs to delete grpc::CompletionQueue. It affects HeavyRpcData
    // test only.
    // TODO(b/132969701): remove when gRPC won't have hangs bug.
    client_.reset();
  }

  base::ScopedTempDir tmpdir_;
  base::FilePath tmpfile_;
};

// Start and shutdown a server and a client.
TEST_F(AsyncGrpcClientServerTest, NoRpcs) {
  StartManualService();
  CreateClient();
}

// Start and shutdown a server and a client using an alternate constructor.
TEST_F(AsyncGrpcClientServerTest, NoRpcsConstructedFromStub) {
  StartManualService();
  CreateClientConstructorFromStub();
}

// Send one RPC and verify that the response arrives at the client.
// Verifies that the response contains the data transferred in the request.
TEST_F(AsyncGrpcClientServerTest, OneRpcWithResponse) {
  StartManualService();
  CreateClient();

  RpcReply<test_rpcs::EchoIntRpcResponse> rpc_reply;
  test_rpcs::EchoIntRpcRequest request;
  request.set_int_to_echo(42);
  client_->CallRpc(&test_rpcs::ExampleService::Stub::AsyncEchoIntRpc, request,
                   rpc_reply.MakeWriter());

  manual_service()->pending_echo_int_rpcs()->WaitUntilPendingRpcCount(1);
  auto pending_rpc =
      manual_service()->pending_echo_int_rpcs()->GetOldestPendingRpc();
  EXPECT_EQ(42, pending_rpc->request->int_to_echo());

  auto response = std::make_unique<test_rpcs::EchoIntRpcResponse>();
  response->set_echoed_int(42);
  std::move(pending_rpc->handler_done_callback)
      .Run(grpc::Status::OK, std::move(response));

  rpc_reply.Wait();
  EXPECT_FALSE(rpc_reply.IsError());
  EXPECT_EQ(42, rpc_reply.response().echoed_int());
}

TEST_F(AsyncGrpcClientServerTest, MultipleRpcTypes) {
  StartManualService();
  CreateClient();

  RpcReply<test_rpcs::EchoIntRpcResponse> echo_int_rpc_reply;
  RpcReply<test_rpcs::EmptyRpcResponse> empty_rpc_reply;

  // Start two different RPC types:
  // - The EmptyRpc first
  // - The EchoIntRpc second
  test_rpcs::EmptyRpcRequest empty_rpc_request;
  client_->CallRpc(&test_rpcs::ExampleService::Stub::AsyncEmptyRpc,
                   empty_rpc_request, empty_rpc_reply.MakeWriter());

  test_rpcs::EchoIntRpcRequest echo_int_rpc_request;
  echo_int_rpc_request.set_int_to_echo(33);
  client_->CallRpc(&test_rpcs::ExampleService::Stub::AsyncEchoIntRpc,
                   echo_int_rpc_request, echo_int_rpc_reply.MakeWriter());

  // Respond to the EchoIntRpc and wait for the response
  manual_service()->pending_echo_int_rpcs()->WaitUntilPendingRpcCount(1);
  auto pending_echo_int_rpc =
      manual_service()->pending_echo_int_rpcs()->GetOldestPendingRpc();
  EXPECT_EQ(33, pending_echo_int_rpc->request->int_to_echo());
  auto echo_int_response = std::make_unique<test_rpcs::EchoIntRpcResponse>();
  echo_int_response->set_echoed_int(33);
  std::move(pending_echo_int_rpc->handler_done_callback)
      .Run(grpc::Status::OK, std::move(echo_int_response));

  echo_int_rpc_reply.Wait();
  EXPECT_FALSE(echo_int_rpc_reply.IsError());
  EXPECT_EQ(33, echo_int_rpc_reply.response().echoed_int());

  // Respond to the EmptyRpc and wait for the response
  manual_service()->pending_empty_rpcs()->WaitUntilPendingRpcCount(1);
  auto pending_empty_rpc =
      manual_service()->pending_empty_rpcs()->GetOldestPendingRpc();
  auto empty_rpc_response = std::make_unique<test_rpcs::EmptyRpcResponse>();
  std::move(pending_empty_rpc->handler_done_callback)
      .Run(grpc::Status::OK, std::move(empty_rpc_response));

  empty_rpc_reply.Wait();
  EXPECT_FALSE(empty_rpc_reply.IsError());
}

// Send one RPC, cancel it on the server side. Verify that the error arrives at
// the client.
TEST_F(AsyncGrpcClientServerTest, OneRpcExplicitCancellation) {
  StartManualService();
  CreateClient();

  RpcReply<test_rpcs::EmptyRpcResponse> rpc_reply;
  test_rpcs::EmptyRpcRequest request;
  client_->CallRpc(&test_rpcs::ExampleService::Stub::AsyncEmptyRpc, request,
                   rpc_reply.MakeWriter());

  manual_service()->pending_empty_rpcs()->WaitUntilPendingRpcCount(1);
  auto pending_rpc =
      manual_service()->pending_empty_rpcs()->GetOldestPendingRpc();
  std::move(pending_rpc->handler_done_callback)
      .Run(grpc::Status(grpc::StatusCode::CANCELLED,
                        "Cancelled on the server side"),
           nullptr);

  rpc_reply.Wait();
  EXPECT_TRUE(rpc_reply.IsError());
}

// Send one RPC and don't answer, then shutdown the server.
// Verify that the client gets an error reply.
// Also implicitly verifies that shutting down the server when there's a pending
// RPC does not e.g. hang or crash.
TEST_F(AsyncGrpcClientServerTest, ShutDownWhileRpcIsPending) {
  StartManualService();
  CreateClient();

  RpcReply<test_rpcs::EmptyRpcResponse> rpc_reply;
  test_rpcs::EmptyRpcRequest request;
  client_->CallRpc(&test_rpcs::ExampleService::Stub::AsyncEmptyRpc, request,
                   rpc_reply.MakeWriter());

  manual_service()->pending_empty_rpcs()->WaitUntilPendingRpcCount(1);
  auto pending_empty_rpc =
      manual_service()->pending_empty_rpcs()->GetOldestPendingRpc();
  ShutDownManualService();

  rpc_reply.Wait();
  EXPECT_TRUE(rpc_reply.IsError());

  // Also test that providing a response now does not crash.
  auto empty_rpc_response = std::make_unique<test_rpcs::EmptyRpcResponse>();
  std::move(pending_empty_rpc->handler_done_callback)
      .Run(grpc::Status::OK, std::move(empty_rpc_response));
}

// Initiate a shutdown of the server and immediately send a response.
// This should not crash, but we expect that the cancellation arrives at the
// sender.
TEST_F(AsyncGrpcClientServerTest, SendResponseAfterInitiatingShutdown) {
  StartManualService();
  CreateClient();

  RpcReply<test_rpcs::EmptyRpcResponse> rpc_reply;
  test_rpcs::EmptyRpcRequest request;
  client_->CallRpc(&test_rpcs::ExampleService::Stub::AsyncEmptyRpc, request,
                   rpc_reply.MakeWriter());

  manual_service()->pending_empty_rpcs()->WaitUntilPendingRpcCount(1);
  auto pending_empty_rpc =
      manual_service()->pending_empty_rpcs()->GetOldestPendingRpc();

  base::RunLoop loop;
  manual_service()->ShutDown(loop.QuitClosure());
  auto empty_rpc_response = std::make_unique<test_rpcs::EmptyRpcResponse>();
  std::move(pending_empty_rpc->handler_done_callback)
      .Run(grpc::Status::OK, std::move(empty_rpc_response));

  loop.Run();
  ShutDownManualService();

  rpc_reply.Wait();
  EXPECT_TRUE(rpc_reply.IsError());
}

// Send many RPCs. The server will accumulate pending RPCs, then respond to all
// of them in a batch.
TEST_F(AsyncGrpcClientServerTest, ManyRpcs) {
  const int kNumOfRpcs = 10;

  StartManualService();
  CreateClient();

  RpcReply<test_rpcs::EchoIntRpcResponse> rpc_replies[kNumOfRpcs];
  for (int i = 0; i < kNumOfRpcs; ++i) {
    test_rpcs::EchoIntRpcRequest request;
    request.set_int_to_echo(i);
    client_->CallRpc(&test_rpcs::ExampleService::Stub::AsyncEchoIntRpc, request,
                     rpc_replies[i].MakeWriter());
  }

  manual_service()->pending_echo_int_rpcs()->WaitUntilPendingRpcCount(
      kNumOfRpcs);
  for (int i = 0; i < kNumOfRpcs; ++i) {
    auto pending_rpc =
        manual_service()->pending_echo_int_rpcs()->GetOldestPendingRpc();
    auto response = std::make_unique<test_rpcs::EchoIntRpcResponse>();
    response->set_echoed_int(pending_rpc->request->int_to_echo());
    std::move(pending_rpc->handler_done_callback)
        .Run(grpc::Status::OK, std::move(response));
  }

  for (int i = 0; i < kNumOfRpcs; ++i) {
    rpc_replies[i].Wait();
    EXPECT_FALSE(rpc_replies[i].IsError());
    EXPECT_EQ(i, rpc_replies[i].response().echoed_int());
  }
}

// Test that heavy, but within the acceptable bounds, requests and responses are
// handled correctly.
TEST_F(AsyncGrpcClientServerTest, HeavyRpcData) {
  // kDataSize must be close to kMaxGrpcMessageSize, but also takes
  // into account protobuf/gRPC size overhead.
  const int kDataSize = kMaxGrpcMessageSize - 100;
  ASSERT_GE(kDataSize, 0);
  const std::string kData(kDataSize, '\1');

  StartManualService();
  CreateClient();

  RpcReply<test_rpcs::HeavyRpcResponse> rpc_reply;
  test_rpcs::HeavyRpcRequest request;
  request.set_data(kData);
  client_->CallRpc(&test_rpcs::ExampleService::Stub::AsyncHeavyRpc, request,
                   rpc_reply.MakeWriter());

  manual_service()->pending_heavy_rpcs()->WaitUntilPendingRpcCount(1);
  auto pending_rpc =
      manual_service()->pending_heavy_rpcs()->GetOldestPendingRpc();
  EXPECT_EQ(kData, pending_rpc->request->data());

  auto response = std::make_unique<test_rpcs::HeavyRpcResponse>();
  response->set_data(kData);
  std::move(pending_rpc->handler_done_callback)
      .Run(grpc::Status::OK, std::move(response));

  rpc_reply.Wait();
  EXPECT_FALSE(rpc_reply.IsError());
  EXPECT_EQ(kData, rpc_reply.response().data());
}

// Test than an excessively big request gets rejected.
TEST_F(AsyncGrpcClientServerTest, ExcessivelyBigRpcRequest) {
  const int kDataSize = kMaxGrpcMessageSize + 1;
  const std::string kData(kDataSize, '\1');

  StartManualService();
  CreateClient();

  RpcReply<test_rpcs::HeavyRpcResponse> rpc_reply;
  test_rpcs::HeavyRpcRequest request;
  request.set_data(kData);
  client_->CallRpc(&test_rpcs::ExampleService::Stub::AsyncHeavyRpc, request,
                   rpc_reply.MakeWriter());

  rpc_reply.Wait();
  EXPECT_TRUE(rpc_reply.IsError());
}

// Test than an excessively big response gets rejected and results in the
// request being resolved with an error.
TEST_F(AsyncGrpcClientServerTest, ExcessivelyBigRpcResponse) {
  const int kDataSize = kMaxGrpcMessageSize + 1;
  const std::string kData(kDataSize, '\1');

  StartManualService();
  CreateClient();

  RpcReply<test_rpcs::HeavyRpcResponse> rpc_reply;
  client_->CallRpc(&test_rpcs::ExampleService::Stub::AsyncHeavyRpc,
                   test_rpcs::HeavyRpcRequest(), rpc_reply.MakeWriter());

  manual_service()->pending_heavy_rpcs()->WaitUntilPendingRpcCount(1);
  auto pending_rpc =
      manual_service()->pending_heavy_rpcs()->GetOldestPendingRpc();

  auto response = std::make_unique<test_rpcs::HeavyRpcResponse>();
  response->set_data(kData);
  std::move(pending_rpc->handler_done_callback)
      .Run(grpc::Status::OK, std::move(response));

  rpc_reply.Wait();
  EXPECT_TRUE(rpc_reply.IsError());
}

// Set up two RPC clients. Send one RPC from each client and verify that
// the response arrives at the corresponding client.
// Verifies that the response contains the data transferred in the request.
TEST_F(AsyncGrpcClientServerTest, TwoRpcClients) {
  const int kNumOfRpcs = 3;

  StartManualService();
  CreateClient();

  RpcReply<test_rpcs::EchoIntRpcResponse> rpc_replies[kNumOfRpcs];
  {
    test_rpcs::EchoIntRpcRequest request;
    request.set_int_to_echo(0);
    client_->CallRpc(&test_rpcs::ExampleService::Stub::AsyncEchoIntRpc, request,
                     rpc_replies[0].MakeWriter());
  }

  CreateSecondClient();
  {
    test_rpcs::EchoIntRpcRequest request;
    request.set_int_to_echo(1);
    client2_->CallRpc(&test_rpcs::ExampleService::Stub::AsyncEchoIntRpc,
                      request, rpc_replies[1].MakeWriter());
  }

  {
    test_rpcs::EchoIntRpcRequest request;
    request.set_int_to_echo(2);
    client_->CallRpc(&test_rpcs::ExampleService::Stub::AsyncEchoIntRpc, request,
                     rpc_replies[2].MakeWriter());
  }

  manual_service()->pending_echo_int_rpcs()->WaitUntilPendingRpcCount(
      kNumOfRpcs);
  for (int i = 0; i < kNumOfRpcs; ++i) {
    auto pending_rpc =
        manual_service()->pending_echo_int_rpcs()->GetOldestPendingRpc();
    auto response = std::make_unique<test_rpcs::EchoIntRpcResponse>();
    response->set_echoed_int(pending_rpc->request->int_to_echo());
    std::move(pending_rpc->handler_done_callback)
        .Run(grpc::Status::OK, std::move(response));
  }

  for (int i = 0; i < kNumOfRpcs; ++i) {
    rpc_replies[i].Wait();
    EXPECT_FALSE(rpc_replies[i].IsError());
    EXPECT_EQ(i, rpc_replies[i].response().echoed_int());
  }
  ShutDownSecondClient();
}

namespace {

void CallEchoIntRpcWithRetry(
    AsyncGrpcClient<test_rpcs::ExampleService>* client,
    const test_rpcs::EchoIntRpcRequest& request,
    RpcReply<test_rpcs::EchoIntRpcResponse>::ReplyCallback reply_callback) {
  client->CallRpc(&test_rpcs::ExampleService::Stub::AsyncEchoIntRpc, request,
                  std::move(reply_callback));
}

void OnRetryableEchoIntRpcReply(
    AsyncGrpcClient<test_rpcs::ExampleService>* client,
    const test_rpcs::EchoIntRpcRequest& request,
    RpcReply<test_rpcs::EchoIntRpcResponse>::ReplyCallback reply_callback,
    grpc::Status status,
    std::unique_ptr<test_rpcs::EchoIntRpcResponse> response) {
  if (status.error_code() == grpc::StatusCode::UNAVAILABLE) {
    CallEchoIntRpcWithRetry(client, request,
                            base::BindOnce(&OnRetryableEchoIntRpcReply, client,
                                           request, std::move(reply_callback)));
    return;
  }
  std::move(reply_callback).Run(status, std::move(response));
}

}  // namespace

// Set up a RPC server, then restart it. Send one RPC to each instance.
TEST_F(AsyncGrpcClientServerTest, RpcServerRestarted) {
  StartManualService();
  CreateClient();

  {
    RpcReply<test_rpcs::EchoIntRpcResponse> rpc_reply;
    test_rpcs::EchoIntRpcRequest request;
    request.set_int_to_echo(1);
    client_->CallRpc(&test_rpcs::ExampleService::Stub::AsyncEchoIntRpc, request,
                     rpc_reply.MakeWriter());

    manual_service()->pending_echo_int_rpcs()->WaitUntilPendingRpcCount(1);
    auto pending_rpc =
        manual_service()->pending_echo_int_rpcs()->GetOldestPendingRpc();
    EXPECT_EQ(1, pending_rpc->request->int_to_echo());

    auto response = std::make_unique<test_rpcs::EchoIntRpcResponse>();
    response->set_echoed_int(1);
    std::move(pending_rpc->handler_done_callback)
        .Run(grpc::Status::OK, std::move(response));

    rpc_reply.Wait();
    EXPECT_FALSE(rpc_reply.IsError());
    EXPECT_EQ(1, rpc_reply.response().echoed_int());
  }

  RestartManualService();

  {
    RpcReply<test_rpcs::EchoIntRpcResponse> rpc_reply;
    test_rpcs::EchoIntRpcRequest request;
    request.set_int_to_echo(2);

    // gRPC has retry mechanism with backoff, however old version of gRPC
    // library (which obviously we use in ChromeOS) does not retry if "RPC goes
    // all the way through the channel, lb_policy, subchannel, to the transport
    // before it realizes the connection has terminated, and at that point it is
    // too late to try to reconnect, so the RPC fails" (check
    // github.com/grpc/grpc/issues/9767 for more details).
    //
    // This error happens one per 20'000 test runs. We are automatically
    // retrying the RPC on |UNAVAILABLE| error. In practice we need to perform
    // only one retry, however it's safer to retry infinitely.
    //
    // TODO(crbug.com/1044752): try to remove retry once gRPC will be upreved.
    CallEchoIntRpcWithRetry(
        client_.get(), request,
        base::BindOnce(&OnRetryableEchoIntRpcReply, client_.get(), request,
                       rpc_reply.MakeWriter()));

    manual_service()->pending_echo_int_rpcs()->WaitUntilPendingRpcCount(1);
    auto pending_rpc =
        manual_service()->pending_echo_int_rpcs()->GetOldestPendingRpc();
    EXPECT_EQ(2, pending_rpc->request->int_to_echo());

    auto response = std::make_unique<test_rpcs::EchoIntRpcResponse>();
    response->set_echoed_int(2);
    std::move(pending_rpc->handler_done_callback)
        .Run(grpc::Status::OK, std::move(response));

    rpc_reply.Wait();
    EXPECT_FALSE(rpc_reply.IsError());
    EXPECT_EQ(2, rpc_reply.response().echoed_int());
  }
}

// Send a request to a stopped server. The request should not fail immediately,
// it should wait for the rpc deadline to pass.
TEST_F(AsyncGrpcClientServerTest, RpcServerStopped) {
  CreateClient();

  client_->SetDefaultRpcDeadlineForTesting(base::Milliseconds(50));

  base::TimeTicks start = base::TimeTicks::Now();

  RpcReply<test_rpcs::EchoIntRpcResponse> rpc_reply;
  test_rpcs::EchoIntRpcRequest request;
  request.set_int_to_echo(1);
  client_->CallRpc(&test_rpcs::ExampleService::Stub::AsyncEchoIntRpc, request,
                   rpc_reply.MakeWriter());

  rpc_reply.Wait();
  EXPECT_TRUE(rpc_reply.IsError());

  base::TimeDelta duration = base::TimeTicks::Now() - start;

  EXPECT_GT(duration.InMilliseconds(), 40);  // Forgiving time comparison.
}

// Like RpcServerStopped. Pass context deadline to CallRpc directly.
TEST_F(AsyncGrpcClientServerTest, RpcServerStopped_PerRequestTimeout) {
  CreateClient();

  client_->SetDefaultRpcDeadlineForTesting(base::Milliseconds(50));

  base::TimeTicks start = base::TimeTicks::Now();

  RpcReply<test_rpcs::EchoIntRpcResponse> rpc_reply;
  test_rpcs::EchoIntRpcRequest request;
  request.set_int_to_echo(1);
  client_->CallRpc(&test_rpcs::ExampleService::Stub::AsyncEchoIntRpc,
                   base::Milliseconds(200), request, rpc_reply.MakeWriter());

  rpc_reply.Wait();
  EXPECT_TRUE(rpc_reply.IsError());

  base::TimeDelta duration = base::TimeTicks::Now() - start;

  EXPECT_GT(duration.InMilliseconds(), 180);  // Forgiving time comparison.
}

// Send a request to a server that starts after the request is made. The client
// should only send the request after the connection has been established.
TEST_F(AsyncGrpcClientServerTest, RpcServerStartedAfter) {
  CreateClient();

  RpcReply<test_rpcs::EchoIntRpcResponse> rpc_reply;
  test_rpcs::EchoIntRpcRequest request;
  request.set_int_to_echo(1);
  client_->CallRpc(&test_rpcs::ExampleService::Stub::AsyncEchoIntRpc, request,
                   rpc_reply.MakeWriter());

  base::TimeTicks start = base::TimeTicks::Now();

  StartManualService();

  manual_service()->pending_echo_int_rpcs()->WaitUntilPendingRpcCount(1);
  auto pending_rpc =
      manual_service()->pending_echo_int_rpcs()->GetOldestPendingRpc();
  EXPECT_EQ(1, pending_rpc->request->int_to_echo());

  auto response = std::make_unique<test_rpcs::EchoIntRpcResponse>();
  response->set_echoed_int(2);
  std::move(pending_rpc->handler_done_callback)
      .Run(grpc::Status::OK, std::move(response));

  rpc_reply.Wait();
  EXPECT_FALSE(rpc_reply.IsError());
  EXPECT_EQ(2, rpc_reply.response().echoed_int());

  base::TimeDelta duration = base::TimeTicks::Now() - start;

  // Check the reduced initial reconnect time. 1 second is the gRPC default.
  EXPECT_LT(duration.InMilliseconds(), 1000);
}

// Test that there's no crash caused by calls incoming during/after the server
// shutdown.
TEST_F(AsyncGrpcClientServerTest, ShutdownBetweenSyncRequests) {
  // This number should be sufficiently large in order to increase the
  // probability of catching bugs in case they occur in the tested code.
  // Typically, 2-5 calls is already sufficient, but it's safe to make this
  // constant much bigger.
  constexpr int kCallCount = 100;

  StartSelfStoppingService();
  CreateClient();
  base::RunLoop run_loop;
  self_stopping_service_->set_on_shutdown_callback(run_loop.QuitClosure());

  for (int i = 0; i < kCallCount; ++i) {
    client_->CallRpc(
        &test_rpcs::ExampleService::Stub::AsyncEmptyRpc,
        test_rpcs::EmptyRpcRequest(),
        base::BindOnce(
            [](grpc::Status, std::unique_ptr<test_rpcs::EmptyRpcResponse>) {}));
  }

  // Waits until the service shuts down itself after receiving the first
  // incoming RPC call.
  run_loop.Run();
}

}  // namespace brillo
