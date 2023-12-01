// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBBRILLO_BRILLO_GRPC_ASYNC_GRPC_CLIENT_H_
#define LIBBRILLO_BRILLO_GRPC_ASYNC_GRPC_CLIENT_H_

#include <memory>
#include <string>
#include <utility>

#include <base/check.h>
#include <base/functional/bind.h>
#include <base/functional/callback.h>
#include <base/functional/callback_helpers.h>
#include <base/logging.h>
#include <base/memory/ref_counted.h>
#include <base/task/sequenced_task_runner.h>
#include <base/time/time.h>
#include <brillo/brillo_export.h>
#include <grpcpp/grpcpp.h>
#include <grpcpp/support/async_unary_call.h>

#include "brillo/grpc/async_grpc_constants.h"
#include "brillo/grpc/grpc_completion_queue_dispatcher.h"
#include "brillo/grpc/time_util.h"

namespace brillo {
namespace internal {

// Base class for a gRPC client that supports sending RPCs to an endpoint and
// posting a task on a task runner when the response has been received. This
// base class is not specific to a Stub or Service.
//
// This class has to be exported as AsyncGrpcClient is a templated class
class BRILLO_EXPORT AsyncGrpcClientBase {
 public:
  // Type of the callback which will be called when an RPC response is
  // available.
  template <typename ResponseType>
  using ReplyCallback = base::OnceCallback<void(
      grpc::Status status, std::unique_ptr<ResponseType> response)>;

  explicit AsyncGrpcClientBase(
      scoped_refptr<base::SequencedTaskRunner> task_runner);
  AsyncGrpcClientBase(const AsyncGrpcClientBase&) = delete;
  AsyncGrpcClientBase& operator=(const AsyncGrpcClientBase&) = delete;

  virtual ~AsyncGrpcClientBase();

  // Shuts down this client. This instance may only be destroyed after
  // |on_shutdown_callback| has been called.
  void ShutDown(base::OnceClosure on_shutdown_callback);

 protected:
  GrpcCompletionQueueDispatcher* dispatcher() { return &dispatcher_; }

  static std::shared_ptr<grpc::Channel> CreateGrpcChannel(
      const std::string& target_uri);

 private:
  grpc::CompletionQueue completion_queue_;
  GrpcCompletionQueueDispatcher dispatcher_;
};

}  // namespace internal

// A gRPC client that is specific to |ServiceType|.
// Example usage:
//   AsyncGrpcClient<Foo>
//   client(base::SingleThreadTaskRunner::GetCurrentDefault(),
//                               "unix:/path/to/socket");
//   client.CallRpc(&FooStub::AsyncDoSomething,
//                  something_request,
//                  std::move(do_something_callback));
//   client.CallRpc(&FooStub::AsyncDoOtherThing,
//                  other_thing_request,
//                  std::move(do_other_thing_callback));
//   client.Shutdown(std::move(on_shutdown_callback));
//   // Important: Make sure |client| is not destroyed before
//   // |on_shutdown_callback| is called.
// The callbacks (e.g. |do_something_callback| in the example) have the
// following form:
//   void DoSomethingCallback(grpc::Status status,
//                            std::unique_ptr<DoSomethingResponse> response);
template <typename ServiceType>
class AsyncGrpcClient final : public internal::AsyncGrpcClientBase {
 public:
  AsyncGrpcClient(scoped_refptr<base::SequencedTaskRunner> task_runner,
                  std::unique_ptr<typename ServiceType::Stub> stub)
      : AsyncGrpcClientBase(task_runner) {
    stub_ = std::move(stub);
  }
  AsyncGrpcClient(scoped_refptr<base::SequencedTaskRunner> task_runner,
                  const std::string& target_uri)
      : AsyncGrpcClient(task_runner,
                        ServiceType::NewStub(CreateGrpcChannel(target_uri))) {}
  AsyncGrpcClient(const AsyncGrpcClient&) = delete;
  AsyncGrpcClient& operator=(const AsyncGrpcClient&) = delete;

  ~AsyncGrpcClient() override = default;

  // A function pointer on a gRPC Stub class to send an RPC.
  template <typename AsyncServiceStub,
            typename RequestType,
            typename ResponseType>
  using AsyncRequestFnPtr =
      std::unique_ptr<grpc::ClientAsyncResponseReader<ResponseType>> (
          AsyncServiceStub::*)(grpc::ClientContext* context,
                               const RequestType& request,
                               grpc::CompletionQueue* cq);

  // Call RPC represented by |async_rpc_start|. Pass |request| as the request
  // with |rpc_deadline| as a timeout. Call |on_reply_callback| on the task
  // runner passed to the constructor when a response is available.
  template <typename AsyncServiceStub,
            typename RequestType,
            typename ResponseType>
  void CallRpc(AsyncRequestFnPtr<AsyncServiceStub, RequestType, ResponseType>
                   async_rpc_start,
               base::TimeDelta rpc_deadline,
               const RequestType& request,
               ReplyCallback<ResponseType> on_reply_callback) {
    std::unique_ptr<RpcState<ResponseType>> rpc_state =
        std::make_unique<RpcState<ResponseType>>(rpc_deadline);
    RpcState<ResponseType>* rpc_state_unowned = rpc_state.get();

    std::unique_ptr<grpc::ClientAsyncResponseReader<ResponseType>> rpc =
        (stub_.get()->*async_rpc_start)(&rpc_state_unowned->context, request,
                                        dispatcher()->completion_queue());
    dispatcher()->RegisterTag(
        rpc_state_unowned->tag(),
        base::BindOnce(&AsyncGrpcClient::OnReplyReceived<ResponseType>,
                       std::move(rpc_state), std::move(on_reply_callback)));
    // Accessing |rpc_state_unowned| is safe, because the RpcState will remain
    // alive (owned by the |dispatcher()|) at least until the corresponding tag
    // becomes available through the gRPC CompletionQueue, which can not happen
    // before |Finish| is called.
    rpc->Finish(rpc_state_unowned->response.get(), &rpc_state_unowned->status,
                rpc_state_unowned->tag());
  }

  // Same as above with the default deadline set by
  // |SetDefaultRpcDeadlineForTesting|
  template <typename AsyncServiceStub,
            typename RequestType,
            typename ResponseType>
  void CallRpc(AsyncRequestFnPtr<AsyncServiceStub, RequestType, ResponseType>
                   async_rpc_start,
               const RequestType& request,
               ReplyCallback<ResponseType> on_reply_callback) {
    CallRpc(async_rpc_start, default_rpc_deadline_, request,
            std::move(on_reply_callback));
  }

  // Sets the request deadline for future requests made with this client.
  void SetDefaultRpcDeadlineForTesting(base::TimeDelta default_rpc_deadline) {
    default_rpc_deadline_ = default_rpc_deadline;
  }

 private:
  // Holds memory for the response and the grpc Status.
  template <typename ResponseType>
  struct RpcState {
    explicit RpcState(base::TimeDelta rpc_deadline) {
      context.set_deadline(GprTimespecWithDeltaFromNow(rpc_deadline));
      context.set_wait_for_ready(true);
    }

    const void* tag() const { return this; }
    void* tag() { return this; }

    grpc::Status status;
    grpc::ClientContext context;
    std::unique_ptr<ResponseType> response = std::make_unique<ResponseType>();
  };

  template <typename ResponseType>
  static void OnReplyReceived(std::unique_ptr<RpcState<ResponseType>> rpc_state,
                              ReplyCallback<ResponseType> on_reply_callback,
                              bool ok) {
    // gRPC CompletionQueue::Next documentation says that |ok| should always
    // be true for client-side |Finish|.
    CHECK(ok);
    if (rpc_state->status.error_code() != grpc::StatusCode::OK) {
      VLOG(1) << "Outgoing RPC failed with error_code="
              << rpc_state->status.error_code() << ", error_message='"
              << rpc_state->status.error_message() << "', error_details='"
              << rpc_state->status.error_details() << "'";
    }
    std::move(on_reply_callback)
        .Run(std::move(rpc_state->status), std::move(rpc_state->response));
  }

  base::TimeDelta default_rpc_deadline_ = kDefaultRpcDeadline;
  std::unique_ptr<typename ServiceType::Stub> stub_;
};

}  // namespace brillo

#endif  // LIBBRILLO_BRILLO_GRPC_ASYNC_GRPC_CLIENT_H_
