// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBBRILLO_BRILLO_GRPC_RPC_STATE_H_
#define LIBBRILLO_BRILLO_GRPC_RPC_STATE_H_

#include <memory>
#include <utility>

#include <base/check.h>
#include <base/functional/bind.h>
#include <base/functional/callback.h>
#include <base/memory/weak_ptr.h>
#include <brillo/brillo_export.h>
#include <grpcpp/grpcpp.h>
#include <grpcpp/support/async_unary_call.h>

namespace base {
class SequencedTaskRunner;
}

namespace brillo {
namespace internal {

// Base class which holds the state of an expected or incoming RPC. Provides an
// interface for driving the RPC which is agnostic of RequestType /
// ResponseType, acting as a proxy towards gRPC and the application's RPC
// handler.
// The templatized |RpcState<RequestType, ResponseType>| class implements this
// interface.
// Lifetime and ownership (same as the templatized RpcState):
// (*) Created when expecting an incoming RPC of this type, i.e. when:
//     - the AsyncGrpcServer starts
//     - an RPC of this type comes in. A new RpcState(Base) is then created
//       to expect the next RPC of this type.
// (*) Owned by the AsyncGrpcServer/GrpcCompletionQueueDispatcher when
//     waiting for gRPC-side events.
// (*) Owned by the AsyncGrpcServer when waiting for the handler to provide
//     a reply.
// (*) Destroyed when gRPC is done sending the reply for the incoming rpc, or
//     when the AsyncGrpcServer is shutting down.
//
// This class has to be exported as RpcState is a templated class
class BRILLO_EXPORT RpcStateBase {
 public:
  RpcStateBase();
  RpcStateBase(const RpcStateBase&) = delete;
  RpcStateBase& operator=(const RpcStateBase&) = delete;

  virtual ~RpcStateBase();

  // Returns the tag uniquely identifying this |RpcStateBase|. Whenever
  // this |RpcStateBase| interacts with gRPC, it uses this tag.
  void* tag() { return this; }

  // Request an incoming RPC of this type in gRPC.
  // Pass |server_completion_queue| as the CompletionQueue which should be
  // notified both for when an incoming RPC starts and for subsequent RPC
  // events (e.g. response has been sent).
  virtual void RequestRpc(
      grpc::ServerCompletionQueue* server_completion_queue) = 0;

  // Call the handler which should provide a reply. Invoke |on_handler_done|
  // when the handler has provided a reply (this could be a response, or a
  // cancellation). Guarantees that |on_handler_done| will only be called if
  // this object has not been destroyed.
  virtual void CallHandler(base::OnceClosure on_handler_done) = 0;

  // Returns true if the handler has provided a response. If this returns false,
  // it means that the RPC should be cancelled.
  virtual bool HasResponse() = 0;

  // Forward the reply to gRPC. This is called by the AsyncGrpcServer(Base)
  // after the handler has provided a reply, and the server has prepared to
  // receive the |tag()| again.
  virtual void SendResponse() = 0;

  // Cancel this RPC in gRPC.
  virtual void Cancel() = 0;

 protected:
  grpc::ServerContext ctx_;
};

// Templatized version of |RpcStateBase|. Implements the actual RequestType /
// ResponseType specific calls to gRPC and the handler callback.
// Lifetime and ownership: See |RpcStateBase|.
template <typename RequestType, typename ResponseType>
class RpcState final : public RpcStateBase {
 public:
  // Call to grpc to request the next RPC of this type.
  using RequestRpcCallback = base::RepeatingCallback<void(
      grpc::ServerContext*,
      RequestType*,
      grpc::ServerAsyncResponseWriter<ResponseType>*,
      grpc::CompletionQueue*,
      grpc::ServerCompletionQueue*,
      void*)>;

  // Called by the handler to send |status| and |response|.
  using HandlerDoneCallback = base::OnceCallback<void(
      grpc::Status status, std::unique_ptr<ResponseType> response)>;

  // The handler callback - will be invoked to compute a response for a request.
  using HandlerCallback =
      base::OnceCallback<void(std::unique_ptr<RequestType> request,
                              HandlerDoneCallback send_response_callback)>;

  RpcState(RequestRpcCallback request_rpc_closure,
           HandlerCallback handler_callback)
      : request_rpc_closure_(request_rpc_closure),
        handler_callback_(std::move(handler_callback)),
        responder_(&ctx_) {}
  RpcState(const RpcState&) = delete;
  RpcState& operator=(const RpcState&) = delete;

  ~RpcState() = default;

  void RequestRpc(
      grpc::ServerCompletionQueue* server_completion_queue) override {
    request_rpc_closure_.Run(&ctx_, request_.get(), &responder_,
                             server_completion_queue, server_completion_queue,
                             tag());
  }

  void CallHandler(base::OnceClosure on_handler_done) override {
    // Ensure that this is not called twice.
    CHECK(request_);
    std::move(handler_callback_)
        .Run(std::move(request_), base::BindOnce(&RpcState::OnHandlerDone,
                                                 weak_ptr_factory_.GetWeakPtr(),
                                                 std::move(on_handler_done)));
  }

  bool HasResponse() override { return response_.get() != nullptr; }

  void SendResponse() override {
    CHECK(response_);
    responder_.Finish(*response_, status_, tag());
  }

  void Cancel() override {
    grpc::Status error_status(grpc::StatusCode::UNKNOWN,
                              "Cancelled by application");
    responder_.FinishWithError(error_status, tag());
  }

 private:
  // This will be invoked by the handler when it provides us a |status| and a
  // |response|.
  void OnHandlerDone(base::OnceClosure on_handler_done,
                     grpc::Status status,
                     std::unique_ptr<ResponseType> response) {
    // Ideally, we would CHECK that |OnHandlerDone| is only called once, but
    // that would require introducing a dedicated boolean flag, which seems to
    // be overkill.
    CHECK(!response_);
    response_ = std::move(response);
    status_ = std::move(status);
    std::move(on_handler_done).Run();
  }

  RequestRpcCallback request_rpc_closure_;
  HandlerCallback handler_callback_;
  std::unique_ptr<RequestType> request_ = std::make_unique<RequestType>();
  // The response generated by the handler. If this is not set after the handler
  // has finished processing this RPC, i.e. when |OnHandlerDone()| is called, it
  // means that the RPC has been cancelled.
  std::unique_ptr<ResponseType> response_;
  grpc::Status status_;
  grpc::ServerAsyncResponseWriter<ResponseType> responder_;

  base::WeakPtrFactory<RpcState> weak_ptr_factory_{this};
};

}  // namespace internal
}  // namespace brillo

#endif  // LIBBRILLO_BRILLO_GRPC_RPC_STATE_H_
