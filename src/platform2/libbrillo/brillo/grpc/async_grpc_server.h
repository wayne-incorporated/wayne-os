// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBBRILLO_BRILLO_GRPC_ASYNC_GRPC_SERVER_H_
#define LIBBRILLO_BRILLO_GRPC_ASYNC_GRPC_SERVER_H_

#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <base/functional/bind.h>
#include <base/functional/callback.h>
#include <base/memory/ref_counted.h>
#include <base/task/sequenced_task_runner.h>
#include <brillo/brillo_export.h>
#include <grpcpp/grpcpp.h>
#include <grpcpp/support/async_unary_call.h>

#include "brillo/grpc/grpc_completion_queue_dispatcher.h"
#include "brillo/grpc/rpc_state.h"

namespace brillo {
namespace internal {

// Base class for the asynchronous RPC Server, contains functionality that does
// not depend on the actual gRPC Service class.
// The server creates an object of type |RpcState| for each RPC that is
// expected. It uses factory functions bound in
// |AsyncGrpcServer::RegisterHandler| to create these |RpcState| objects. The
// AsyncGrpcServerBase then drives incoming RPCs by interacting with the
// |RpcStateBase| interface of the |RpcState| objects. This interface hides the
// RPC-specific details (such as RequestType, ResponseType) and acts as proxy
// towards gRPC and the application's RPC handler.
class BRILLO_EXPORT AsyncGrpcServerBase {
 public:
  // A factory function which creates an |RpcStateBase| for an expected
  // RPC type.
  using RpcStateFactory =
      base::RepeatingCallback<std::unique_ptr<RpcStateBase>()>;

  AsyncGrpcServerBase(scoped_refptr<base::SequencedTaskRunner> task_runner,
                      const std::vector<std::string>& server_uris);
  AsyncGrpcServerBase(const AsyncGrpcServerBase&) = delete;
  AsyncGrpcServerBase& operator=(const AsyncGrpcServerBase&) = delete;

  virtual ~AsyncGrpcServerBase();

  // Starts this server. When this returns failure, no further methods are
  // allowed to be called, except Shutdown() - which is allowed but not required
  // in this case.
  // This function must not be called twice.
  bool Start();

  // Shuts down this server. This must be used before deleting this instance in
  // case when the server successfully started - the instance must be destroyed
  // only after |on_shutdown| has been called.
  // If this server has not been successfully started, calling Shutdown() is
  // optional but allowed (|on_shutdown_| will be called immediately in this
  // case).
  // This function must not be called twice.
  void ShutDown(base::OnceClosure on_shutdown);

 protected:
  // Returns the grpc::Service instance this server is exposing.
  virtual grpc::Service* service() = 0;

  // Adds |rpc_state_factory| which will be used to create a |RpcStateBase|
  // instance for an RPC type.
  void AddRpcStateFactory(const RpcStateFactory& rpc_state_factory);

 private:
  enum class State { kNotStarted, kStarted, kShutDown };

  // Expects the next RPC of the type described by |rpc_state_factory|.
  // In detail, uses |rpc_state_factory| to create a |RpcStateBase| object
  // for the expected RPC, registers the state's tag with |dispatcher_|, and
  // requests the RPC in gRPC. After this function, ownership of the created
  // |RpcStateBase| has been transferred to |dispatcher_| (wrapped in a bound
  // Callback argument).
  void ExpectNextRpc(const RpcStateFactory& rpc_state_factory);

  // Called on an incoming RPC. |rpc_state| holds all state about that RPC.
  // |rpc_state_factory| for the RPC type is passed in too so this function can
  // start expecting the next RPC.
  // |ok| is the gRPC |CompletionQueue| ok parameter.
  // After this, ownership of the |RpcStateBase| has been transferred to
  // |rpcs_awaiting_handler_reply_|.
  void OnIncomingRpc(const RpcStateFactory& rpc_state_factory,
                     std::unique_ptr<RpcStateBase> rpc_state,
                     bool ok);

  // Called when the handler has made a reply available for the RpcState
  // identified by |tag|. This registers the |RpcStateBase|'s tag with
  // |dispatcher_| again and actually sends the reply or cancellation.
  // After this function, ownership of the |RpcStateBase| has
  // been transferred to |dispatcher_| (wrapped in a bound Callback argument).
  void OnHandlerDone(const void* tag);

  // Called when the response for the RPC described by |rpc_state| has been
  // sent. |ok| is the gRPC |CompletionQueue| ok parameter.
  void OnResponseSent(std::unique_ptr<RpcStateBase> rpc_state, bool ok);

  // State of this server.
  State state_ = State::kNotStarted;

  // The TaskRunner used for |dispatcher_|.
  scoped_refptr<base::SequencedTaskRunner> task_runner_;

  // The addresses this server listens on.
  const std::vector<std::string> server_uris_;

  // The gRPC |Server| instance.
  std::unique_ptr<grpc::Server> server_;

  // The |ServerCompletionQueue| associated with |server_|. This is the
  // completion queue |dispatcher_| monitors.
  std::unique_ptr<grpc::ServerCompletionQueue> completion_queue_;

  // Monitors |completion_queue_| and for available tags and posts tasks to
  // |task_runner_|.
  std::unique_ptr<GrpcCompletionQueueDispatcher> dispatcher_;

  // Factories that are used to create |RpcState| objects. One such object is
  // needed per expected/incoming RPC. This is used to accumulate the factories
  // registered through |AsyncGrpcServer::RegisterHandler| /
  // |AddRpcStateFactory| before |Start| is called and will be cleared in
  // |Start|.
  std::vector<RpcStateFactory> rpc_state_factories_;

  // Holds all |RpcState| objects which have been passed to the corresponding
  // Handler but do not have a reply yet.
  std::map<const void*, std::unique_ptr<RpcStateBase>>
      rpcs_awaiting_handler_reply_;
};

}  // namespace internal

// Templatized concrete class implementing an asynchronous gRPC server receiving
// RPCs defined by |AsyncService| on a task runner. Each RPC which should be
// handled must be registered using |RegisterHandler| before starting the server
// using |AsyncGrpcServerBase::Start|.
// Example usage:
//   AsyncGrpcServer<Foo>
//   server(base::SingleThreadTaskRunner::GetCurrentDefault(),
//                               "unix:/path/to/socket");
//   server.RegisterHandler(&FooService::AsyncService::RequestDoSomething,
//                          do_something_handler);
//   server.RegisterHandler(&FooService::AsyncService::RequestDoOtherThing,
//                          do_other_thing_handler);
//   server.Start();
//   // ...
//   server.Shutdown(std::move(on_shutdown_callback));
//   // Important: Make sure |server| is not destroyed before
//   // |on_shutdown_callback| is called.
// The handlers (e.g. |do_something_handler| in the example) have the following
// form:
//   void DoSomethingHandler(
//       std::unique_ptr<DoSomethingRequest> request,
//       const base::RepeatingCallback<void(
//           grpc::Status,
//           std::unique_ptr<DoSomethingResponse>)>&
//           send_response_callback);
template <typename AsyncService>
class AsyncGrpcServer final : public internal::AsyncGrpcServerBase {
 public:
  using RpcStateBase = internal::RpcStateBase;
  template <typename RequestType, typename ResponseType>
  using RpcState = internal::RpcState<RequestType, ResponseType>;

  // Creates a server which exposes |service| on each URI in |server_uris|.
  // It will post tasks for processing incoming RPCs on |task_runner|.
  AsyncGrpcServer(scoped_refptr<base::SequencedTaskRunner> task_runner,
                  const std::vector<std::string>& server_uris)
      : internal::AsyncGrpcServerBase(task_runner, server_uris),
        service_(std::make_unique<AsyncService>()) {}
  AsyncGrpcServer(const AsyncGrpcServer&) = delete;
  AsyncGrpcServer& operator=(const AsyncGrpcServer&) = delete;

  ~AsyncGrpcServer() = default;

  // A factory function which creates a |RpcState<RequestType, ResponseType>|.
  template <typename RequestType, typename ResponseType>
  static std::unique_ptr<RpcStateBase> RpcStateFactoryFunction(
      const typename RpcState<RequestType, ResponseType>::RequestRpcCallback&
          request_rpc_callback,
      typename RpcState<RequestType, ResponseType>::HandlerCallback
          handler_callback) {
    return std::make_unique<RpcState<RequestType, ResponseType>>(
        request_rpc_callback, std::move(handler_callback));
  }

  // A member function pointer which has the signature of functions used to
  // request an async RPC on a GRPC AsyncService class.
  // Note that the |AsyncService| class-level template argument is not used
  // here, because the |request_rpc_function| could be defined on a base class.
  template <typename AsyncServiceBase,
            typename RequestType,
            typename ResponseType>
  using RequestRpcFunction =
      void (AsyncServiceBase::*)(grpc::ServerContext*,
                                 RequestType*,
                                 grpc::ServerAsyncResponseWriter<ResponseType>*,
                                 grpc::CompletionQueue*,
                                 grpc::ServerCompletionQueue*,
                                 void*);

  // The repeating version of HandlerCallback. This type is used for
  // registering RPC handlers.
  template <typename RequestType, typename ResponseType>
  using RepeatingHandlerCallback = base::RepeatingCallback<void(
      std::unique_ptr<RequestType> request,
      typename RpcState<RequestType, ResponseType>::HandlerDoneCallback
          send_response_callback)>;

  // Makes this server process RPCs of the type specified by
  // |request_rpc_function|. When such an RPC is received, this server will call
  // |handler_callback| on the task runner passed to the constructor.
  // Note that the |AsyncService| class-level template argument is not used
  // here, because the |request_rpc_function| could be defined on a base class.
  // This should be called before the server is started using |Start()|.
  template <typename AsyncServiceBase,
            typename RequestType,
            typename ResponseType>
  void RegisterHandler(
      RequestRpcFunction<AsyncServiceBase, RequestType, ResponseType>
          request_rpc_function,
      const RepeatingHandlerCallback<RequestType, ResponseType>&
          handler_callback) {
    auto request_rpc_callback = base::BindRepeating(
        request_rpc_function, base::Unretained(service_.get()));
    AddRpcStateFactory(base::BindRepeating(
        &AsyncGrpcServer::RpcStateFactoryFunction<RequestType, ResponseType>,
        request_rpc_callback, handler_callback));
  }

  // AsyncGrpcServerBase:
  grpc::Service* service() override { return service_.get(); }

 private:
  std::unique_ptr<AsyncService> service_;
};

}  // namespace brillo

#endif  // LIBBRILLO_BRILLO_GRPC_ASYNC_GRPC_SERVER_H_
