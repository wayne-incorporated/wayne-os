// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "brillo/grpc/async_grpc_server.h"

#include <base/check.h>
#include <base/check_op.h>
#include <base/logging.h>

#include "brillo/grpc/async_grpc_constants.h"

namespace brillo {
namespace internal {

AsyncGrpcServerBase::AsyncGrpcServerBase(
    scoped_refptr<base::SequencedTaskRunner> task_runner,
    const std::vector<std::string>& server_uris)
    : task_runner_(task_runner), server_uris_(server_uris) {
  DCHECK(!server_uris_.empty());
}

AsyncGrpcServerBase::~AsyncGrpcServerBase() = default;

bool AsyncGrpcServerBase::Start() {
  CHECK_EQ(State::kNotStarted, state_);
  state_ = State::kStarted;

  grpc::ServerBuilder builder;
  builder.SetMaxSendMessageSize(kMaxGrpcMessageSize);
  builder.SetMaxReceiveMessageSize(kMaxGrpcMessageSize);

  for (const auto& uri : server_uris_) {
    builder.AddListeningPort(uri, grpc::InsecureServerCredentials());
  }

  builder.RegisterService(service());
  completion_queue_ = builder.AddCompletionQueue();
  server_ = builder.BuildAndStart();
  if (!server_)
    return false;
  dispatcher_ = std::make_unique<GrpcCompletionQueueDispatcher>(
      completion_queue_.get(), task_runner_);
  dispatcher_->Start();

  for (const auto& rpc_state_factory : rpc_state_factories_)
    ExpectNextRpc(rpc_state_factory);
  rpc_state_factories_.clear();
  return true;
}

void AsyncGrpcServerBase::ShutDown(base::OnceClosure on_shutdown) {
  CHECK_NE(state_, State::kShutDown);
  // Don't do anything if Start() was not called or it failed.
  if (state_ != State::kStarted || !server_) {
    state_ = State::kShutDown;
    std::move(on_shutdown).Run();
    return;
  }

  state_ = State::kShutDown;

  // Shut down the server immediately, not waiting until the application
  // provides responses to pending requests.
  server_->Shutdown(gpr_now(GPR_CLOCK_MONOTONIC));
  rpcs_awaiting_handler_reply_.clear();
  dispatcher_->Shutdown(std::move(on_shutdown));
}

void AsyncGrpcServerBase::AddRpcStateFactory(
    const RpcStateFactory& rpc_state_factory) {
  CHECK_EQ(State::kNotStarted, state_);
  rpc_state_factories_.push_back(rpc_state_factory);
}

void AsyncGrpcServerBase::ExpectNextRpc(
    const RpcStateFactory& rpc_state_factory) {
  std::unique_ptr<RpcStateBase> rpc_state = rpc_state_factory.Run();
  RpcStateBase* rpc_state_unowned = rpc_state.get();
  dispatcher_->RegisterTag(
      rpc_state_unowned->tag(),
      base::BindOnce(&AsyncGrpcServerBase::OnIncomingRpc,
                     base::Unretained(this), rpc_state_factory,
                     std::move(rpc_state)));
  // Note: It is OK to use |rpc_state_unowned| because |dispatcher_| guarantees
  // that it will remain alive until the associated tag becomes available
  // through the grpc |CompletionQueue|. This can only happen after it has been
  // requested.
  rpc_state_unowned->RequestRpc(completion_queue_.get());
}

void AsyncGrpcServerBase::OnIncomingRpc(
    const RpcStateFactory& rpc_state_factory,
    std::unique_ptr<RpcStateBase> rpc_state,
    bool ok) {
  if (state_ == State::kStarted)
    ExpectNextRpc(rpc_state_factory);
  // Exit on shutdown. In theory, incoming RPCs with |ok|==false can only happen
  // after gRPC shutdown has been triggered, which only happens after |state_|
  // has been switched to State::kShutdown, so it would be enough to check
  // |state_|. Checking both doesn't hurt and spells out the different
  // conditions explicitly.
  // The CompletionQueue gives back all pending tags in case of shutdown, so
  // that the server has the chance to free memory. Freeing memory happens
  // implicitly by letting the |rpc_state| go out of scope here.
  if (!ok || state_ == State::kShutDown)
    return;
  RpcStateBase* rpc_state_unowned = rpc_state.get();
  CHECK(rpcs_awaiting_handler_reply_.find(rpc_state_unowned->tag()) ==
        rpcs_awaiting_handler_reply_.end());
  rpcs_awaiting_handler_reply_.insert(
      std::make_pair(rpc_state_unowned->tag(), std::move(rpc_state)));
  // Note: It os OK to use |rpc_state_unowned| because it is now owned by
  // |rpcs_awaiting_handler_reply_|.
  // It is OK to use Unretained here, because |RpcStateBase| guarantees to
  // only call the callback if it hasn't been destroyed.
  rpc_state_unowned->CallHandler(
      base::BindOnce(&AsyncGrpcServerBase::OnHandlerDone,
                     base::Unretained(this), rpc_state_unowned->tag()));
}

void AsyncGrpcServerBase::OnHandlerDone(const void* tag) {
  auto iter = rpcs_awaiting_handler_reply_.find(tag);
  CHECK(iter != rpcs_awaiting_handler_reply_.end());
  std::unique_ptr<RpcStateBase> rpc_state = std::move(iter->second);
  rpcs_awaiting_handler_reply_.erase(iter);

  RpcStateBase* rpc_state_unowned = rpc_state.get();
  dispatcher_->RegisterTag(
      rpc_state_unowned->tag(),
      base::BindOnce(&AsyncGrpcServerBase::OnResponseSent,
                     base::Unretained(this), std::move(rpc_state)));
  // Note: It is OK to use |rpc_state_unowned| because |dispatcher_| guarantees
  // that it will remain alive until the associated tag becomes available
  // through the grpc |CompletionQueue|. This can only happen after it has been
  // added through |SendReply|.
  if (rpc_state_unowned->HasResponse()) {
    rpc_state_unowned->SendResponse();
    return;
  }
  rpc_state_unowned->Cancel();
}

void AsyncGrpcServerBase::OnResponseSent(
    std::unique_ptr<RpcStateBase> rpc_state, bool ok) {}

}  // namespace internal
}  // namespace brillo
