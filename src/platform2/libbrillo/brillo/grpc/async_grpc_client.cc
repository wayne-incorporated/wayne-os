// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "brillo/grpc/async_grpc_client.h"

#include <utility>

#include "brillo/grpc/async_grpc_constants.h"

namespace brillo {
namespace internal {

AsyncGrpcClientBase::AsyncGrpcClientBase(
    scoped_refptr<base::SequencedTaskRunner> task_runner)
    : dispatcher_(&completion_queue_, task_runner) {
  dispatcher_.Start();
}

AsyncGrpcClientBase::~AsyncGrpcClientBase() = default;

void AsyncGrpcClientBase::ShutDown(base::OnceClosure on_shutdown_callback) {
  dispatcher_.Shutdown(std::move(on_shutdown_callback));
}

// static
std::shared_ptr<grpc::Channel> AsyncGrpcClientBase::CreateGrpcChannel(
    const std::string& target_uri) {
  grpc::ChannelArguments arguments;
  arguments.SetMaxSendMessageSize(kMaxGrpcMessageSize);
  arguments.SetMaxReceiveMessageSize(kMaxGrpcMessageSize);
  arguments.SetInt(GRPC_ARG_MIN_RECONNECT_BACKOFF_MS,
                   kMinGrpcReconnectBackoffTime.InMilliseconds());
  arguments.SetInt(GRPC_ARG_INITIAL_RECONNECT_BACKOFF_MS,
                   kInitialGrpcReconnectBackoffTime.InMilliseconds());
  arguments.SetInt(GRPC_ARG_MAX_RECONNECT_BACKOFF_MS,
                   kMaxGrpcReconnectBackoffTime.InMilliseconds());
  return grpc::CreateCustomChannel(
      target_uri, grpc::InsecureChannelCredentials(), arguments);
}

}  // namespace internal
}  // namespace brillo
