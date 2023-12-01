// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/dpsl/internal/dpsl_rpc_server_impl.h"

#include <functional>
#include <utility>

#include <base/check.h>
#include <base/functional/bind.h>
#include <base/location.h>
#include <base/logging.h>
#include <base/memory/ref_counted.h>
#include <base/notreached.h>
#include <base/run_loop.h>
#include <base/task/single_thread_task_runner.h>

#include "diagnostics/constants/grpc_constants.h"
#include "diagnostics/dpsl/internal/callback_utils.h"
#include "diagnostics/dpsl/public/dpsl_rpc_handler.h"
#include "diagnostics/dpsl/public/dpsl_thread_context.h"

namespace diagnostics {

namespace {

std::string GetWilcoDtcGrpcUri(DpslRpcServer::GrpcServerUri grpc_server_uri) {
  switch (grpc_server_uri) {
    case DpslRpcServer::GrpcServerUri::kVmVsock:
      return GetWilcoDtcGrpcGuestVsockUri();
    case DpslRpcServer::GrpcServerUri::kUiMessageReceiverVmVsock:
      return GetUiMessageReceiverWilcoDtcGrpcGuestVsockUri();
  }
  NOTREACHED() << "Unexpected GrpcServerUri: "
               << static_cast<int>(grpc_server_uri);
  return "";
}

}  // namespace

DpslRpcServerImpl::DpslRpcServerImpl(DpslRpcHandler* rpc_handler,
                                     GrpcServerUri grpc_server_uri,
                                     const std::string& grpc_server_uri_string)
    : rpc_handler_(rpc_handler),
      async_grpc_server_(base::SingleThreadTaskRunner::GetCurrentDefault(),
                         {grpc_server_uri_string}) {
  DCHECK(rpc_handler_);
  auto handle_message_from_ui_handler =
      &DpslRpcServerImpl::HandleMessageFromUiStub;
  switch (grpc_server_uri) {
    case GrpcServerUri::kVmVsock:
      break;
    case GrpcServerUri::kUiMessageReceiverVmVsock:
      handle_message_from_ui_handler = &DpslRpcServerImpl::HandleMessageFromUi;
      break;
  }
  async_grpc_server_.RegisterHandler(
      &grpc_api::WilcoDtc::AsyncService::RequestHandleMessageFromUi,
      base::BindRepeating(handle_message_from_ui_handler,
                          base::Unretained(this)));

  async_grpc_server_.RegisterHandler(
      &grpc_api::WilcoDtc::AsyncService::RequestHandleEcNotification,
      base::BindRepeating(&DpslRpcServerImpl::HandleEcNotification,
                          base::Unretained(this)));
  async_grpc_server_.RegisterHandler(
      &grpc_api::WilcoDtc::AsyncService::RequestHandlePowerNotification,
      base::BindRepeating(&DpslRpcServerImpl::HandlePowerNotification,
                          base::Unretained(this)));
  async_grpc_server_.RegisterHandler(
      &grpc_api::WilcoDtc::AsyncService::RequestHandleConfigurationDataChanged,
      base::BindRepeating(&DpslRpcServerImpl::HandleConfigurationDataChanged,
                          base::Unretained(this)));
  async_grpc_server_.RegisterHandler(
      &grpc_api::WilcoDtc::AsyncService::RequestHandleBluetoothDataChanged,
      base::BindRepeating(&DpslRpcServerImpl::HandleBluetoothDataChanged,
                          base::Unretained(this)));
}

DpslRpcServerImpl::~DpslRpcServerImpl() {
  CHECK(sequence_checker_.CalledOnValidSequence());

  base::RunLoop run_loop;
  async_grpc_server_.ShutDown(run_loop.QuitClosure());
  run_loop.Run();
}

bool DpslRpcServerImpl::Init() {
  DCHECK(sequence_checker_.CalledOnValidSequence());

  return async_grpc_server_.Start();
}

void DpslRpcServerImpl::HandleMessageFromUi(
    std::unique_ptr<grpc_api::HandleMessageFromUiRequest> request,
    HandleMessageFromUiCallback callback) {
  DCHECK(sequence_checker_.CalledOnValidSequence());

  rpc_handler_->HandleMessageFromUi(
      std::move(request),
      MakeStdFunctionFromCallbackGrpc(
          MakeOriginTaskRunnerPostingCallback(FROM_HERE, std::move(callback))));
}

void DpslRpcServerImpl::HandleMessageFromUiStub(
    std::unique_ptr<grpc_api::HandleMessageFromUiRequest> request,
    HandleMessageFromUiCallback callback) {
  DCHECK(sequence_checker_.CalledOnValidSequence());

  std::move(callback).Run(
      grpc::Status(grpc::StatusCode::UNIMPLEMENTED, "Unimplemented"),
      nullptr /* response */);
}

void DpslRpcServerImpl::HandleEcNotification(
    std::unique_ptr<grpc_api::HandleEcNotificationRequest> request,
    HandleEcNotificationCallback callback) {
  DCHECK(sequence_checker_.CalledOnValidSequence());

  rpc_handler_->HandleEcNotification(
      std::move(request),
      MakeStdFunctionFromCallbackGrpc(
          MakeOriginTaskRunnerPostingCallback(FROM_HERE, std::move(callback))));
}

void DpslRpcServerImpl::HandlePowerNotification(
    std::unique_ptr<grpc_api::HandlePowerNotificationRequest> request,
    HandlePowerNotificationCallback callback) {
  DCHECK(sequence_checker_.CalledOnValidSequence());

  rpc_handler_->HandlePowerNotification(
      std::move(request),
      MakeStdFunctionFromCallbackGrpc(
          MakeOriginTaskRunnerPostingCallback(FROM_HERE, std::move(callback))));
}

void DpslRpcServerImpl::HandleConfigurationDataChanged(
    std::unique_ptr<grpc_api::HandleConfigurationDataChangedRequest> request,
    HandleConfigurationDataChangedCallback callback) {
  DCHECK(sequence_checker_.CalledOnValidSequence());

  rpc_handler_->HandleConfigurationDataChanged(
      std::move(request),
      MakeStdFunctionFromCallbackGrpc(
          MakeOriginTaskRunnerPostingCallback(FROM_HERE, std::move(callback))));
}

void DpslRpcServerImpl::HandleBluetoothDataChanged(
    std::unique_ptr<grpc_api::HandleBluetoothDataChangedRequest> request,
    HandleBluetoothDataChangedCallback callback) {
  DCHECK(sequence_checker_.CalledOnValidSequence());

  rpc_handler_->HandleBluetoothDataChanged(
      std::move(request),
      MakeStdFunctionFromCallbackGrpc(
          MakeOriginTaskRunnerPostingCallback(FROM_HERE, std::move(callback))));
}

// static
std::unique_ptr<DpslRpcServer> DpslRpcServer::Create(
    DpslThreadContext* thread_context,
    DpslRpcHandler* rpc_handler,
    GrpcServerUri grpc_server_uri) {
  CHECK(thread_context) << "Thread context is nullptr";
  CHECK(rpc_handler) << "Rpc handler is nullptr";
  CHECK(thread_context->BelongsToCurrentThread()) << "Called from wrong thread";

  auto dpsl_rpc_server_impl = std::make_unique<DpslRpcServerImpl>(
      rpc_handler, grpc_server_uri, GetWilcoDtcGrpcUri(grpc_server_uri));
  if (!dpsl_rpc_server_impl->Init())
    return nullptr;
  return dpsl_rpc_server_impl;
}

}  // namespace diagnostics
