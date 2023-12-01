// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "vm_tools/cicerone/tremplin_listener_impl.h"

#include <arpa/inet.h>
#include <inttypes.h>
#include <stdio.h>

#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/strings/string_util.h>
#include <base/task/single_thread_task_runner.h>

#include "vm_tools/cicerone/service.h"

namespace vm_tools {
namespace cicerone {

TremplinListenerImpl::TremplinListenerImpl(
    base::WeakPtr<vm_tools::cicerone::Service> service)
    : service_(service),
      task_runner_(base::SingleThreadTaskRunner::GetCurrentDefault()) {}

void TremplinListenerImpl::OverridePeerAddressForTesting(
    const std::string& testing_peer_address) {
  base::AutoLock lock_scope(testing_peer_address_lock_);
  testing_peer_address_ = testing_peer_address;
}

grpc::Status TremplinListenerImpl::TremplinReady(
    grpc::ServerContext* ctx,
    const vm_tools::tremplin::TremplinStartupInfo* request,
    vm_tools::tremplin::EmptyMessage* response) {
  uint32_t cid = ExtractCidFromPeerAddress(ctx);
  if (cid == 0) {
    return grpc::Status(grpc::FAILED_PRECONDITION,
                        "Failed parsing vsock cid for TremplinListener");
  }

  bool result = false;
  base::WaitableEvent event(base::WaitableEvent::ResetPolicy::AUTOMATIC,
                            base::WaitableEvent::InitialState::NOT_SIGNALED);
  task_runner_->PostTask(
      FROM_HERE, base::BindOnce(&vm_tools::cicerone::Service::ConnectTremplin,
                                service_, cid, &result, &event));
  event.Wait();
  if (!result) {
    LOG(ERROR) << "Received TremplinReady but could not find matching VM: "
               << ctx->peer();
    return grpc::Status(grpc::FAILED_PRECONDITION,
                        "Cannot find VM for TremplinListener");
  }

  return grpc::Status::OK;
}

grpc::Status TremplinListenerImpl::UpdateCreateStatus(
    grpc::ServerContext* ctx,
    const vm_tools::tremplin::ContainerCreationProgress* request,
    vm_tools::tremplin::EmptyMessage* response) {
  uint32_t cid = ExtractCidFromPeerAddress(ctx);
  if (cid == 0) {
    return grpc::Status(grpc::FAILED_PRECONDITION,
                        "Failed parsing vsock cid for TremplinListener");
  }

  bool result = false;
  base::WaitableEvent event(base::WaitableEvent::ResetPolicy::AUTOMATIC,
                            base::WaitableEvent::InitialState::NOT_SIGNALED);
  if (request->status() == tremplin::ContainerCreationProgress::DOWNLOADING) {
    task_runner_->PostTask(
        FROM_HERE,
        base::BindOnce(&vm_tools::cicerone::Service::LxdContainerDownloading,
                       service_, cid, request->container_name(),
                       request->download_progress(), &result, &event));
  } else {
    vm_tools::cicerone::Service::CreateStatus status;
    switch (request->status()) {
      case tremplin::ContainerCreationProgress::CREATED:
        status = vm_tools::cicerone::Service::CreateStatus::CREATED;
        break;
      case tremplin::ContainerCreationProgress::DOWNLOAD_TIMED_OUT:
        status = vm_tools::cicerone::Service::CreateStatus::DOWNLOAD_TIMED_OUT;
        break;
      case tremplin::ContainerCreationProgress::CANCELLED:
        status = vm_tools::cicerone::Service::CreateStatus::CANCELLED;
        break;
      case tremplin::ContainerCreationProgress::FAILED:
        status = vm_tools::cicerone::Service::CreateStatus::FAILED;
        break;
      default:
        status = vm_tools::cicerone::Service::CreateStatus::UNKNOWN;
        break;
    }
    task_runner_->PostTask(
        FROM_HERE,
        base::BindOnce(&vm_tools::cicerone::Service::LxdContainerCreated,
                       service_, cid, request->container_name(), status,
                       request->failure_reason(), &result, &event));
  }

  event.Wait();
  if (!result) {
    LOG(ERROR)
        << "Received UpdateCreateStatus RPC but could not find matching VM: "
        << ctx->peer();
    return grpc::Status(grpc::FAILED_PRECONDITION,
                        "Cannot find VM for TremplinListener");
  }

  return grpc::Status::OK;
}

grpc::Status TremplinListenerImpl::UpdateDeletionStatus(
    grpc::ServerContext* ctx,
    const vm_tools::tremplin::ContainerDeletionProgress* request,
    vm_tools::tremplin::EmptyMessage* response) {
  uint32_t cid = ExtractCidFromPeerAddress(ctx);
  if (cid == 0) {
    return grpc::Status(grpc::FAILED_PRECONDITION,
                        "Failed parsing vsock cid for TremplinListener");
  }

  bool result = false;
  base::WaitableEvent event(base::WaitableEvent::ResetPolicy::AUTOMATIC,
                            base::WaitableEvent::InitialState::NOT_SIGNALED);

  task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(&vm_tools::cicerone::Service::LxdContainerDeleted,
                     service_, cid, request->container_name(),
                     request->status(), request->failure_reason(), &result,
                     &event));

  event.Wait();
  if (!result) {
    LOG(ERROR)
        << "Received UpdateDeletionStatus RPC but could not find matching VM: "
        << ctx->peer();
    return grpc::Status(grpc::FAILED_PRECONDITION,
                        "Cannot find VM for TremplinListener");
  }

  return grpc::Status::OK;
}

grpc::Status TremplinListenerImpl::UpdateStartStatus(
    grpc::ServerContext* ctx,
    const vm_tools::tremplin::ContainerStartProgress* request,
    vm_tools::tremplin::EmptyMessage* response) {
  uint32_t cid = ExtractCidFromPeerAddress(ctx);
  if (cid == 0) {
    return grpc::Status(grpc::FAILED_PRECONDITION,
                        "Failed parsing vsock cid for TremplinListener");
  }

  bool result = false;
  base::WaitableEvent event(base::WaitableEvent::ResetPolicy::AUTOMATIC,
                            base::WaitableEvent::InitialState::NOT_SIGNALED);
  vm_tools::cicerone::Service::StartStatus status;
  switch (request->status()) {
    case tremplin::ContainerStartProgress::STARTED:
      status = vm_tools::cicerone::Service::StartStatus::STARTED;
      break;
    case tremplin::ContainerStartProgress::CANCELLED:
      status = vm_tools::cicerone::Service::StartStatus::CANCELLED;
      break;
    case tremplin::ContainerStartProgress::FAILED:
      status = vm_tools::cicerone::Service::StartStatus::FAILED;
      break;
    case tremplin::ContainerStartProgress::STARTING:
      status = vm_tools::cicerone::Service::StartStatus::STARTING;
      break;
    default:
      status = vm_tools::cicerone::Service::StartStatus::UNKNOWN;
      break;
  }
  task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(&vm_tools::cicerone::Service::LxdContainerStarting,
                     service_, cid, request->container_name(), status,
                     request->failure_reason(), &result, &event));

  event.Wait();
  if (!result) {
    LOG(ERROR)
        << "Received UpdateStartStatus RPC but could not find matching VM: "
        << ctx->peer();
    return grpc::Status(grpc::FAILED_PRECONDITION,
                        "Cannot find VM for TremplinListener");
  }

  return grpc::Status::OK;
}

grpc::Status TremplinListenerImpl::UpdateStopStatus(
    grpc::ServerContext* ctx,
    const vm_tools::tremplin::ContainerStopProgress* request,
    vm_tools::tremplin::EmptyMessage* response) {
  uint32_t cid = ExtractCidFromPeerAddress(ctx);
  if (cid == 0) {
    return grpc::Status(grpc::FAILED_PRECONDITION,
                        "Failed parsing vsock cid for TremplinListener");
  }

  bool result = false;
  base::WaitableEvent event(base::WaitableEvent::ResetPolicy::AUTOMATIC,
                            base::WaitableEvent::InitialState::NOT_SIGNALED);
  vm_tools::cicerone::Service::StopStatus status;
  switch (request->status()) {
    case tremplin::ContainerStopProgress::STOPPED:
      status = vm_tools::cicerone::Service::StopStatus::STOPPED;
      break;
    case tremplin::ContainerStopProgress::CANCELLED:
      status = vm_tools::cicerone::Service::StopStatus::CANCELLED;
      break;
    case tremplin::ContainerStopProgress::FAILED:
      status = vm_tools::cicerone::Service::StopStatus::FAILED;
      break;
    case tremplin::ContainerStopProgress::STOPPING:
      status = vm_tools::cicerone::Service::StopStatus::STOPPING;
      break;
    default:
      status = vm_tools::cicerone::Service::StopStatus::UNKNOWN;
      break;
  }
  task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(&vm_tools::cicerone::Service::LxdContainerStopping,
                     service_, cid, request->container_name(), status,
                     request->failure_reason(), &result, &event));

  event.Wait();
  if (!result) {
    LOG(ERROR)
        << "Received UpdateStartStatus RPC but could not find matching VM: "
        << ctx->peer();
    return grpc::Status(grpc::FAILED_PRECONDITION,
                        "Cannot find VM for TremplinListener");
  }

  return grpc::Status::OK;
}

grpc::Status TremplinListenerImpl::UpdateExportStatus(
    grpc::ServerContext* ctx,
    const vm_tools::tremplin::ContainerExportProgress* request,
    vm_tools::tremplin::EmptyMessage* response) {
  uint32_t cid = ExtractCidFromPeerAddress(ctx);
  if (cid == 0) {
    return grpc::Status(grpc::FAILED_PRECONDITION,
                        "Failed parsing vsock cid for TremplinListener");
  }

  ExportLxdContainerProgressSignal progress_signal;
  if (!ExportLxdContainerProgressSignal::Status_IsValid(
          static_cast<int>(request->status()))) {
    return grpc::Status(grpc::FAILED_PRECONDITION,
                        "Invalid status field in protobuf request");
  }
  progress_signal.set_status(
      static_cast<ExportLxdContainerProgressSignal::Status>(request->status()));
  progress_signal.set_container_name(request->container_name());
  progress_signal.set_failure_reason(request->failure_reason());
  progress_signal.set_total_input_files(request->total_input_files());
  progress_signal.set_total_input_bytes(request->total_input_bytes());
  progress_signal.set_input_files_streamed(request->input_files_streamed());
  progress_signal.set_input_bytes_streamed(request->input_bytes_streamed());
  progress_signal.set_bytes_exported(request->bytes_exported());
  base::WaitableEvent event(base::WaitableEvent::ResetPolicy::AUTOMATIC,
                            base::WaitableEvent::InitialState::NOT_SIGNALED);
  bool result = false;
  task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(&vm_tools::cicerone::Service::ContainerExportProgress,
                     service_, cid, &progress_signal, &result, &event));
  event.Wait();
  if (!result) {
    LOG(ERROR) << "Failure updating container export progress";
    return grpc::Status(grpc::FAILED_PRECONDITION,
                        "Failure in UpdateExportStatus");
  }

  return grpc::Status::OK;
}

grpc::Status TremplinListenerImpl::UpdateImportStatus(
    grpc::ServerContext* ctx,
    const vm_tools::tremplin::ContainerImportProgress* request,
    vm_tools::tremplin::EmptyMessage* response) {
  uint32_t cid = ExtractCidFromPeerAddress(ctx);
  if (cid == 0) {
    return grpc::Status(grpc::FAILED_PRECONDITION,
                        "Failed parsing vsock cid for TremplinListener");
  }

  ImportLxdContainerProgressSignal progress_signal;
  if (!ImportLxdContainerProgressSignal::Status_IsValid(
          static_cast<int>(request->status()))) {
    return grpc::Status(grpc::FAILED_PRECONDITION,
                        "Invalid status field in protobuf request");
  }
  progress_signal.set_status(
      static_cast<ImportLxdContainerProgressSignal::Status>(request->status()));
  progress_signal.set_container_name(request->container_name());
  progress_signal.set_progress_percent(request->progress_percent());
  progress_signal.set_progress_speed(request->progress_speed());
  progress_signal.set_failure_reason(request->failure_reason());
  progress_signal.set_architecture_device(request->architecture_device());
  progress_signal.set_architecture_container(request->architecture_container());
  progress_signal.set_available_space(request->disk_space_available_bytes());
  progress_signal.set_min_required_space(request->disk_space_required_bytes());

  base::WaitableEvent event(base::WaitableEvent::ResetPolicy::AUTOMATIC,
                            base::WaitableEvent::InitialState::NOT_SIGNALED);
  bool result = false;
  task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(&vm_tools::cicerone::Service::ContainerImportProgress,
                     service_, cid, &progress_signal, &result, &event));
  event.Wait();
  if (!result) {
    LOG(ERROR) << "Failure updating container import progress";
    return grpc::Status(grpc::FAILED_PRECONDITION,
                        "Failure in UpdateImportStatus");
  }

  return grpc::Status::OK;
}

grpc::Status TremplinListenerImpl::ContainerShutdown(
    grpc::ServerContext* ctx,
    const vm_tools::tremplin::ContainerShutdownInfo* request,
    vm_tools::tremplin::EmptyMessage* response) {
  uint32_t cid = ExtractCidFromPeerAddress(ctx);
  if (cid == 0) {
    return grpc::Status(grpc::FAILED_PRECONDITION,
                        "Failed parsing vsock cid for TremplinListener");
  }

  if (request->container_name().empty()) {
    return grpc::Status(grpc::INVALID_ARGUMENT,
                        "`container_name` cannot be empty");
  }

  // Calls coming from tremplin are trusted to use container_name rather than
  // container_token.
  std::string container_token = "";
  base::WaitableEvent event(base::WaitableEvent::ResetPolicy::AUTOMATIC,
                            base::WaitableEvent::InitialState::NOT_SIGNALED);

  bool result = false;
  task_runner_->PostTask(
      FROM_HERE, base::BindOnce(&vm_tools::cicerone::Service::ContainerShutdown,
                                service_, request->container_name(),
                                container_token, cid, &result, &event));
  event.Wait();
  if (!result) {
    LOG(ERROR) << "Error in tremplin listener ContainerShutdown for "
               << request->container_name();
  }
  return grpc::Status::OK;
}

grpc::Status TremplinListenerImpl::UpdateListeningPorts(
    grpc::ServerContext* ctx,
    const vm_tools::tremplin::ListeningPortInfo* request,
    vm_tools::tremplin::EmptyMessage* response) {
  uint32_t cid = ExtractCidFromPeerAddress(ctx);
  if (cid == 0) {
    return grpc::Status(grpc::FAILED_PRECONDITION,
                        "Failed parsing vsock cid for TremplinListener");
  }

  std::map<std::string, std::vector<uint16_t>> listening_tcp4_ports;
  for (auto& pair : request->container_ports()) {
    std::vector<uint16_t> target_ports;
    for (int i = 0; i < pair.second.listening_tcp4_ports_size(); i++) {
      target_ports.push_back(pair.second.listening_tcp4_ports(i));
    }

    listening_tcp4_ports[pair.first] = target_ports;
  }

  base::WaitableEvent event(base::WaitableEvent::ResetPolicy::AUTOMATIC,
                            base::WaitableEvent::InitialState::NOT_SIGNALED);

  bool result = false;
  task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(&vm_tools::cicerone::Service::UpdateListeningPorts,
                     service_, std::move(listening_tcp4_ports), cid, &result,
                     &event));
  event.Wait();
  if (!result) {
    LOG(ERROR) << "Error in tremplin listener UpdateListeningPorts";
  }
  return grpc::Status::OK;
}

grpc::Status TremplinListenerImpl::UpgradeContainerStatus(
    grpc::ServerContext* ctx,
    const vm_tools::tremplin::UpgradeContainerProgress* request,
    vm_tools::tremplin::EmptyMessage* response) {
  uint32_t cid = ExtractCidFromPeerAddress(ctx);
  if (cid == 0) {
    return grpc::Status(grpc::FAILED_PRECONDITION,
                        "Failed parsing vsock cid for TremplinListener");
  }

  UpgradeContainerProgressSignal progress_signal;
  if (!UpgradeContainerProgressSignal::Status_IsValid(
          static_cast<int>(request->status()))) {
    return grpc::Status(grpc::FAILED_PRECONDITION,
                        "Invalid status field in protobuf request");
  }
  progress_signal.set_status(
      static_cast<UpgradeContainerProgressSignal::Status>(request->status()));
  progress_signal.set_container_name(request->container_name());
  progress_signal.set_failure_reason(request->failure_reason());
  progress_signal.mutable_progress_messages()->CopyFrom(
      request->progress_messages());

  base::WaitableEvent event(base::WaitableEvent::ResetPolicy::AUTOMATIC,
                            base::WaitableEvent::InitialState::NOT_SIGNALED);
  bool result = false;
  task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(&vm_tools::cicerone::Service::ContainerUpgradeProgress,
                     service_, cid, &progress_signal, &result, &event));
  event.Wait();
  if (!result) {
    LOG(ERROR) << "Failure sending upgrade container progress";
    return grpc::Status(grpc::FAILED_PRECONDITION,
                        "Failure in UgradeContainertatus");
  }

  return grpc::Status::OK;
}

grpc::Status TremplinListenerImpl::UpdateStartLxdStatus(
    grpc::ServerContext* ctx,
    const vm_tools::tremplin::StartLxdProgress* request,
    vm_tools::tremplin::EmptyMessage* response) {
  uint32_t cid = ExtractCidFromPeerAddress(ctx);
  if (cid == 0) {
    return grpc::Status(grpc::FAILED_PRECONDITION,
                        "Failed parsing vsock cid for TremplinListener");
  }

  StartLxdProgressSignal progress_signal;
  if (!StartLxdProgressSignal::Status_IsValid(
          static_cast<int>(request->status()))) {
    return grpc::Status(grpc::FAILED_PRECONDITION,
                        "Invalid status field in protobuf request");
  }
  progress_signal.set_status(
      static_cast<StartLxdProgressSignal::Status>(request->status()));
  progress_signal.set_failure_reason(request->failure_reason());

  base::WaitableEvent event(base::WaitableEvent::ResetPolicy::AUTOMATIC,
                            base::WaitableEvent::InitialState::NOT_SIGNALED);
  bool result = false;
  task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(&vm_tools::cicerone::Service::StartLxdProgress, service_,
                     cid, &progress_signal, &result, &event));
  event.Wait();
  if (!result) {
    LOG(ERROR) << "Failure sending start lxd progress";
    return grpc::Status(grpc::FAILED_PRECONDITION, "Failure in StartLxdStatus");
  }

  return grpc::Status::OK;
}

// Returns 0 on failure, otherwise returns the 32-bit vsock cid.
uint32_t TremplinListenerImpl::ExtractCidFromPeerAddress(
    grpc::ServerContext* ctx) {
  uint32_t cid = 0;
  std::string peer_address = ctx->peer();
  {
    base::AutoLock lock_scope(testing_peer_address_lock_);
    if (!testing_peer_address_.empty()) {
      peer_address = testing_peer_address_;
    }
  }
  if (sscanf(peer_address.c_str(), "vsock:%" SCNu32, &cid) != 1) {
    LOG(WARNING) << "Failed to parse peer address " << peer_address;
    return 0;
  }
  return cid;
}

}  // namespace cicerone
}  // namespace vm_tools
