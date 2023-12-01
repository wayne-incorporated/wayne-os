// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "vm_tools/cicerone/container_listener_impl.h"

#include <arpa/inet.h>
#include <inttypes.h>
#include <stdio.h>

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/strings/string_util.h>
#include <base/task/single_thread_task_runner.h>
#include <vm_applications/apps.pb.h>
#include <vm_cicerone/cicerone_service.pb.h>
#include <vm_protos/proto_bindings/container_host.pb.h>
#include <re2/re2.h>

#include "vm_tools/cicerone/service.h"

namespace {
// These rate limit settings ensure that calls that open a new window/tab can't
// be made more than 10 times in a 15 second interval approximately.
constexpr base::TimeDelta kOpenRateWindow = base::Seconds(15);
constexpr uint32_t kOpenRateLimit = 10;
}  // namespace

namespace vm_tools {
namespace cicerone {

ContainerListenerImpl::ContainerListenerImpl(
    base::WeakPtr<vm_tools::cicerone::Service> service)
    : service_(service),
      task_runner_(base::SingleThreadTaskRunner::GetCurrentDefault()),
      open_count_(0),
      open_rate_window_start_(base::TimeTicks::Now()) {}

void ContainerListenerImpl::OverridePeerAddressForTesting(
    const std::string& testing_peer_address) {
  base::AutoLock lock_scope(testing_peer_address_lock_);
  testing_peer_address_ = testing_peer_address;
}

grpc::Status ContainerListenerImpl::ContainerReady(
    grpc::ServerContext* ctx,
    const vm_tools::container::ContainerStartupInfo* request,
    vm_tools::EmptyMessage* response) {
  uint32_t cid = ExtractCidFromPeerAddress(ctx);
  // Plugin VMs (i.e. containerless) can call this, so allow a zero value CID.
  bool result = false;
  base::WaitableEvent event(base::WaitableEvent::ResetPolicy::AUTOMATIC,
                            base::WaitableEvent::InitialState::NOT_SIGNALED);
  task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(&vm_tools::cicerone::Service::ContainerStartupCompleted,
                     service_, request->token(), cid, request->garcon_port(),
                     request->sftp_port(), &result, &event));
  event.Wait();
  if (!result) {
    LOG(ERROR) << "Received ContainerReady but could not find matching VM: "
               << ctx->peer();
    return grpc::Status(grpc::FAILED_PRECONDITION,
                        "Cannot find VM for ContainerListener");
  }

  return grpc::Status::OK;
}

grpc::Status ContainerListenerImpl::ContainerShutdown(
    grpc::ServerContext* ctx,
    const vm_tools::container::ContainerShutdownInfo* request,
    vm_tools::EmptyMessage* response) {
  uint32_t cid = ExtractCidFromPeerAddress(ctx);
  if (cid == 0) {
    return grpc::Status(grpc::FAILED_PRECONDITION,
                        "Failed parsing cid for ContainerListener");
  }

  if (request->token().empty()) {
    return grpc::Status(grpc::INVALID_ARGUMENT, "`token` cannot be empty");
  }

  // Calls coming from garcon should not be trusted to set container_name and
  // must use container_token.
  std::string container_name = "";
  bool result = false;
  base::WaitableEvent event(base::WaitableEvent::ResetPolicy::AUTOMATIC,
                            base::WaitableEvent::InitialState::NOT_SIGNALED);
  task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(&vm_tools::cicerone::Service::ContainerShutdown, service_,
                     container_name, request->token(), cid, &result, &event));
  event.Wait();
  if (!result) {
    LOG(WARNING)
        << "Received ContainerShutdown but could not find matching VM: "
        << ctx->peer();
    return grpc::Status(grpc::FAILED_PRECONDITION,
                        "Cannot find VM for ContainerListener");
  }

  return grpc::Status::OK;
}

grpc::Status ContainerListenerImpl::PendingUpdateApplicationListCalls(
    grpc::ServerContext* ctx,
    const vm_tools::container::PendingAppListUpdateCount* request,
    vm_tools::EmptyMessage* response) {
  uint32_t cid = ExtractCidFromPeerAddress(ctx);
  if (cid == 0) {
    return grpc::Status(grpc::FAILED_PRECONDITION,
                        "Failed parsing cid for ContainerListener");
  }

  if (request->token().empty()) {
    return grpc::Status(grpc::INVALID_ARGUMENT, "`token` cannot be empty");
  }

  bool result = false;
  base::WaitableEvent event(base::WaitableEvent::ResetPolicy::AUTOMATIC,
                            base::WaitableEvent::InitialState::NOT_SIGNALED);
  task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(
          &vm_tools::cicerone::Service::PendingUpdateApplicationListCalls,
          service_, request->token(), cid, request->count(), &result, &event));
  event.Wait();
  if (!result) {
    LOG(ERROR) << "Received ContainerShutdown but could not find matching VM: "
               << ctx->peer();
    return grpc::Status(grpc::FAILED_PRECONDITION,
                        "Cannot find VM for ContainerListener");
  }

  return grpc::Status::OK;
}

grpc::Status ContainerListenerImpl::UpdateApplicationList(
    grpc::ServerContext* ctx,
    const vm_tools::container::UpdateApplicationListRequest* request,
    vm_tools::EmptyMessage* response) {
  uint32_t cid = ExtractCidFromPeerAddress(ctx);
  // Plugin VMs (i.e. containerless) can call this, so allow a zero value CID.
  vm_tools::apps::ApplicationList app_list;
  // vm_name and container_name are set in the UpdateApplicationList call but
  // we need to copy everything else out of the incoming protobuf here.
  for (const auto& app_in : request->application()) {
    auto app_out = app_list.add_apps();
    // Set the non-repeating fields first.
    app_out->set_desktop_file_id(app_in.desktop_file_id());
    app_out->set_no_display(app_in.no_display());
    app_out->set_startup_wm_class(app_in.startup_wm_class());
    app_out->set_startup_notify(app_in.startup_notify());
    app_out->set_package_id(app_in.package_id());
    app_out->set_exec(app_in.exec());
    app_out->set_executable_file_name(app_in.executable_file_name());
    app_out->set_terminal(app_in.terminal());
    // Set the mime types.
    for (const auto& mime_type : app_in.mime_types()) {
      app_out->add_mime_types(mime_type);
    }
    // Set the names, comments & keywords.
    if (app_in.has_name()) {
      auto name_out = app_out->mutable_name();
      for (const auto& names : app_in.name().values()) {
        auto curr_name = name_out->add_values();
        curr_name->set_locale(names.locale());
        curr_name->set_value(names.value());
      }
    }
    if (app_in.has_comment()) {
      auto comment_out = app_out->mutable_comment();
      for (const auto& comments : app_in.comment().values()) {
        auto curr_comment = comment_out->add_values();
        curr_comment->set_locale(comments.locale());
        curr_comment->set_value(comments.value());
      }
    }
    if (app_in.has_keywords()) {
      auto keywords_out = app_out->mutable_keywords();
      for (const auto& keyword : app_in.keywords().values()) {
        auto curr_keywords = keywords_out->add_values();
        curr_keywords->set_locale(keyword.locale());
        for (const auto& curr_value : keyword.value()) {
          curr_keywords->add_value(curr_value);
        }
      }
    }
    // Set the extensions.
    for (const auto& extension : app_in.extensions()) {
      app_out->add_extensions(extension);
    }
  }
  base::WaitableEvent event(base::WaitableEvent::ResetPolicy::AUTOMATIC,
                            base::WaitableEvent::InitialState::NOT_SIGNALED);
  bool result = false;
  task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(&vm_tools::cicerone::Service::UpdateApplicationList,
                     service_, request->token(), cid, &app_list, &result,
                     &event));
  event.Wait();
  if (!result) {
    LOG(ERROR) << "Failure updating application list from ContainerListener";
    return grpc::Status(grpc::FAILED_PRECONDITION,
                        "Failure in UpdateApplicationList");
  }

  return grpc::Status::OK;
}

grpc::Status ContainerListenerImpl::OpenUrl(
    grpc::ServerContext* ctx,
    const vm_tools::container::OpenUrlRequest* request,
    vm_tools::EmptyMessage* response) {
  // Check on rate limiting before we process this.
  if (!CheckOpenRateLimit()) {
    return grpc::Status(grpc::RESOURCE_EXHAUSTED,
                        "OpenUrl rate limit exceeded, blocking request");
  }
  LOG(INFO) << "Got OpenUrl request from container";

  uint32_t cid = ExtractCidFromPeerAddress(ctx);
  // Plugin VMs (i.e. containerless) can call this, so allow a zero value CID.
  base::WaitableEvent event(base::WaitableEvent::ResetPolicy::AUTOMATIC,
                            base::WaitableEvent::InitialState::NOT_SIGNALED);
  bool result = false;
  task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(&vm_tools::cicerone::Service::OpenUrl, service_,
                     request->token(), request->url(), cid, &result, &event));
  event.Wait();
  if (!result) {
    LOG(ERROR) << "Failure opening URL from ContainerListener";
    return grpc::Status(grpc::FAILED_PRECONDITION, "Failure in OpenUrl");
  }
  return grpc::Status::OK;
}

grpc::Status ContainerListenerImpl::InstallLinuxPackageProgress(
    grpc::ServerContext* ctx,
    const vm_tools::container::InstallLinuxPackageProgressInfo* request,
    vm_tools::EmptyMessage* response) {
  uint32_t cid = ExtractCidFromPeerAddress(ctx);
  if (cid == 0) {
    return grpc::Status(grpc::FAILED_PRECONDITION,
                        "Failed parsing cid for ContainerListener");
  }
  InstallLinuxPackageProgressSignal progress_signal;
  if (!InstallLinuxPackageProgressSignal::Status_IsValid(
          static_cast<int>(request->status()))) {
    return grpc::Status(grpc::FAILED_PRECONDITION,
                        "Invalid status field in protobuf request");
  }
  progress_signal.set_status(
      static_cast<InstallLinuxPackageProgressSignal::Status>(
          request->status()));
  progress_signal.set_progress_percent(request->progress_percent());
  progress_signal.set_failure_details(request->failure_details());
  progress_signal.set_command_uuid(request->command_uuid());
  base::WaitableEvent event(base::WaitableEvent::ResetPolicy::AUTOMATIC,
                            base::WaitableEvent::InitialState::NOT_SIGNALED);
  bool result = false;
  task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(&vm_tools::cicerone::Service::InstallLinuxPackageProgress,
                     service_, request->token(), cid, &progress_signal, &result,
                     &event));
  event.Wait();
  if (!result) {
    LOG(ERROR) << "Failure updating Linux package install progress from "
                  "ContainerListener";
    return grpc::Status(grpc::FAILED_PRECONDITION,
                        "Failure in InstallLinuxPackageProgress");
  }

  return grpc::Status::OK;
}

grpc::Status ContainerListenerImpl::UninstallPackageProgress(
    grpc::ServerContext* ctx,
    const vm_tools::container::UninstallPackageProgressInfo* request,
    vm_tools::EmptyMessage* response) {
  uint32_t cid = ExtractCidFromPeerAddress(ctx);
  if (cid == 0) {
    return grpc::Status(grpc::FAILED_PRECONDITION,
                        "Failed parsing cid for ContainerListener");
  }
  UninstallPackageProgressSignal progress_signal;
  switch (request->status()) {
    case vm_tools::container::UninstallPackageProgressInfo::SUCCEEDED:
      progress_signal.set_status(UninstallPackageProgressSignal::SUCCEEDED);
      break;
    case vm_tools::container::UninstallPackageProgressInfo::FAILED:
      progress_signal.set_status(UninstallPackageProgressSignal::FAILED);
      progress_signal.set_failure_details(request->failure_details());
      break;
    case vm_tools::container::UninstallPackageProgressInfo::UNINSTALLING:
      progress_signal.set_status(UninstallPackageProgressSignal::UNINSTALLING);
      progress_signal.set_progress_percent(request->progress_percent());
      break;
    default:
      return grpc::Status(grpc::FAILED_PRECONDITION,
                          "Invalid status field in protobuf request");
  }
  base::WaitableEvent event(base::WaitableEvent::ResetPolicy::AUTOMATIC,
                            base::WaitableEvent::InitialState::NOT_SIGNALED);
  bool result = false;
  task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(&vm_tools::cicerone::Service::UninstallPackageProgress,
                     service_, request->token(), cid, &progress_signal, &result,
                     &event));
  event.Wait();
  if (!result) {
    LOG(ERROR) << "Failure updating Linux package uninstall progress from "
                  "ContainerListener";
    return grpc::Status(grpc::FAILED_PRECONDITION,
                        "Failure in UninstallPackageProgress");
  }

  return grpc::Status::OK;
}

grpc::Status ContainerListenerImpl::ApplyAnsiblePlaybookProgress(
    grpc::ServerContext* ctx,
    const vm_tools::container::ApplyAnsiblePlaybookProgressInfo* request,
    vm_tools::EmptyMessage* response) {
  uint32_t cid = ExtractCidFromPeerAddress(ctx);
  if (cid == 0) {
    return grpc::Status(grpc::FAILED_PRECONDITION,
                        "Failed parsing cid for ContainerListener");
  }
  ApplyAnsiblePlaybookProgressSignal progress_signal;
  if (!ApplyAnsiblePlaybookProgressSignal::Status_IsValid(
          static_cast<int>(request->status()))) {
    return grpc::Status(grpc::FAILED_PRECONDITION,
                        "Invalid status field in protobuf request");
  }
  progress_signal.set_status(
      static_cast<ApplyAnsiblePlaybookProgressSignal::Status>(
          request->status()));
  progress_signal.set_failure_details(request->failure_details());
  for (auto line : request->status_string())
    progress_signal.add_status_string(line);
  base::WaitableEvent event(base::WaitableEvent::ResetPolicy::AUTOMATIC,
                            base::WaitableEvent::InitialState::NOT_SIGNALED);
  bool result = false;
  task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(&vm_tools::cicerone::Service::ApplyAnsiblePlaybookProgress,
                     service_, request->token(), cid, &progress_signal, &result,
                     &event));
  event.Wait();
  if (!result) {
    LOG(ERROR) << "Failure updating Ansible playbook application progress from "
                  "ContainerListener";
    return grpc::Status(grpc::FAILED_PRECONDITION,
                        "Failure in ApplyAnsiblePlaybookProgress");
  }

  return grpc::Status::OK;
}

grpc::Status ContainerListenerImpl::OpenTerminal(
    grpc::ServerContext* ctx,
    const vm_tools::container::OpenTerminalRequest* request,
    vm_tools::EmptyMessage* response) {
  // Check on rate limiting before we process this.
  if (!CheckOpenRateLimit()) {
    return grpc::Status(grpc::RESOURCE_EXHAUSTED,
                        "OpenTerminal rate limit exceeded, blocking request");
  }
  uint32_t cid = ExtractCidFromPeerAddress(ctx);
  if (cid == 0) {
    return grpc::Status(grpc::FAILED_PRECONDITION,
                        "Failed parsing cid for ContainerListener");
  }
  vm_tools::apps::TerminalParams terminal_params;
  terminal_params.mutable_params()->CopyFrom(request->params());
  base::WaitableEvent event(base::WaitableEvent::ResetPolicy::AUTOMATIC,
                            base::WaitableEvent::InitialState::NOT_SIGNALED);
  bool result = false;
  task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(&vm_tools::cicerone::Service::OpenTerminal, service_,
                     request->token(), std::move(terminal_params), cid, &result,
                     &event));
  event.Wait();
  if (!result) {
    LOG(ERROR) << "Failure opening terminal from ContainerListener";
    return grpc::Status(grpc::FAILED_PRECONDITION, "Failure in OpenTerminal");
  }
  return grpc::Status::OK;
}

grpc::Status ContainerListenerImpl::UpdateMimeTypes(
    grpc::ServerContext* ctx,
    const vm_tools::container::UpdateMimeTypesRequest* request,
    vm_tools::EmptyMessage* response) {
  uint32_t cid = ExtractCidFromPeerAddress(ctx);
  if (cid == 0) {
    return grpc::Status(grpc::FAILED_PRECONDITION,
                        "Failed parsing cid for ContainerListener");
  }
  vm_tools::apps::MimeTypes mime_types;
  mime_types.mutable_mime_type_mappings()->insert(
      request->mime_type_mappings().begin(),
      request->mime_type_mappings().end());
  base::WaitableEvent event(base::WaitableEvent::ResetPolicy::AUTOMATIC,
                            base::WaitableEvent::InitialState::NOT_SIGNALED);
  bool result = false;
  task_runner_->PostTask(
      FROM_HERE, base::BindOnce(&vm_tools::cicerone::Service::UpdateMimeTypes,
                                service_, request->token(),
                                std::move(mime_types), cid, &result, &event));
  event.Wait();
  if (!result) {
    LOG(ERROR) << "Failure updating MIME types from ContainerListener";
    return grpc::Status(grpc::FAILED_PRECONDITION,
                        "Failure in UpdateMimeTypes");
  }
  return grpc::Status::OK;
}

grpc::Status ContainerListenerImpl::FileWatchTriggered(
    grpc::ServerContext* ctx,
    const vm_tools::container::FileWatchTriggeredInfo* request,
    vm_tools::EmptyMessage* response) {
  uint32_t cid = ExtractCidFromPeerAddress(ctx);
  if (cid == 0) {
    return grpc::Status(grpc::FAILED_PRECONDITION,
                        "Failed parsing cid for ContainerListener");
  }
  FileWatchTriggeredSignal triggered_signal;
  triggered_signal.set_path(request->path());
  base::WaitableEvent event(base::WaitableEvent::ResetPolicy::AUTOMATIC,
                            base::WaitableEvent::InitialState::NOT_SIGNALED);
  bool result = false;
  task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(&vm_tools::cicerone::Service::FileWatchTriggered, service_,
                     request->token(), cid, &triggered_signal, &result,
                     &event));
  event.Wait();
  if (!result) {
    LOG(ERROR) << "Failure notifying FileWatchTriggered from ContainerListener";
    return grpc::Status(grpc::FAILED_PRECONDITION,
                        "Failure in FileWatchTriggered");
  }
  return grpc::Status::OK;
}

grpc::Status ContainerListenerImpl::LowDiskSpaceTriggered(
    grpc::ServerContext* ctx,
    const vm_tools::container::LowDiskSpaceTriggeredInfo* request,
    vm_tools::EmptyMessage* response) {
  uint32_t cid = ExtractCidFromPeerAddress(ctx);
  if (cid == 0) {
    return grpc::Status(grpc::FAILED_PRECONDITION,
                        "Failed parsing cid for ContainerListener");
  }
  LowDiskSpaceTriggeredSignal triggered_signal;
  triggered_signal.set_free_bytes(request->free_bytes());
  base::WaitableEvent event(base::WaitableEvent::ResetPolicy::AUTOMATIC,
                            base::WaitableEvent::InitialState::NOT_SIGNALED);
  bool result = false;
  task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(&vm_tools::cicerone::Service::LowDiskSpaceTriggered,
                     service_, request->token(), cid, &triggered_signal,
                     &result, &event));
  event.Wait();
  if (!result) {
    LOG(ERROR)
        << "Failure notifying LowDiskSpaceTriggered from ContainerListener";
    return grpc::Status(grpc::FAILED_PRECONDITION,
                        "Failure in LowDiskSpaceTriggered");
  }
  return grpc::Status::OK;
}

grpc::Status ContainerListenerImpl::ForwardSecurityKeyMessage(
    grpc::ServerContext* ctx,
    const vm_tools::container::ForwardSecurityKeyMessageRequest* request,
    vm_tools::container::ForwardSecurityKeyMessageResponse* response) {
  uint32_t cid = ExtractCidFromPeerAddress(ctx);
  if (cid == 0) {
    return grpc::Status(grpc::FAILED_PRECONDITION,
                        "Failed parsing cid for ContainerListener");
  }
  vm_tools::sk_forwarding::ForwardSecurityKeyMessageRequest
      security_key_message;
  security_key_message.set_message(request->message());

  base::WaitableEvent event(base::WaitableEvent::ResetPolicy::AUTOMATIC,
                            base::WaitableEvent::InitialState::NOT_SIGNALED);
  vm_tools::sk_forwarding::ForwardSecurityKeyMessageResponse
      security_key_response;

  task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(&vm_tools::cicerone::Service::ForwardSecurityKeyMessage,
                     service_, cid, std::move(security_key_message),
                     &security_key_response, &event));
  event.Wait();
  if (security_key_response.message().empty()) {
    LOG(ERROR)
        << "Failure forwarding security key message from ContainerListener.";
    return grpc::Status(grpc::FAILED_PRECONDITION,
                        "Failure in ForwardSecurityKeyMessage");
  }

  response->set_message(security_key_response.message());
  return grpc::Status::OK;
}

grpc::Status ContainerListenerImpl::SelectFile(
    grpc::ServerContext* ctx,
    const vm_tools::container::SelectFileRequest* request,
    vm_tools::container::SelectFileResponse* response) {
  uint32_t cid = ExtractCidFromPeerAddress(ctx);
  if (cid == 0) {
    return grpc::Status(grpc::FAILED_PRECONDITION,
                        "Failed parsing cid for ContainerListener");
  }
  vm_tools::apps::SelectFileRequest select_file;
  select_file.set_type(request->type());
  select_file.set_title(request->title());
  select_file.set_default_path(request->default_path());
  select_file.set_allowed_extensions(request->allowed_extensions());
  base::WaitableEvent event(base::WaitableEvent::ResetPolicy::AUTOMATIC,
                            base::WaitableEvent::InitialState::NOT_SIGNALED);
  std::vector<std::string> files;
  task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(&vm_tools::cicerone::Service::SelectFile, service_,
                     request->token(), cid, &select_file, &files, &event));
  // Waits for dialog to be shown, and user to select file(s), then chrome sends
  // back the FileSelectedSignal.
  event.Wait();
  std::copy(
      std::make_move_iterator(files.begin()),
      std::make_move_iterator(files.end()),
      google::protobuf::RepeatedFieldBackInserter(response->mutable_files()));
  return grpc::Status::OK;
}

grpc::Status ContainerListenerImpl::GetDiskInfo(
    grpc::ServerContext* ctx,
    const vm_tools::container::GetDiskInfoRequest* request,
    vm_tools::container::GetDiskInfoResponse* response) {
  uint32_t cid = ExtractCidFromPeerAddress(ctx);
  if (cid == 0) {
    return grpc::Status(grpc::FAILED_PRECONDITION,
                        "Failed parsing cid for ContainerListener");
  }
  base::WaitableEvent event(base::WaitableEvent::ResetPolicy::AUTOMATIC,
                            base::WaitableEvent::InitialState::NOT_SIGNALED);
  vm_tools::disk_management::GetDiskInfoResponse result;
  task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(&vm_tools::cicerone::Service::GetDiskInfo, service_,
                     request->token(), cid, &result, &event));
  event.Wait();
  response->set_error(result.error());
  response->set_available_space(result.available_space());
  response->set_expandable_space(result.expandable_space());
  response->set_disk_size(result.disk_size());
  return grpc::Status::OK;
}

grpc::Status ContainerListenerImpl::RequestSpace(
    grpc::ServerContext* ctx,
    const vm_tools::container::RequestSpaceRequest* request,
    vm_tools::container::RequestSpaceResponse* response) {
  uint32_t cid = ExtractCidFromPeerAddress(ctx);
  if (cid == 0) {
    return grpc::Status(grpc::FAILED_PRECONDITION,
                        "Failed parsing cid for ContainerListener");
  }
  base::WaitableEvent event(base::WaitableEvent::ResetPolicy::AUTOMATIC,
                            base::WaitableEvent::InitialState::NOT_SIGNALED);
  vm_tools::disk_management::RequestSpaceResponse result;
  task_runner_->PostTask(
      FROM_HERE, base::BindOnce(&vm_tools::cicerone::Service::RequestSpace,
                                service_, request->token(), cid,
                                request->space_requested(), &result, &event));
  event.Wait();
  response->set_error(result.error());
  response->set_space_granted(result.space_granted());
  return grpc::Status::OK;
}

grpc::Status ContainerListenerImpl::ReleaseSpace(
    grpc::ServerContext* ctx,
    const vm_tools::container::ReleaseSpaceRequest* request,
    vm_tools::container::ReleaseSpaceResponse* response) {
  uint32_t cid = ExtractCidFromPeerAddress(ctx);
  if (cid == 0) {
    return grpc::Status(grpc::FAILED_PRECONDITION,
                        "Failed parsing cid for ContainerListener");
  }
  base::WaitableEvent event(base::WaitableEvent::ResetPolicy::AUTOMATIC,
                            base::WaitableEvent::InitialState::NOT_SIGNALED);
  vm_tools::disk_management::ReleaseSpaceResponse result;
  task_runner_->PostTask(
      FROM_HERE, base::BindOnce(&vm_tools::cicerone::Service::ReleaseSpace,
                                service_, request->token(), cid,
                                request->space_to_release(), &result, &event));
  event.Wait();
  response->set_error(result.error());
  response->set_space_released(result.space_released());
  return grpc::Status::OK;
}

grpc::Status ContainerListenerImpl::ReportMetrics(
    grpc::ServerContext* ctx,
    const vm_tools::container::ReportMetricsRequest* request,
    vm_tools::container::ReportMetricsResponse* response) {
  uint32_t cid = ExtractCidFromPeerAddress(ctx);
  if (cid == 0) {
    return grpc::Status(grpc::FAILED_PRECONDITION,
                        "Failed parsing cid for ContainerListener");
  }

  // Validate ReportMetricsRequest
  if (request->metric_size() > 10) {
    return grpc::Status(grpc::FAILED_PRECONDITION, "Too many metrics");
  }
  for (const auto& metric : request->metric()) {
    // Check that metric name is valid
    const RE2 re("[A-Za-z.-]{1,64}");
    if (!RE2::FullMatch(metric.name(), re)) {
      return grpc::Status(grpc::FAILED_PRECONDITION, "Invalid metric name");
    }
  }

  base::WaitableEvent event(base::WaitableEvent::ResetPolicy::AUTOMATIC,
                            base::WaitableEvent::InitialState::NOT_SIGNALED);
  task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(&vm_tools::cicerone::Service::ReportMetrics, service_,
                     request->token(), cid, *request, response, &event));
  event.Wait();

  return grpc::Status::OK;
}

grpc::Status ContainerListenerImpl::InhibitScreensaver(
    grpc::ServerContext* ctx,
    const vm_tools::container::InhibitScreensaverInfo* request,
    vm_tools::EmptyMessage* response) {
  uint32_t cid = ExtractCidFromPeerAddress(ctx);
  if (cid == 0) {
    return grpc::Status(grpc::FAILED_PRECONDITION,
                        "Failed parsing cid for ContainerListener");
  }

  InhibitScreensaverSignal signal;
  signal.set_cookie(request->cookie());
  signal.set_client(request->client());
  signal.set_reason(request->reason());

  base::WaitableEvent event(base::WaitableEvent::ResetPolicy::AUTOMATIC,
                            base::WaitableEvent::InitialState::NOT_SIGNALED);
  bool result = false;
  task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(&vm_tools::cicerone::Service::InhibitScreensaver, service_,
                     request->token(), cid, &signal, &result, &event));
  event.Wait();
  if (!result) {
    LOG(ERROR) << "Failure notifying InhibitScreensaver from ContainerListener";
    return grpc::Status(grpc::FAILED_PRECONDITION,
                        "Failure in InhibitScreensaver");
  }

  return grpc::Status::OK;
}

grpc::Status ContainerListenerImpl::UninhibitScreensaver(
    grpc::ServerContext* ctx,
    const vm_tools::container::UninhibitScreensaverInfo* request,
    vm_tools::EmptyMessage* response) {
  uint32_t cid = ExtractCidFromPeerAddress(ctx);
  if (cid == 0) {
    return grpc::Status(grpc::FAILED_PRECONDITION,
                        "Failed parsing cid for ContainerListener");
  }

  UninhibitScreensaverSignal signal;
  signal.set_cookie(request->cookie());

  base::WaitableEvent event(base::WaitableEvent::ResetPolicy::AUTOMATIC,
                            base::WaitableEvent::InitialState::NOT_SIGNALED);
  bool result = false;
  task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(&vm_tools::cicerone::Service::UninhibitScreensaver,
                     service_, request->token(), cid, &signal, &result,
                     &event));
  event.Wait();
  if (!result) {
    LOG(ERROR)
        << "Failure notifying UninhibitScreensaver from ContainerListener";
    return grpc::Status(grpc::FAILED_PRECONDITION,
                        "Failure in UninhibitScreensaver");
  }

  return grpc::Status::OK;
}

uint32_t ContainerListenerImpl::ExtractCidFromPeerAddress(
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
    // This is not necessarily a failure if this is a unix socket.
    return 0;
  }
  return cid;
}

bool ContainerListenerImpl::CheckOpenRateLimit() {
  base::TimeTicks now = base::TimeTicks::Now();
  if (now - open_rate_window_start_ > kOpenRateWindow) {
    // Beyond the window, reset the window start time and counter.
    open_rate_window_start_ = now;
    open_count_ = 1;
    return true;
  }
  if (++open_count_ <= kOpenRateLimit)
    return true;
  // Only log the first one over the limit to prevent log spam if this is
  // getting hit quickly.
  LOG_IF(ERROR, open_count_ == kOpenRateLimit + 1)
      << "OpenUrl/Terminal rate limit hit, blocking requests until window "
         "closes";
  return false;
}

grpc::Status ContainerListenerImpl::InstallShaderCache(
    grpc::ServerContext* ctx,
    const vm_tools::container::InstallShaderCacheRequest* request,
    vm_tools::EmptyMessage* response) {
  uint32_t cid = ExtractCidFromPeerAddress(ctx);
  base::WaitableEvent event(base::WaitableEvent::ResetPolicy::AUTOMATIC,
                            base::WaitableEvent::InitialState::NOT_SIGNALED);
  std::string error = "";

  task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(&vm_tools::cicerone::Service::InstallVmShaderCache,
                     service_, cid, request, &error, &event));
  event.Wait();

  if (error.empty()) {
    return grpc::Status::OK;
  }
  return grpc::Status(grpc::INTERNAL, error);
}

grpc::Status ContainerListenerImpl::UninstallShaderCache(
    grpc::ServerContext* ctx,
    const vm_tools::container::UninstallShaderCacheRequest* request,
    vm_tools::EmptyMessage* response) {
  uint32_t cid = ExtractCidFromPeerAddress(ctx);
  base::WaitableEvent event(base::WaitableEvent::ResetPolicy::AUTOMATIC,
                            base::WaitableEvent::InitialState::NOT_SIGNALED);
  std::string error = "";

  task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(&vm_tools::cicerone::Service::UninstallVmShaderCache,
                     service_, cid, request, &error, &event));
  event.Wait();

  if (error.empty()) {
    return grpc::Status::OK;
  }
  return grpc::Status(grpc::INTERNAL, error);
}

grpc::Status ContainerListenerImpl::UnmountShaderCache(
    grpc::ServerContext* ctx,
    const vm_tools::container::UnmountShaderCacheRequest* request,
    vm_tools::EmptyMessage* response) {
  uint32_t cid = ExtractCidFromPeerAddress(ctx);
  base::WaitableEvent event(base::WaitableEvent::ResetPolicy::AUTOMATIC,
                            base::WaitableEvent::InitialState::NOT_SIGNALED);
  std::string error = "";

  task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(&vm_tools::cicerone::Service::UnmountVmShaderCache,
                     service_, cid, request, &error, &event));
  event.Wait();

  if (error.empty()) {
    return grpc::Status::OK;
  }
  return grpc::Status(grpc::INTERNAL, error);
}

}  // namespace cicerone
}  // namespace vm_tools
