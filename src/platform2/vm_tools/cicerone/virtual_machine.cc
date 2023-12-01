// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "vm_tools/cicerone/virtual_machine.h"

#include <arpa/inet.h>
#include <inttypes.h>

#include <algorithm>
#include <memory>
#include <utility>

#include <base/check.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/memory/ptr_util.h>
#include <base/strings/stringprintf.h>
#include <base/uuid.h>
#include <google/protobuf/repeated_field.h>
#include <grpcpp/grpcpp.h>
#include <vm_cicerone/cicerone_service.pb.h>
#include <vm_protos/proto_bindings/container_guest.grpc.pb.h>
#include <chromeos/constants/vm_tools.h>

#include "vm_tools/cicerone/grpc_util.h"

using std::string;

namespace vm_tools {
namespace cicerone {
namespace {

// Default name to use for a container.
constexpr char kDefaultContainerName[] = "penguin";

VirtualMachine::VmType DetermineTypeFromCidAndToken(uint32_t cid,
                                                    const std::string& token) {
  // PluginVm does not have a CID
  if (cid == 0)
    return VirtualMachine::VmType::PLUGIN_VM;
  // Termina hosts containers, so it does not have a VM token.
  if (token.empty())
    return VirtualMachine::VmType::TERMINA;
  return VirtualMachine::VmType::BOREALIS;
}

}  // namespace

VirtualMachine::VirtualMachine(uint32_t cid, pid_t pid, std::string vm_token)
    : vsock_cid_(cid),
      pid_(pid),
      vm_token_(std::move(vm_token)),
      vm_type_(DetermineTypeFromCidAndToken(cid, vm_token_)),
      using_mock_tremplin_stub_(false),
      weak_ptr_factory_(this) {
  // CID-less VMs must also be containerless.
  DCHECK(vsock_cid_ != 0 || IsContainerless());
  if (IsContainerless()) {
    // This is a containerless VM, so create one container for this VM that uses
    // the same token as the VM itself.
    pending_containers_[vm_token_] = std::make_unique<Container>(
        kDefaultContainerName, vm_token_, weak_ptr_factory_.GetWeakPtr());
  }
}

VirtualMachine::~VirtualMachine() = default;

VirtualMachine::VmType VirtualMachine::GetType() const {
  return vm_type_;
}

bool VirtualMachine::IsContainerless() const {
  // Termina runs containers, the others do not.
  return GetType() != VmType::TERMINA;
}

bool VirtualMachine::ConnectTremplin() {
  // Tremplin manages LXD/containers, so containerless VMs dont use it.
  if (IsContainerless())
    return false;
  if (!using_mock_tremplin_stub_) {
    std::string tremplin_address =
        base::StringPrintf("vsock:%u:%u", vsock_cid_, kTremplinPort);
    auto channel = grpc::CreateChannel(tremplin_address,
                                       grpc::InsecureChannelCredentials());
    if (channel->WaitForConnected(ToGprDeadline(kConnectTimeoutSeconds))) {
      LOG(ERROR) << "Tremplin channel not connected after "
                 << kConnectTimeoutSeconds << " seconds.";
    }
    tremplin_stub_ =
        std::make_unique<vm_tools::tremplin::Tremplin::Stub>(channel);
  }
  return tremplin_stub_ != nullptr;
}

void VirtualMachine::SetTremplinStubForTesting(
    std::unique_ptr<vm_tools::tremplin::Tremplin::StubInterface>
        mock_tremplin_stub) {
  CHECK(using_mock_tremplin_stub_ || !tremplin_stub_)
      << "Calling SetTremplinStubForTesting too late";
  using_mock_tremplin_stub_ = true;
  tremplin_stub_ = std::move(mock_tremplin_stub);
}

bool VirtualMachine::SetTimezone(
    const std::string& timezone_name,
    const std::string& posix_tz_string,
    const std::vector<std::string>& container_names,
    VirtualMachine::SetTimezoneResults* out_results,
    std::string* out_error) {
  DCHECK(out_results);
  DCHECK(out_error);
  if (!tremplin_stub_) {
    *out_error = "tremplin is not connected";
    return false;
  }
  LOG(INFO) << "Setting timezone to: " << timezone_name;

  vm_tools::tremplin::SetTimezoneRequest request;
  vm_tools::tremplin::SetTimezoneResponse response;

  request.set_timezone_name(timezone_name);
  request.set_posix_tz_string(posix_tz_string);
  for (const std::string& name : container_names)
    request.add_container_names(name);

  grpc::ClientContext ctx;
  ctx.set_deadline(ToGprDeadline(kDefaultTimeoutSeconds));

  grpc::Status status = tremplin_stub_->SetTimezone(&ctx, request, &response);
  if (!status.ok()) {
    LOG(ERROR) << "SetTimezone RPC failed: " << status.error_message();
    out_error->assign(status.error_message());
    return false;
  }

  int failure_count = response.failure_reasons_size();
  if (failure_count != 0) {
    LOG(ERROR) << "Failed to set timezone for " << failure_count
               << " containers";
  }
  out_results->failure_reasons.clear();
  for (int i = 0; i < failure_count; i++) {
    out_results->failure_reasons.push_back(response.failure_reasons(i));
  }

  out_results->successes = response.successes();
  return true;
}

bool VirtualMachine::RegisterContainer(const std::string& container_token,
                                       const uint32_t garcon_vsock_port,
                                       const std::string& container_ip) {
  // The token will be in the pending map if this is the first start of the
  // container. It will be in the main map if this is from a crash/restart of
  // the garcon process in the container.
  auto pending_iter = pending_containers_.find(container_token);
  if (pending_iter != pending_containers_.end()) {
    containers_[pending_iter->first] = std::move(pending_iter->second);
    pending_containers_.erase(pending_iter);
  } else {
    string container_name = GetContainerNameForToken(container_token);
    if (container_name.empty()) {
      return false;
    }
  }

  auto iter = containers_.find(container_token);
  std::string garcon_addr;
  if (GetType() == VmType::PLUGIN_VM) {
    garcon_addr = base::StringPrintf("unix:///run/vm_cicerone/client/%s.sock",
                                     container_token.c_str());
  } else {
    garcon_addr = base::StringPrintf("vsock:%" PRIu32 ":%" PRIu32, vsock_cid_,
                                     garcon_vsock_port);
  }

  iter->second->ConnectToGarcon(garcon_addr);

  return true;
}

bool VirtualMachine::UnregisterContainer(const std::string& container_token) {
  auto iter = containers_.find(container_token);
  if (iter == containers_.end()) {
    return false;
  }
  containers_.erase(iter);
  return true;
}

std::string VirtualMachine::GenerateContainerToken(
    const std::string& container_name) {
  if (IsContainerless())
    return "";
  std::string token = base::Uuid::GenerateRandomV4().AsLowercaseString();
  pending_containers_[token] = std::make_unique<Container>(
      container_name, token, weak_ptr_factory_.GetWeakPtr());
  return token;
}

void VirtualMachine::CreateContainerWithTokenForTesting(
    const std::string& container_name, const std::string& container_token) {
  pending_containers_[container_token] = std::make_unique<Container>(
      container_name, container_token, weak_ptr_factory_.GetWeakPtr());
}

std::string VirtualMachine::GetContainerNameForToken(
    const std::string& container_token) {
  auto iter = containers_.find(container_token);
  if (iter == containers_.end()) {
    return "";
  }
  return iter->second->name();
}

Container* VirtualMachine::GetContainerForToken(
    const std::string& container_token) {
  auto iter = containers_.find(container_token);
  if (iter == containers_.end()) {
    return nullptr;
  }

  return iter->second.get();
}

Container* VirtualMachine::GetPendingContainerForToken(
    const std::string& container_token) {
  auto iter = pending_containers_.find(container_token);
  if (iter == pending_containers_.end()) {
    return nullptr;
  }

  return iter->second.get();
}

Container* VirtualMachine::GetContainerForName(
    const std::string& container_name) {
  for (auto iter = containers_.begin(); iter != containers_.end(); ++iter) {
    if (iter->second->name() == container_name) {
      return iter->second.get();
    }
  }
  return nullptr;
}

const OsRelease* VirtualMachine::GetOsReleaseForContainer(
    const std::string& container_name) const {
  auto iter = container_os_releases_.find(container_name);
  if (iter == container_os_releases_.end()) {
    return nullptr;
  }

  return &iter->second;
}

void VirtualMachine::SetOsReleaseForTesting(const std::string& container_name,
                                            const OsRelease& os_release) {
  container_os_releases_[container_name] = os_release;
}

std::vector<std::string> VirtualMachine::GetContainerNames() {
  std::vector<std::string> retval;
  for (auto& container_entry : containers_) {
    retval.emplace_back(container_entry.second->name());
  }
  return retval;
}

const std::map<std::string, std::unique_ptr<Container>>&
VirtualMachine::GetContainers() {
  return containers_;
}

VirtualMachine::CreateLxdContainerStatus VirtualMachine::CreateLxdContainer(
    const std::string& container_name,
    const std::string& image_server,
    const std::string& image_alias,
    const std::string& rootfs_path,
    const std::string& metadata_path,
    std::string* out_error) {
  DCHECK(out_error);
  if (!tremplin_stub_) {
    *out_error = "tremplin is not connected";
    return VirtualMachine::CreateLxdContainerStatus::FAILED;
  }

  vm_tools::tremplin::CreateContainerRequest request;
  vm_tools::tremplin::CreateContainerResponse response;

  request.set_container_name(container_name);
  request.set_image_server(image_server);
  request.set_image_alias(image_alias);
  request.set_rootfs_path(rootfs_path);
  request.set_metadata_path(metadata_path);

  grpc::ClientContext ctx;
  ctx.set_deadline(ToGprDeadline(kLongOperationTimeoutSeconds));

  grpc::Status status =
      tremplin_stub_->CreateContainer(&ctx, request, &response);
  if (!status.ok()) {
    LOG(ERROR) << "CreateContainer RPC failed: " << status.error_message();
    out_error->assign(status.error_message());
    return VirtualMachine::CreateLxdContainerStatus::FAILED;
  }

  if (response.status() != tremplin::CreateContainerResponse::CREATING &&
      response.status() != tremplin::CreateContainerResponse::EXISTS) {
    LOG(ERROR) << "Failed to create LXD container: "
               << response.failure_reason();
    out_error->assign(response.failure_reason());
    return VirtualMachine::CreateLxdContainerStatus::FAILED;
  }

  if (response.status() == tremplin::CreateContainerResponse::EXISTS) {
    return VirtualMachine::CreateLxdContainerStatus::EXISTS;
  }

  return VirtualMachine::CreateLxdContainerStatus::CREATING;
}

VirtualMachine::DeleteLxdContainerStatus VirtualMachine::DeleteLxdContainer(
    const std::string& container_name, std::string* out_error) {
  DCHECK(out_error);
  if (!tremplin_stub_) {
    *out_error = "tremplin is not connected";
    return VirtualMachine::DeleteLxdContainerStatus::FAILED;
  }

  vm_tools::tremplin::DeleteContainerRequest request;
  vm_tools::tremplin::DeleteContainerResponse response;

  request.set_container_name(container_name);

  grpc::ClientContext ctx;
  ctx.set_deadline(ToGprDeadline(kDefaultTimeoutSeconds));

  grpc::Status status =
      tremplin_stub_->DeleteContainer(&ctx, request, &response);
  if (!status.ok()) {
    LOG(ERROR) << "DeleteContainer RPC failed: " << status.error_message();
    out_error->assign(status.error_message());
    return VirtualMachine::DeleteLxdContainerStatus::FAILED;
  }

  switch (response.status()) {
    case tremplin::DeleteContainerResponse::DELETING:
      return VirtualMachine::DeleteLxdContainerStatus::DELETING;
    case tremplin::DeleteContainerResponse::DOES_NOT_EXIST:
      return VirtualMachine::DeleteLxdContainerStatus::DOES_NOT_EXIST;

    case tremplin::DeleteContainerResponse::UNKNOWN:
    case tremplin::DeleteContainerResponse::FAILED:
      LOG(ERROR) << "Failed to delete LXD container: "
                 << response.failure_reason();
      out_error->assign(response.failure_reason());
      return VirtualMachine::DeleteLxdContainerStatus::FAILED;

    default:
      LOG(ERROR) << "Unknown response received: " << response.status() << " "
                 << response.failure_reason();
      out_error->assign(response.failure_reason());
      return VirtualMachine::DeleteLxdContainerStatus::UNKNOWN;
  }
}

VirtualMachine::StartLxdContainerStatus VirtualMachine::StartLxdContainer(
    const std::string& container_name,
    const std::string& token,
    tremplin::StartContainerRequest::PrivilegeLevel privilege_level,
    bool disable_audio_capture,
    std::string* out_error) {
  DCHECK(out_error);
  if (!tremplin_stub_) {
    *out_error = "tremplin is not connected";
    return VirtualMachine::StartLxdContainerStatus::FAILED;
  }

  vm_tools::tremplin::StartContainerRequest request;
  vm_tools::tremplin::StartContainerResponse response;

  request.set_container_name(container_name);
  request.set_token(token);
  request.set_privilege_level(privilege_level);
  request.set_disable_audio_capture(disable_audio_capture);

  grpc::ClientContext ctx;
  ctx.set_deadline(ToGprDeadline(kLongOperationTimeoutSeconds));

  grpc::Status status =
      tremplin_stub_->StartContainer(&ctx, request, &response);
  if (!status.ok()) {
    LOG(ERROR) << "StartContainer RPC failed: " << status.error_message();
    out_error->assign(status.error_message());
    return VirtualMachine::StartLxdContainerStatus::FAILED;
  }

  if (response.status() != tremplin::StartContainerResponse::RUNNING &&
      response.status() != tremplin::StartContainerResponse::FAILED) {
    // Set the os_release on the container. This information is known by
    // tremplin even if the container hasn't started fully. Note also that
    // Tremplin's version of OsRelease is not the same type as cicerone's, even
    // though they currently have the same fields.
    OsRelease os_release;
    os_release.set_pretty_name(response.os_release().pretty_name());
    os_release.set_name(response.os_release().name());
    os_release.set_version(response.os_release().version());
    os_release.set_version_id(response.os_release().version_id());
    os_release.set_id(response.os_release().id());
    // We don't use emplace() here because it doesn't replace existing values.
    container_os_releases_[container_name] = os_release;
  }

  switch (response.status()) {
    case tremplin::StartContainerResponse::STARTING:
      return VirtualMachine::StartLxdContainerStatus::STARTING;
    case tremplin::StartContainerResponse::STARTED:
      return VirtualMachine::StartLxdContainerStatus::STARTED;
    case tremplin::StartContainerResponse::REMAPPING:
      return VirtualMachine::StartLxdContainerStatus::REMAPPING;
    case tremplin::StartContainerResponse::RUNNING:
      return VirtualMachine::StartLxdContainerStatus::RUNNING;
    case tremplin::StartContainerResponse::FAILED:
      LOG(ERROR) << "Failed to start LXD container: "
                 << response.failure_reason();
      out_error->assign(response.failure_reason());
      return VirtualMachine::StartLxdContainerStatus::FAILED;
    default:
      return VirtualMachine::StartLxdContainerStatus::UNKNOWN;
  }
}

VirtualMachine::StopLxdContainerStatus VirtualMachine::StopLxdContainer(
    const std::string& container_name, std::string* out_error) {
  DCHECK(out_error);
  if (!tremplin_stub_) {
    *out_error = "tremplin is not connected";
    return VirtualMachine::StopLxdContainerStatus::FAILED;
  }

  if (!GetContainerForName(container_name)) {
    // We call it stopped if the container hasn't yet been registered.
    return VirtualMachine::StopLxdContainerStatus::STOPPED;
  }

  vm_tools::tremplin::StopContainerRequest request;
  vm_tools::tremplin::StopContainerResponse response;

  request.set_container_name(container_name);

  grpc::ClientContext ctx;
  ctx.set_deadline(ToGprDeadline(kDefaultTimeoutSeconds));

  grpc::Status status = tremplin_stub_->StopContainer(&ctx, request, &response);
  if (!status.ok()) {
    LOG(ERROR) << "StopContainer RPC failed: " << status.error_message();
    out_error->assign(status.error_message());
    return VirtualMachine::StopLxdContainerStatus::FAILED;
  }

  switch (response.status()) {
    case tremplin::StopContainerResponse::STOPPING:
      return VirtualMachine::StopLxdContainerStatus::STOPPING;
    case tremplin::StopContainerResponse::STOPPED:
      return VirtualMachine::StopLxdContainerStatus::STOPPED;
    case tremplin::StopContainerResponse::DOES_NOT_EXIST:
      return VirtualMachine::StopLxdContainerStatus::DOES_NOT_EXIST;

    case tremplin::StopContainerResponse::UNKNOWN:
    case tremplin::StopContainerResponse::FAILED:
      LOG(ERROR) << "Failed to stop LXD container: "
                 << response.failure_reason();
      out_error->assign(response.failure_reason());
      return VirtualMachine::StopLxdContainerStatus::FAILED;

    default:
      LOG(ERROR) << "Unknown response received: " << response.status() << " "
                 << response.failure_reason();
      out_error->assign(response.failure_reason());
      return VirtualMachine::StopLxdContainerStatus::UNKNOWN;
  }
}

VirtualMachine::GetLxdContainerUsernameStatus
VirtualMachine::GetLxdContainerUsername(const std::string& container_name,
                                        std::string* out_username,
                                        std::string* out_homedir,
                                        std::string* out_error) {
  DCHECK(out_username);
  DCHECK(out_homedir);
  DCHECK(out_error);
  if (!tremplin_stub_) {
    *out_error = "tremplin is not connected";
    return VirtualMachine::GetLxdContainerUsernameStatus::FAILED;
  }

  vm_tools::tremplin::GetContainerUsernameRequest request;
  vm_tools::tremplin::GetContainerUsernameResponse response;

  request.set_container_name(container_name);

  grpc::ClientContext ctx;
  ctx.set_deadline(ToGprDeadline(kDefaultTimeoutSeconds));

  grpc::Status status =
      tremplin_stub_->GetContainerUsername(&ctx, request, &response);
  if (!status.ok()) {
    LOG(ERROR) << "GetContainerUsername RPC failed: " << status.error_message();
    out_error->assign(status.error_message());
    return VirtualMachine::GetLxdContainerUsernameStatus::FAILED;
  }

  out_error->assign(response.failure_reason());
  out_username->assign(response.username());
  out_homedir->assign(response.homedir());

  switch (response.status()) {
    case tremplin::GetContainerUsernameResponse::UNKNOWN:
      return VirtualMachine::GetLxdContainerUsernameStatus::UNKNOWN;
    case tremplin::GetContainerUsernameResponse::SUCCESS:
      return VirtualMachine::GetLxdContainerUsernameStatus::SUCCESS;
    case tremplin::GetContainerUsernameResponse::CONTAINER_NOT_FOUND:
      return VirtualMachine::GetLxdContainerUsernameStatus::CONTAINER_NOT_FOUND;
    case tremplin::GetContainerUsernameResponse::CONTAINER_NOT_RUNNING:
      return VirtualMachine::GetLxdContainerUsernameStatus::
          CONTAINER_NOT_RUNNING;
    case tremplin::GetContainerUsernameResponse::USER_NOT_FOUND:
      return VirtualMachine::GetLxdContainerUsernameStatus::USER_NOT_FOUND;
    case tremplin::GetContainerUsernameResponse::FAILED:
      return VirtualMachine::GetLxdContainerUsernameStatus::FAILED;
    default:
      return VirtualMachine::GetLxdContainerUsernameStatus::UNKNOWN;
  }
}

VirtualMachine::SetUpLxdContainerUserStatus
VirtualMachine::SetUpLxdContainerUser(const std::string& container_name,
                                      const std::string& container_username,
                                      std::string* out_username,
                                      std::string* out_error) {
  DCHECK(out_username);
  DCHECK(out_error);
  if (!tremplin_stub_) {
    *out_error = "tremplin is not connected";
    return VirtualMachine::SetUpLxdContainerUserStatus::FAILED;
  }

  vm_tools::tremplin::SetUpUserRequest request;
  vm_tools::tremplin::SetUpUserResponse response;

  request.set_container_name(container_name);
  request.set_container_username(container_username);

  grpc::ClientContext ctx;
  ctx.set_deadline(ToGprDeadline(kDefaultTimeoutSeconds));

  grpc::Status status = tremplin_stub_->SetUpUser(&ctx, request, &response);
  out_username->assign(response.username());
  if (!status.ok()) {
    LOG(ERROR) << "SetUpUser RPC failed: " << status.error_message();
    out_error->assign(status.error_message());
    return VirtualMachine::SetUpLxdContainerUserStatus::FAILED;
  }

  out_error->assign(response.failure_reason());
  switch (response.status()) {
    case tremplin::SetUpUserResponse::UNKNOWN:
      LOG(ERROR) << "Failed to set up user: " << response.failure_reason();
      return VirtualMachine::SetUpLxdContainerUserStatus::UNKNOWN;
    case tremplin::SetUpUserResponse::SUCCESS:
      return VirtualMachine::SetUpLxdContainerUserStatus::SUCCESS;
    case tremplin::SetUpUserResponse::EXISTS:
      return VirtualMachine::SetUpLxdContainerUserStatus::EXISTS;
    case tremplin::SetUpUserResponse::FAILED:
      LOG(ERROR) << "Failed to set up user: " << response.failure_reason();
      return VirtualMachine::SetUpLxdContainerUserStatus::FAILED;
    default:
      NOTREACHED();
      return VirtualMachine::SetUpLxdContainerUserStatus::FAILED;
  }
}

VirtualMachine::GetLxdContainerInfoStatus VirtualMachine::GetLxdContainerInfo(
    const std::string& container_name,
    VirtualMachine::LxdContainerInfo* out_info,
    std::string* out_error) {
  DCHECK(out_info);
  DCHECK(out_error);
  if (!tremplin_stub_) {
    *out_error = "tremplin is not connected";
    return VirtualMachine::GetLxdContainerInfoStatus::FAILED;
  }

  vm_tools::tremplin::GetContainerInfoRequest request;
  vm_tools::tremplin::GetContainerInfoResponse response;

  request.set_container_name(container_name);

  grpc::ClientContext ctx;
  ctx.set_deadline(ToGprDeadline(kDefaultTimeoutSeconds));

  grpc::Status status =
      tremplin_stub_->GetContainerInfo(&ctx, request, &response);
  if (!status.ok()) {
    LOG(ERROR) << "GetContainerInfo RPC failed: " << status.error_message();
    out_error->assign(status.error_message());
    return VirtualMachine::GetLxdContainerInfoStatus::FAILED;
  }

  out_info->ipv4_address = response.ipv4_address();
  out_error->assign(response.failure_reason());

  switch (response.status()) {
    case tremplin::GetContainerInfoResponse::RUNNING:
      return VirtualMachine::GetLxdContainerInfoStatus::RUNNING;
    case tremplin::GetContainerInfoResponse::STOPPED:
      return VirtualMachine::GetLxdContainerInfoStatus::STOPPED;
    case tremplin::GetContainerInfoResponse::NOT_FOUND:
      return VirtualMachine::GetLxdContainerInfoStatus::NOT_FOUND;
    default:
      return VirtualMachine::GetLxdContainerInfoStatus::UNKNOWN;
  }
}

VirtualMachine::ExportLxdContainerStatus VirtualMachine::ExportLxdContainer(
    const std::string& container_name,
    const std::string& export_path,
    std::string* out_error) {
  DCHECK(out_error);
  if (!tremplin_stub_) {
    *out_error = "tremplin is not connected";
    return VirtualMachine::ExportLxdContainerStatus::FAILED;
  }

  vm_tools::tremplin::ExportContainerRequest request;
  vm_tools::tremplin::ExportContainerResponse response;

  request.set_container_name(container_name);
  request.set_export_path(export_path);

  grpc::ClientContext ctx;
  ctx.set_deadline(ToGprDeadline(kDefaultTimeoutSeconds));

  grpc::Status status =
      tremplin_stub_->ExportContainer(&ctx, request, &response);
  if (!status.ok()) {
    LOG(ERROR) << "ExportLxdContainer RPC failed: " << status.error_message()
               << " " << status.error_code();
    out_error->assign(status.error_message());
    return VirtualMachine::ExportLxdContainerStatus::FAILED;
  }

  switch (response.status()) {
    case tremplin::ExportContainerResponse::EXPORTING:
      return VirtualMachine::ExportLxdContainerStatus::EXPORTING;
    case tremplin::ExportContainerResponse::FAILED:
      return VirtualMachine::ExportLxdContainerStatus::FAILED;
    default:
      return VirtualMachine::ExportLxdContainerStatus::UNKNOWN;
  }
}

VirtualMachine::CancelExportLxdContainerStatus
VirtualMachine::CancelExportLxdContainer(
    const std::string& in_progress_container_name, std::string* out_error) {
  DCHECK(out_error);
  if (!tremplin_stub_) {
    *out_error = "tremplin is not connected";
    return VirtualMachine::CancelExportLxdContainerStatus::FAILED;
  }

  vm_tools::tremplin::CancelExportContainerRequest request;
  vm_tools::tremplin::CancelExportContainerResponse response;

  request.set_in_progress_container_name(in_progress_container_name);

  grpc::ClientContext ctx;
  ctx.set_deadline(ToGprDeadline(kDefaultTimeoutSeconds));

  grpc::Status status =
      tremplin_stub_->CancelExportContainer(&ctx, request, &response);
  if (!status.ok()) {
    LOG(ERROR) << "CancelExportLxdContainer RPC failed: "
               << status.error_message() << " " << status.error_code();
    out_error->assign(status.error_message());
    return VirtualMachine::CancelExportLxdContainerStatus::FAILED;
  }

  switch (response.status()) {
    case tremplin::CancelExportContainerResponse::CANCEL_QUEUED:
      return VirtualMachine::CancelExportLxdContainerStatus::CANCEL_QUEUED;
    case tremplin::CancelExportContainerResponse::OPERATION_NOT_FOUND:
      return VirtualMachine::CancelExportLxdContainerStatus::
          OPERATION_NOT_FOUND;
    default:
      return VirtualMachine::CancelExportLxdContainerStatus::UNKNOWN;
  }
}

VirtualMachine::ImportLxdContainerStatus VirtualMachine::ImportLxdContainer(
    const std::string& container_name,
    const std::string& import_path,
    uint64_t available_disk_space,
    std::string* out_error) {
  DCHECK(out_error);
  if (!tremplin_stub_) {
    *out_error = "tremplin is not connected";
    return VirtualMachine::ImportLxdContainerStatus::FAILED;
  }

  vm_tools::tremplin::ImportContainerRequest request;
  vm_tools::tremplin::ImportContainerResponse response;

  request.set_container_name(container_name);
  request.set_import_path(import_path);
  request.set_available_disk_space(available_disk_space);

  grpc::ClientContext ctx;
  ctx.set_deadline(ToGprDeadline(kDefaultTimeoutSeconds));

  grpc::Status status =
      tremplin_stub_->ImportContainer(&ctx, request, &response);
  if (!status.ok()) {
    LOG(ERROR) << "ImportLxdContainer RPC failed: " << status.error_message()
               << " " << status.error_code();
    out_error->assign(status.error_message());
    return VirtualMachine::ImportLxdContainerStatus::FAILED;
  }

  switch (response.status()) {
    case tremplin::ImportContainerResponse::IMPORTING:
      return VirtualMachine::ImportLxdContainerStatus::IMPORTING;
    case tremplin::ImportContainerResponse::FAILED:
      return VirtualMachine::ImportLxdContainerStatus::FAILED;
    default:
      return VirtualMachine::ImportLxdContainerStatus::UNKNOWN;
  }
}

VirtualMachine::CancelImportLxdContainerStatus
VirtualMachine::CancelImportLxdContainer(
    const std::string& in_progress_container_name, std::string* out_error) {
  DCHECK(out_error);
  if (!tremplin_stub_) {
    *out_error = "tremplin is not connected";
    return VirtualMachine::CancelImportLxdContainerStatus::FAILED;
  }

  vm_tools::tremplin::CancelImportContainerRequest request;
  vm_tools::tremplin::CancelImportContainerResponse response;

  request.set_in_progress_container_name(in_progress_container_name);

  grpc::ClientContext ctx;
  ctx.set_deadline(ToGprDeadline(kDefaultTimeoutSeconds));

  grpc::Status status =
      tremplin_stub_->CancelImportContainer(&ctx, request, &response);
  if (!status.ok()) {
    LOG(ERROR) << "CancelImportLxdContainer RPC failed: "
               << status.error_message() << " " << status.error_code();
    out_error->assign(status.error_message());
    return VirtualMachine::CancelImportLxdContainerStatus::FAILED;
  }

  switch (response.status()) {
    case tremplin::CancelImportContainerResponse::CANCEL_QUEUED:
      return VirtualMachine::CancelImportLxdContainerStatus::CANCEL_QUEUED;
    case tremplin::CancelImportContainerResponse::OPERATION_NOT_FOUND:
      return VirtualMachine::CancelImportLxdContainerStatus::
          OPERATION_NOT_FOUND;
    default:
      return VirtualMachine::CancelImportLxdContainerStatus::UNKNOWN;
  }
}

namespace {
vm_tools::tremplin::UpgradeContainerRequest::Version ConvertVersion(
    UpgradeContainerRequest::Version version) {
  switch (version) {
    case UpgradeContainerRequest::UNKNOWN:
      return vm_tools::tremplin::UpgradeContainerRequest::UNKNOWN;
    case UpgradeContainerRequest::DEBIAN_STRETCH:
      return vm_tools::tremplin::UpgradeContainerRequest::DEBIAN_STRETCH;
    case UpgradeContainerRequest::DEBIAN_BUSTER:
      return vm_tools::tremplin::UpgradeContainerRequest::DEBIAN_BUSTER;
    case UpgradeContainerRequest::DEBIAN_BULLSEYE:
      return vm_tools::tremplin::UpgradeContainerRequest::DEBIAN_BULLSEYE;
    default:
      return vm_tools::tremplin::UpgradeContainerRequest::UNKNOWN;
  }
}
}  // namespace

VirtualMachine::UpgradeContainerStatus VirtualMachine::UpgradeContainer(
    const Container* container,
    const UpgradeContainerRequest::Version& target_version,
    std::string* out_error) {
  DCHECK(container);
  DCHECK(out_error);
  if (!tremplin_stub_) {
    *out_error = "tremplin is not connected";
    return VirtualMachine::UpgradeContainerStatus::FAILED;
  }

  vm_tools::tremplin::UpgradeContainerRequest request;
  vm_tools::tremplin::UpgradeContainerResponse response;

  request.set_container_name(container->name());
  request.set_target_version(ConvertVersion(target_version));

  grpc::ClientContext ctx;
  ctx.set_deadline(ToGprDeadline(kDefaultTimeoutSeconds));

  grpc::Status status =
      tremplin_stub_->UpgradeContainer(&ctx, request, &response);
  if (!status.ok()) {
    LOG(ERROR) << "UpgradeLxdContainer RPC failed: " << status.error_message()
               << " " << status.error_code();
    out_error->assign(status.error_message());
    return VirtualMachine::UpgradeContainerStatus::FAILED;
  }
  out_error->assign(response.failure_reason());
  switch (response.status()) {
    case tremplin::UpgradeContainerResponse::UNKNOWN:
      return VirtualMachine::UpgradeContainerStatus::UNKNOWN;
    case tremplin::UpgradeContainerResponse::STARTED:
      return VirtualMachine::UpgradeContainerStatus::STARTED;
    case tremplin::UpgradeContainerResponse::ALREADY_RUNNING:
      return VirtualMachine::UpgradeContainerStatus::ALREADY_RUNNING;
    case tremplin::UpgradeContainerResponse::NOT_SUPPORTED:
      return VirtualMachine::UpgradeContainerStatus::NOT_SUPPORTED;
    case tremplin::UpgradeContainerResponse::ALREADY_UPGRADED:
      return VirtualMachine::UpgradeContainerStatus::ALREADY_UPGRADED;
    case tremplin::UpgradeContainerResponse::FAILED:
      return VirtualMachine::UpgradeContainerStatus::FAILED;
    default:
      return VirtualMachine::UpgradeContainerStatus::UNKNOWN;
  }
}

VirtualMachine::CancelUpgradeContainerStatus
VirtualMachine::CancelUpgradeContainer(Container* container,
                                       std::string* out_error) {
  DCHECK(container);
  DCHECK(out_error);
  vm_tools::tremplin::CancelUpgradeContainerRequest request;
  vm_tools::tremplin::CancelUpgradeContainerResponse response;

  request.set_container_name(container->name());

  grpc::ClientContext ctx;
  ctx.set_deadline(ToGprDeadline(kDefaultTimeoutSeconds));

  grpc::Status status =
      tremplin_stub_->CancelUpgradeContainer(&ctx, request, &response);
  if (!status.ok()) {
    LOG(ERROR) << "CancelUpgradeLxdContainer RPC failed: "
               << status.error_message() << " " << status.error_code();
    out_error->assign(status.error_message());
    return VirtualMachine::CancelUpgradeContainerStatus::FAILED;
  }
  out_error->assign(response.failure_reason());
  switch (response.status()) {
    case tremplin::CancelUpgradeContainerResponse::UNKNOWN:
      return VirtualMachine::CancelUpgradeContainerStatus::UNKNOWN;
    case tremplin::CancelUpgradeContainerResponse::NOT_RUNNING:
      return VirtualMachine::CancelUpgradeContainerStatus::NOT_RUNNING;
    case tremplin::CancelUpgradeContainerResponse::CANCELLED:
      return VirtualMachine::CancelUpgradeContainerStatus::CANCELLED;
    case tremplin::CancelUpgradeContainerResponse::FAILED:
      return VirtualMachine::CancelUpgradeContainerStatus::FAILED;
    default:
      return VirtualMachine::CancelUpgradeContainerStatus::UNKNOWN;
  }
}

VirtualMachine::AttachUsbToContainerStatus VirtualMachine::AttachUsbToContainer(
    const Container* container, uint32_t port_num, std::string* out_error) {
  DCHECK(container);
  DCHECK(out_error);

  if (IsContainerless()) {
    *out_error = "VM does not host containers";
    return VirtualMachine::AttachUsbToContainerStatus::FAILED;
  } else if (!tremplin_stub_) {
    *out_error = "tremplin is not connected";
    return VirtualMachine::AttachUsbToContainerStatus::FAILED;
  }

  vm_tools::tremplin::AttachUsbToContainerRequest request;
  vm_tools::tremplin::AttachUsbToContainerResponse response;

  request.set_container_name(container->name());
  request.set_port_num(port_num);

  grpc::ClientContext ctx;
  ctx.set_deadline(ToGprDeadline(kDefaultTimeoutSeconds));

  grpc::Status status =
      tremplin_stub_->AttachUsbToContainer(&ctx, request, &response);
  if (!status.ok()) {
    LOG(ERROR) << "AttachUsbToContainer RPC failed: " << status.error_message()
               << " " << status.error_code();
    out_error->assign(status.error_message());
    return VirtualMachine::AttachUsbToContainerStatus::FAILED;
  }
  out_error->assign(response.failure_reason());
  switch (response.status()) {
    case tremplin::AttachUsbToContainerResponse::UNKNOWN:
      return VirtualMachine::AttachUsbToContainerStatus::UNKNOWN;
    case tremplin::AttachUsbToContainerResponse::OK:
      return VirtualMachine::AttachUsbToContainerStatus::OK;
    case tremplin::AttachUsbToContainerResponse::NO_SUCH_CONTAINER:
      return VirtualMachine::AttachUsbToContainerStatus::NO_SUCH_CONTAINER;
    case tremplin::AttachUsbToContainerResponse::FAILED:
      return VirtualMachine::AttachUsbToContainerStatus::FAILED;
    default:
      return VirtualMachine::AttachUsbToContainerStatus::UNKNOWN;
  }
}

VirtualMachine::DetachUsbFromContainerStatus
VirtualMachine::DetachUsbFromContainer(uint32_t port_num,
                                       std::string* out_error) {
  DCHECK(out_error);

  if (IsContainerless()) {
    *out_error = "VM does not host containers";
    return VirtualMachine::DetachUsbFromContainerStatus::FAILED;
  } else if (!tremplin_stub_) {
    *out_error = "tremplin is not connected";
    return VirtualMachine::DetachUsbFromContainerStatus::FAILED;
  }

  vm_tools::tremplin::DetachUsbFromContainerRequest request;
  vm_tools::tremplin::DetachUsbFromContainerResponse response;

  request.set_port_num(port_num);

  grpc::ClientContext ctx;
  ctx.set_deadline(ToGprDeadline(kDefaultTimeoutSeconds));

  grpc::Status status =
      tremplin_stub_->DetachUsbFromContainer(&ctx, request, &response);
  if (!status.ok()) {
    LOG(ERROR) << "DetachUsbFromContainer RPC failed: "
               << status.error_message() << " " << status.error_code();
    out_error->assign(status.error_message());
    return VirtualMachine::DetachUsbFromContainerStatus::FAILED;
  }
  out_error->assign(response.failure_reason());
  switch (response.status()) {
    case tremplin::DetachUsbFromContainerResponse::UNKNOWN:
      return VirtualMachine::DetachUsbFromContainerStatus::UNKNOWN;
    case tremplin::DetachUsbFromContainerResponse::OK:
      return VirtualMachine::DetachUsbFromContainerStatus::OK;
    case tremplin::DetachUsbFromContainerResponse::FAILED:
      return VirtualMachine::DetachUsbFromContainerStatus::FAILED;
    default:
      return VirtualMachine::DetachUsbFromContainerStatus::UNKNOWN;
  }
}

namespace {
template <typename key_t, typename src_value_t, typename dst_value_t>
void ConvertProtoMap(const google::protobuf::Map<key_t, src_value_t>& src,
                     google::protobuf::Map<key_t, dst_value_t>* dst,
                     bool (*is_valid)(int)) {
  for (const auto& iter : src) {
    if (is_valid(static_cast<int>(iter.second))) {
      (*dst)[iter.first] =
          static_cast<dst_value_t>(static_cast<int>(iter.second));
    }
  }
}

}  // namespace

VirtualMachine::UpdateContainerDevicesStatus
VirtualMachine::UpdateContainerDevices(
    Container* container,
    const google::protobuf::Map<std::string, VmDeviceAction>& updates,
    google::protobuf::Map<std::string,
                          UpdateContainerDevicesResponse::UpdateResult>*
        results,
    std::string* out_error) {
  DCHECK(container);
  DCHECK(out_error);

  if (IsContainerless()) {
    *out_error = "VM does not host containers";
    return VirtualMachine::UpdateContainerDevicesStatus::NO_SUCH_CONTAINER;
  } else if (!tremplin_stub_) {
    *out_error = "tremplin is not connected";
    return VirtualMachine::UpdateContainerDevicesStatus::FAILED;
  }

  vm_tools::tremplin::UpdateContainerDevicesRequest request;
  vm_tools::tremplin::UpdateContainerDevicesResponse response;

  request.set_container_name(container->name());
  ConvertProtoMap(updates, request.mutable_updates(),
                  &vm_tools::tremplin::VmDeviceAction_IsValid);

  grpc::ClientContext ctx;
  ctx.set_deadline(ToGprDeadline(kDefaultTimeoutSeconds));

  grpc::Status status =
      tremplin_stub_->UpdateContainerDevices(&ctx, request, &response);

  if (!status.ok()) {
    LOG(ERROR) << "UpdateContainerDevices RPC failed: "
               << status.error_message() << " " << status.error_code();
    out_error->assign(status.error_message());
    return VirtualMachine::UpdateContainerDevicesStatus::FAILED;
  }
  out_error->assign(response.failure_reason());
  ConvertProtoMap(response.results(), results,
                  &UpdateContainerDevicesResponse::UpdateResult_IsValid);

  switch (response.status()) {
    case tremplin::UpdateContainerDevicesResponse::UNKNOWN:
      return VirtualMachine::UpdateContainerDevicesStatus::UNKNOWN;
    case tremplin::UpdateContainerDevicesResponse::OK:
      return VirtualMachine::UpdateContainerDevicesStatus::OK;
    case tremplin::UpdateContainerDevicesResponse::NO_SUCH_CONTAINER:
      return VirtualMachine::UpdateContainerDevicesStatus::NO_SUCH_CONTAINER;
    default:
      return VirtualMachine::UpdateContainerDevicesStatus::UNKNOWN;
  }
}

VirtualMachine::StartLxdStatus VirtualMachine::StartLxd(
    bool reset_lxd_db, std::string* out_error) {
  DCHECK(out_error);
  if (!tremplin_stub_) {
    *out_error = "tremplin is not connected";
    return VirtualMachine::StartLxdStatus::FAILED;
  }

  vm_tools::tremplin::StartLxdRequest request;
  vm_tools::tremplin::StartLxdResponse response;

  grpc::ClientContext ctx;
  ctx.set_deadline(ToGprDeadline(kDefaultTimeoutSeconds));

  request.set_reset_lxd_db(reset_lxd_db);

  grpc::Status status = tremplin_stub_->StartLxd(&ctx, request, &response);
  if (!status.ok()) {
    LOG(ERROR) << "StartLxd RPC failed: " << status.error_message() << " "
               << status.error_code();
    out_error->assign(status.error_message());
    return VirtualMachine::StartLxdStatus::FAILED;
  }
  out_error->assign(response.failure_reason());
  switch (response.status()) {
    case tremplin::StartLxdResponse::UNKNOWN:
      return VirtualMachine::StartLxdStatus::UNKNOWN;
    case tremplin::StartLxdResponse::STARTING:
      return VirtualMachine::StartLxdStatus::STARTING;
    case tremplin::StartLxdResponse::ALREADY_RUNNING:
      return VirtualMachine::StartLxdStatus::ALREADY_RUNNING;
    case tremplin::StartLxdResponse::FAILED:
      return VirtualMachine::StartLxdStatus::FAILED;
    default:
      LOG(ERROR) << "Received unrecognised StartLxdStatus";
      return VirtualMachine::StartLxdStatus::UNKNOWN;
  }
}

void VirtualMachine::HostNetworkChanged() {
  if (!tremplin_stub_) {
    return;
  }

  vm_tools::tremplin::HostNetworkChangedRequest request;
  vm_tools::tremplin::HostNetworkChangedResponse response;

  grpc::ClientContext ctx;
  ctx.set_deadline(ToGprDeadline(kDefaultTimeoutSeconds));

  grpc::Status status =
      tremplin_stub_->HostNetworkChanged(&ctx, request, &response);
  if (!status.ok()) {
    LOG(ERROR) << "HostNetworkChanged RPC failed: " << status.error_message();
    return;
  }
}

bool VirtualMachine::GetTremplinDebugInfo(std::string* out) {
  if (!tremplin_stub_) {
    out->assign("Tremplin is not connected");
    return false;
  }

  vm_tools::tremplin::GetDebugInfoRequest request;
  vm_tools::tremplin::GetDebugInfoResponse response;

  grpc::ClientContext ctx;
  ctx.set_deadline(ToGprDeadline(kLongOperationTimeoutSeconds));

  grpc::Status status = tremplin_stub_->GetDebugInfo(&ctx, request, &response);
  if (!status.ok()) {
    LOG(ERROR) << "GetDebugInfo RPC failed: " << status.error_message();
    out->assign(status.error_message());
    return false;
  }
  out->assign(response.debug_information());
  return true;
}

}  // namespace cicerone
}  // namespace vm_tools
