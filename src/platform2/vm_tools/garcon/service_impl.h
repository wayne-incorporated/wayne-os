// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef VM_TOOLS_GARCON_SERVICE_IMPL_H_
#define VM_TOOLS_GARCON_SERVICE_IMPL_H_

#include <base/task/task_runner.h>
#include <grpcpp/grpcpp.h>
#include <vm_protos/proto_bindings/container_guest.grpc.pb.h>

#include "vm_tools/garcon/host_notifier.h"

namespace vm_tools {
namespace garcon {

class AnsiblePlaybookApplication;
class PackageKitProxy;

// Actually implements the garcon service.
class ServiceImpl final : public vm_tools::container::Garcon::Service {
 public:
  explicit ServiceImpl(PackageKitProxy* package_kit_proxy,
                       base::TaskRunner* task_runner,
                       HostNotifier* host_notifier);
  ServiceImpl(const ServiceImpl&) = delete;
  ServiceImpl& operator=(const ServiceImpl&) = delete;

  ~ServiceImpl() override = default;

  // Garcon::Service overrides.
  grpc::Status LaunchApplication(
      grpc::ServerContext* ctx,
      const vm_tools::container::LaunchApplicationRequest* request,
      vm_tools::container::LaunchApplicationResponse* response) override;

  grpc::Status GetIcon(grpc::ServerContext* ctx,
                       const vm_tools::container::IconRequest* request,
                       vm_tools::container::IconResponse* response) override;

  grpc::Status LaunchVshd(
      grpc::ServerContext* ctx,
      const vm_tools::container::LaunchVshdRequest* request,
      vm_tools::container::LaunchVshdResponse* response) override;

  grpc::Status GetLinuxPackageInfo(
      grpc::ServerContext* ctx,
      const vm_tools::container::LinuxPackageInfoRequest* request,
      vm_tools::container::LinuxPackageInfoResponse* response) override;

  grpc::Status InstallLinuxPackage(
      grpc::ServerContext* ctx,
      const vm_tools::container::InstallLinuxPackageRequest* request,
      vm_tools::container::InstallLinuxPackageResponse* response) override;

  grpc::Status UninstallPackageOwningFile(
      grpc::ServerContext* ctx,
      const vm_tools::container::UninstallPackageOwningFileRequest* request,
      vm_tools::container::UninstallPackageOwningFileResponse* response)
      override;

  grpc::Status GetDebugInformation(
      grpc::ServerContext* ctx,
      const vm_tools::container::GetDebugInformationRequest* request,
      vm_tools::container::GetDebugInformationResponse* response) override;

  grpc::Status ConnectChunnel(
      grpc::ServerContext* ctx,
      const vm_tools::container::ConnectChunnelRequest* request,
      vm_tools::container::ConnectChunnelResponse* response) override;

  grpc::Status ApplyAnsiblePlaybook(
      grpc::ServerContext* ctx,
      const vm_tools::container::ApplyAnsiblePlaybookRequest* request,
      vm_tools::container::ApplyAnsiblePlaybookResponse* response) override;

  grpc::Status ConfigureForArcSideload(
      grpc::ServerContext* ctx,
      const vm_tools::container::ConfigureForArcSideloadRequest* request,
      vm_tools::container::ConfigureForArcSideloadResponse* response) override;

  grpc::Status AddFileWatch(
      grpc::ServerContext* ctx,
      const vm_tools::container::AddFileWatchRequest* request,
      vm_tools::container::AddFileWatchResponse* response) override;

  grpc::Status RemoveFileWatch(
      grpc::ServerContext* ctx,
      const vm_tools::container::RemoveFileWatchRequest* request,
      vm_tools::container::RemoveFileWatchResponse* response) override;

  grpc::Status GetGarconSessionInfo(
      grpc::ServerContext* ctx,
      const vm_tools::container::GetGarconSessionInfoRequest* request,
      vm_tools::container::GetGarconSessionInfoResponse* response) override;

 private:
  PackageKitProxy* package_kit_proxy_;  // Not owned.
  base::TaskRunner* task_runner_;
  HostNotifier* host_notifier_;
};

}  // namespace garcon
}  // namespace vm_tools

#endif  // VM_TOOLS_GARCON_SERVICE_IMPL_H_
