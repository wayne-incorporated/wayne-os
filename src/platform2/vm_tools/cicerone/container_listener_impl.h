// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef VM_TOOLS_CICERONE_CONTAINER_LISTENER_IMPL_H_
#define VM_TOOLS_CICERONE_CONTAINER_LISTENER_IMPL_H_

#include <stdint.h>

#include <string>

#include <base/memory/weak_ptr.h>
#include <base/task/sequenced_task_runner.h>
#include <base/time/time.h>
#include <grpcpp/grpcpp.h>
#include <vm_protos/proto_bindings/container_host.grpc.pb.h>
#include <vm_protos/proto_bindings/container_host.pb.h>

namespace vm_tools {
namespace cicerone {

class Service;

// gRPC server implementation for receiving messages from a container in a VM.
class ContainerListenerImpl final
    : public vm_tools::container::ContainerListener::Service {
 public:
  explicit ContainerListenerImpl(
      base::WeakPtr<vm_tools::cicerone::Service> service);
  ContainerListenerImpl(const ContainerListenerImpl&) = delete;
  ContainerListenerImpl& operator=(const ContainerListenerImpl&) = delete;

  ~ContainerListenerImpl() override = default;

  // Pretend that every service call comes from |testing_peer_address| instead
  // of ctx->peer().
  void OverridePeerAddressForTesting(const std::string& testing_peer_address);

  // ContainerListener overrides.
  grpc::Status ContainerReady(
      grpc::ServerContext* ctx,
      const vm_tools::container::ContainerStartupInfo* request,
      vm_tools::EmptyMessage* response) override;
  grpc::Status ContainerShutdown(
      grpc::ServerContext* ctx,
      const vm_tools::container::ContainerShutdownInfo* request,
      vm_tools::EmptyMessage* response) override;
  grpc::Status PendingUpdateApplicationListCalls(
      grpc::ServerContext* ctx,
      const vm_tools::container::PendingAppListUpdateCount* request,
      vm_tools::EmptyMessage* response) override;
  grpc::Status UpdateApplicationList(
      grpc::ServerContext* ctx,
      const vm_tools::container::UpdateApplicationListRequest* request,
      vm_tools::EmptyMessage* response) override;
  grpc::Status OpenUrl(grpc::ServerContext* ctx,
                       const vm_tools::container::OpenUrlRequest* request,
                       vm_tools::EmptyMessage* response) override;
  grpc::Status InstallLinuxPackageProgress(
      grpc::ServerContext* ctx,
      const vm_tools::container::InstallLinuxPackageProgressInfo* request,
      vm_tools::EmptyMessage* response) override;
  grpc::Status UninstallPackageProgress(
      grpc::ServerContext* ctx,
      const vm_tools::container::UninstallPackageProgressInfo* request,
      vm_tools::EmptyMessage* response) override;
  grpc::Status ApplyAnsiblePlaybookProgress(
      grpc::ServerContext* ctx,
      const vm_tools::container::ApplyAnsiblePlaybookProgressInfo* request,
      vm_tools::EmptyMessage* response) override;
  grpc::Status OpenTerminal(
      grpc::ServerContext* ctx,
      const vm_tools::container::OpenTerminalRequest* request,
      vm_tools::EmptyMessage* response) override;
  grpc::Status UpdateMimeTypes(
      grpc::ServerContext* ctx,
      const vm_tools::container::UpdateMimeTypesRequest* request,
      vm_tools::EmptyMessage* response) override;
  grpc::Status FileWatchTriggered(
      grpc::ServerContext* ctx,
      const vm_tools::container::FileWatchTriggeredInfo* request,
      vm_tools::EmptyMessage* response) override;
  grpc::Status LowDiskSpaceTriggered(
      grpc::ServerContext* ctx,
      const vm_tools::container::LowDiskSpaceTriggeredInfo* request,
      vm_tools::EmptyMessage* response) override;
  grpc::Status ForwardSecurityKeyMessage(
      grpc::ServerContext* ctx,
      const vm_tools::container::ForwardSecurityKeyMessageRequest* request,
      vm_tools::container::ForwardSecurityKeyMessageResponse* response)
      override;
  grpc::Status SelectFile(
      grpc::ServerContext* ctx,
      const vm_tools::container::SelectFileRequest* request,
      vm_tools::container::SelectFileResponse* response) override;
  grpc::Status GetDiskInfo(
      grpc::ServerContext* ctx,
      const vm_tools::container::GetDiskInfoRequest* request,
      vm_tools::container::GetDiskInfoResponse* response) override;
  grpc::Status RequestSpace(
      grpc::ServerContext* ctx,
      const vm_tools::container::RequestSpaceRequest* request,
      vm_tools::container::RequestSpaceResponse* response) override;
  grpc::Status ReleaseSpace(
      grpc::ServerContext* ctx,
      const vm_tools::container::ReleaseSpaceRequest* request,
      vm_tools::container::ReleaseSpaceResponse* response) override;
  grpc::Status ReportMetrics(
      grpc::ServerContext* ctx,
      const vm_tools::container::ReportMetricsRequest* request,
      vm_tools::container::ReportMetricsResponse* response) override;
  grpc::Status InstallShaderCache(
      grpc::ServerContext* ctx,
      const vm_tools::container::InstallShaderCacheRequest* request,
      vm_tools::EmptyMessage* response) override;
  grpc::Status UninstallShaderCache(
      grpc::ServerContext* ctx,
      const vm_tools::container::UninstallShaderCacheRequest* request,
      vm_tools::EmptyMessage* response) override;
  grpc::Status UnmountShaderCache(
      grpc::ServerContext* ctx,
      const vm_tools::container::UnmountShaderCacheRequest* request,
      vm_tools::EmptyMessage* response) override;
  grpc::Status InhibitScreensaver(
      grpc::ServerContext* ctx,
      const vm_tools::container::InhibitScreensaverInfo* request,
      vm_tools::EmptyMessage* response) override;
  grpc::Status UninhibitScreensaver(
      grpc::ServerContext* ctx,
      const vm_tools::container::UninhibitScreensaverInfo* request,
      vm_tools::EmptyMessage* response) override;

 private:
  // Returns 0 on failure, otherwise the parsed vsock cid from a
  // vsock:cid:port string from ctx->peer()
  uint32_t ExtractCidFromPeerAddress(grpc::ServerContext* ctx);

  // Returns true if the performing an open window/tab operation will be within
  // the rules for rate limiting, false if it should be blocked. This will also
  // increment the rate limit counter as a side effect.
  bool CheckOpenRateLimit();

  base::WeakPtr<vm_tools::cicerone::Service> service_;  // not owned
  // Task runner for the D-Bus thread; requests to perform D-Bus operations
  // on |service_| generally need to be posted to this thread.
  scoped_refptr<base::SequencedTaskRunner> task_runner_;

  // Protects testing_peer_address_ so that OverridePeerAddressForTesting can
  // be called on any thread.
  base::Lock testing_peer_address_lock_;
  // Overrides ServerContext::peer if set.
  std::string testing_peer_address_;

  // We rate limit the requests to open a window/tab in Chrome to prevent an
  // accidental DOS of Chrome from a bad script in Linux. We use a fixed window
  // rate control algorithm to do this.
  uint32_t open_count_;
  base::TimeTicks open_rate_window_start_;
};

}  // namespace cicerone
}  // namespace vm_tools

#endif  // VM_TOOLS_CICERONE_CONTAINER_LISTENER_IMPL_H_
