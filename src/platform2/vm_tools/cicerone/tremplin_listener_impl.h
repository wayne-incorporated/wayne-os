// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef VM_TOOLS_CICERONE_TREMPLIN_LISTENER_IMPL_H_
#define VM_TOOLS_CICERONE_TREMPLIN_LISTENER_IMPL_H_

#include <stdint.h>

#include <string>

#include <base/memory/weak_ptr.h>
#include <base/task/sequenced_task_runner.h>
#include <base/time/time.h>
#include <grpcpp/grpcpp.h>
#include <vm_applications/apps.pb.h>
#include <vm_protos/proto_bindings/tremplin.grpc.pb.h>

namespace vm_tools {
namespace cicerone {

class Service;

// gRPC server implementation for receiving messages from a container in a VM.
class TremplinListenerImpl final
    : public vm_tools::tremplin::TremplinListener::Service {
 public:
  explicit TremplinListenerImpl(
      base::WeakPtr<vm_tools::cicerone::Service> service);
  TremplinListenerImpl(const TremplinListenerImpl&) = delete;
  TremplinListenerImpl& operator=(const TremplinListenerImpl&) = delete;

  ~TremplinListenerImpl() override = default;

  // Pretend that every service call comes from |testing_peer_address| instead
  // of ctx->peer().
  void OverridePeerAddressForTesting(const std::string& testing_peer_address);

  grpc::Status TremplinReady(
      grpc::ServerContext* ctx,
      const vm_tools::tremplin::TremplinStartupInfo* request,
      vm_tools::tremplin::EmptyMessage* response) override;

  grpc::Status UpdateCreateStatus(
      grpc::ServerContext* ctx,
      const vm_tools::tremplin::ContainerCreationProgress* request,
      vm_tools::tremplin::EmptyMessage* response) override;

  grpc::Status UpdateDeletionStatus(
      grpc::ServerContext* ctx,
      const vm_tools::tremplin::ContainerDeletionProgress* request,
      vm_tools::tremplin::EmptyMessage* response) override;

  grpc::Status UpdateStartStatus(
      grpc::ServerContext* ctx,
      const vm_tools::tremplin::ContainerStartProgress* request,
      vm_tools::tremplin::EmptyMessage* response) override;

  grpc::Status UpdateStopStatus(
      grpc::ServerContext* ctx,
      const vm_tools::tremplin::ContainerStopProgress* request,
      vm_tools::tremplin::EmptyMessage* response) override;

  grpc::Status UpdateExportStatus(
      grpc::ServerContext* ctx,
      const vm_tools::tremplin::ContainerExportProgress* request,
      vm_tools::tremplin::EmptyMessage* response) override;

  grpc::Status UpdateImportStatus(
      grpc::ServerContext* ctx,
      const vm_tools::tremplin::ContainerImportProgress* request,
      vm_tools::tremplin::EmptyMessage* response) override;

  grpc::Status ContainerShutdown(
      grpc::ServerContext* ctx,
      const vm_tools::tremplin::ContainerShutdownInfo* request,
      vm_tools::tremplin::EmptyMessage* response) override;

  grpc::Status UpdateListeningPorts(
      grpc::ServerContext* ctx,
      const vm_tools::tremplin::ListeningPortInfo* request,
      vm_tools::tremplin::EmptyMessage* response) override;

  grpc::Status UpgradeContainerStatus(
      grpc::ServerContext* ctx,
      const vm_tools::tremplin::UpgradeContainerProgress* request,
      vm_tools::tremplin::EmptyMessage* response) override;

  grpc::Status UpdateStartLxdStatus(
      grpc::ServerContext* ctx,
      const vm_tools::tremplin::StartLxdProgress* request,
      vm_tools::tremplin::EmptyMessage* response) override;

 private:
  uint32_t ExtractCidFromPeerAddress(grpc::ServerContext* ctx);

  // Protects testing_peer_address_ so that OverridePeerAddressForTesting can
  // be called on any thread.
  base::Lock testing_peer_address_lock_;
  // Overrides ServerContext::peer if set.
  std::string testing_peer_address_;

  base::WeakPtr<vm_tools::cicerone::Service> service_;  // not owned
  // Task runner for the DBus thread; requests to perform DBus operations
  // on |service_| generally need to be posted to this thread.
  scoped_refptr<base::SequencedTaskRunner> task_runner_;
};

}  // namespace cicerone
}  // namespace vm_tools

#endif  // VM_TOOLS_CICERONE_TREMPLIN_LISTENER_IMPL_H_
