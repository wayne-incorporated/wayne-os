// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef VM_TOOLS_MAITRED_SERVICE_IMPL_H_
#define VM_TOOLS_MAITRED_SERVICE_IMPL_H_

#include <map>
#include <memory>
#include <string>
#include <utility>

#include "base/files/file_path.h"
#include <base/functional/callback.h>
#include "brillo/storage_balloon.h"
#include <dbus/bus.h>
#include <dbus/object_proxy.h>
#include <grpcpp/grpcpp.h>
#include <vm_protos/proto_bindings/vm_guest.grpc.pb.h>

#include "vm_tools/maitred/init.h"

namespace vm_tools {
namespace maitred {

// Actually implements the maitred service.
class ServiceImpl final : public vm_tools::Maitred::Service {
 public:
  explicit ServiceImpl(std::unique_ptr<Init> init, bool maitred_is_pid1);
  ServiceImpl(const ServiceImpl&) = delete;
  ServiceImpl& operator=(const ServiceImpl&) = delete;

  ~ServiceImpl() override = default;

  // Initializes ServiceImpl for first use.
  bool Init(scoped_refptr<base::SequencedTaskRunner> dbus_task_runner);

  void set_shutdown_cb(base::OnceCallback<bool(void)> cb) {
    shutdown_cb_ = std::move(cb);
  }

  void set_localtime_file_path_for_test(const base::FilePath& dir) {
    localtime_file_path_ = dir;
  }

  void set_zoneinfo_file_path_for_test(const base::FilePath& dir) {
    zoneinfo_file_path_ = dir;
  }

  // Maitred::Service overrides.
  grpc::Status ConfigureNetwork(grpc::ServerContext* ctx,
                                const vm_tools::NetworkConfigRequest* request,
                                vm_tools::EmptyMessage* response) override;
  grpc::Status Shutdown(grpc::ServerContext* ctx,
                        const vm_tools::EmptyMessage* request,
                        vm_tools::EmptyMessage* response) override;
  grpc::Status LaunchProcess(
      grpc::ServerContext* ctx,
      const vm_tools::LaunchProcessRequest* request,
      vm_tools::LaunchProcessResponse* response) override;

  grpc::Status Mount(grpc::ServerContext* ctx,
                     const vm_tools::MountRequest* request,
                     vm_tools::MountResponse* response) override;
  grpc::Status Mount9P(grpc::ServerContext* ctx,
                       const vm_tools::Mount9PRequest* request,
                       vm_tools::MountResponse* response) override;

  // DEPRECATED. Use OnHostNetworkChanged instead.
  grpc::Status ResetIPv6(grpc::ServerContext* ctx,
                         const vm_tools::EmptyMessage* request,
                         vm_tools::EmptyMessage* response) override;

  grpc::Status OnHostNetworkChanged(grpc::ServerContext* ctx,
                                    const vm_tools::EmptyMessage* request,
                                    vm_tools::EmptyMessage* response) override;

  grpc::Status ConfigureContainerGuest(
      grpc::ServerContext* ctx,
      const vm_tools::ConfigureContainerGuestRequest* request,
      vm_tools::EmptyMessage* response) override;

  grpc::Status StartTermina(grpc::ServerContext* ctx,
                            const vm_tools::StartTerminaRequest* request,
                            vm_tools::StartTerminaResponse* response) override;

  grpc::Status SetResolvConfig(grpc::ServerContext* ctx,
                               const vm_tools::SetResolvConfigRequest* request,
                               vm_tools::EmptyMessage* response) override;

  grpc::Status SetTime(grpc::ServerContext* ctx,
                       const vm_tools::SetTimeRequest* request,
                       vm_tools::EmptyMessage* response) override;

  grpc::Status SetTimezone(grpc::ServerContext* ctx,
                           const vm_tools::SetTimezoneRequest* request,
                           vm_tools::EmptyMessage* response) override;

  grpc::Status GetKernelVersion(
      grpc::ServerContext* ctx,
      const vm_tools::EmptyMessage* request,
      vm_tools::GetKernelVersionResponse* response) override;

  grpc::Status ResizeFilesystem(
      grpc::ServerContext* ctx,
      const vm_tools::ResizeFilesystemRequest* request,
      vm_tools::ResizeFilesystemResponse* response) override;

  grpc::Status GetResizeStatus(
      grpc::ServerContext* ctx,
      const vm_tools::EmptyMessage* request,
      vm_tools::GetResizeStatusResponse* response) override;

  grpc::Status GetResizeBounds(
      grpc::ServerContext* ctx,
      const EmptyMessage* request,
      vm_tools::GetResizeBoundsResponse* response) override;

  grpc::Status GetAvailableSpace(
      grpc::ServerContext* ctx,
      const EmptyMessage* request,
      vm_tools::GetAvailableSpaceResponse* response) override;

  grpc::Status PrepareToSuspend(grpc::ServerContext* ctx,
                                const EmptyMessage* request,
                                EmptyMessage* response) override;

  // TODO(b/241185611): Remove this grpc when we put ballooning into its own
  // service.
  grpc::Status UpdateStorageBalloon(
      grpc::ServerContext* ctx,
      const vm_tools::UpdateStorageBalloonRequest* request,
      vm_tools::UpdateStorageBalloonResponse* response) override;

 private:
  bool maitred_is_pid1_;

  std::unique_ptr<vm_tools::maitred::Init> init_;

  // Callback used for shutting down the gRPC server.  Called when handling a
  // Shutdown RPC.
  base::OnceCallback<bool(void)> shutdown_cb_;

  // Flags to configure LXD functionality. Configuration happens statically in
  // the constructor as well as at runtime in the |StartTermina| function.
  std::map<std::string, std::string> lxd_env_;

  void ResizeCommandExitCallback(Init::ProcessStatus status, int code);

  // Global resize status for the stateful filesystem (/mnt/stateful).
  // All accesses must be done while resize_state_.lock is held.
  struct {
    base::Lock lock;
    bool resize_in_progress = false;
    uint64_t current_size = 0;
    uint64_t target_size = 0;
  } resize_state_;

  // Name of the stateful device (e.g. /dev/vdb) as determined by StartTermina.
  std::string stateful_device_;

  // Set timezone according to different implementations.
  grpc::Status SetTimezoneSymlink(const std::string& zoneinfo_file);
  grpc::Status SetTimezoneBindMount(const std::string& zoneinfo_file);
  // Path to system localtime file
  base::FilePath localtime_file_path_;
  // Path to zoneinfo directory
  base::FilePath zoneinfo_file_path_;

  std::unique_ptr<brillo::StorageBalloon> balloon_;

  scoped_refptr<dbus::Bus> bus_;
  dbus::ObjectProxy* logind_service_proxy_;
};

}  // namespace maitred
}  // namespace vm_tools

#endif  // VM_TOOLS_MAITRED_SERVICE_IMPL_H_
