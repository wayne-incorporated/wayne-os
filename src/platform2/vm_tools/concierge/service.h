// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef VM_TOOLS_CONCIERGE_SERVICE_H_
#define VM_TOOLS_CONCIERGE_SERVICE_H_

#include <stdint.h>

#include <list>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include <base/files/file_descriptor_watcher_posix.h>
#include <base/files/file_path.h>
#include <base/files/file_path_watcher.h>
#include <base/files/scoped_file.h>
#include <base/functional/callback.h>
#include <base/memory/ref_counted.h>
#include <base/memory/weak_ptr.h>
#include <base/sequence_checker.h>
#include <base/synchronization/lock.h>
#include <base/thread_annotations.h>
#include <base/threading/thread.h>
#include <base/timer/timer.h>
#include <brillo/dbus/dbus_object.h>
#include <chromeos/dbus/resource_manager/dbus-constants.h>
#include <dbus/bus.h>
#include <dbus/exported_object.h>
#include <dbus/message.h>
#include <featured/feature_library.h>
#include <grpcpp/grpcpp.h>
#include <shadercached/proto_bindings/shadercached.pb.h>
#include <spaced/disk_usage_proxy.h>
#include <vm_concierge/concierge_service.pb.h>

#include "vm_tools/common/vm_id.h"
#include "vm_tools/concierge/dbus_adaptors/org.chromium.VmConcierge.h"
#include "vm_tools/concierge/disk_image.h"
#include "vm_tools/concierge/power_manager_client.h"
#include "vm_tools/concierge/shill_client.h"
#include "vm_tools/concierge/startup_listener_impl.h"
#include "vm_tools/concierge/termina_vm.h"
#include "vm_tools/concierge/untrusted_vm_utils.h"
#include "vm_tools/concierge/vm_base_impl.h"
#include "vm_tools/concierge/vm_builder.h"
#include "vm_tools/concierge/vm_util.h"
#include "vm_tools/concierge/vmm_swap_tbw_policy.h"
#include "vm_tools/concierge/vsock_cid_pool.h"

namespace vm_tools {
namespace concierge {

class DlcHelper;

// VM Launcher Service responsible for responding to DBus method calls for
// starting, stopping, and otherwise managing VMs.
class Service final : public org::chromium::VmConciergeInterface,
                      public spaced::SpacedObserverInterface {
 public:
  // Creates a new Service instance.  |quit_closure| is posted to the TaskRunner
  // for the current thread when this process receives a SIGTERM.
  static std::unique_ptr<Service> Create(base::OnceClosure quit_closure);
  ~Service();

 private:
  // Describes GPU shader cache paths.
  struct VMGpuCacheSpec {
    base::FilePath device;
    base::FilePath render_server;
    base::FilePath foz_db_list;
  };

  explicit Service(base::OnceClosure quit_closure);
  Service(const Service&) = delete;
  Service& operator=(const Service&) = delete;

  // Initializes the service by connecting to the system DBus daemon, exporting
  // its methods, and taking ownership of it's name.
  bool Init();

  // Handles the termination of a child process.
  void HandleChildExit();

  // Handles a SIGTERM.
  void HandleSigterm();

  // Helper function that is used by StartVm, StartPluginVm and StartArcVm
  //
  // Returns false if any preconditions are not met for Start*Vm.
  template <class StartXXRequest>
  bool CheckStartVmPreconditions(const StartXXRequest& request,
                                 StartVmResponse* response);
  // Checks if existing disk with same name is there before creating. true if
  // name is available, false if one already exists.
  template <class StartXXRequest>
  bool CheckExistingDisk(const StartXXRequest& request,
                         StartVmResponse* response);
  // Checks if existing VM with same name is there before creating. true if name
  // is available, false if one already exists.
  template <class StartXXRequest>
  bool CheckExistingVm(const StartXXRequest& request,
                       StartVmResponse* response);

  // Handles a request to start a VM.
  StartVmResponse StartVmInternal(StartVmRequest request,
                                  std::unique_ptr<dbus::MessageReader> reader);
  void StartVm(dbus::MethodCall* method_call,
               dbus::ExportedObject::ResponseSender sender) override;

  // Handles a request to start a plugin-based VM.
  StartVmResponse StartPluginVmInternal(StartPluginVmRequest request,
                                        StartVmResponse& response);
  void StartPluginVm(
      std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
          vm_tools::concierge::StartVmResponse>> response,
      const vm_tools::concierge::StartPluginVmRequest& request) override;

  // Handles a request to start ARCVM.
  StartVmResponse StartArcVmInternal(StartArcVmRequest request,
                                     StartVmResponse& response);
  void StartArcVm(
      std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
          vm_tools::concierge::StartVmResponse>> response,
      const vm_tools::concierge::StartArcVmRequest& request) override;

  // Handles a request to stop a VM.
  StopVmResponse StopVm(const StopVmRequest& request) override;

  // Handles a request to stop a VM.
  bool StopVmInternal(const VmId& vm_id, VmStopReason reason);
  // Wrapper to post |StopVmInternal| as a task. Only difference is that we
  // ignore the return value here.
  void StopVmInternalAsTask(VmId vm_id, VmStopReason reason);

  // Handles a request to suspend a VM.
  SuspendVmResponse SuspendVm(const SuspendVmRequest& request) override;

  // Handles a request to resume a VM.
  ResumeVmResponse ResumeVm(const ResumeVmRequest& request) override;

  // Handles a request to stop all running VMs.
  void StopAllVmsImpl(VmStopReason reason);
  void StopAllVms() override;

  // Handles a request to get VM info.
  GetVmInfoResponse GetVmInfo(const GetVmInfoRequest& request) override;

  // Handles a request to get VM info specific to enterprise reporting.
  GetVmEnterpriseReportingInfoResponse GetVmEnterpriseReportingInfo(
      const GetVmEnterpriseReportingInfoRequest& request) override;

  // Handles a request to complete the boot of an ARC VM.
  ArcVmCompleteBootResponse ArcVmCompleteBoot(
      const ArcVmCompleteBootRequest& request) override;

  // Handles a request to update balloon timer.
  SetBalloonTimerResponse SetBalloonTimer(
      const SetBalloonTimerRequest& request) override;

  // Handles a request to update all VMs' times to the current host time.
  SyncVmTimesResponse SyncVmTimes() override;

  // Handles a request to create a disk image.
  void CreateDiskImage(dbus::MethodCall* method_call,
                       dbus::ExportedObject::ResponseSender sender) override;
  CreateDiskImageResponse CreateDiskImageInternal(
      CreateDiskImageRequest request, base::ScopedFD in_fd);

  // Handles a request to destroy a disk image.
  DestroyDiskImageResponse DestroyDiskImage(
      const DestroyDiskImageRequest& request) override;

  // Handles a request to resize a disk image.
  ResizeDiskImageResponse ResizeDiskImage(
      const ResizeDiskImageRequest& request) override;

  // Handles a request to get disk resize status.
  std::unique_ptr<dbus::Response> GetDiskResizeStatus(
      dbus::MethodCall* method_call);

  // Handles a request to export a disk image.
  void ExportDiskImage(dbus::MethodCall* method_call,
                       dbus::ExportedObject::ResponseSender sender) override;
  ExportDiskImageResponse ExportDiskImageInternal(
      ExportDiskImageRequest request,
      base::ScopedFD storage_fd,
      base::ScopedFD digest_fd);

  // Handles a request to import a disk image.
  ImportDiskImageResponse ImportDiskImage(const ImportDiskImageRequest& request,
                                          const base::ScopedFD& in_fd) override;

  // Handles a request to check status of a disk image operation.
  DiskImageStatusResponse DiskImageStatus(
      const DiskImageStatusRequest& request) override;

  // Handles a request to cancel a disk image operation.
  CancelDiskImageResponse CancelDiskImageOperation(
      const CancelDiskImageRequest& request) override;

  // Run import/export disk image operation with given UUID.
  void RunDiskImageOperation(std::string uuid);

  // Handles a request to list existing disk images.
  ListVmDisksResponse ListVmDisks(const ListVmDisksRequest& request) override;

  AttachUsbDeviceResponse AttachUsbDevice(const AttachUsbDeviceRequest& request,
                                          const base::ScopedFD& fd) override;
  DetachUsbDeviceResponse DetachUsbDevice(
      const DetachUsbDeviceRequest& request) override;
  ListUsbDeviceResponse ListUsbDevices(
      const ListUsbDeviceRequest& request) override;

  DnsSettings GetDnsSettings() override;

  SetVmCpuRestrictionResponse SetVmCpuRestriction(
      const SetVmCpuRestrictionRequest& request) override;

  // Handles a request to adjust parameters of a given VM.
  AdjustVmResponse AdjustVm(const AdjustVmRequest& request) override;

  // Handles a request to list all the VMs.
  ListVmsResponse ListVms(const ListVmsRequest& request) override;

  // Handles a request to get VM's GPU cache path.
  bool GetVmGpuCachePath(brillo::ErrorPtr* error,
                         const GetVmGpuCachePathRequest& request,
                         GetVmGpuCachePathResponse* response) override;

  // Handles a request to add group permission to directories created by mesa
  // for a specified VM.
  bool AddGroupPermissionMesa(
      brillo::ErrorPtr* error,
      const AddGroupPermissionMesaRequest& request) override;

  // Handles a request to get if allowed to launch VM.
  GetVmLaunchAllowedResponse GetVmLaunchAllowed(
      const GetVmLaunchAllowedRequest& request) override;

  // Handles a request to get VM logs.
  bool GetVmLogs(brillo::ErrorPtr* error,
                 const GetVmLogsRequest& request,
                 GetVmLogsResponse* response) override;

  // Handles a request to change VM swap state.
  void SwapVm(
      std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<SwapVmResponse>>
          response_sender,
      const SwapVmRequest& request) override;

  void NotifyVmSwapping(const VmId& vm_id);

  // Handles a request to install the Pflash image associated with a VM.
  InstallPflashResponse InstallPflash(
      const InstallPflashRequest& request,
      const base::ScopedFD& pflash_src_fd) override;

  // Asynchronously handles a request to reclaim memory of a given VM.
  void ReclaimVmMemory(
      std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
          vm_tools::concierge::ReclaimVmMemoryResponse>> response,
      const vm_tools::concierge::ReclaimVmMemoryRequest& request) override;

  // Inflate balloon in a vm until perceptible processes in the guest are tried
  // to kill.
  void AggressiveBalloon(std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
                             AggressiveBalloonResponse>> response,
                         const AggressiveBalloonRequest& request) override;

  // Creates DnsSettings from current configuration.
  DnsSettings ComposeDnsResponse();

  // Handles DNS changes from shill.
  void OnResolvConfigChanged(std::vector<std::string> nameservers,
                             std::vector<std::string> search_domains);

  // Handles Default service changes from shill.
  void OnDefaultNetworkServiceChanged();

  // Helper for starting termina VMs, e.g. starting lxd.
  bool StartTermina(TerminaVm* vm,
                    bool allow_privileged_containers,
                    const google::protobuf::RepeatedField<int>& features,
                    std::string* failure_reason,
                    vm_tools::StartTerminaResponse::MountResult* result,
                    int64_t* out_free_bytes);

  // Helpers for notifying cicerone and sending signals of VM started/stopped
  // events, and generating container tokens.
  void NotifyCiceroneOfVmStarted(const VmId& vm_id,
                                 uint32_t vsock_cid,
                                 pid_t pid,
                                 std::string vm_token);
  void HandleVmStarted(const VmId& vm_id,
                       const vm_tools::concierge::VmInfo& vm_info,
                       const std::string& vm_socket,
                       vm_tools::concierge::VmStatus status);
  void SendVmStartedSignal(const VmId& vm_id,
                           const vm_tools::concierge::VmInfo& vm_info,
                           vm_tools::concierge::VmStatus status);
  void SendVmStartingUpSignal(const VmId& vm_id,
                              const vm_tools::concierge::VmInfo& vm_info);
  void SendVmGuestUserlandReadySignal(
      const VmId& vm_id, const vm_tools::concierge::GuestUserlandReady ready);
  void NotifyVmStopping(const VmId& vm_id, int64_t cid);
  void NotifyVmStopped(const VmId& vm_id, int64_t cid, VmStopReason reason);

  std::string GetContainerToken(const VmId& vm_id,
                                const std::string& container_name);

  void OnTremplinStartedSignal(dbus::Signal* signal);
  void OnVmToolsStateChangedSignal(dbus::Signal* signal);

  void OnSignalConnected(const std::string& interface_name,
                         const std::string& signal_name,
                         bool is_connected);
  void OnSignalReadable();

  // Called by |power_manager_client_| when the device is about to suspend or
  // resumed from suspend.
  void HandleSuspendImminent();
  void HandleSuspendDone();

  // Send D-Bus message to check if a Feature is enabled.
  // If there was an error with the dbus message (ex. Feature not present),
  // |error_out| is set with the message.
  std::optional<bool> IsFeatureEnabled(const std::string& feature_name,
                                       std::string* error_out);

  using DiskImageStatusEnum = vm_tools::concierge::DiskImageStatus;

  // Initiate a disk resize request for the VM identified by |owner_id| and
  // |vm_name|.
  void ResizeDisk(const std::string& owner_id,
                  const std::string& vm_name,
                  StorageLocation location,
                  uint64_t new_size,
                  DiskImageStatusEnum* status,
                  std::string* failure_reason);
  // Query the status of the most recent ResizeDisk request.
  // If this returns DISK_STATUS_FAILED, |failure_reason| will be filled with an
  // error message.
  void ProcessResize(const std::string& owner_id,
                     const std::string& vm_name,
                     StorageLocation location,
                     uint64_t target_size,
                     DiskImageStatusEnum* status,
                     std::string* failure_reason);

  // Finalize the resize process after a success resize has completed.
  void FinishResize(const std::string& owner_id,
                    const std::string& vm_name,
                    StorageLocation location,
                    DiskImageStatusEnum* status,
                    std::string* failure_reason);

  // Executes rename operation of a Plugin VM.
  bool RenamePluginVm(const std::string& owner_id,
                      const std::string& old_name,
                      const std::string& new_name,
                      std::string* failure_reason);

  // Callback for when the localtime file is changed
  void OnLocaltimeFileChanged(const base::FilePath& path, bool error);

  // Get the host system time zone
  std::string GetHostTimeZone();

  using VmMap = std::map<VmId, std::unique_ptr<VmBaseImpl>>;

  // Returns an iterator to vm with key |vm_id|.
  VmMap::iterator FindVm(const VmId& vm_id);

  // Returns an iterator to vm with key (|owner_id|, |vm_name|).
  VmMap::iterator FindVm(const std::string& owner_id,
                         const std::string& vm_name);

  std::optional<int64_t> GetAvailableMemory();
  std::optional<int64_t> GetForegroundAvailableMemory();
  std::optional<MemoryMargins> GetMemoryMargins();
  std::optional<ComponentMemoryMargins> GetComponentMemoryMargins();
  std::optional<resource_manager::GameMode> GetGameMode();
  void RunBalloonPolicy();
  void FinishBalloonPolicy(
      MemoryMargins memory_margins,
      std::vector<std::pair<uint32_t, BalloonStats>> stats);

  bool ListVmDisksInLocation(const std::string& cryptohome_id,
                             StorageLocation location,
                             const std::string& lookup_name,
                             ListVmDisksResponse* response);

  // Determine the path for a VM image based on |dlc_id| (or the component, if
  // the id is empty). Returns the empty path and sets failure_reason in the
  // event of a failure.
  base::FilePath GetVmImagePath(const std::string& dlc_id,
                                std::string* failure_reason);

  // Determines key components of a VM image. Also, decides if it's a trusted
  // VM. Returns the empty struct and sets |failure_reason| in the event of a
  // failure.
  VMImageSpec GetImageSpec(const vm_tools::concierge::VirtualMachineSpec& vm,
                           const std::optional<base::ScopedFD>& kernel_fd,
                           const std::optional<base::ScopedFD>& rootfs_fd,
                           const std::optional<base::ScopedFD>& initrd_fd,
                           const std::optional<base::ScopedFD>& bios_fd,
                           const std::optional<base::ScopedFD>& pflash_fd,
                           bool is_termina,
                           std::string* failure_reason);

  // Get GPU cache path for the VM.
  base::FilePath GetVmGpuCachePathInternal(const std::string& owner_id,
                                           const std::string& vm_name);

  // Prepares the GPU shader disk cache directories and if necessary erases
  // old caches for all VMs. Returns the prepared paths.
  VMGpuCacheSpec PrepareVmGpuCachePaths(const std::string& owner_id,
                                        const std::string& vm_name,
                                        bool enable_render_server,
                                        bool enable_foz_db_list);

  // Checks the current Feature settings and returns the CPU quota value (e.g.
  // 50 meaning 50%) to be set as the cpu.cfs_quota_us cgroup. When the Feature
  // is not enabled, returns kCpuPercentUnlimited.
  int GetCpuQuota();

  // Handles StatefulDiskSpaceUpdate from spaced.
  void OnStatefulDiskSpaceUpdate(
      const spaced::StatefulDiskSpaceUpdate& update) override;

  // Delegates a stateful disk update to be handled by the VM with the specified
  // |vm_id|.
  void HandleStatefulDiskSpaceUpdate(
      VmId vm_id, const spaced::StatefulDiskSpaceUpdate update);

  // Adds |vm_id| to the list of VMs that are using storage ballooning.
  void AddStorageBalloonVm(VmId vm_id);

  // Removes the |vm_id| from the list of VMs that are using storage
  // ballooning.
  void RemoveStorageBalloonVm(VmId vm_id);

  // Callback called by a |TerminaVm| instance (running as a sibling VM) when a
  // sibling VM process has died on the hypervisor.
  void OnSiblingVmDead(VmId vm_id);

  // Resource allocators for VMs.
  VsockCidPool vsock_cid_pool_;

  // Current DNS resolution config.
  std::vector<std::string> nameservers_;
  std::vector<std::string> search_domains_;

  // File descriptor for the SIGCHLD events.
  base::ScopedFD signal_fd_;
  std::unique_ptr<base::FileDescriptorWatcher::Controller> watcher_;

  // Connection to the system bus.
  base::Thread dbus_thread_{"dbus thread"};
  scoped_refptr<dbus::Bus> bus_;
  dbus::ExportedObject* exported_object_;              // Owned by |bus_|.
  dbus::ObjectProxy* cicerone_service_proxy_;          // Owned by |bus_|.
  dbus::ObjectProxy* seneschal_service_proxy_;         // Owned by |bus_|.
  dbus::ObjectProxy* vm_permission_service_proxy_;     // Owned by |bus_|.
  dbus::ObjectProxy* vmplugin_service_proxy_;          // Owned by |bus_|.
  dbus::ObjectProxy* resource_manager_service_proxy_;  // Owned by |bus_|.
  dbus::ObjectProxy* chrome_features_service_proxy_;   // Owned by |bus_|.
  dbus::ObjectProxy* shadercached_proxy_;              // Owned by |bus_|.

  std::unique_ptr<brillo::dbus_utils::DBusObject> dbus_object_;
  org::chromium::VmConciergeAdaptor concierge_adaptor_{this};

  // The port number to assign to the next shared directory server.
  uint32_t next_seneschal_server_port_;

  // Active VMs keyed by VmId which is (owner_id, vm_name).
  VmMap vms_ GUARDED_BY_CONTEXT(sequence_checker_);

  // The shill D-Bus client.
  std::unique_ptr<ShillClient> shill_client_;

  // The power manager D-Bus client.
  std::unique_ptr<PowerManagerClient> power_manager_client_;

  // The dlcservice helper D-Bus client.
  std::unique_ptr<DlcHelper> dlcservice_client_;

  // The StartupListener service.
  StartupListenerImpl startup_listener_;

  // Thread on which the StartupListener service lives.
  base::Thread grpc_thread_vm_{"gRPC VM Server Thread"};

  // The server where the StartupListener service lives.
  std::shared_ptr<grpc::Server> grpc_server_vm_;

  // Closure that's posted to the current thread's TaskRunner when the service
  // receives a SIGTERM.
  base::OnceClosure quit_closure_;

  // Ensure calls are made on the right thread.
  SEQUENCE_CHECKER(sequence_checker_);

  // Signal must be connected before we can call SetTremplinStarted in a VM.
  bool is_tremplin_started_signal_connected_ = false;

  // List of currently executing operations to import/export disk images.
  struct DiskOpInfo {
    std::unique_ptr<DiskImageOperation> op;
    bool canceled;
    base::TimeTicks last_report_time;

    explicit DiskOpInfo(std::unique_ptr<DiskImageOperation> disk_op)
        : op(std::move(disk_op)),
          canceled(false),
          last_report_time(base::TimeTicks::Now()) {}
  };
  std::list<DiskOpInfo> disk_image_ops_;

  // The kernel version of the host.
  const KernelVersionAndMajorRevision host_kernel_version_;

  // Used to check for, and possibly enable, the conditions required for
  // untrusted VMs.
  std::unique_ptr<UntrustedVMUtils> untrusted_vm_utils_;

  // Thread on which memory reclaim operations are performed.
  base::Thread reclaim_thread_{"memory reclaim thread"};

  // The timer which invokes the balloon resizing logic.
  base::RepeatingTimer balloon_resizing_timer_;

  // Proxy for interacting with spaced.
  std::unique_ptr<spaced::DiskUsageProxy> disk_usage_proxy_;

  // List of active VMs using storage ballooning.
  std::set<VmId> storage_balloon_vms_;

  // Used to serialize erasing and creating the GPU shader disk cache in the
  // event that VMs are started simultaneously from multiple threads.
  base::Lock cache_mutex_;

  // Watcher to monitor changes to the system timezone file.
  base::FilePathWatcher localtime_watcher_;

  // The vmm swap TBW (total bytes written) policy managing TBW from each VM on
  // vmm-swap. This is instantiated by Service and shared with each VM.
  std::unique_ptr<VmmSwapTbwPolicy> vmm_swap_tbw_policy_ GUARDED_BY_CONTEXT(
      sequence_checker_) = std::make_unique<VmmSwapTbwPolicy>();

  // This should be the last member of the class.
  base::WeakPtrFactory<Service> weak_ptr_factory_;
};

}  // namespace concierge
}  // namespace vm_tools

#endif  // VM_TOOLS_CONCIERGE_SERVICE_H_
