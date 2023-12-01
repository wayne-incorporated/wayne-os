// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef VM_TOOLS_CONCIERGE_TERMINA_VM_H_
#define VM_TOOLS_CONCIERGE_TERMINA_VM_H_

#include <stdint.h>
#include <unistd.h>

#include <map>
#include <memory>
#include <string>
#include <vector>

#include <base/files/file_descriptor_watcher_posix.h>
#include <base/files/file_path.h>
#include <base/functional/callback_forward.h>
#include <base/notreached.h>
#include <base/threading/thread.h>
#include <base/time/time.h>
#include <brillo/process/process.h>
#include <chromeos/patchpanel/mac_address_generator.h>
#include <chromeos/patchpanel/dbus/client.h>
#include <chromeos/patchpanel/subnet.h>
#include <spaced/proto_bindings/spaced.pb.h>
#include <vm_concierge/concierge_service.pb.h>
#include <vm_protos/proto_bindings/vm_guest.grpc.pb.h>

#include "vm_tools/common/vm_id.h"
#include "vm_tools/concierge/seneschal_server_proxy.h"
#include "vm_tools/concierge/vm_base_impl.h"
#include "vm_tools/concierge/vm_builder.h"
#include "vm_tools/concierge/vm_util.h"
#include "vm_tools/concierge/vsock_cid_pool.h"

namespace vm_tools {
namespace concierge {

class ScopedWlSocket;

// The CPU cgroup where all the Termina main crosvm process should belong to.
constexpr char kTerminaVcpuCpuCgroup[] = "/sys/fs/cgroup/cpu/termina-vcpus";

// The cpuset cgroup where the Borealis vGPU server threads are to go into.
constexpr char kBorealisGpuServerCpusetCgroup[] =
    "/sys/fs/cgroup/cpuset/borealis-vgpuserver";

// The CPU cgroup where all the Termina crosvm processes other than main should
// belong to.
constexpr char kTerminaCpuCgroup[] = "/sys/fs/cgroup/cpu/termina";

// Name of the control socket used for controlling crosvm.
constexpr char kTerminaCrosvmSocket[] = "crosvm.sock";

struct VmFeatures {
  // Enable GPU in the started VM.
  bool gpu;
  // Enable DGPU passthrough in the started VM.
  bool dgpu_passthrough;
  bool vulkan;
  bool big_gl;
  bool virtgpu_native_context;
  bool render_server;

  // Provide software-based virtual Trusted Platform Module to the VM.
  bool software_tpm;

  // Provide vtpm connection to the VM.
  bool vtpm_proxy;

  // Enable audio capture function in the started VM.
  bool audio_capture;

  // Extra kernel cmdline params passed to the VM.
  std::vector<std::string> kernel_params;

  // Type 11 SMBIOS DMI OEM strings passed to the VM.
  std::vector<std::string> oem_strings;
};

// Represents a single instance of a running termina VM.
class TerminaVm final : public VmBaseImpl {
 public:
  // Type of a disk image.
  enum class DiskImageType {
    // Raw disk image file.
    RAW,

    // QCOW2 disk image.
    QCOW2,
  };

  enum class DiskResizeType {
    NONE,
    EXPAND,
    SHRINK,
  };

  struct Config {
    uint32_t vsock_cid;
    std::unique_ptr<patchpanel::Client> network_client;
    std::unique_ptr<SeneschalServerProxy> seneschal_server_proxy;
    std::string cros_vm_socket{kTerminaCrosvmSocket};
    base::FilePath runtime_dir;
    base::FilePath log_path;
    std::string stateful_device;
    uint64_t stateful_size;
    VmFeatures features;
    dbus::ObjectProxy* vm_permission_service_proxy;
    scoped_refptr<dbus::Bus> bus;
    VmId id;
    VmId::Type classification;
    VmBuilder vm_builder;
    std::unique_ptr<ScopedWlSocket> socket;
  };

  // Starts a new virtual machine.  Returns nullptr if the virtual machine
  // failed to start for any reason.
  static std::unique_ptr<TerminaVm> Create(Config config);
  ~TerminaVm() override;

  // Configures the network interfaces inside the VM.  Returns true iff
  // successful.
  bool ConfigureNetwork(const std::vector<std::string>& nameservers,
                        const std::vector<std::string>& search_domains);

  // Configures the VM to allow it to support a (single) container guest API
  // endpoint using |vm_token| as the container token.
  bool ConfigureContainerGuest(const std::string& vm_token,
                               const std::string& vm_username,
                               std::string* out_error);

  // Mounts a file system inside the VM.  Both |source| (if it is a file path)
  // and |target| must be valid paths inside the VM.  Returns true on success.
  bool Mount(std::string source,
             std::string target,
             std::string fstype,
             uint64_t mountflags,
             std::string options);

  // Starts Termina-specific services in the guest.
  bool StartTermina(std::string lxd_subnet,
                    bool allow_privileged_containers,
                    const google::protobuf::RepeatedField<int>& features,
                    std::string* out_error,
                    vm_tools::StartTerminaResponse* response);

  // Mount a 9p file system inside the VM.  The guest VM connects to a server
  // listening on the vsock port |port| and mounts the file system on |target|.
  bool Mount9P(uint32_t port, std::string target);

  // Mounts an extra disk device inside the VM an an external disk.  |source|
  // must be a valid path inside the VM.  |target| is a name of mount point
  // which will be created under /mnt/external inside the VM. Returns true on
  // success.
  bool MountExternalDisk(std::string source, std::string target_dir);

  // Sets the resolv.conf in the VM to |config|. Returns true if successful,
  // false if the resolv.conf in the guest could not be updated.
  bool SetResolvConfig(const std::vector<std::string>& nameservers,
                       const std::vector<std::string>& search_domains) override;

  // Reset IPv6 stack in the VM if needed. This is triggered during a default
  // network change. Return true if successful.
  void HostNetworkChanged() override;

  // Set the guest time to the current time as given by gettimeofday.
  bool SetTime(std::string* failure_reason) override;

  // Set VM timezone by calling Maitred.SetTimeZone.
  bool SetTimezone(const std::string& timezone,
                   std::string* out_error) override;

  // The pid of the child process.
  pid_t pid() { return process_.pid(); }

  // The VM's cid.
  uint32_t cid() const { return vsock_cid_; }

  // The IPv4 address of the VM's gateway in network byte order.
  uint32_t GatewayAddress() const;

  // The IPv4 address of the VM in network byte order.
  uint32_t IPv4Address() const;

  // The netmask of the VM's subnet in network byte order.
  uint32_t Netmask() const;

  // The VM's container subnet netmask in network byte order. Returns INADDR_ANY
  // if there is no container subnet.
  uint32_t ContainerNetmask() const;

  // The VM's container subnet prefix length. Returns 0 if there is no container
  // subnet.
  size_t ContainerPrefixLength() const;

  // The first address in the VM's container subnet in network byte order.
  // Returns INADDR_ANY if there is no container subnet.
  uint32_t ContainerSubnet() const;

  // Token assigned to the VM by the permission service. Used for communicating
  // with the permission service.
  std::string PermissionToken() const;

  // Name of the guest block device for the stateful filesystem (e.g. /dev/vdb).
  std::string StatefulDevice() const { return stateful_device_; }

  // Whether a TremplinStartedSignal has been received for the VM.
  bool IsTremplinStarted() const { return is_tremplin_started_; }

  // VmBaseImpl overrides.
  // Shuts down the VM.  First attempts a clean shutdown of the VM by sending
  // a Shutdown RPC to maitre'd.  If that fails, attempts to shut down the VM
  // using the control socket for the hypervisor.  If that fails, then sends a
  // SIGTERM to the hypervisor.  Finally, if nothing works forcibly stops the VM
  // by sending it a SIGKILL.  Returns true if the VM was shut down and false
  // otherwise.
  bool Shutdown() override;
  VmBaseImpl::Info GetInfo() override;
  bool AttachUsbDevice(uint8_t bus,
                       uint8_t addr,
                       uint16_t vid,
                       uint16_t pid,
                       int fd,
                       uint8_t* out_port) override;
  bool DetachUsbDevice(uint8_t port) override;
  bool ListUsbDevice(std::vector<UsbDeviceEntry>* devices) override;
  bool GetVmEnterpriseReportingInfo(
      GetVmEnterpriseReportingInfoResponse* response) override;
  vm_tools::concierge::DiskImageStatus ResizeDisk(
      uint64_t new_size, std::string* failure_reason) override;
  vm_tools::concierge::DiskImageStatus GetDiskResizeStatus(
      std::string* failure_reason) override;
  uint64_t GetMinDiskSize() override;
  uint64_t GetAvailableDiskSpace() override;

  void SetTremplinStarted() override { is_tremplin_started_ = true; }
  void VmToolsStateChanged(bool running) override { NOTREACHED(); }

  // Adjusts the amount of CPU the Termina VM processes are allowed to use.
  static bool SetVmCpuRestriction(CpuRestrictionState cpu_restriction_state);

  // Sends a stateful update to be handled by the VM. Generally this means
  // adjusting the size of a storage balloon and/or tweaking disk settings (i.e
  // proc/sys/vm/dirty_ratio).
  void HandleStatefulUpdate(
      const spaced::StatefulDiskSpaceUpdate update) override;

  static std::unique_ptr<TerminaVm> CreateForTesting(
      std::unique_ptr<patchpanel::Subnet> subnet,
      uint32_t vsock_cid,
      base::FilePath runtime_dir,
      base::FilePath log_path,
      std::string stateful_device,
      uint64_t stateful_size,
      std::string kernel_version,
      std::unique_ptr<vm_tools::Maitred::Stub> stub,
      VmBuilder vm_builder);

 private:
  explicit TerminaVm(Config config);

  TerminaVm(const TerminaVm&) = delete;
  TerminaVm& operator=(const TerminaVm&) = delete;

  void HandleSuspendImminent() override;
  void HandleSuspendDone() override;

  // Returns the string value of the 'serial' arg passed to crosvm.
  // If |log_path_| is empty, syslog will be used.
  // |hardware| should be one of "serial" or "virtio-console".
  // |console_type| should be either "console" or "earlycon".
  std::string GetCrosVmSerial(std::string hardware,
                              std::string console_type) const;

  // Starts the VM with the given kernel and root file system.
  bool Start(VmBuilder vm_builder);

  // Helper version to record the VM kernel version at startup.
  void RecordKernelVersionForEnterpriseReporting();

  bool ResizeDiskImage(uint64_t new_size);
  bool ResizeFilesystem(uint64_t new_size);

  // Sends a gRPC message to the VM to shutdown.
  grpc::Status SendVMShutdownMessage();

  void set_kernel_version_for_testing(std::string kernel_version);
  void set_stub_for_testing(std::unique_ptr<vm_tools::Maitred::Stub> stub);

  // The /30 subnet assigned to the VM.
  std::unique_ptr<patchpanel::Subnet> subnet_;

  // An optional /28 container subnet.
  std::unique_ptr<patchpanel::Subnet> container_subnet_;

  // Termina virtual network device created by patchpanel.
  patchpanel::Client::VirtualDevice network_device_;

  // Flags passed to vmc start.
  VmFeatures features_;

  // Token assigned to the VM by the permission service.
  std::string permission_token_;

  // Stub for making RPC requests to the maitre'd process inside the VM.
  std::unique_ptr<vm_tools::Maitred::Stub> stub_;

  // Whether a TremplinStartedSignal has been received for the VM.
  bool is_tremplin_started_ = false;

  // Kernel version retrieved at startup.
  std::string kernel_version_;

  // Stateful device name.
  std::string stateful_device_;

  // Current size of the stateful disk.
  uint64_t stateful_size_;

  // Target size of the stateful disk during a resize (when
  // stateful_resize_type_ is not NONE).
  uint64_t stateful_target_size_;

  // Type of disk resize currently in progress.
  // If this is NONE, then no resize is in progress right now.
  enum DiskResizeType stateful_resize_type_;

  // Status of the current resize operation (or most recent resize operation,
  // if no resize is currently in progress).
  vm_tools::concierge::DiskImageStatus last_stateful_resize_status_ =
      DiskImageStatus::DISK_STATUS_RESIZED;

  base::FilePath log_path_;

  // This VM ID. It is used to communicate with the dispatcher to request
  // VM state changes.
  const VmId id_;

  // Connection to the system bus.
  scoped_refptr<dbus::Bus> bus_;

  // Proxy to the dispatcher service.  Not owned.
  dbus::ObjectProxy* vm_permission_service_proxy_;

  // Record's this VM's "type" in the classification sense (e.g. termina,
  // borealis, other...).
  const VmId::Type classification_;

  // Handle to the wayland socket used by this VM. This object cleans up the
  // server/socket in its destructor.
  //
  // TODO(b/237960042): this should be in vm_base once all VMs use it.
  std::unique_ptr<ScopedWlSocket> socket_;
};

}  // namespace concierge
}  // namespace vm_tools

#endif  // VM_TOOLS_CONCIERGE_TERMINA_VM_H_
