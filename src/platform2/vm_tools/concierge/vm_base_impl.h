// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef VM_TOOLS_CONCIERGE_VM_BASE_IMPL_H_
#define VM_TOOLS_CONCIERGE_VM_BASE_IMPL_H_
#include <stdint.h>
#include <unistd.h>

#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <base/files/scoped_temp_dir.h>
#include <base/strings/string_split.h>
#include <brillo/process/process.h>
#include <chromeos/patchpanel/dbus/client.h>
#include <spaced/proto_bindings/spaced.pb.h>
#include <vm_concierge/concierge_service.pb.h>

#include "vm_tools/common/vm_id.h"
#include "vm_tools/concierge/balloon_policy.h"
#include "vm_tools/concierge/seneschal_server_proxy.h"

namespace patchpanel {
class Client;
}

namespace vm_tools {
namespace concierge {

// See VmBaseImpl.Info.vm_memory_id
typedef uint32_t VmMemoryId;

// A base class implementing common features that are shared with ArcVm,
// PluginVm and TerminaVm
class VmBaseImpl {
 public:
  struct Config {
    std::unique_ptr<patchpanel::Client> network_client;
    uint32_t vsock_cid{0};
    std::unique_ptr<SeneschalServerProxy> seneschal_server_proxy;
    std::string cros_vm_socket{};
    base::FilePath runtime_dir;
  };
  explicit VmBaseImpl(Config config);

  VmBaseImpl(const VmBaseImpl&) = delete;
  VmBaseImpl& operator=(const VmBaseImpl&) = delete;
  virtual ~VmBaseImpl() = default;

  // The pid of the child process.
  pid_t pid() { return process_.pid(); }

  // The current status of the VM.
  enum class Status {
    STARTING,
    RUNNING,
    STOPPED,
  };

  // Information about a virtual machine.
  struct Info {
    // The IPv4 address in network-byte order.
    uint32_t ipv4_address;

    // The pid of the main crosvm process for the VM.
    pid_t pid;

    // The vsock context id for the VM, if one exists.  Must be set to 0 if
    // there is no vsock context id.
    uint32_t cid;

    // ID for identifying a VM in the context of managing memory. This field is
    // valid for all VMs. On non-manaTEE systems, this is set by concierge. On
    // manaTEE, it is specified by the manatee memory service, and it specifies
    // the balloon control socket that this VM's crosvm instance should connect
    // to - /run/mms_control_%d.sock.
    VmMemoryId vm_memory_id;

    // The handle for the 9P server managed by seneschal on behalf of this VM
    // if one exists, 0 otherwise.
    uint32_t seneschal_server_handle;

    // Token assigned to the VM when registering with permission service.
    // Used to identify the VM to service providers and fetching set of
    // permissions granted to the VM.
    std::string permission_token;

    // The current status of the VM.
    Status status;

    // Type of the VM.
    VmId::Type type;

    // Whether the VM is using storage ballooning.
    bool storage_ballooning;
  };

  using SwapVmCallback = base::OnceCallback<void(SwapVmResponse response)>;
  using AggressiveBalloonCallback =
      base::OnceCallback<void(AggressiveBalloonResponse response)>;

  // Suspends the VM.
  void Suspend() {
    HandleSuspendImminent();
    suspended_ = true;
  }

  // Resumes the VM.
  void Resume() {
    HandleSuspendDone();
    suspended_ = false;
  }

  bool IsSuspended() { return suspended_; }

  // Shuts down the VM. Returns true if the VM was successfully shut down and
  // false otherwise.
  virtual bool Shutdown() = 0;

  // Information about the VM.
  virtual Info GetInfo() = 0;

  // Returns balloon stats info retrieved from virtio-balloon device.
  virtual std::optional<BalloonStats> GetBalloonStats();

  // Resize the balloon size.
  virtual bool SetBalloonSize(int64_t byte_size);

  // Get the virtio_balloon sizing policy for this VM.
  virtual const std::unique_ptr<BalloonPolicyInterface>& GetBalloonPolicy(
      const MemoryMargins& margins, const std::string& vm);

  // Attach an usb device at host bus:addr, with vid, pid and an opened fd.
  virtual bool AttachUsbDevice(uint8_t bus,
                               uint8_t addr,
                               uint16_t vid,
                               uint16_t pid,
                               int fd,
                               uint8_t* out_port);

  // Detach the usb device at guest port.
  virtual bool DetachUsbDevice(uint8_t port);

  // List all usb devices attached to guest.
  virtual bool ListUsbDevice(std::vector<UsbDeviceEntry>* devices);

  // Returns true if this VM depends on external signals for suspend and resume.
  // The D-Bus suspend/resume messages from powerd, SuspendImminent and
  // SuspendDone will not be propagated to this VM. Otherwise,
  // HandleSuspendImminent and HandleSuspendDone will be invoked when these
  // messages received.
  virtual bool UsesExternalSuspendSignals() { return false; }

  // Update resolv.conf data.
  virtual bool SetResolvConfig(
      const std::vector<std::string>& nameservers,
      const std::vector<std::string>& search_domains) = 0;

  // Perform necessary cleanup when host network changes.
  virtual void HostNetworkChanged() {}

  // Set the guest time to the current time as given by gettimeofday.
  virtual bool SetTime(std::string* failure_reason) = 0;

  // Set the guest timezone
  virtual bool SetTimezone(const std::string& timezone,
                           std::string* out_error) = 0;

  // Get enterprise reporting information. Also sets the
  // response fields for success and failure_reason.
  virtual bool GetVmEnterpriseReportingInfo(
      GetVmEnterpriseReportingInfoResponse* response) = 0;

  // Notes that TremplinStartedSignal has been received for the VM.
  virtual void SetTremplinStarted() = 0;

  // Notes that guest agent is running in the VM.
  virtual void VmToolsStateChanged(bool running) = 0;

  // Initiate a disk resize operation for the VM.
  // |new_size| is the requested size in bytes.
  virtual vm_tools::concierge::DiskImageStatus ResizeDisk(
      uint64_t new_size, std::string* failure_reason) = 0;

  // Get the status of the most recent ResizeDisk operation.
  virtual vm_tools::concierge::DiskImageStatus GetDiskResizeStatus(
      std::string* failure_reason) = 0;

  // Get the smallest valid resize parameter for this disk,
  // or 0 for unknown.
  virtual uint64_t GetMinDiskSize() { return 0; }

  // Get the space that is available/unallocated on the disk,
  // or 0 for unknown.
  virtual uint64_t GetAvailableDiskSpace() { return 0; }

  // Makes RT vCPU for the VM.
  virtual void MakeRtVcpu();

  virtual void HandleSwapVmRequest(const SwapVmRequest& request,
                                   SwapVmCallback callback);

  // Inflate balloon until perceptible processes are tried to kill.
  virtual void InflateAggressiveBalloon(AggressiveBalloonCallback callback);

  // Stop inflating aggressive balloon.
  virtual void StopAggressiveBalloon(AggressiveBalloonResponse& response);

  // Handle the low disk notification from spaced.
  virtual void HandleStatefulUpdate(
      const spaced::StatefulDiskSpaceUpdate update) = 0;

  std::string GetVmSocketPath() const;

 protected:
  // Adjusts the amount of CPU the VM processes are allowed to use.
  static bool SetVmCpuRestriction(CpuRestrictionState cpu_restriction_state,
                                  const char* cpu_cgroup);

  static void RunFailureAggressiveBalloonCallback(
      AggressiveBalloonCallback callback, std::string failure_reason);

  // Starts |process_| with |args|. Returns true iff started successfully.
  bool StartProcess(base::StringPairs args);

  // Stops this VM
  // Returns true on success, false otherwise
  bool Stop() const;

  // Suspends this VM
  // Returns true on success, false otherwise
  bool SuspendCrosvm() const;

  // Resumes this VM
  // Returns true on success, false otherwise
  bool ResumeCrosvm() const;

  // The 9p server managed by seneschal that provides access to shared files for
  // this VM. Returns 0 if there is no seneschal server associated with this
  // VM.
  uint32_t seneschal_server_handle() const;

  // DBus client for the networking service.
  std::unique_ptr<patchpanel::Client> network_client_;

  // Runtime directory for this VM.
  // TODO(abhishekbh): Try to move this to private.
  base::ScopedTempDir runtime_dir_;

  // Handle to the VM process.
  brillo::ProcessImpl process_;

  // Proxy to the server providing shared directory access for this VM.
  std::unique_ptr<SeneschalServerProxy> seneschal_server_proxy_;

  // Virtual socket context id to be used when communicating with this VM.
  uint32_t vsock_cid_ = 0;

  // Balloon policy with its state.
  std::unique_ptr<BalloonPolicyInterface> balloon_policy_;

 private:
  // Handle the device going to suspend.
  virtual void HandleSuspendImminent() = 0;

  // Handle the device resuming from a suspend.
  virtual void HandleSuspendDone() = 0;

  // Whether the VM is currently suspended.
  bool suspended_ = false;

  // Name of the socket to communicate to the crosvm binary.
  const std::string cros_vm_socket_;
};

}  // namespace concierge
}  // namespace vm_tools

#endif  // VM_TOOLS_CONCIERGE_VM_BASE_IMPL_H_
