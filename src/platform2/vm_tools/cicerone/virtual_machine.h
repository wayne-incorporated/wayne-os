// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef VM_TOOLS_CICERONE_VIRTUAL_MACHINE_H_
#define VM_TOOLS_CICERONE_VIRTUAL_MACHINE_H_

#include <stdint.h>

#include <map>
#include <memory>
#include <string>
#include <vector>

#include <vm_applications/apps.pb.h>
#include <vm_cicerone/cicerone_service.pb.h>
#include <vm_protos/proto_bindings/container_guest.grpc.pb.h>
#include <vm_protos/proto_bindings/tremplin.grpc.pb.h>

#include "vm_tools/cicerone/container.h"

namespace vm_tools {
namespace cicerone {

class OsRelease;

// Represents a single instance of a virtual machine.
class VirtualMachine {
 public:
  // Convenience for the enumeration over vm types defined in vm_applications.
  using VmType = vm_tools::apps::VmType;

  enum class CreateLxdContainerStatus {
    UNKNOWN,
    CREATING,
    EXISTS,
    FAILED,
  };

  enum class DeleteLxdContainerStatus {
    UNKNOWN,
    DELETING,
    DOES_NOT_EXIST,
    FAILED,
  };

  enum class StartLxdContainerStatus {
    UNKNOWN,
    STARTING,
    STARTED,
    REMAPPING,
    RUNNING,
    FAILED,
  };

  enum class StopLxdContainerStatus {
    UNKNOWN,
    STOPPING,
    STOPPED,
    DOES_NOT_EXIST,
    FAILED,
  };

  enum class GetLxdContainerUsernameStatus {
    UNKNOWN,
    SUCCESS,
    CONTAINER_NOT_FOUND,
    CONTAINER_NOT_RUNNING,
    USER_NOT_FOUND,
    FAILED,
  };

  enum class SetUpLxdContainerUserStatus {
    UNKNOWN,
    SUCCESS,
    EXISTS,
    FAILED,
  };

  enum class GetLxdContainerInfoStatus {
    UNKNOWN,
    RUNNING,
    STOPPED,
    NOT_FOUND,
    FAILED,
  };

  enum class ExportLxdContainerStatus {
    UNKNOWN,
    EXPORTING,
    FAILED,
  };

  enum class CancelExportLxdContainerStatus {
    UNKNOWN,
    CANCEL_QUEUED,
    OPERATION_NOT_FOUND,
    FAILED,
  };

  enum class ImportLxdContainerStatus {
    UNKNOWN,
    IMPORTING,
    FAILED,
  };

  enum class CancelImportLxdContainerStatus {
    UNKNOWN,
    CANCEL_QUEUED,
    OPERATION_NOT_FOUND,
    FAILED,
  };

  enum class UpgradeContainerStatus {
    UNKNOWN,
    STARTED,
    ALREADY_RUNNING,
    NOT_SUPPORTED,
    ALREADY_UPGRADED,
    FAILED,
  };

  enum class CancelUpgradeContainerStatus {
    UNKNOWN,
    NOT_RUNNING,
    CANCELLED,
    FAILED,
  };

  enum class StartLxdStatus {
    UNKNOWN,
    STARTING,
    ALREADY_RUNNING,
    FAILED,
  };

  enum class AttachUsbToContainerStatus {
    UNKNOWN,
    OK,
    NO_SUCH_CONTAINER,
    FAILED,
  };

  enum class DetachUsbFromContainerStatus {
    UNKNOWN,
    OK,
    FAILED,
  };

  enum class UpdateContainerDevicesStatus {
    UNKNOWN,
    OK,
    NO_SUCH_CONTAINER,
    FAILED,
  };

  // Info about the LXD container.
  struct LxdContainerInfo {
    // The IPv4 address of the container in network byte order.
    // This field is only valid if the container status is RUNNING.
    uint32_t ipv4_address;
  };

  // Results of a set timezone request
  struct SetTimezoneResults {
    int successes;
    std::vector<std::string> failure_reasons;
  };

  // |cid| is nonzero for termina VMs, |vm_token| is non-empty for plugin VMs.
  VirtualMachine(uint32_t cid, pid_t pid, std::string vm_token);
  VirtualMachine(const VirtualMachine&) = delete;
  VirtualMachine& operator=(const VirtualMachine&) = delete;

  ~VirtualMachine();

  bool is_stopping() const { return is_stopping_; }
  void notify_shutdown() { is_stopping_ = true; }

  // The VM's cid.
  uint32_t cid() const { return vsock_cid_; }

  pid_t pid() const { return pid_; }

  // The VM's token.
  std::string vm_token() const { return vm_token_; }

  // The type of VM this is (termina, pluginvm, ...).
  VmType GetType() const;

  // Returns true if this VM does not run containers.
  bool IsContainerless() const;

  // Call during unit tests to force this class to use |mock_tremplin_stub|
  // instead of creating a real tremplin stub by connecting to the GPRC
  // service. Must be called before ConnectTremplin().
  void SetTremplinStubForTesting(
      std::unique_ptr<vm_tools::tremplin::Tremplin::StubInterface>
          mock_tremplin_stub);

  // Connect to the tremplin instance in the VM.
  bool ConnectTremplin();

  // Tries to set the default timezone for all containers in |container_names|
  // to |timezone_name|. If that fails, falls back to setting the TZ environment
  // variable to |posix_tz_string|.
  //
  // If setting the timezone fails entirely due to high-level issues
  // (e.g. tremplin not connected, rpc failed), this will return false and set
  // |out_error|.
  //
  // Otherwise, the results from individual containers will be stored in
  // |out_results|.
  bool SetTimezone(const std::string& timezone_name,
                   const std::string& posix_tz_string,
                   const std::vector<std::string>& container_names,
                   SetTimezoneResults* out_results,
                   std::string* out_error);

  // Registers a container with the VM using the |container_ip| address,
  // |vsock_garcon_port|, and |container_token|. Returns true if the token is
  // valid, false otherwise.
  bool RegisterContainer(const std::string& container_token,
                         const uint32_t vsock_garcon_port,
                         const std::string& container_ip);

  // Unregister a container with |container_token| within this VM. Returns true
  // if the token is valid, false otherwise.
  bool UnregisterContainer(const std::string& container_token);

  // Generates a random token string that should be passed into the container
  // which can then be used by the container to identify itself when it
  // communicates back with us.
  std::string GenerateContainerToken(const std::string& container_name);

  // For testing only. Add a container with the indicated security token. This
  // is the only way to get a consistent security token for unit tests & fuzz
  // tests.
  void CreateContainerWithTokenForTesting(const std::string& container_name,
                                          const std::string& container_token);

  // Returns the name of the container associated with the passed in
  // |container_token|. Returns the empty string if no such mapping exists. This
  // will only return a name that has been confirmed after calling
  // RegisterContainer.
  std::string GetContainerNameForToken(const std::string& container_token);

  // Returns a pointer to the container associated with the passed in
  // |container_token|. Returns nullptr if the container does not exist.
  // This function will only return a container that has been confirmed after
  // calling RegisterContainer.
  //
  // The pointer returned is owned by VirtualMachine and may not be stored.
  Container* GetContainerForToken(const std::string& container_token);

  // Returns a pointer to the pending container associated with the passed in
  // |container_token|. Returns nullptr if the container does not exist.
  // This function will only return a container that has NOT been confirmed by
  // calling RegisterContainer.
  //
  // The pointer returned is owned by VirtualMachine and may not be stored.
  Container* GetPendingContainerForToken(const std::string& container_token);

  // Returns a pointer to the container associated with the passed in
  // |container_name|. Returns nullptr if the container does not exist.
  // This function will only return a name that has been confirmed after calling
  // RegisterContainer.
  //
  // The pointer returned is owned by VirtualMachine and may not be stored.
  Container* GetContainerForName(const std::string& container_name);

  // Returns a pointer to the OsRelease proto associated with the passed in
  // |container_name|. Returns nullptr if the container does not exist..
  //
  // The pointer returned is owned by VirtualMachine and may not be stored.
  const OsRelease* GetOsReleaseForContainer(
      const std::string& container_name) const;

  void SetOsReleaseForTesting(const std::string& container_name,
                              const OsRelease& os_release);

  // Creates an LXD container.
  CreateLxdContainerStatus CreateLxdContainer(const std::string& container_name,
                                              const std::string& image_server,
                                              const std::string& image_alias,
                                              const std::string& rootfs_path,
                                              const std::string& metadata_path,
                                              std::string* out_error);

  // Deletes an LXD container.
  DeleteLxdContainerStatus DeleteLxdContainer(const std::string& container_name,
                                              std::string* out_error);

  // Starts an LXD container.
  StartLxdContainerStatus StartLxdContainer(
      const std::string& container_name,
      const std::string& token,
      tremplin::StartContainerRequest::PrivilegeLevel privilege_level,
      bool disable_audio_capture,
      std::string* out_error);

  // Stop an LXD container.
  StopLxdContainerStatus StopLxdContainer(const std::string& container_name,
                                          std::string* out_error);

  // Gets the primary user of an LXD container.
  GetLxdContainerUsernameStatus GetLxdContainerUsername(
      const std::string& container_name,
      std::string* username,
      std::string* homedir,
      std::string* out_error);

  // Sets up an LXD container.
  SetUpLxdContainerUserStatus SetUpLxdContainerUser(
      const std::string& container_name,
      const std::string& container_username,
      std::string* out_username,
      std::string* out_error);

  // Gets info about an LXD container.
  GetLxdContainerInfoStatus GetLxdContainerInfo(
      const std::string& container_name,
      LxdContainerInfo* out_info,
      std::string* out_error);

  // Exports an LXD container.
  ExportLxdContainerStatus ExportLxdContainer(const std::string& container_name,
                                              const std::string& export_path,
                                              std::string* out_error);

  CancelExportLxdContainerStatus CancelExportLxdContainer(
      const std::string& in_progress_container_name, std::string* out_error);

  // Imports an LXD container. |available_disk_space| of zero means unlimited
  ImportLxdContainerStatus ImportLxdContainer(const std::string& container_name,
                                              const std::string& import_path,
                                              uint64_t available_disk_space,
                                              std::string* out_error);

  CancelImportLxdContainerStatus CancelImportLxdContainer(
      const std::string& in_progress_container_name, std::string* out_error);

  // Begins a container OS upgrade (e.g. from debian/stretch to debian/buster).
  UpgradeContainerStatus UpgradeContainer(
      const Container* container,
      const UpgradeContainerRequest::Version& target_version,
      std::string* out_error);

  // Cancels a running container OS upgrade.
  CancelUpgradeContainerStatus CancelUpgradeContainer(Container* container,
                                                      std::string* out_error);

  // Attaches a USB device on a given port to a container.
  AttachUsbToContainerStatus AttachUsbToContainer(const Container* container,
                                                  uint32_t port_num,
                                                  std::string* out_error);

  // Detaches a USB device on a given port from a container.
  DetachUsbFromContainerStatus DetachUsbFromContainer(uint32_t port_num,
                                                      std::string* out_error);

  UpdateContainerDevicesStatus UpdateContainerDevices(
      Container* container,
      const google::protobuf::Map<std::string, VmDeviceAction>& updates,
      google::protobuf::Map<std::string,
                            UpdateContainerDevicesResponse::UpdateResult>*
          results,
      std::string* out_error);

  // Tells Tremplin to start LXD.
  StartLxdStatus StartLxd(bool reset_lxd_db, std::string* out_error);

  // Informs the VM that the host network has changed.
  void HostNetworkChanged();

  // Gets a list of all the active container names in this VM.
  std::vector<std::string> GetContainerNames();

  // Gets a reference to the mapping of tokens to active containers in this VM.
  const std::map<std::string, std::unique_ptr<Container>>& GetContainers();

  bool GetTremplinDebugInfo(std::string* out);

 private:
  // Virtual socket context id to be used when communicating with this VM, only
  // valid for termina VMs.
  uint32_t vsock_cid_;

  // The pid of the main VM process.
  pid_t pid_;

  // Token for identifying this VM. Required for VMs which will have a zero
  // value cid (e.g. PluginVM).
  std::string vm_token_;

  // The type of vm this is.
  VmType vm_type_;

  // Mapping of tokens to containers. The tokens are used to securely
  // identify a container when it connects back to concierge to identify itself.
  std::map<std::string, std::unique_ptr<Container>> containers_;

  // Pending map of tokens to containers. The tokens are put in here when
  // they are generated and removed once we have a connection from the
  // container. We do not immediately put them in the containers map because we
  // may get redundant requests to start a container that is already running
  // and we don't want to invalidate an in-use token.
  std::map<std::string, std::unique_ptr<Container>> pending_containers_;

  // Mapping of container name to OsRelease proto as reported by tremplin.
  // This data can change during a session if a user upgrades their container.
  std::map<std::string, OsRelease> container_os_releases_;

  // The stub for the tremplin instance in this VM.
  std::unique_ptr<vm_tools::tremplin::Tremplin::StubInterface> tremplin_stub_;

  // Set if |tremplin_stub_| is actually a mock object set for testing. In this
  // case, we don't try to connect to tremplin even if ConnectTremplin is called
  // for some reason.
  bool using_mock_tremplin_stub_;

  // True if the VM is expected to shutdown soon.
  bool is_stopping_ = false;

  base::WeakPtrFactory<VirtualMachine> weak_ptr_factory_;
};

}  // namespace cicerone
}  // namespace vm_tools

#endif  // VM_TOOLS_CICERONE_VIRTUAL_MACHINE_H_
