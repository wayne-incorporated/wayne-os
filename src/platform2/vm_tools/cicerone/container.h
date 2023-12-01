// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef VM_TOOLS_CICERONE_CONTAINER_H_
#define VM_TOOLS_CICERONE_CONTAINER_H_

#include <stdint.h>

#include <map>
#include <memory>
#include <string>
#include <vector>

#include <base/memory/weak_ptr.h>
#include <vm_protos/proto_bindings/container_guest.grpc.pb.h>

namespace vm_tools {
namespace cicerone {

class VirtualMachine;

// Represents a single container running in a VM.
class Container {
 public:
  // Linux application ID and its icon content.
  struct Icon {
    std::string desktop_file_id;
    std::string content;
    vm_tools::container::DesktopIcon::Format format;
  };
  // Information about a Linux package file.
  struct LinuxPackageInfo {
    std::string package_id;
    std::string license;
    std::string description;
    std::string project_url;
    uint64_t size;
    std::string summary;
  };

  // The container's name.
  std::string name() const { return name_; }

  // The container's security token.
  std::string token() const { return token_; }

  // The container's IPv4 address.
  uint32_t ipv4_address() const { return ipv4_address_; }

  // Sets the container's IPv4 address.
  void set_ipv4_address(uint32_t ipv4_address);

  // The container's DriveFS mount path.
  std::string drivefs_mount_path() const { return drivefs_mount_path_; }

  // Sets the container's DriveFS mount path.
  void set_drivefs_mount_path(std::string drivefs_mount_path);

  // The container's homedir.
  std::string homedir() const { return homedir_; }

  // Sets the container's uid=1000 primary user's homedir.
  void set_homedir(const std::string& homedir);

  // Gets the listening TCP4 ports for the container.
  const std::vector<uint16_t>& listening_tcp4_ports() const {
    return listening_tcp4_ports_;
  }

  // Sets the listening TCP4 ports for the container.
  void set_listening_tcp4_ports(std::vector<uint16_t> ports);

  Container(const std::string& name,
            const std::string& token,
            base::WeakPtr<VirtualMachine> vm);
  Container(const Container&) = delete;
  Container& operator=(const Container&) = delete;

  ~Container() = default;

  void ConnectToGarcon(const std::string& addr);

  bool LaunchContainerApplication(
      const std::string& desktop_file_id,
      std::vector<std::string> files,
      vm_tools::container::LaunchApplicationRequest::DisplayScaling
          display_scaling,
      std::vector<vm_tools::container::ContainerFeature> container_features,
      std::string* out_error);

  bool LaunchVshd(
      uint32_t port,
      std::vector<vm_tools::container::ContainerFeature> container_features,
      std::string* out_error);

  bool GetDebugInformation(std::string* out);

  bool GetContainerAppIcon(std::vector<std::string> desktop_file_ids,
                           uint32_t icon_size,
                           uint32_t scale,
                           std::vector<Icon>* icons);

  bool GetLinuxPackageInfo(const std::string& file_path,
                           const std::string& package_name,
                           LinuxPackageInfo* out_pkg_info,
                           std::string* out_error);

  vm_tools::container::InstallLinuxPackageResponse::Status InstallLinuxPackage(
      const std::string& file_path,
      const std::string& package_id,
      const std::string& command_uuid,
      std::string* out_error);

  vm_tools::container::UninstallPackageOwningFileResponse::Status
  UninstallPackageOwningFile(const std::string& desktop_file_id,
                             std::string* out_error);

  vm_tools::container::ApplyAnsiblePlaybookResponse::Status
  ApplyAnsiblePlaybook(const std::string& playbook, std::string* out_error);

  vm_tools::container::ConfigureForArcSideloadResponse::Status
  ConfigureForArcSideload(std::string* out_error);

  bool ConnectChunnel(uint32_t chunneld_port,
                      uint32_t tcp4_port,
                      std::string* out_error);

  bool AddFileWatch(const std::string& path, std::string* out_error);

  bool RemoveFileWatch(const std::string& path, std::string* out_error);

  void RegisterVshSession(int32_t host_vsh_pid, int32_t container_shell_pid);

  int32_t GetVshSession(int32_t host_vsh_pid);

  bool GetGarconSessionInfo(std::string* out_failure_reason,
                            std::string* out_container_username,
                            std::string* out_container_homedir,
                            uint32_t* out_sftp_vsock_port);

  static void DisableChannelWaitForTesting();

 private:
  std::string name_;
  std::string token_;
  uint32_t ipv4_address_;
  std::string drivefs_mount_path_;
  std::string homedir_;
  std::vector<uint16_t> listening_tcp4_ports_;
  std::map<int32_t, int32_t> vsh_pids_;

  // The VM that owns this container.
  base::WeakPtr<VirtualMachine> vm_;

  // Stub for making RPC requests to the garcon process inside the container.
  std::unique_ptr<vm_tools::container::Garcon::Stub> garcon_stub_;

  static bool wait_for_channel_;
};

}  // namespace cicerone
}  // namespace vm_tools

#endif  // VM_TOOLS_CICERONE_CONTAINER_H_
