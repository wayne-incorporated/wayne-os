// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef VM_TOOLS_GARCON_HOST_NOTIFIER_H_
#define VM_TOOLS_GARCON_HOST_NOTIFIER_H_

#include <cstdint>
#include <memory>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <base/files/file_descriptor_watcher_posix.h>
#include <base/files/file_path_watcher.h>
#include <base/files/scoped_file.h>
#include <base/timer/timer.h>
#include <base/synchronization/waitable_event.h>
#include <grpcpp/grpcpp.h>
#include <vm_protos/proto_bindings/container_host.grpc.pb.h>
#include <base/memory/weak_ptr.h>

#include "vm_tools/garcon/ansible_playbook_application.h"
#include "vm_tools/garcon/package_kit_proxy.h"

namespace vm_tools {
namespace garcon {

// Handles making calls to cicerone running in the host.
class HostNotifier : public PackageKitProxy::PackageKitObserver,
                     public AnsiblePlaybookApplication::Observer {
 public:
  // Creates and inits the HostNotifier for running on the current sequence.
  // Returns null if there was any failure.
  static std::unique_ptr<HostNotifier> Create(const std::string& token);

  // Sends a gRPC call to the host to notify it to open the specified URL with
  // the web browser. Returns true on success, false otherwise.
  bool OpenUrlInHost(const std::string& url);

  // Sends a gRPC call to the host to notify it to open a terminal window that
  // is connected to this container. |args| will be executed as a program in
  // the terminal if any are passed.
  bool OpenTerminal(std::vector<std::string> args);

  // Sends a gRPC call to the host to request a SelectFile dialog be shown.
  bool SelectFile(const std::string& type,
                  const std::string& title,
                  const std::string& default_path,
                  const std::string& allowed_extensions,
                  std::vector<std::string>* files);

  // Sends a gRPC call to the host to request information about what space is
  // available on the VM disk and how much it could be expanded by.
  bool GetDiskInfo(vm_tools::container::GetDiskInfoResponse* response);

  // Sends a gRPC call to the host to request that the disk be expanded by
  // |space_requested| bytes. Will return the number of bytes that the disk was
  // expanded by or an error.
  bool RequestSpace(uint64_t space_requested,
                    vm_tools::container::RequestSpaceResponse* response);

  // Sends a gRPC call to the host to notify it that it can shrink the disk by
  // |space_to_release| bytes. Will return the number of bytes the disk was
  // shrunk by or an error.
  bool ReleaseSpace(uint64_t space_to_release,
                    vm_tools::container::ReleaseSpaceResponse* response);

  // Sends a gRPC call to the host to report metrics.
  bool ReportMetrics(vm_tools::container::ReportMetricsRequest request,
                     vm_tools::container::ReportMetricsResponse* response);

  // Install Shader Cache DLC and optionally mount it
  bool InstallShaderCache(uint64_t steam_app_id, bool mount, bool wait);

  // Unmount and uninstall shader cache DLC
  bool UninstallShaderCache(uint64_t steam_app_id);

  // Unmount shader cache DLC
  bool UnmountShaderCache(uint64_t steam_app_id, bool wait);

  // Sends a gRPC call to the host to request that sleep be inhibited.
  bool InhibitScreensaver(vm_tools::container::InhibitScreensaverInfo info);

  // Sends a gRPC call to the host to request that sleep be uninhibited.
  bool UninhibitScreensaver(vm_tools::container::UninhibitScreensaverInfo info);

  ~HostNotifier() override;

  // Notifies the host that garcon is ready. This will send the initial update
  // for the application list and also establish a watcher for any updates to
  // the list of installed applications. Returns false if there was any failure.
  // Not required when used as a client.
  bool InitServer(base::OnceClosure shutdown_closure,
                  uint32_t garcon_port,
                  uint32_t sftp_port,
                  PackageKitProxy* package_kit_proxy);

  // vm_tools::garcon::PackageKitObserver overrides.
  void OnInstallCompletion(const std::string& command_uuid,
                           bool success,
                           const std::string& failure_reason) override;
  void OnInstallProgress(
      const std::string& command_uuid,
      vm_tools::container::InstallLinuxPackageProgressInfo::Status status,
      uint32_t percent_progress) override;
  void OnUninstallCompletion(bool success,
                             const std::string& failure_reason) override;
  void OnUninstallProgress(uint32_t percent_progress) override;

  // vm_tools::garcon::AnsiblePlaybookApplication::Observer overrides.
  void OnApplyAnsiblePlaybookCompletion(
      bool success, const std::string& failure_reason) override;
  void OnApplyAnsiblePlaybookProgress(
      const std::vector<std::string>& status_string) override;
  void CreateAnsiblePlaybookApplication(
      base::WaitableEvent* event,
      AnsiblePlaybookApplication** ansible_playbook_application_ptr);
  void RemoveAnsiblePlaybookApplication();

  // Watch files in the specified directory and notify if there are changes.
  // This is used by FilesApp. |path| is relative to $HOME.
  bool AddFileWatch(const base::FilePath& path, std::string* error_msg);
  // Stop watching files in |path| relative to $HOME.
  bool RemoveFileWatch(const base::FilePath& path, std::string* error_msg);

  uint32_t sftp_vsock_port() const { return sftp_vsock_port_; }

 private:
  // Callback structure for SendAppListToHost callback chain.
  struct AppListBuilderState {
    // The protobuffer we will return to the caller.
    vm_tools::container::UpdateApplicationListRequest request;

    // The actual paths to the .desktop files we used to get the applications
    // in |request|. This must correspond 1-to-1 with the entries in
    // |request.application| (same number, same order).
    std::vector<base::FilePath> desktop_files_for_application;

    // Number of .desktop files we have already queried for their package_id.
    // Thus, also the index of the next .desktop file we need to query for
    // its package_id.
    int num_package_id_queries_completed = 0;
  };

  explicit HostNotifier(const std::string& token);
  HostNotifier(const HostNotifier&) = delete;
  HostNotifier& operator=(const HostNotifier&) = delete;

  // Sends a message to the host indicating that our server is ready for
  // accepting incoming calls.
  bool NotifyHostGarconIsReady(uint32_t garcon_port, uint32_t sftp_port);

  // Sends a message to the host indicating the container is shutting down.
  void NotifyHostOfContainerShutdown();

  // Sends a message to the host indicating the number of triggered, but not yet
  // sent, app list updates.
  void NotifyHostOfPendingAppListUpdates();

  // Sends a list of the installed applications to the host.
  void SendAppListToHost();

  // Sends a list of the system configured MIME types to the host.
  void SendMimeTypesToHost();

  // Callback for PackageKitProxy::SearchLinuxPackagesForFile. Called each time
  // PackageKitProxy gets the package_id info for another .desktop file.
  void PackageIdCallback(std::unique_ptr<AppListBuilderState> state,
                         bool success,
                         bool pkg_found,
                         const PackageKitProxy::LinuxPackageInfo& pkg_info,
                         const std::string& error);

  // Callback for when desktop file path changes occur.
  void DesktopPathsChanged(const base::FilePath& path, bool error);

  // Callback for when changes to /etc/ or $HOME occur which hold the MIME types
  // files.
  void MimeTypesChanged(const base::FilePath& path, bool error);

  // Notifies host that a file has changed in a watched directory.
  void SendFileWatchTriggeredToHost(const base::FilePath& path);

  // Called when a file changes in a watched directory from AddFileWatch().
  // |absolute_path| must be converted to a path relative to $HOME.
  void FileWatchTriggered(const base::FilePath& absolute_path, bool error);

  // Creates a ContainerListener::Stub using vsock.
  void SetUpContainerListenerStub();

  // Kicks off the next step in the process of getting package_id data while
  // building an UpdateApplicationListRequest. It either kicks off another
  // request to PackageKit, or it finishes the request and sends it to the host.
  void RequestNextPackageIdOrCompleteUpdateApplicationList(
      std::unique_ptr<AppListBuilderState> state);

  // Called when signal_fd_ becomes readable.
  void OnSignalReadable();

  // Checks the amount of free disk space and sends a notification if free
  // space is low.
  void CheckDiskSpace();

  // gRPC stub for communicating with cicerone on the host.
  std::unique_ptr<vm_tools::container::ContainerListener::Stub> stub_;

  // Security token for communicating with cicerone.
  std::string token_;

  // Watchers for tracking filesystem changes to .desktop files/dirs,
  // /etc/mime.types and $HOME/.mime.types files.
  std::vector<std::unique_ptr<base::FilePathWatcher>> watchers_;

  // True if there is currently a delayed task pending for updating the
  // application list.
  bool update_app_list_posted_;

  // True if SendAppListToHost has started a callback chain which hasn't
  // completed yet.
  bool send_app_list_to_host_in_progress_;

  // True if there is currently a delayed task pending for updating the
  // MIME types list.
  bool update_mime_types_posted_;

  // Watchers for tracking paths requested via AddFilePathWatcher.  This is used
  // by FilesApp.
  std::unordered_map<base::FilePath, std::unique_ptr<base::FilePathWatcher>>
      file_path_watchers_;

  // Timestamps of when last change was notified.
  std::unordered_map<base::FilePath, base::TimeTicks> file_watch_last_change_;

  // Contains directories for which there is a delayed task pending to notify
  // that a file has changed.
  std::unordered_set<base::FilePath> file_watch_change_posted_;

  // Closure for stopping the MessageLoop.  Posted to the thread's TaskRunner
  // when this program receives a SIGTERM.
  base::OnceClosure shutdown_closure_;

  // File descriptor for receiving signals.
  base::ScopedFD signal_fd_;
  std::unique_ptr<base::FileDescriptorWatcher::Controller> signal_controller_;

  // Pointer to the PackageKit needed for querying package_id data.
  PackageKitProxy* package_kit_proxy_;  // Not owned.

  // HostNotifier manages AnsiblePlaybookApplication life cycle.
  std::unique_ptr<AnsiblePlaybookApplication> ansible_playbook_application_;

  scoped_refptr<base::SingleThreadTaskRunner> task_runner_;

  base::RepeatingTimer free_disk_space_timer_;

  uint32_t sftp_vsock_port_ = 0;

  void HandleSteamApp(std::unordered_set<uint64_t> found_steam_apps);
  std::unordered_set<uint64_t> installed_steam_apps_;

  base::WeakPtrFactory<HostNotifier> weak_ptr_factory_{this};
};

}  // namespace garcon
}  // namespace vm_tools

#endif  // VM_TOOLS_GARCON_HOST_NOTIFIER_H_
