// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef VM_TOOLS_GARCON_PACKAGE_KIT_PROXY_H_
#define VM_TOOLS_GARCON_PACKAGE_KIT_PROXY_H_

#include <memory>
#include <string>
#include <vector>

#include <base/files/file_path.h>
#include <base/functional/callback_forward.h>
#include <base/observer_list.h>
#include <base/observer_list_types.h>
#include <base/sequence_checker.h>
#include <base/synchronization/lock.h>
#include <base/task/single_thread_task_runner.h>
#include <dbus/bus.h>
#include <dbus/object_proxy.h>
#include <vm_protos/proto_bindings/container_guest.grpc.pb.h>
#include <vm_protos/proto_bindings/container_host.grpc.pb.h>

namespace vm_tools {
namespace garcon {

// Proxy for communicating with the PackageKit daemon over D-Bus. This is used
// for handling software installation/removal.
class PackageKitProxy {
 public:
  class PackageKitObserver : public base::CheckedObserver {
   public:
    virtual ~PackageKitObserver() {}
    virtual void OnInstallCompletion(const std::string& command_uuid,
                                     bool success,
                                     const std::string& failure_reason) = 0;
    virtual void OnInstallProgress(
        const std::string& command_uuid,
        vm_tools::container::InstallLinuxPackageProgressInfo::Status status,
        uint32_t percent_progress) = 0;
    virtual void OnUninstallProgress(uint32_t percent_progress) = 0;
    // TODO(iby): Special error code for dependent file case.
    virtual void OnUninstallCompletion(bool success,
                                       const std::string& failure_reason) = 0;
  };
  struct LinuxPackageInfo {
    std::string package_id;
    std::string license;
    std::string description;
    std::string project_url;
    uint64_t size;
    std::string summary;
  };

  typedef base::OnceCallback<void(bool success,
                                  bool pkg_found,
                                  const LinuxPackageInfo& pkg_info,
                                  const std::string& error)>
      PackageSearchCallback;

  // Creates an instance of PackageKitProxy that will use the calling thread for
  // its message loop for D-Bus communication. Returns nullptr if there was a
  // failure.
  static std::unique_ptr<PackageKitProxy> Create(PackageKitObserver* observer);

  ~PackageKitProxy();

  // Gets the information about a local Linux package file located at
  // |file_path| and populates |out_pkg_info| with the details on success.
  // Returns true on success, and false otherwise. On failure, |out_error| will
  // be populated with error details.
  bool GetLinuxPackageInfoFromFilePath(
      const base::FilePath& file_path,
      std::shared_ptr<LinuxPackageInfo> out_pkg_info,
      std::string* out_error);

  // Tries to resolve |package_name| into a package id which is then used to
  // get more information about the Linux Package and populates |out_pkg_info|
  // with the details on success. Returns true on success and false otherwise.
  // On failure, |out_error| will be populated with error details.
  bool GetLinuxPackageInfoFromPackageName(
      const std::string& package_name,
      std::shared_ptr<LinuxPackageInfo> out_pkg_info,
      std::string* out_error);

  // Gets information about the Linux package (if any) which owns the file
  // located at |file_path|. Once the transaction is complete, |callback| will
  // be called. If a package which owns the file is found, |success| and
  // |pkg_found| will be true and |pkg_info| will be filled in with some package
  // details. If there is no such package, |pkg_found| will be set
  // to false, |pkg_info| will be empty, but |success| will be true --
  // this is not an error. On error, |success| will be false and |error| will be
  // populated with the error details. Regardless, |callback| will be called
  // only once.
  //
  // The returned LinuxPackageInfo will only have package_id and summary filled
  // in.
  //
  // Only installed packages are considered. This function is intended for use
  // by uninstallers and similar systems that care only about .desktop files
  // that are on the local files system, so we don't care about uninstalled
  // packages.
  void SearchLinuxPackagesForFile(const base::FilePath& file_path,
                                  PackageSearchCallback callback);

  // Tries to resolve the name of a Linux Package |package_name| into its
  // qualified ID of "name;version;arch;data". Once the transaction is
  // complete, |callback| will be called. If the name was resolved sucessfully,
  // |success| and |pkg_found| will be true and |pkg_info| will be filled in
  // with some package including the package ID. If the package name could not
  // be resolved, |pkg_found| will be set to false, |pkg_info| will be empty,
  // but |success| will be true -- this is not an error. On error, |success|
  // will be false and |error| will be populated with the error details.
  // Regardless, |callback| will be called only once.
  //
  // The returned LinuxPackageInfo will only have package_id and summary filled
  // in.
  void ResolvePackageName(const std::string& package_name,
                          PackageSearchCallback callback);

  // Requests that installation of the Linux package located at |file_path| be
  // performed. |out_error| will be set in the case of failure.
  vm_tools::container::InstallLinuxPackageResponse::Status
  InstallLinuxPackageFromFilePath(const base::FilePath& file_path,
                                  const std::string& command_uuid,
                                  std::string* out_error);

  // Requests that installation of the Linux package with the ID of
  // |package_id| be performed. |out_error| will be set in the case of failure.
  vm_tools::container::InstallLinuxPackageResponse::Status
  InstallLinuxPackageFromPackageId(const std::string& package_id,
                                   const std::string& command_uuid,
                                   std::string* out_error);

  // Kicks off a sequence of requests to uninstall the package owning the
  // file at |file_path|. Returns a status code indicating if the uninstall
  // sequence was successfully started.
  // On success, returns as soon as the sequence starts; actual results are
  // posted later via the PackageKitObserver callback.
  vm_tools::container::UninstallPackageOwningFileResponse::Status
  UninstallPackageOwningFile(const base::FilePath& file_path,
                             std::string* out_error);

  // For use by this implementation only, these are public because helper
  // classes also utilize them.
  struct PackageInfoTransactionData {
    PackageInfoTransactionData(const base::FilePath& file_path_in,
                               std::shared_ptr<LinuxPackageInfo> pkg_info_in);
    PackageInfoTransactionData(const std::string& package_id_in,
                               std::shared_ptr<LinuxPackageInfo> pkg_info_in);
    const base::FilePath file_path;
    std::string package_id;
    base::WaitableEvent event;
    bool result;
    std::shared_ptr<LinuxPackageInfo> pkg_info;
    std::string error;
  };

  class PackageKitDeathObserver : public base::CheckedObserver {
   public:
    virtual ~PackageKitDeathObserver() {}
    // Invoked when the name owner changed signal is received indicating loss
    // of ownership.
    virtual void OnPackageKitDeath() = 0;
  };
  // Internal use only: Sets blocking_operation_active_ to false when destroyed.
  // Does not set blocking_operation_active_ to true ever.
  class BlockingOperationActiveClearer {
   public:
    BlockingOperationActiveClearer(base::Lock* blocking_operation_active_mutex,
                                   bool* blocking_operation_active);
    ~BlockingOperationActiveClearer();

    // Not moveable, not copyable
    BlockingOperationActiveClearer(const BlockingOperationActiveClearer&) =
        delete;
    BlockingOperationActiveClearer& operator=(
        const BlockingOperationActiveClearer&) = delete;

   private:
    base::Lock* blocking_operation_active_mutex_;  // Not owned
    bool* blocking_operation_active_;              // Not owned either
  };
  void AddPackageKitDeathObserver(PackageKitDeathObserver* observer);
  void RemovePackageKitDeathObserver(PackageKitDeathObserver* observer);

 private:
  explicit PackageKitProxy(PackageKitObserver* observer);
  PackageKitProxy(const PackageKitProxy&) = delete;
  PackageKitProxy& operator=(const PackageKitProxy&) = delete;

  bool Init();
  void GetLinuxPackageInfoOnDBusThread(
      std::shared_ptr<PackageInfoTransactionData> data);
  void InstallLinuxPackageFromFilePathOnDBusThread(
      const base::FilePath& file_path,
      const std::string& command_uuid,
      std::unique_ptr<BlockingOperationActiveClearer> clearer);
  void InstallLinuxPackageFromPackageIdOnDBusThread(
      const std::string& package_name,
      const std::string& command_uuid,
      std::unique_ptr<BlockingOperationActiveClearer> clearer);
  void SearchLinuxPackagesForFileOnDBusThread(const base::FilePath& file_path,
                                              PackageSearchCallback callback);
  void ResolvePackageNameOnDBusThread(const std::string& package_name,
                                      PackageSearchCallback callback);

  // Callback for ownership change of PackageKit service, used to detect if it
  // crashes while we are waiting on something that doesn't have a timeout.
  void OnPackageKitNameOwnerChanged(const std::string& old_owner,
                                    const std::string& new_owner);

  // Callback for PackageKit service availability, this needs to be called in
  // order for name ownership change events to come through.
  void OnPackageKitServiceAvailable(bool service_is_available);

  // Callback from SearchLinuxPackagesForFile, used by
  // UninstallPackageOwningFile. If an owning package is found, kicks off the
  // actual uninstall.
  void UninstallPackageOwningFileSearchForFileCallback(
      base::FilePath file_path,
      std::unique_ptr<BlockingOperationActiveClearer> clearer,
      bool success,
      bool pkg_found,
      const LinuxPackageInfo& pkg_info,
      const std::string& error);

  // Callback from ResolvePackageName, used by
  // GetLinuxPackageInfoFromPackageName. If the package name is resolved into a
  // package id, this returns details about that package.
  void GetLinuxPackageInfoFromPackageNameResolvePackageNameCallback(
      std::shared_ptr<PackageInfoTransactionData> data,
      std::string* out_error,
      bool success,
      bool pkg_resolved,
      const LinuxPackageInfo& pkg_info,
      const std::string& error);

  scoped_refptr<dbus::Bus> bus_;
  // Owned by |bus_|, but adds refcount to PostTask
  scoped_refptr<dbus::ObjectProxy> packagekit_service_proxy_;

  scoped_refptr<base::SingleThreadTaskRunner> task_runner_;
  PackageKitObserver* observer_;  // Not owned.

  // Ensures that only one blocking operation (install, uninstall) happens at a
  // time. Two reasons for this:
  // 1. If we don't block here, PackageKit will generally fail anyways because
  //    it can't acquire the dpkg lock.
  // 2. The interface is simpler if only one operation can be in flight at once.
  //    In particular, we don't need to indicate which uninstall / install we
  //    are reporting status on.
  base::Lock blocking_operation_active_mutex_;
  bool blocking_operation_active_;  // Lock blocking_operation_active_mutex_
                                    // before accessing.

  // Ensure calls are made on the right thread.
  base::SequenceChecker sequence_checker_;

  base::ObserverList<PackageKitDeathObserver> death_observers_;
};

}  // namespace garcon
}  // namespace vm_tools

#endif  // VM_TOOLS_GARCON_PACKAGE_KIT_PROXY_H_
