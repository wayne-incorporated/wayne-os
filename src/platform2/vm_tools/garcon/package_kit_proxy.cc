// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "vm_tools/garcon/package_kit_proxy.h"

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <base/check.h>
#include <base/check_op.h>
#include <base/command_line.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/files/scoped_file.h>
#include <base/functional/bind.h>
#include <base/functional/callback_helpers.h>
#include <base/location.h>
#include <base/logging.h>
#include <base/memory/ptr_util.h>
#include <base/notreached.h>
#include <base/process/launch.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_split.h>
#include <base/strings/string_util.h>
#include <base/task/single_thread_task_runner.h>
#include <dbus/message.h>
#include <dbus/property.h>
#include <dbus/scoped_dbus_error.h>
#include <vm_protos/proto_bindings/container_guest.grpc.pb.h>

namespace vm_tools {
namespace garcon {

namespace {

// Package ID suffix we require in order to perform an automatic upgrade, this
// corresponds to the repository the package comes from.
constexpr char kManagedPackageIdSuffix[] = ";google-stable-main";

// Constants for the PackageKit D-Bus service.
// See:
// https://github.com/hughsie/PackageKit/blob/HEAD/src/org.freedesktop.PackageKit.Transaction.xml
constexpr char kPackageKitInterface[] = "org.freedesktop.PackageKit";
constexpr char kPackageKitServicePath[] = "/org/freedesktop/PackageKit";
constexpr char kPackageKitServiceName[] = "org.freedesktop.PackageKit";
constexpr char kPackageKitTransactionInterface[] =
    "org.freedesktop.PackageKit.Transaction";
constexpr char kSetHintsMethod[] = "SetHints";
constexpr char kCreateTransactionMethod[] = "CreateTransaction";
constexpr char kGetDetailsMethod[] = "GetDetails";
constexpr char kGetDetailsLocalMethod[] = "GetDetailsLocal";
constexpr char kSearchFilesMethod[] = "SearchFiles";
constexpr char kInstallFilesMethod[] = "InstallFiles";
constexpr char kInstallPackagesMethod[] = "InstallPackages";
constexpr char kRemovePackagesMethod[] = "RemovePackages";
constexpr char kResolveMethod[] = "Resolve";
constexpr char kGetUpdatesMethod[] = "GetUpdates";
constexpr char kUpdatePackagesMethod[] = "UpdatePackages";
constexpr char kErrorCodeSignal[] = "ErrorCode";
constexpr char kFinishedSignal[] = "Finished";
constexpr char kDetailsSignal[] = "Details";
constexpr char kPackageSignal[] = "Package";

// Key names for the Details signal from PackageKit.
constexpr char kDetailsKeyPackageId[] = "package-id";
constexpr char kDetailsKeyLicense[] = "license";
constexpr char kDetailsKeyDescription[] = "description";
constexpr char kDetailsKeyUrl[] = "url";
constexpr char kDetailsKeySize[] = "size";
constexpr char kDetailsKeySummary[] = "summary";

// See:
// https://www.freedesktop.org/software/PackageKit/gtk-doc/PackageKit-Enumerations.html#PkExitEnum
constexpr uint32_t kPackageKitExitCodeSuccess = 1;
// See:
// https://www.freedesktop.org/software/PackageKit/gtk-doc/PackageKit-Enumerations.html#PkStatusEnum
constexpr uint32_t kPackageKitStatusRemoving = 6;
constexpr uint32_t kPackageKitStatusDownload = 8;
constexpr uint32_t kPackageKitStatusInstall = 9;
// See:
// https://www.freedesktop.org/software/PackageKit/gtk-doc/PackageKit-Enumerations.html#PkFilterEnum
constexpr uint32_t kPackageKitFilterNone = 1;
constexpr uint32_t kPackageKitFilterInstalled = 2;
// See:
// https://www.freedesktop.org/software/PackageKit/gtk-doc/PackageKit-Enumerations.html#PkInfoEnum
constexpr uint32_t kPackageKitInfoSecurity = 8;
constexpr uint32_t kPackageKitInfoBlocked = 9;
// See:
// https://www.freedesktop.org/software/PackageKit/gtk-doc/PackageKit-Enumerations.html#PkTransactionFlagEnum
constexpr uint32_t kPackageKitTransactionFlagEnumNone = 0;

// Timeout for when we are querying for package information.
constexpr int kGetLinuxPackageInfoTimeoutSeconds = 60;
constexpr base::TimeDelta kGetLinuxPackageInfoTimeout =
    base::Seconds(kGetLinuxPackageInfoTimeoutSeconds);

// Delay after startup for doing a repository cache refresh.
constexpr base::TimeDelta kRefreshCacheStartupDelay = base::Minutes(5);

// Periodic delay between repository cache refreshes after we do the initial one
// after startup.
constexpr base::TimeDelta kRefreshCachePeriod = base::Days(1);

// Ridiculously large size for a config file.
constexpr size_t kMaxConfigFileSize = 10 * 1024;  // 10 KB
// Constants for the configuration directory/files.
constexpr char kXdgConfigHomeEnvVar[] = "XDG_CONFIG_HOME";
constexpr char kDefaultConfigDir[] = ".config";
constexpr char kConfigFilename[] = "cros-garcon.conf";
constexpr char kDisableAutoCrosUpdatesSetting[] =
    "DisableAutomaticCrosPackageUpdates";
constexpr char kDisableAutoSecurityUpdatesSetting[] =
    "DisableAutomaticSecurityUpdates";

// Bitmask values for all the signals from PackageKit
constexpr uint32_t kErrorCodeSignalMask = 1 << 0;
constexpr uint32_t kFinishedSignalMask = 1 << 1;
constexpr uint32_t kPackageSignalMask = 1 << 2;
constexpr uint32_t kDetailsSignalMask = 1 << 3;
constexpr uint32_t kPropertiesSignalMask = 1 << 4;
constexpr uint32_t kValidSignalMask =
    kErrorCodeSignalMask | kFinishedSignalMask | kPackageSignalMask |
    kDetailsSignalMask | kPropertiesSignalMask;

// Parses the configuration file and returns the results through the parameters.
void CheckDisabledUpdates(bool* disable_cros_updates_out,
                          bool* disable_security_updates_out) {
  DCHECK(disable_cros_updates_out);
  DCHECK(disable_security_updates_out);
  *disable_cros_updates_out = false;
  *disable_security_updates_out = false;
  base::FilePath config_dir;
  const char* xdg_config_dir = getenv(kXdgConfigHomeEnvVar);
  if (!xdg_config_dir || strlen(xdg_config_dir) == 0) {
    config_dir = base::GetHomeDir().Append(kDefaultConfigDir);
  } else {
    config_dir = base::FilePath(xdg_config_dir);
  }
  base::FilePath config_file = config_dir.Append(kConfigFilename);
  // First read in the file as a string.
  std::string config_contents;
  if (!ReadFileToStringWithMaxSize(config_file, &config_contents,
                                   kMaxConfigFileSize)) {
    LOG(ERROR) << "Failed reading in config file: " << config_file.value();
    return;
  }
  base::StringPairs config_pairs;
  base::SplitStringIntoKeyValuePairs(config_contents, '=', '\n', &config_pairs);
  for (auto entry : config_pairs) {
    if (entry.first == kDisableAutoCrosUpdatesSetting) {
      *disable_cros_updates_out = (entry.second == "true");
    } else if (entry.first == kDisableAutoSecurityUpdatesSetting) {
      *disable_security_updates_out = (entry.second == "true");
    }
  }
}

struct PackageKitTransactionProperties : public dbus::PropertySet {
  // These are the only 2 properties we care about.
  dbus::Property<uint32_t> status;
  dbus::Property<uint32_t> percentage;
  PackageKitTransactionProperties(dbus::ObjectProxy* object_proxy,
                                  const PropertyChangedCallback callback)
      : dbus::PropertySet(
            object_proxy, kPackageKitTransactionInterface, callback) {
    RegisterProperty("Status", &status);
    RegisterProperty("Percentage", &percentage);
  }
};

// Base class for the helpers for interacting with PackageKit. This will handle
// all the odd D-Bus failures as well as PackageKit death. This object manages
// its own lifecycle, so it should always be created in a leaky fashion, but
// StartTransaction must ALWAYS be invoked after object creation to ensure
// proper cleanup.
class PackageKitTransaction : PackageKitProxy::PackageKitDeathObserver {
 public:
  explicit PackageKitTransaction(
      scoped_refptr<dbus::Bus> bus,
      PackageKitProxy* packagekit_proxy,
      scoped_refptr<dbus::ObjectProxy> packagekit_service_proxy,
      uint32_t signal_mask)
      : bus_(bus),
        packagekit_proxy_(packagekit_proxy),
        packagekit_service_proxy_(packagekit_service_proxy),
        signal_mask_(signal_mask) {
    DCHECK_EQ(signal_mask, signal_mask & kValidSignalMask);
    packagekit_proxy_->AddPackageKitDeathObserver(this);
  }
  PackageKitTransaction(const PackageKitTransaction&) = delete;
  PackageKitTransaction& operator=(const PackageKitTransaction&) = delete;

  virtual ~PackageKitTransaction() {
    if (transaction_path_.IsValid()) {
      bus_->RemoveObjectProxy(kPackageKitServiceName, transaction_path_,
                              base::DoNothing());
    }
    packagekit_proxy_->RemovePackageKitDeathObserver(this);
  }

  // This MUST be invoked after object construction in order to ensure proper
  // cleanup. Even if this fails, it will take care of its own destruction.
  void StartTransaction() {
    // Create a transaction with PackageKit for performing the operation.
    dbus::MethodCall method_call(kPackageKitInterface,
                                 kCreateTransactionMethod);
    dbus::MessageWriter writer(&method_call);
    std::unique_ptr<dbus::Response> dbus_response =
        packagekit_service_proxy_->CallMethodAndBlockWithErrorDetails(
            &method_call, dbus::ObjectProxy::TIMEOUT_USE_DEFAULT, &dbus_error_);
    if (!dbus_response) {
      GeneralErrorInternal("Failure calling CreateTransaction");
      return;
    }
    // CreateTransaction returns the object path for the transaction session we
    // have created.
    dbus::MessageReader reader(dbus_response.get());
    if (!reader.PopObjectPath(&transaction_path_)) {
      GeneralErrorInternal(
          "Failure reading object path from transaction result");
      return;
    }
    transaction_proxy_ =
        bus_->GetObjectProxy(kPackageKitServiceName, transaction_path_);
    if (!transaction_proxy_) {
      GeneralErrorInternal("Failed to get proxy for transaction");
      return;
    }

    // Set the hint that we don't support interactivity. I haven't seen a case
    // of this yet, but it seems like a good idea to set it if it does occur.
    // Set locale with UTF-8 to support unicode in control files.  This is
    // what 'pkcon get-details-local <file>' does.
    dbus::ScopedDBusError error;
    dbus::MethodCall sethints_call(kPackageKitTransactionInterface,
                                   kSetHintsMethod);
    dbus::MessageWriter sethints_writer(&sethints_call);
    sethints_writer.AppendArrayOfStrings(
        {"locale=en_US.UTF-8", "interactive=false"});
    dbus_response = transaction_proxy_->CallMethodAndBlockWithErrorDetails(
        &sethints_call, dbus::ObjectProxy::TIMEOUT_USE_DEFAULT, &error);
    if (!dbus_response) {
      // Don't propagate a failure, this was just a hint.
      LOG(WARNING) << "Failure calling SetHints - " << error.name() << ": "
                   << error.message();
    }

    // Hook up all the necessary signals to PackageKit for monitoring the
    // transaction. After these are all hooked up, we will invoke the method
    // so the subclass can initiate the actual request.

    // The properties Signal is special, there exists a helper class for that
    // where we don't manage hooking up the signals ourself.
    if (signal_mask_ & kPropertiesSignalMask) {
      // Remove the bit from the mask to indicate we processed it already.
      signal_mask_ = signal_mask_ & ~kPropertiesSignalMask;
      transaction_properties_ =
          std::make_unique<PackageKitTransactionProperties>(
              transaction_proxy_,
              base::BindRepeating(
                  &PackageKitTransaction::OnPackageKitPropertyChanged,
                  base::Unretained(this)));
      transaction_properties_->ConnectSignals();
      transaction_properties_->GetAll();
    }

    if (signal_mask_ == 0) {
      // No signals to hookup, just go right into the request.
      if (!ExecuteRequest(transaction_proxy_)) {
        GeneralErrorInternal(
            "Failure executing the request in the transaction");
        return;
      }
    }
    ConnectNextSignal();
  }

  // Override to execute the actual request within the transaction such as
  // GetUpdates, RefreshCache, etc. Returns true if the call succeeded, false
  // otherwise. If this method fails, then GeneralError will be invoked.
  virtual bool ExecuteRequest(dbus::ObjectProxy* transaction_proxy) = 0;

  // Invoked when something went wrong in the D-Bus communication, the object
  // will self-destruct after this call.
  virtual void GeneralError(const std::string& details) {
    LOG(ERROR) << details;
  }

  // Invoked when the corresponding signals are received and decoded. If a
  // Finished signal occurs, then no other calls will be made after that and
  // this object will self-destruct.
  virtual void ErrorReceived(uint32_t error_code, const std::string& details) {
    LOG(ERROR) << "Error occured with PackageKit transaction with code: "
               << error_code << " and details: " << details;
  }
  virtual void FinishedReceived(uint32_t exit_code) {
    if (exit_code == kPackageKitExitCodeSuccess) {
      LOG(INFO) << "PackageKit transaction completed successfully";
    } else {
      LOG(ERROR) << "PackageKit transaction failed with code: " << exit_code;
    }
  }
  virtual void PackageReceived(uint32_t code,
                               const std::string& package_id,
                               const std::string& summary) {}
  virtual void DetailsReceived(const std::string& package_id,
                               const std::string& license,
                               const std::string& description,
                               const std::string& project_url,
                               uint64_t size,
                               const std::string& summary) {}
  virtual void PropertyChangeReceived(
      const std::string& name, PackageKitTransactionProperties* properties) {}

 private:
  // PackageKitDeathObserver overrides:
  void OnPackageKitDeath() {
    GeneralErrorInternal("PackageKit D-Bus service died, abort operation");
  }

  void GeneralErrorInternal(const std::string& details) {
    if (dbus_error_.is_set()) {
      GeneralError(details + "(error=" + dbus_error_.name() + ": " +
                   dbus_error_.message() + ")");
    } else {
      GeneralError(details);
    }
    // An unknown error has occurred, we should self-destruct now.
    delete this;
  }

  void ConnectNextSignal() {
    std::string signal_name;
    dbus::ObjectProxy::SignalCallback signal_callback;
    if (signal_mask_ & kErrorCodeSignalMask) {
      signal_mask_ = signal_mask_ & ~kErrorCodeSignalMask;
      signal_name.assign(kErrorCodeSignal);
      signal_callback = base::BindRepeating(
          &PackageKitTransaction::OnErrorSignal, base::Unretained(this));
    } else if (signal_mask_ & kFinishedSignalMask) {
      signal_mask_ = signal_mask_ & ~kFinishedSignalMask;
      signal_name.assign(kFinishedSignal);
      signal_callback = base::BindRepeating(
          &PackageKitTransaction::OnFinishedSignal, base::Unretained(this));
    } else if (signal_mask_ & kPackageSignalMask) {
      signal_mask_ = signal_mask_ & ~kPackageSignalMask;
      signal_name.assign(kPackageSignal);
      signal_callback = base::BindRepeating(
          &PackageKitTransaction::OnPackageSignal, base::Unretained(this));
    } else if (signal_mask_ & kDetailsSignalMask) {
      signal_mask_ = signal_mask_ & ~kDetailsSignalMask;
      signal_name.assign(kDetailsSignal);
      signal_callback = base::BindRepeating(
          &PackageKitTransaction::OnDetailsSignal, base::Unretained(this));
    } else {
      NOTREACHED();
    }

    transaction_proxy_->ConnectToSignal(
        kPackageKitTransactionInterface, signal_name, signal_callback,
        base::BindOnce(&PackageKitTransaction::OnSignalConnected,
                       base::Unretained(this)));
  }

  void OnSignalConnected(const std::string& interface_name,
                         const std::string& signal_name,
                         bool is_connected) {
    if (!is_connected) {
      // Any failures in signal hookups mean we should abort.
      GeneralErrorInternal("Failed to hookup " + signal_name + " signal");
      return;
    }
    if (signal_mask_ == 0) {
      // Done hooking up our signals, let the subclass invoke the request.
      if (!ExecuteRequest(transaction_proxy_)) {
        GeneralErrorInternal(
            "Failure executing the request in the transaction");
      }
    } else {
      ConnectNextSignal();
    }
  }

  void OnErrorSignal(dbus::Signal* signal) {
    CHECK(signal);
    dbus::MessageReader reader(signal);
    uint32_t code;
    std::string details;
    if (!reader.PopUint32(&code) || !reader.PopString(&details)) {
      GeneralErrorInternal("Failure parsing PackageKit error signal");
      return;
    }
    ErrorReceived(code, details);
  }

  void OnFinishedSignal(dbus::Signal* signal) {
    CHECK(signal);
    dbus::MessageReader reader(signal);
    uint32_t exit_code;
    if (!reader.PopUint32(&exit_code)) {
      GeneralErrorInternal("Failure parsing PackageKit finished signal");
      return;
    }
    FinishedReceived(exit_code);
    // We are done, we should self-destruct.
    delete this;
  }

  void OnPackageSignal(dbus::Signal* signal) {
    CHECK(signal);
    dbus::MessageReader reader(signal);
    uint32_t code;
    std::string package_id;
    std::string summary;
    if (!reader.PopUint32(&code) || !reader.PopString(&package_id) ||
        !reader.PopString(&summary)) {
      GeneralErrorInternal("Failure parsing PackageKit Package signal");
      return;
    }
    PackageReceived(code, package_id, summary);
  }

  void OnDetailsSignal(dbus::Signal* signal) {
    CHECK(signal);
    dbus::MessageReader reader(signal);
    // Read all of the details on the package. This is an array of dict entries
    // with string keys and variant values.
    dbus::MessageReader array_reader(nullptr);
    if (!reader.PopArray(&array_reader)) {
      GeneralErrorInternal("Failure parsing PackageKit Details signal");
      return;
    }
    std::string package_id;
    std::string license;
    std::string description;
    std::string project_url;
    uint64_t size = 0;
    std::string summary;
    while (array_reader.HasMoreData()) {
      dbus::MessageReader dict_entry_reader(nullptr);
      if (array_reader.PopDictEntry(&dict_entry_reader)) {
        dbus::MessageReader value_reader(nullptr);
        std::string name;
        if (!dict_entry_reader.PopString(&name) ||
            !dict_entry_reader.PopVariant(&value_reader)) {
          LOG(WARNING) << "Error popping dictionary entry from D-Bus message";
          continue;
        }
        if (name == kDetailsKeyPackageId) {
          if (!value_reader.PopString(&package_id)) {
            LOG(WARNING) << "Error popping package_id from details";
          }
        } else if (name == kDetailsKeyLicense) {
          if (!value_reader.PopString(&license)) {
            LOG(WARNING) << "Error popping license from details";
          }
        } else if (name == kDetailsKeyDescription) {
          if (!value_reader.PopString(&description)) {
            LOG(WARNING) << "Error popping description from details";
          }
        } else if (name == kDetailsKeyUrl) {
          if (!value_reader.PopString(&project_url)) {
            LOG(WARNING) << "Error popping url from details";
          }
        } else if (name == kDetailsKeySize) {
          if (!value_reader.PopUint64(&size)) {
            LOG(WARNING) << "Error popping size from details";
          }
        } else if (name == kDetailsKeySummary) {
          if (!value_reader.PopString(&summary)) {
            LOG(WARNING) << "Error popping summary from details";
          }
        }
      }
    }
    DetailsReceived(package_id, license, description, project_url, size,
                    summary);
  }

  void OnPackageKitPropertyChanged(const std::string& name) {
    PropertyChangeReceived(name, transaction_properties_.get());
  }

 protected:
  scoped_refptr<dbus::Bus> bus_;
  dbus::ScopedDBusError dbus_error_;
  PackageKitProxy* packagekit_proxy_;                          // Not owned.
  scoped_refptr<dbus::ObjectProxy> packagekit_service_proxy_;  // Not owned.

 private:
  uint32_t signal_mask_;

  dbus::ObjectProxy* transaction_proxy_;  // Owned by bus_.
  dbus::ObjectPath transaction_path_;
  std::unique_ptr<PackageKitTransactionProperties> transaction_properties_;
};

// Sublcass for handling GetDetailsLocal and GetDetails transactions. If
// |data->package_id| is empty, uses the |data->file_path| and GetDetailsLocal,
// else uses |data->package_id| and GetDetails.
class GetDetailsTransaction : public PackageKitTransaction {
 public:
  GetDetailsTransaction(
      scoped_refptr<dbus::Bus> bus,
      PackageKitProxy* packagekit_proxy,
      scoped_refptr<dbus::ObjectProxy> packagekit_service_proxy,
      std::shared_ptr<PackageKitProxy::PackageInfoTransactionData> data)
      : PackageKitTransaction(
            bus,
            packagekit_proxy,
            packagekit_service_proxy,
            kErrorCodeSignalMask | kFinishedSignalMask | kDetailsSignalMask),
        data_(data) {
    data_->result = false;
  }

  void GeneralError(const std::string& details) override {
    LOG(ERROR) << "Problem with GetDetailsLocal transaction: " << details;
    // Check if we've already indicated we are done.
    if (data_->event.IsSignaled())
      return;
    data_->error.assign(details);
    data_->event.Signal();
  }

  bool ExecuteRequest(dbus::ObjectProxy* transaction_proxy) override {
    std::string method_name;
    std::string value;
    if (data_->package_id.empty()) {
      method_name = kGetDetailsLocalMethod;
      value = data_->file_path.value();
    } else {
      method_name = kGetDetailsMethod;
      value = data_->package_id;
    }

    dbus::MethodCall method_call(kPackageKitTransactionInterface, method_name);
    dbus::MessageWriter writer(&method_call);
    writer.AppendArrayOfStrings({value});

    std::unique_ptr<dbus::Response> dbus_response =
        transaction_proxy->CallMethodAndBlockWithErrorDetails(
            &method_call, dbus::ObjectProxy::TIMEOUT_USE_DEFAULT, &dbus_error_);
    return !!dbus_response;
  }

  void ErrorReceived(uint32_t error_code, const std::string& details) override {
    LOG(ERROR) << "Failure querying Linux package of: " << details;
    // Check if we've already indicated we are done.
    if (data_->event.IsSignaled())
      return;
    // We will still get a Finished signal where we finalize everything.
    data_->error.assign(details);
  }

  void FinishedReceived(uint32_t exit_code) override {
    LOG(INFO) << "Finished with query for Linux package info";
    // Check if we've already indicated we are done.
    if (data_->event.IsSignaled())
      return;
    // If this is a failure, the error message should have already been set via
    // that callback.
    data_->result = kPackageKitExitCodeSuccess == exit_code;
    data_->event.Signal();
  }

  void DetailsReceived(const std::string& package_id,
                       const std::string& license,
                       const std::string& description,
                       const std::string& project_url,
                       uint64_t size,
                       const std::string& summary) override {
    // Check if we've already indicated we are done.
    if (data_->event.IsSignaled())
      return;
    data_->pkg_info->package_id.assign(package_id);
    data_->pkg_info->license.assign(license);
    data_->pkg_info->description.assign(description);
    data_->pkg_info->project_url.assign(project_url);
    data_->pkg_info->size = size;
    data_->pkg_info->summary.assign(summary);
  }

 private:
  std::shared_ptr<PackageKitProxy::PackageInfoTransactionData> data_;
};

// Subclass for handling SearchFiles transaction. Different from GetDetailsLocal
// in that we do a callback on the current thread instead of saving the
// information to a structure in order to return it on a different thread.
class SearchFilesTransaction : public PackageKitTransaction {
 public:
  SearchFilesTransaction(
      scoped_refptr<dbus::Bus> bus,
      PackageKitProxy* packagekit_proxy,
      scoped_refptr<dbus::ObjectProxy> packagekit_service_proxy,
      const base::FilePath& file_path,
      PackageKitProxy::PackageSearchCallback callback)
      : PackageKitTransaction(
            bus,
            packagekit_proxy,
            packagekit_service_proxy,
            kErrorCodeSignalMask | kFinishedSignalMask | kPackageSignalMask),
        file_path_(file_path),
        callback_(std::move(callback)) {}

  bool ExecuteRequest(dbus::ObjectProxy* transaction_proxy) override {
    dbus::MethodCall method_call(kPackageKitTransactionInterface,
                                 kSearchFilesMethod);
    dbus::MessageWriter writer(&method_call);
    // As explained in the comments for
    // PackageKitProxy::SearchLinuxPackagesForFile, we only consider installed
    // packages.
    writer.AppendUint64(kPackageKitFilterInstalled);
    writer.AppendArrayOfStrings({file_path_.value()});
    std::unique_ptr<dbus::Response> dbus_response =
        transaction_proxy->CallMethodAndBlockWithErrorDetails(
            &method_call, dbus::ObjectProxy::TIMEOUT_USE_DEFAULT, &dbus_error_);
    return !!dbus_response;
  }

  void GeneralError(const std::string& details) override {
    LOG(ERROR) << "Problem with SearchFiles transaction for file "
               << file_path_.value() << ": " << details;
    // Check if we've already done the callback.
    if (!callback_)
      return;
    std::move(callback_).Run(false /*success*/, false /*pkg_found*/,
                             PackageKitProxy::LinuxPackageInfo(), details);
  }

  void ErrorReceived(uint32_t error_code, const std::string& details) override {
    LOG(ERROR) << "Failure searching local Linux Packages by file "
               << file_path_.value() << ": " << details;
    // Check if we've already done the callback.
    if (!callback_)
      return;
    // We will still get a Finished signal where we finalize everything, but
    // no need to wait for it.
    std::move(callback_).Run(false /*success*/, false /*pkg_found*/,
                             PackageKitProxy::LinuxPackageInfo(), details);
  }

  void PackageReceived(uint32_t code,
                       const std::string& package_id,
                       const std::string& summary) override {
    LOG(INFO) << "Got a package for local file " << file_path_.value();
    // Check if we've already done the callback.
    if (!callback_)
      return;
    PackageKitProxy::LinuxPackageInfo pkg_info;
    pkg_info.package_id = package_id;
    pkg_info.summary = summary;
    std::move(callback_).Run(true /*success*/, true /*pkg_found*/, pkg_info,
                             "");
  }

  void FinishedReceived(uint32_t exit_code) override {
    LOG(INFO) << "Finished with SearchFiles transaction for local file "
              << file_path_.value();
    if (!callback_)
      return;

    // If we got here without calling the callback, PackageKit couldn't find a
    // package corresponding to the file.
    std::move(callback_).Run(true /*success*/, false /*pkg_found*/,
                             PackageKitProxy::LinuxPackageInfo(), "");
  }

 private:
  base::FilePath file_path_;
  PackageKitProxy::PackageSearchCallback callback_;
};

// Sublcass for handling InstallFiles and InstallPackages. If |package_id|
// is empty, uses |file_path| and InstallFiles transaction, else it uses
// |package_id| and InstallPackages transaction.
class InstallTransaction : public PackageKitTransaction {
 public:
  InstallTransaction(
      scoped_refptr<dbus::Bus> bus,
      PackageKitProxy* packagekit_proxy,
      scoped_refptr<dbus::ObjectProxy> packagekit_service_proxy,
      PackageKitProxy::PackageKitObserver* observer,
      base::FilePath file_path,
      std::string command_uuid,
      std::unique_ptr<PackageKitProxy::BlockingOperationActiveClearer> clearer)
      : PackageKitTransaction(
            bus,
            packagekit_proxy,
            packagekit_service_proxy,
            kErrorCodeSignalMask | kFinishedSignalMask | kPropertiesSignalMask),
        file_path_(file_path),
        command_uuid_(command_uuid),
        clearer_(std::move(clearer)),
        observer_(observer) {}

  InstallTransaction(
      scoped_refptr<dbus::Bus> bus,
      PackageKitProxy* packagekit_proxy,
      scoped_refptr<dbus::ObjectProxy> packagekit_service_proxy,
      PackageKitProxy::PackageKitObserver* observer,
      std::string package_id,
      std::string command_uuid,
      std::unique_ptr<PackageKitProxy::BlockingOperationActiveClearer> clearer)
      : PackageKitTransaction(
            bus,
            packagekit_proxy,
            packagekit_service_proxy,
            kErrorCodeSignalMask | kFinishedSignalMask | kPropertiesSignalMask),
        package_id_(package_id),
        command_uuid_(command_uuid),
        clearer_(std::move(clearer)),
        observer_(observer) {}

  void GeneralError(const std::string& details) override {
    if (!observer_)
      return;
    observer_->OnInstallCompletion(command_uuid_, false, details);
    observer_ = nullptr;
  }

  bool ExecuteRequest(dbus::ObjectProxy* transaction_proxy) override {
    std::string method_name;
    std::string value;
    if (package_id_.empty()) {
      method_name = kInstallFilesMethod;
      value = file_path_.value();
    } else {
      method_name = kInstallPackagesMethod;
      value = package_id_;
    }
    dbus::MethodCall method_call(kPackageKitTransactionInterface, method_name);
    dbus::MessageWriter writer(&method_call);
    writer.AppendUint64(0);  // Allow installing untrusted files.
    writer.AppendArrayOfStrings({value});

    std::unique_ptr<dbus::Response> dbus_response =
        transaction_proxy->CallMethodAndBlockWithErrorDetails(
            &method_call, dbus::ObjectProxy::TIMEOUT_USE_DEFAULT, &dbus_error_);
    return !!dbus_response;
  }

  void ErrorReceived(uint32_t error_code, const std::string& details) override {
    LOG(ERROR) << "Failure installing Linux package of: " << details;
    if (!observer_)
      return;
    observer_->OnInstallCompletion(command_uuid_, false, details);
    observer_ = nullptr;
  }

  void FinishedReceived(uint32_t exit_code) override {
    LOG(INFO) << "Finished installing Linux package result: " << exit_code;
    if (!observer_)
      return;
    observer_->OnInstallCompletion(
        command_uuid_, kPackageKitExitCodeSuccess == exit_code,
        "Exit Code: " + base::NumberToString(exit_code));
    observer_ = nullptr;
  }

  void PropertyChangeReceived(
      const std::string& name,
      PackageKitTransactionProperties* properties) override {
    if (!observer_)
      return;
    // There's only 2 progress states we actually care about which are logical
    // to report to the user. These are downloading and installing, which
    // correspond to similar experiences in Android and elsewhere. There are
    // various other phases this goes through, but they happen rather quickly
    // and would not be worth informing the user of.
    if (name != properties->percentage.name()) {
      // We only want to see progress percentage changes and then we filter
      // these below based on the current status.
      return;
    }
    vm_tools::container::InstallLinuxPackageProgressInfo::Status status;
    switch (properties->status.value()) {
      case kPackageKitStatusDownload:
        status =
            vm_tools::container::InstallLinuxPackageProgressInfo::DOWNLOADING;
        break;
      case kPackageKitStatusInstall:
        status =
            vm_tools::container::InstallLinuxPackageProgressInfo::INSTALLING;
        break;
      default:
        // Not a status state we care about.
        return;
    }
    int percentage = properties->percentage.value();
    // PackageKit uses 101 for the percent when it doesn't know, treat that as
    // zero because you see this at the beginning of phases.
    if (percentage == 101)
      percentage = 0;
    observer_->OnInstallProgress(command_uuid_, status, percentage);
  }

 private:
  base::FilePath file_path_;
  std::string package_id_;
  std::string command_uuid_;
  // Ensure blocking_operation_active is cleared when this object is deleted.
  std::unique_ptr<PackageKitProxy::BlockingOperationActiveClearer> clearer_;
  PackageKitProxy::PackageKitObserver* observer_;  // Not owned.
};

// Runs a RemovePackages transaction as part of a larger
// UninstallPackageOwningFile chain. The only reason that this is specific to
// UninstallPackageOwningFile is the name of the observer functions called.
// This could be used in other uninstall chains if it had generic callbacks,
// but right now UninstallPackageOwningFile is the only way of uninstalling
// anything, so more complexity would be a YAGNI smell.
class UninstallPackagesTransaction : public PackageKitTransaction {
 public:
  UninstallPackagesTransaction(
      scoped_refptr<dbus::Bus> bus,
      PackageKitProxy* packagekit_proxy,
      scoped_refptr<dbus::ObjectProxy> packagekit_service_proxy,
      const std::string& package_id,
      std::unique_ptr<PackageKitProxy::BlockingOperationActiveClearer> clearer,
      PackageKitProxy::PackageKitObserver* observer)
      : PackageKitTransaction(
            bus,
            packagekit_proxy,
            packagekit_service_proxy,
            kErrorCodeSignalMask | kFinishedSignalMask | kPropertiesSignalMask),
        package_id_(package_id),
        clearer_(std::move(clearer)),
        observer_(observer) {}

  bool ExecuteRequest(dbus::ObjectProxy* transaction_proxy) override {
    dbus::MethodCall method_call(kPackageKitTransactionInterface,
                                 kRemovePackagesMethod);
    dbus::MessageWriter writer(&method_call);
    // Transaction flags: we are not simulating the transaction.
    writer.AppendUint64(kPackageKitTransactionFlagEnumNone);
    // Package IDs
    writer.AppendArrayOfStrings({package_id_});
    // Boolean: allow_deps. If true, we will remove all dependent packages. If
    // false, we will fail if the package has dependencies. We don't want to
    // surprise the user by removing packages they weren't expected, so we
    // currently hardcode this to false.
    writer.AppendBool(false);
    // Boolean: autoremove. If true, removes packages that were installed
    // together with the to-be-removed package which are no longer depending on.
    // We hardcode this to true; many Chromebooks have limited storage and we
    // don't want to rely on the user knowing they need to run special cleanup
    // commands.
    writer.AppendBool(true);
    std::unique_ptr<dbus::Response> dbus_response =
        transaction_proxy->CallMethodAndBlockWithErrorDetails(
            &method_call, dbus::ObjectProxy::TIMEOUT_USE_DEFAULT, &dbus_error_);
    return !!dbus_response;
  }

  void GeneralError(const std::string& details) override {
    LOG(ERROR) << "General error uninstalling package: " << details;
    if (!observer_) {
      return;
    }
    observer_->OnUninstallCompletion(false, details);
    observer_ = nullptr;
  }

  void ErrorReceived(uint32_t error_code, const std::string& details) override {
    LOG(ERROR) << "Error uninstalling package: " << details << " (code "
               << error_code << ")";
    if (!observer_) {
      return;
    }
    observer_->OnUninstallCompletion(false, details);
    observer_ = nullptr;
  }

  void PropertyChangeReceived(
      const std::string& name,
      PackageKitTransactionProperties* properties) override {
    VLOG(3) << "PropertyChangeReceived:" << name
            << ", status: " << properties->status.value()
            << ", %: " << properties->percentage.value();
    // There are several states, but the only one that takes any significant
    // time is the 'Removing' state.
    if (properties->status.value() != kPackageKitStatusRemoving) {
      return;
    }

    if (!observer_) {
      return;
    }

    int percentage = properties->percentage.value();
    // PackageKit uses 101 for the percent when it doesn't know, treat that as
    // zero because you see this at the beginning of phases.
    if (percentage == 101) {
      percentage = 0;
    }

    observer_->OnUninstallProgress(percentage);
  }

  void FinishedReceived(uint32_t exit_code) override {
    if (!observer_) {
      return;
    }
    if (exit_code == kPackageKitExitCodeSuccess) {
      LOG(INFO) << "Uninstall transaction completed successfully";
      observer_->OnUninstallCompletion(true, "");
    } else {
      LOG(ERROR) << "Uninstall transaction failed with code: " << exit_code;
      observer_->OnUninstallCompletion(
          false, "Uninstall transaction failed with code: " +
                     base::NumberToString(exit_code));
    }
    observer_ = nullptr;
  }

 private:
  std::string package_id_;
  // Ensure blocking_operation_active is cleared when this object is deleted.
  std::unique_ptr<PackageKitProxy::BlockingOperationActiveClearer> clearer_;
  PackageKitProxy::PackageKitObserver* observer_;  // Not owned.
};

// Sublcass for handling UpdatePackages transaction.
class UpdatePackagesTransaction : public PackageKitTransaction {
 public:
  UpdatePackagesTransaction(
      scoped_refptr<dbus::Bus> bus,
      PackageKitProxy* packagekit_proxy,
      scoped_refptr<dbus::ObjectProxy> packagekit_service_proxy,
      std::vector<std::string> package_ids)
      : PackageKitTransaction(bus,
                              packagekit_proxy,
                              packagekit_service_proxy,
                              kErrorCodeSignalMask | kFinishedSignalMask),
        package_ids_(package_ids) {
    LOG(INFO) << "Attempting to upgrade package IDs: "
              << base::JoinString(package_ids, ", ");
  }

  void GeneralError(const std::string& details) override {
    LOG(ERROR) << "Error occurred with UpdatePackages: " << details;
  }

  bool ExecuteRequest(dbus::ObjectProxy* transaction_proxy) override {
    dbus::MethodCall method_call(kPackageKitTransactionInterface,
                                 kUpdatePackagesMethod);
    dbus::MessageWriter writer(&method_call);
    writer.AppendUint64(0);  // No transaction flag.
    writer.AppendArrayOfStrings(package_ids_);
    std::unique_ptr<dbus::Response> dbus_response =
        transaction_proxy->CallMethodAndBlockWithErrorDetails(
            &method_call, dbus::ObjectProxy::TIMEOUT_USE_DEFAULT, &dbus_error_);
    return !!dbus_response;
  }

  void ErrorReceived(uint32_t error_code, const std::string& details) override {
    LOG(ERROR) << "Failure with UpdatePackages of: " << details;
  }

  void FinishedReceived(uint32_t exit_code) override {
    if (exit_code == kPackageKitExitCodeSuccess) {
      LOG(INFO) << "Successfully performed upgrade of managed packages";
    } else {
      // PackageKit will log the specific error itself.
      LOG(ERROR) << "Failure performing upgrade of managed packages, code: "
                 << exit_code;
    }
  }

 private:
  std::vector<std::string> package_ids_;
};

// Sublcass for handling GetUpdates transaction.
class GetUpdatesTransaction : public PackageKitTransaction {
 public:
  GetUpdatesTransaction(
      scoped_refptr<dbus::Bus> bus,
      PackageKitProxy* packagekit_proxy,
      scoped_refptr<dbus::ObjectProxy> packagekit_service_proxy)
      : PackageKitTransaction(
            bus,
            packagekit_proxy,
            packagekit_service_proxy,
            kErrorCodeSignalMask | kFinishedSignalMask | kPackageSignalMask) {
    CheckDisabledUpdates(&cros_updates_disabled_, &security_updates_disabled_);
  }

  void GeneralError(const std::string& details) override {
    LOG(ERROR) << "Error occurred with GetUpdates: " << details;
  }

  bool ExecuteRequest(dbus::ObjectProxy* transaction_proxy) override {
    dbus::MethodCall method_call(kPackageKitTransactionInterface,
                                 kGetUpdatesMethod);
    dbus::MessageWriter writer(&method_call);
    // Set the filter to installed packages.
    writer.AppendUint64(kPackageKitFilterInstalled);
    std::unique_ptr<dbus::Response> dbus_response =
        transaction_proxy->CallMethodAndBlockWithErrorDetails(
            &method_call, dbus::ObjectProxy::TIMEOUT_USE_DEFAULT, &dbus_error_);
    return !!dbus_response;
  }

  void ErrorReceived(uint32_t error_code, const std::string& details) override {
    LOG(ERROR) << "Failure with GetUpdates of: " << details;
  }

  void PackageReceived(uint32_t code,
                       const std::string& package_id,
                       const std::string& /* summary */) override {
    if (!cros_updates_disabled_ &&
        base::EndsWith(package_id, kManagedPackageIdSuffix,
                       base::CompareCase::SENSITIVE)) {
      if (code == kPackageKitInfoBlocked) {
        LOG(WARNING) << "Managed package is blocked from upgrading: "
                     << package_id;
      } else {
        LOG(INFO) << "Found managed package that is upgradeable, add it to the "
                  << "list: " << package_id;
        package_ids_.emplace_back(package_id);
      }
    } else if (!security_updates_disabled_ && code == kPackageKitInfoSecurity) {
      LOG(INFO) << "Found package with security update, add it to the "
                << "list: " << package_id;
      package_ids_.emplace_back(package_id);
    }
  }

  void FinishedReceived(uint32_t exit_code) override {
    if (exit_code == kPackageKitExitCodeSuccess) {
      LOG(INFO) << "PackageKit GetUpdates transaction has completed with "
                << package_ids_.size() << " available managed updates";
      if (!package_ids_.empty()) {
        // This object is intentionally leaked and will clean itself up when
        // done with all the D-Bus communication.
        UpdatePackagesTransaction* transaction = new UpdatePackagesTransaction(
            bus_, packagekit_proxy_, packagekit_service_proxy_,
            std::move(package_ids_));
        transaction->StartTransaction();
      }
    } else {
      LOG(ERROR) << "Failure performing GetUpdates, code: " << exit_code;
    }
  }

 private:
  std::vector<std::string> package_ids_;
  bool cros_updates_disabled_;
  bool security_updates_disabled_;
};

void RunAptUpdate(scoped_refptr<dbus::Bus> bus,
                  PackageKitProxy* packagekit_proxy,
                  scoped_refptr<dbus::ObjectProxy> packagekit_service_proxy) {
  bool disable_cros_updates;
  bool disable_security_updates;
  CheckDisabledUpdates(&disable_cros_updates, &disable_security_updates);
  if (disable_cros_updates && disable_security_updates) {
    // Don't do the update now, but schedule another one for later and we will
    // check the setting again then.
    LOG(INFO) << "Not performing automatic update because they are disabled";
    base::SingleThreadTaskRunner::GetCurrentDefault()->PostDelayedTask(
        FROM_HERE,
        base::BindOnce(&RunAptUpdate, bus, packagekit_proxy,
                       packagekit_service_proxy),
        kRefreshCachePeriod);
    return;
  }

  LOG(INFO) << "Refreshing the remote repository packages";
  // Run the entire thing under sh, otherwise it's going to fail with "Waited
  // for apt-key but it wasn't there". This seems to be caused by
  // GetAppOutputAndError setting up a weird context where SIGCHLD doesn't
  // work the way waitpid wants it to.
  // https://unix.stackexchange.com/questions/485682/apt-get-dpkg-fails-from-a-bluetooth-serial-port-but-succeed-from-the-physi
  // has some investigation by someone else who hit this over a serial port,
  // though they weren't able to solve it.
  std::string output;
  bool success =
      base::GetAppOutputAndError({"sudo", "sh", "-c",
                                  "DEBIAN_FRONTEND=noninteractive apt-get "
                                  "update -y --allow-releaseinfo-change"},
                                 &output);

  // TODO(crbug/1245498): GetAppOutputAndError is buggy when it comes to
  // detecting failure of the executed process (also see arc_sideload.cc).
  // It's fine for now since it's harmless to apt upgrade without an apt update
  // (worst case is it fails).
  success = true;
  if (success) {
    LOG(INFO) << "Successfully performed refresh of package cache";
    // Now we need to get the list of updatable packages that we control so we
    // can perform upgrades on anything that's available.
    // This object is intentionally leaked and will clean itself up when done
    // with all the D-Bus communication.
    GetUpdatesTransaction* transaction = new GetUpdatesTransaction(
        bus, packagekit_proxy, packagekit_service_proxy);
    transaction->StartTransaction();
  } else {
    LOG(ERROR) << "Failure performing refresh of package cache, output: "
               << output;
  }
  base::SingleThreadTaskRunner::GetCurrentDefault()->PostDelayedTask(
      FROM_HERE,
      base::BindOnce(&RunAptUpdate, bus, packagekit_proxy,
                     packagekit_service_proxy),
      kRefreshCachePeriod);
}

// Sublcass for handling Resolve transaction.
class ResolveTransaction : public PackageKitTransaction {
 public:
  ResolveTransaction(scoped_refptr<dbus::Bus> bus,
                     PackageKitProxy* packagekit_proxy,
                     scoped_refptr<dbus::ObjectProxy> packagekit_service_proxy,
                     const std::string& package_name,
                     PackageKitProxy::PackageSearchCallback callback)
      : PackageKitTransaction(
            bus,
            packagekit_proxy,
            packagekit_service_proxy,
            kErrorCodeSignalMask | kFinishedSignalMask | kPackageSignalMask),
        package_name_(package_name),
        callback_(std::move(callback)) {}

  bool ExecuteRequest(dbus::ObjectProxy* transaction_proxy) override {
    dbus::MethodCall method_call(kPackageKitTransactionInterface,
                                 kResolveMethod);
    dbus::MessageWriter writer(&method_call);
    writer.AppendUint64(kPackageKitFilterNone);
    writer.AppendArrayOfStrings({package_name_});
    std::unique_ptr<dbus::Response> dbus_response =
        transaction_proxy->CallMethodAndBlockWithErrorDetails(
            &method_call, dbus::ObjectProxy::TIMEOUT_USE_DEFAULT, &dbus_error_);
    return !!dbus_response;
  }

  void GeneralError(const std::string& details) override {
    LOG(ERROR) << "Problem with Resolve transaction for package: "
               << package_name_ << ": " << details;
    // Check if we've already done the callback.
    if (!callback_)
      return;
    std::move(callback_).Run(false /*success*/, false /*pkg_found*/,
                             PackageKitProxy::LinuxPackageInfo(), details);
  }

  void ErrorReceived(uint32_t error_code, const std::string& details) override {
    LOG(ERROR) << "Failure resolving package " << package_name_ << ": "
               << details;
    // Check if we've already done the callback.
    if (!callback_)
      return;
    // We will still get a Finished signal where we finalize everything, but
    // no need to wait for it.
    std::move(callback_).Run(false /*success*/, false /*pkg_found*/,
                             PackageKitProxy::LinuxPackageInfo(), details);
  }

  void PackageReceived(uint32_t code,
                       const std::string& package_id,
                       const std::string& summary) override {
    LOG(INFO) << "Got a package for package name: " << package_name_;
    // Check if we've already done the callback.
    if (!callback_)
      return;
    PackageKitProxy::LinuxPackageInfo pkg_info;
    pkg_info.package_id = package_id;
    pkg_info.summary = summary;
    std::move(callback_).Run(true /*success*/, true /*pkg_found*/, pkg_info,
                             "");
  }

  void FinishedReceived(uint32_t exit_code) override {
    LOG(INFO) << "Finished resolving package name";
    if (!callback_)
      return;

    // If we got here without calling the callback, PackageKit couldn't resolve
    // the package name into a package id.
    std::move(callback_).Run(true /*success*/, false /*pkg_found*/,
                             PackageKitProxy::LinuxPackageInfo(), "");
  }

 private:
  std::string package_name_;
  PackageKitProxy::PackageSearchCallback callback_;
};

}  // namespace

PackageKitProxy::BlockingOperationActiveClearer::BlockingOperationActiveClearer(
    base::Lock* blocking_operation_active_mutex,
    bool* blocking_operation_active)
    : blocking_operation_active_mutex_(blocking_operation_active_mutex),
      blocking_operation_active_(blocking_operation_active) {}

PackageKitProxy::BlockingOperationActiveClearer::
    ~BlockingOperationActiveClearer() {
  base::AutoLock auto_lock(*blocking_operation_active_mutex_);
  *blocking_operation_active_ = false;
}

PackageKitProxy::PackageInfoTransactionData::PackageInfoTransactionData(
    const base::FilePath& file_path_in,
    std::shared_ptr<LinuxPackageInfo> pkg_info_in)
    : file_path(file_path_in),
      event(base::WaitableEvent::ResetPolicy::AUTOMATIC,
            base::WaitableEvent::InitialState::NOT_SIGNALED),
      pkg_info(pkg_info_in) {}

PackageKitProxy::PackageInfoTransactionData::PackageInfoTransactionData(
    const std::string& package_id_in,
    std::shared_ptr<LinuxPackageInfo> pkg_info_in)
    : package_id(package_id_in),
      event(base::WaitableEvent::ResetPolicy::AUTOMATIC,
            base::WaitableEvent::InitialState::NOT_SIGNALED),
      pkg_info(pkg_info_in) {}

// static
std::unique_ptr<PackageKitProxy> PackageKitProxy::Create(
    PackageKitObserver* observer) {
  if (!observer)
    return nullptr;
  auto pk_proxy = base::WrapUnique(new PackageKitProxy(observer));
  if (!pk_proxy->Init()) {
    pk_proxy.reset();
  }
  return pk_proxy;
}

PackageKitProxy::PackageKitProxy(PackageKitObserver* observer)
    : task_runner_(base::SingleThreadTaskRunner::GetCurrentDefault()),
      observer_(observer),
      blocking_operation_active_(false) {}

PackageKitProxy::~PackageKitProxy() = default;

bool PackageKitProxy::Init() {
  DCHECK(sequence_checker_.CalledOnValidSequence());

  dbus::Bus::Options opts;
  opts.bus_type = dbus::Bus::SYSTEM;
  bus_ = new dbus::Bus(std::move(opts));
  if (!bus_->Connect()) {
    LOG(ERROR) << "Failed to connect to system bus";
    return false;
  }
  packagekit_service_proxy_ = bus_->GetObjectProxy(
      kPackageKitServiceName, dbus::ObjectPath(kPackageKitServicePath));
  if (!packagekit_service_proxy_) {
    LOG(ERROR) << "Failed to get PackageKit D-Bus proxy";
    return false;
  }
  packagekit_service_proxy_->WaitForServiceToBeAvailable(base::BindOnce(
      &PackageKitProxy::OnPackageKitServiceAvailable, base::Unretained(this)));

  // Fire off a delayed task to do a repo update so that we can do automatic
  // upgrades on our managed packages.
  task_runner_->PostDelayedTask(
      FROM_HERE,
      base::BindOnce(&RunAptUpdate, bus_, base::Unretained(this),
                     packagekit_service_proxy_),
      kRefreshCacheStartupDelay);
  return true;
}

bool PackageKitProxy::GetLinuxPackageInfoFromFilePath(
    const base::FilePath& file_path,
    std::shared_ptr<LinuxPackageInfo> out_pkg_info,
    std::string* out_error) {
  CHECK(out_error);
  // We use another var for the error message into the D-Bus thread call so we
  // don't have contention with that var in the case of a timeout since we want
  // to set the error in a timeout, but not the pkg_info. Shared pointers are
  // used so that if the call times out the pointers are still valid on the
  // D-Bus thread.
  std::shared_ptr<PackageInfoTransactionData> data =
      std::make_shared<PackageInfoTransactionData>(file_path, out_pkg_info);
  task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(&PackageKitProxy::GetLinuxPackageInfoOnDBusThread,
                     base::Unretained(this), data));

  bool result;
  if (!data->event.TimedWait(kGetLinuxPackageInfoTimeout)) {
    LOG(ERROR) << "Timeout waiting on Linux package info";
    out_error->assign("Timeout");
    result = false;
  } else {
    out_error->assign(data->error);
    result = data->result;
  }
  return result;
}

bool PackageKitProxy::GetLinuxPackageInfoFromPackageName(
    const std::string& package_name,
    std::shared_ptr<LinuxPackageInfo> out_pkg_info,
    std::string* out_error) {
  CHECK(out_error);
  // We use another var for the error message into the D-Bus thread call so we
  // don't have contention with that var in the case of a timeout since we want
  // to set the error in a timeout, but not the pkg_info. Shared pointers are
  // used so that if the call times out the pointers are still valid on the
  // D-Bus thread.

  // We put |package_name| into the |package_id| field because we use it in an
  // error message later.
  std::shared_ptr<PackageInfoTransactionData> data =
      std::make_shared<PackageInfoTransactionData>(package_name, out_pkg_info);

  ResolvePackageName(
      package_name,
      base::BindOnce(
          &PackageKitProxy::
              GetLinuxPackageInfoFromPackageNameResolvePackageNameCallback,
          base::Unretained(this), data, out_error));

  bool result;
  if (!data->event.TimedWait(kGetLinuxPackageInfoTimeout)) {
    LOG(ERROR) << "Timeout waiting on Linux package info";
    out_error->assign("Timeout");
    result = false;
  } else {
    out_error->assign(data->error);
    result = data->result;
  }
  return result;
}

void PackageKitProxy::ResolvePackageName(const std::string& package_name,
                                         PackageSearchCallback callback) {
  LOG(INFO) << "Resolving package name: " << package_name;
  task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(&PackageKitProxy::ResolvePackageNameOnDBusThread,
                     base::Unretained(this), package_name,
                     std::move(callback)));
}

void PackageKitProxy::
    GetLinuxPackageInfoFromPackageNameResolvePackageNameCallback(
        std::shared_ptr<PackageInfoTransactionData> data,
        std::string* out_error,
        bool success,
        bool pkg_resolved,
        const LinuxPackageInfo& pkg_info,
        const std::string& error) {
  DCHECK(sequence_checker_.CalledOnValidSequence());
  if (!success) {
    data->error =
        "GetLinuxPackageInfoFromPackageName failed at resolve package name "
        "step: " +
        error;
    data->result = false;
    LOG(ERROR) << data->error;
    data->event.Signal();
    return;
  }

  if (!pkg_resolved) {
    data->error = "GetLinuxPackageInfoFromPackageName failed to resolve: " +
                  data->package_id + " into a package_id";
    data->result = false;
    LOG(ERROR) << data->error;
    data->event.Signal();
    return;
  }
  LOG(INFO) << "Getting package details for " << pkg_info.package_id;
  data->package_id = pkg_info.package_id;
  // This object is intentionally leaked and will clean itself up when done
  // with all the D-Bus communication.
  task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(&PackageKitProxy::GetLinuxPackageInfoOnDBusThread,
                     base::Unretained(this), data));
}

vm_tools::container::InstallLinuxPackageResponse::Status
PackageKitProxy::InstallLinuxPackageFromFilePath(
    const base::FilePath& file_path,
    const std::string& command_uuid,
    std::string* out_error) {
  // Make sure we don't already have one in progress.
  {  // Scope mutex lock
    base::AutoLock auto_lock(blocking_operation_active_mutex_);
    if (blocking_operation_active_) {
      *out_error = "Install or other blocking operation is already active";
      LOG(ERROR) << *out_error;
      return vm_tools::container::InstallLinuxPackageResponse::
          INSTALL_ALREADY_ACTIVE;
    }
    blocking_operation_active_ = true;
  }  // Release mutex lock
  // We own blocking_operation_active, make sure we clear it later.
  auto clearer = std::make_unique<BlockingOperationActiveClearer>(
      &blocking_operation_active_mutex_, &blocking_operation_active_);
  task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(
          &PackageKitProxy::InstallLinuxPackageFromFilePathOnDBusThread,
          base::Unretained(this), file_path, command_uuid, std::move(clearer)));
  return vm_tools::container::InstallLinuxPackageResponse::STARTED;
}

vm_tools::container::InstallLinuxPackageResponse::Status
PackageKitProxy::InstallLinuxPackageFromPackageId(
    const std::string& package_id,
    const std::string& command_uuid,
    std::string* out_error) {
  // Make sure we don't already have one in progress.
  {  // Scope mutex lock
    base::AutoLock auto_lock(blocking_operation_active_mutex_);
    if (blocking_operation_active_) {
      *out_error = "Install or other blocking operation is already active";
      LOG(ERROR) << *out_error;
      return vm_tools::container::InstallLinuxPackageResponse::
          INSTALL_ALREADY_ACTIVE;
    }
    blocking_operation_active_ = true;
  }  // Release mutex lock
  // We own blocking_operation_active, make sure we clear it later.
  auto clearer = std::make_unique<BlockingOperationActiveClearer>(
      &blocking_operation_active_mutex_, &blocking_operation_active_);
  task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(
          &PackageKitProxy::InstallLinuxPackageFromPackageIdOnDBusThread,
          base::Unretained(this), package_id, command_uuid,
          std::move(clearer)));
  return vm_tools::container::InstallLinuxPackageResponse::STARTED;
}

vm_tools::container::UninstallPackageOwningFileResponse::Status
PackageKitProxy::UninstallPackageOwningFile(const base::FilePath& file_path,
                                            std::string* out_error) {
  // Fail if there is a blocking operation in progress.
  {  // Scope mutex lock
    base::AutoLock auto_lock(blocking_operation_active_mutex_);
    if (blocking_operation_active_) {
      *out_error = "Uninstall or other blocking operation is already active";
      LOG(ERROR) << *out_error;
      return vm_tools::container::UninstallPackageOwningFileResponse::
          BLOCKING_OPERATION_IN_PROGRESS;
    }
    blocking_operation_active_ = true;
  }  // Release mutex lock
  // We own blocking_operation_active, make sure we clear it later.
  auto clearer = std::make_unique<BlockingOperationActiveClearer>(
      &blocking_operation_active_mutex_, &blocking_operation_active_);

  // Start search
  PackageSearchCallback callback = base::BindOnce(
      &PackageKitProxy::UninstallPackageOwningFileSearchForFileCallback,
      base::Unretained(this), file_path, std::move(clearer));
  SearchLinuxPackagesForFile(file_path, std::move(callback));
  return vm_tools::container::UninstallPackageOwningFileResponse::STARTED;
}

void PackageKitProxy::UninstallPackageOwningFileSearchForFileCallback(
    base::FilePath file_path,
    std::unique_ptr<BlockingOperationActiveClearer>
        blocking_operation_active_lock,
    bool success,
    bool pkg_found,
    const LinuxPackageInfo& pkg_info,
    const std::string& error) {
  DCHECK(sequence_checker_.CalledOnValidSequence());
  if (!success) {
    LOG(ERROR) << "UninstallPackageOwningFile failed at search package step: "
               << error;
    if (observer_) {
      observer_->OnUninstallCompletion(false, error);
    }
    return;
  }

  if (!pkg_found) {
    LOG(ERROR) << "UninstallPackageOwningFile failed to find a package for "
               << file_path.value();
    if (observer_) {
      observer_->OnUninstallCompletion(
          false, "Could not find package that owns " + file_path.value());
    }
    return;
  }
  LOG(INFO) << "Uninstalling Linux package " << pkg_info.package_id;
  // This object is intentionally leaked and will clean itself up when done
  // with all the D-Bus communication.
  UninstallPackagesTransaction* transaction = new UninstallPackagesTransaction(
      bus_, this, packagekit_service_proxy_, pkg_info.package_id,
      std::move(blocking_operation_active_lock), observer_);
  transaction->StartTransaction();
}

void PackageKitProxy::SearchLinuxPackagesForFile(
    const base::FilePath& file_path, PackageSearchCallback callback) {
  LOG(INFO) << "Searching for local Linux package that owns "
            << file_path.value();
  task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(&PackageKitProxy::SearchLinuxPackagesForFileOnDBusThread,
                     base::Unretained(this), file_path, std::move(callback)));
}

void PackageKitProxy::AddPackageKitDeathObserver(
    PackageKitDeathObserver* observer) {
  DCHECK(sequence_checker_.CalledOnValidSequence());
  death_observers_.AddObserver(observer);
}

void PackageKitProxy::RemovePackageKitDeathObserver(
    PackageKitDeathObserver* observer) {
  DCHECK(sequence_checker_.CalledOnValidSequence());
  death_observers_.RemoveObserver(observer);
}

void PackageKitProxy::GetLinuxPackageInfoOnDBusThread(
    std::shared_ptr<PackageInfoTransactionData> data) {
  DCHECK(sequence_checker_.CalledOnValidSequence());
  LOG(INFO) << "Getting information on Linux package";
  // This object is intentionally leaked and will clean itself up when done
  // with all the D-Bus communication.
  GetDetailsTransaction* transaction =
      new GetDetailsTransaction(bus_, this, packagekit_service_proxy_, data);
  transaction->StartTransaction();
}

void PackageKitProxy::InstallLinuxPackageFromFilePathOnDBusThread(
    const base::FilePath& file_path,
    const std::string& command_uuid,
    std::unique_ptr<BlockingOperationActiveClearer> clearer) {
  DCHECK(sequence_checker_.CalledOnValidSequence());
  // This object is intentionally leaked and will clean itself up when done
  // with all the D-Bus communication.
  InstallTransaction* transaction =
      new InstallTransaction(bus_, this, packagekit_service_proxy_, observer_,
                             file_path, command_uuid, std::move(clearer));
  transaction->StartTransaction();
}

void PackageKitProxy::InstallLinuxPackageFromPackageIdOnDBusThread(
    const std::string& package_id,
    const std::string& command_uuid,
    std::unique_ptr<BlockingOperationActiveClearer> clearer) {
  DCHECK(sequence_checker_.CalledOnValidSequence());
  // This object is intentionally leaked and will clean itself up when done
  // with all the D-Bus communication.
  InstallTransaction* transaction =
      new InstallTransaction(bus_, this, packagekit_service_proxy_, observer_,
                             package_id, command_uuid, std::move(clearer));
  transaction->StartTransaction();
}

void PackageKitProxy::SearchLinuxPackagesForFileOnDBusThread(
    const base::FilePath& file_path, PackageSearchCallback callback) {
  DCHECK(sequence_checker_.CalledOnValidSequence());
  // This object is intentionally leaked and will clean itself up when done
  // with all the D-Bus communication.
  SearchFilesTransaction* transaction = new SearchFilesTransaction(
      bus_, this, packagekit_service_proxy_, file_path, std::move(callback));
  transaction->StartTransaction();
}

void PackageKitProxy::ResolvePackageNameOnDBusThread(
    const std::string& package_name, PackageSearchCallback callback) {
  DCHECK(sequence_checker_.CalledOnValidSequence());
  // This object is intentionally leaked and will clean itself up when done
  // with all the D-Bus communication.
  ResolveTransaction* transaction = new ResolveTransaction(
      bus_, this, packagekit_service_proxy_, package_name, std::move(callback));
  transaction->StartTransaction();
}

void PackageKitProxy::OnPackageKitNameOwnerChanged(
    const std::string& old_owner, const std::string& new_owner) {
  DCHECK(sequence_checker_.CalledOnValidSequence());
  if (new_owner.empty()) {
    for (PackageKitDeathObserver& obs : death_observers_)
      obs.OnPackageKitDeath();
  }
}

void PackageKitProxy::OnPackageKitServiceAvailable(bool service_is_available) {
  if (service_is_available) {
    packagekit_service_proxy_->SetNameOwnerChangedCallback(
        base::BindRepeating(&PackageKitProxy::OnPackageKitNameOwnerChanged,
                            base::Unretained(this)));
  }
}

}  // namespace garcon
}  // namespace vm_tools
