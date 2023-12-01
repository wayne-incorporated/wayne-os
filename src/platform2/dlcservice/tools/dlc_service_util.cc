// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <sysexits.h>
#include <unistd.h>

#include <fstream>
#include <iostream>
#include <set>
#include <string>
#include <vector>

#include <base/check.h>
#include <base/check_op.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/json/json_writer.h>
#include <base/notreached.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_piece.h>
#include <base/strings/string_split.h>
#include <base/strings/string_util.h>
#include <base/values.h>
#include <brillo/daemons/daemon.h>
#include <brillo/flag_helper.h>
#include <chromeos/constants/imageloader.h>
#include <dbus/bus.h>
#include <dlcservice/proto_bindings/dlcservice.pb.h>
#include <libimageloader/manifest.h>
#include <libminijail.h>
#include <scoped_minijail.h>

#include "dlcservice/dbus-proxies.h"
#include "dlcservice/proto_utils.h"
#include "dlcservice/utils.h"

using base::FilePath;
using base::Value;
using Dict = base::Value::Dict;
using List = base::Value::List;
using dlcservice::DlcState;
using dlcservice::DlcsWithContent;
using org::chromium::DlcServiceInterfaceProxy;
using std::string;
using std::vector;

namespace {

constexpr uid_t kRootUid = 0;
constexpr uid_t kChronosUid = 1000;
constexpr uid_t kDlcServiceUid = 20118;
constexpr char kDlcServiceUser[] = "dlcservice";
constexpr char kDlcServiceGroup[] = "dlcservice";

void EnterMinijail() {
  ScopedMinijail jail(minijail_new());
  CHECK_EQ(0, minijail_change_user(jail.get(), kDlcServiceUser));
  CHECK_EQ(0, minijail_change_group(jail.get(), kDlcServiceGroup));
  minijail_inherit_usergroups(jail.get());
  minijail_no_new_privs(jail.get());
  minijail_enter(jail.get());
}

string ErrorPtrStr(const brillo::ErrorPtr& err) {
  std::ostringstream err_stream;
  err_stream << "Domain=" << err->GetDomain() << " "
             << "Error Code=" << err->GetCode() << " "
             << "Error Message=" << err->GetMessage();
  // TODO(crbug.com/999284): No inner error support, err->GetInnerError().
  return err_stream.str();
}

}  // namespace

class DlcServiceUtil : public brillo::Daemon {
 public:
  DlcServiceUtil(int argc, const char** argv)
      : argc_(argc), argv_(argv), weak_ptr_factory_(this) {}
  ~DlcServiceUtil() override = default;

 private:
  int OnEventLoopStarted() override {
    // "--install" related flags.
    DEFINE_bool(install, false, "Install a single DLC.");
    DEFINE_string(omaha_url, "",
                  "Overrides the default Omaha URL in the update_engine.");
    DEFINE_bool(reserve, false, "Reserve the DLC on install success/failure.");

    // "--uninstall" related flags.
    DEFINE_bool(uninstall, false, "Uninstall a single DLC.");

    // "--purge" related flags.
    DEFINE_bool(purge, false, "Purge a single DLC.");

    // "--install", "--purge", and "--uninstall" related flags.
    DEFINE_string(id, "", "The ID of the DLC.");

    // "--dlc_state" related flags.
    DEFINE_bool(dlc_state, false, "Get the state of a given DLC.");

    // "--get_existing" related flags.
    DEFINE_bool(get_existing, false,
                "Returns a list of DLCs that have content on disk.");

    // "--list" related flags.
    DEFINE_bool(list, false, "List installed DLC(s).");
    DEFINE_string(dump, "",
                  "Path to dump to, by default will print to stdout.");

    brillo::FlagHelper::Init(argc_, argv_, "dlcservice_util");

    // Enforce mutually exclusive flags.
    vector<bool> exclusive_flags = {FLAGS_install,   FLAGS_uninstall,
                                    FLAGS_purge,     FLAGS_list,
                                    FLAGS_dlc_state, FLAGS_get_existing};
    if (std::count(exclusive_flags.begin(), exclusive_flags.end(), true) != 1) {
      LOG(ERROR) << "Only one of --install, --uninstall, --purge, --list, "
                    "--get_existing, --dlc_state must be set.";
      return EX_SOFTWARE;
    }

    int error = EX_OK;
    if (!Init(&error)) {
      LOG(ERROR) << "Failed to initialize client.";
      return error;
    }

    // Called with "--list".
    if (FLAGS_list) {
      vector<DlcState> installed_dlcs;
      if (!GetInstalled(&installed_dlcs))
        return EX_SOFTWARE;
      PrintInstalled(FLAGS_dump, installed_dlcs);
      Quit();
      return EX_OK;
    }

    // Called with "--get_existing".
    if (FLAGS_get_existing) {
      DlcsWithContent dlcs_with_content;
      if (!GetExisting(&dlcs_with_content))
        return EX_SOFTWARE;
      PrintDlcsWithContent(FLAGS_dump, dlcs_with_content);
      Quit();
      return EX_OK;
    }

    if (FLAGS_id.empty()) {
      LOG(ERROR) << "Please specify a single DLC ID.";
      Quit();
      return EX_SOFTWARE;
    }

    dlc_id_ = FLAGS_id;
    omaha_url_ = FLAGS_omaha_url;
    reserve_ = FLAGS_reserve;

    // Called with "--install".
    if (FLAGS_install) {
      // Set up callbacks
      dlc_service_proxy_->RegisterDlcStateChangedSignalHandler(
          base::BindRepeating(&DlcServiceUtil::OnDlcStateChanged,
                              weak_ptr_factory_.GetWeakPtr()),
          base::BindOnce(&DlcServiceUtil::OnDlcStateChangedConnect,
                         weak_ptr_factory_.GetWeakPtr()));
      if (Install()) {
        // Don't |Quit()| as we will need to wait for signal of install.
        return EX_OK;
      }
    }

    // Called with "--uninstall".
    if (FLAGS_uninstall) {
      if (Uninstall(false)) {
        Quit();
        return EX_OK;
      }
    }

    // Called with "--purge".
    if (FLAGS_purge) {
      if (Uninstall(true)) {
        Quit();
        return EX_OK;
      }
    }

    // Called with "--dlc_state".
    if (FLAGS_dlc_state) {
      DlcState state;
      if (!GetDlcState(dlc_id_, &state))
        return EX_SOFTWARE;
      PrintDlcState(FLAGS_dump, state);
      Quit();
      return EX_OK;
    }

    Quit();
    return EX_SOFTWARE;
  }

  // Initialize the dlcservice proxy. Returns true on success, false otherwise.
  // Sets the given error pointer on failure.
  bool Init(int* error_ptr) {
    dbus::Bus::Options options;
    options.bus_type = dbus::Bus::SYSTEM;
    scoped_refptr<dbus::Bus> bus{new dbus::Bus{options}};
    if (!bus->Connect()) {
      LOG(ERROR) << "Failed to connect to DBus.";
      *error_ptr = EX_UNAVAILABLE;
      return false;
    }
    dlc_service_proxy_ = std::make_unique<DlcServiceInterfaceProxy>(bus);

    return true;
  }

  // Callback invoked on receiving |OnDlcStateChanged| signal.
  void OnDlcStateChanged(const DlcState& dlc_state) {
    // Ignore the status as it's not the one we care about.
    if (dlc_state.id() != dlc_id_)
      return;
    switch (dlc_state.state()) {
      case DlcState::INSTALLED:
        LOG(INFO) << "Install successful for DLC: " << dlc_id_;
        Quit();
        break;
      case DlcState::INSTALLING:
        LOG(INFO) << static_cast<int>(dlc_state.progress() * 100)
                  << "% installed DLC: " << dlc_id_;
        break;
      case DlcState::NOT_INSTALLED:
        LOG(ERROR) << "Failed to install DLC: " << dlc_id_
                   << " with error code: " << dlc_state.last_error_code();
        QuitWithExitCode(EX_SOFTWARE);
        break;
      default:
        NOTREACHED();
    }
  }

  // Callback invoked on connecting |OnDlcStateChanged| signal.
  void OnDlcStateChangedConnect(const string& interface_name,
                                const string& signal_name,
                                bool success) {
    if (!success) {
      LOG(ERROR) << "Error connecting " << interface_name << "." << signal_name;
      QuitWithExitCode(EX_SOFTWARE);
    }
  }

  // Install current DLC module. Returns true if current module can be
  // installed. False otherwise.
  bool Install() {
    brillo::ErrorPtr err;
    LOG(INFO) << "Attempting to install DLC modules: " << dlc_id_;
    // TODO(b/177932564): Temporary increase in timeout to unblock CQ cases that
    // hit DLC installation while dlcservice is busy.
    auto install_request =
        dlcservice::CreateInstallRequest(dlc_id_, omaha_url_, reserve_);
    if (!dlc_service_proxy_->Install(install_request, &err,
                                     /*timeout_ms=*/5 * 60 * 1000)) {
      LOG(ERROR) << "Failed to install: " << dlc_id_ << ", "
                 << ErrorPtrStr(err);
      return false;
    }
    return true;
  }

  // Uninstalls or purges a list of DLC modules based on input argument
  // |purge|. Returns true if all uninstall/purge operations complete
  // successfully, false otherwise. Sets the given error pointer on failure.
  bool Uninstall(bool purge) {
    auto cmd_str = purge ? "purge" : "uninstall";
    brillo::ErrorPtr err;
    LOG(INFO) << "Attempting to " << cmd_str << " DLC: " << dlc_id_;
    bool result = purge ? dlc_service_proxy_->Purge(dlc_id_, &err)
                        : dlc_service_proxy_->Uninstall(dlc_id_, &err);
    if (!result) {
      LOG(ERROR) << "Failed to " << cmd_str << " DLC: " << dlc_id_ << ", "
                 << ErrorPtrStr(err);
      return false;
    }
    LOG(INFO) << "Successfully " << (purge ? "purged" : "uninstalled")
              << " DLC: " << dlc_id_;
    return true;
  }

  // Gets the state of current DLC module.
  bool GetDlcState(const string& id, DlcState* state) {
    brillo::ErrorPtr err;
    if (!dlc_service_proxy_->GetDlcState(id, state, &err)) {
      LOG(ERROR) << "Failed to get state of DLC " << dlc_id_ << ", "
                 << ErrorPtrStr(err);
      return false;
    }
    return true;
  }

  // Prints the DLC state.
  void PrintDlcState(const string& dump, const DlcState& state) {
    Dict dict;
    dict.Set("id", state.id());
    dict.Set("last_error_code", state.last_error_code());
    dict.Set("progress", state.progress());
    dict.Set("root_path", state.root_path());
    dict.Set("state", state.state());
    PrintToFileOrStdout(dump, Value(std::move(dict)));
  }

  // Retrieves a list of all installed DLC modules. Returns true if the list is
  // retrieved successfully, false otherwise. Sets the given error pointer on
  // failure.
  bool GetInstalled(vector<DlcState>* dlcs) {
    brillo::ErrorPtr err;
    vector<string> ids;
    if (!dlc_service_proxy_->GetInstalled(&ids, &err)) {
      LOG(ERROR) << "Failed to get the list of installed DLC modules, "
                 << ErrorPtrStr(err);
      return false;
    }

    for (const auto& id : ids) {
      DlcState dlc_state;
      if (GetDlcState(id, &dlc_state))
        dlcs->push_back(dlc_state);
    }
    return true;
  }

  // Prints the information for DLCs with content.
  void PrintDlcsWithContent(const string& dump,
                            const dlcservice::DlcsWithContent& dlcs) {
    List list;
    for (const auto& dlc_info : dlcs.dlc_infos()) {
      Dict info;
      info.Set("id", dlc_info.id());
      info.Set("name", dlc_info.name());
      info.Set("description", dlc_info.description());
      info.Set("used_bytes_on_disk",
               base::NumberToString(dlc_info.used_bytes_on_disk()));
      info.Set("is_removable", dlc_info.is_removable());
      list.Append(std::move(info));
    }
    PrintToFileOrStdout(dump, Value(std::move(list)));
  }

  // Retrieves a list of all existing DLC modules. Returns true if the list is
  // retrieved successfully, false otherwise.
  bool GetExisting(dlcservice::DlcsWithContent* dlcs) {
    brillo::ErrorPtr err;
    if (!dlc_service_proxy_->GetExistingDlcs(dlcs, &err)) {
      LOG(ERROR) << "Failed to get the list of existing DLC modules, "
                 << ErrorPtrStr(err);
      return false;
    }
    return true;
  }

  decltype(auto) GetPackages(const string& id) {
    return dlcservice::ScanDirectory(
        dlcservice::JoinPaths(imageloader::kDlcManifestRootpath, id));
  }

  std::shared_ptr<imageloader::Manifest> GetManifest(const string& id,
                                                     const string& package) {
    return dlcservice::GetDlcManifest(
        FilePath(imageloader::kDlcManifestRootpath), id, package);
  }

  // Helper to print to file, or stdout if |path| is empty.
  void PrintToFileOrStdout(const string& path, const Value& value) {
    string json;
    if (!base::JSONWriter::WriteWithOptions(
            value, base::JSONWriter::OPTIONS_PRETTY_PRINT, &json)) {
      LOG(ERROR) << "Failed to write json.";
      return;
    }
    if (!path.empty()) {
      if (!dlcservice::WriteToFile(FilePath(path), json))
        PLOG(ERROR) << "Failed to write to file " << path;
    } else {
      std::cout << json;
    }
  }

  void PrintInstalled(const string& dump, const vector<DlcState>& dlcs) {
    Dict dict;
    for (const auto& dlc_state : dlcs) {
      const auto& id = dlc_state.id();
      const auto& packages = GetPackages(id);
      if (packages.empty())
        continue;
      List dlc_info_list;
      for (const auto& package : packages) {
        auto manifest = GetManifest(id, package);
        if (!manifest)
          return;
        Dict dlc_info;
        dlc_info.Set("name", manifest->name());
        dlc_info.Set("id", manifest->id());
        dlc_info.Set("package", manifest->package());
        dlc_info.Set("version", manifest->version());
        dlc_info.Set("preallocated_size",
                     base::NumberToString(manifest->preallocated_size()));
        dlc_info.Set("size", base::NumberToString(manifest->size()));
        dlc_info.Set("image_type", manifest->image_type());
        switch (manifest->fs_type()) {
          case imageloader::FileSystem::kExt4:
            dlc_info.Set("fs-type", "ext4");
            break;
          case imageloader::FileSystem::kSquashFS:
            dlc_info.Set("fs-type", "squashfs");
            break;
        }
        dlc_info.Set(
            "manifest",
            dlcservice::JoinPaths(FilePath(imageloader::kDlcManifestRootpath),
                                  id, package, dlcservice::kManifestName)
                .value());
        dlc_info.Set("root_mount", dlc_state.root_path());
        dlc_info_list.Append(std::move(dlc_info));
      }
      dict.Set(id, std::move(dlc_info_list));
    }

    PrintToFileOrStdout(dump, Value(std::move(dict)));
  }

  std::unique_ptr<DlcServiceInterfaceProxy> dlc_service_proxy_;

  // argc and argv passed to main().
  int argc_;
  const char** argv_;

  // The ID of the current DLC.
  string dlc_id_;
  // Customized Omaha server URL (empty being the default URL).
  string omaha_url_;
  // Reserve the DLC on install success/failure.
  bool reserve_ = false;

  base::WeakPtrFactory<DlcServiceUtil> weak_ptr_factory_;

  DlcServiceUtil(const DlcServiceUtil&) = delete;
  DlcServiceUtil& operator=(const DlcServiceUtil&) = delete;
};

int main(int argc, const char** argv) {
  // Check user that is running dlcservice_util.
  switch (getuid()) {
    case kRootUid:
      EnterMinijail();
      break;
    case kChronosUid:
    case kDlcServiceUid:
      break;
    default:
      LOG(ERROR) << "dlcservice_util can only be run as "
                    "root, chronos, or dlcservice";
      return 1;
  }
  DlcServiceUtil client(argc, argv);
  return client.Run();
}
