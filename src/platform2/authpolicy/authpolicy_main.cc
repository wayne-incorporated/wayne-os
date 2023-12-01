// Copyright 2016 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>

#include <base/check.h>
#include <base/logging.h>
#include <base/memory/ptr_util.h>
#include <base/memory/weak_ptr.h>
#include <brillo/daemons/dbus_daemon.h>
#include <brillo/syslog_logging.h>
#include <brillo/userdb_utils.h>
#include <install_attributes/libinstallattributes.h>

#include "authpolicy/authpolicy.h"
#include "authpolicy/constants.h"
#include "authpolicy/path_service.h"
#include "authpolicy/platform_helper.h"

namespace {

const char kObjectServicePath[] = "/org/chromium/AuthPolicy/ObjectManager";
const char kAuthPolicydUser[] = "authpolicyd";
const char kAuthPolicydExecUser[] = "authpolicyd-exec";

const int kExitCodeStartupFailure = 175;  // This number is hex AF.

}  // namespace

namespace authpolicy {

class Daemon : public brillo::DBusServiceDaemon {
 public:
  explicit Daemon(bool device_is_locked)
      : DBusServiceDaemon(kAuthPolicyServiceName, kObjectServicePath),
        device_is_locked_(device_is_locked),
        weak_ptr_factory_(this) {}
  Daemon(const Daemon&) = delete;
  Daemon& operator=(const Daemon&) = delete;

  // Cleans the authpolicy daemon state directory. Returns true if all files
  // were cleared.
  static bool CleanState() {
    PathService path_service;
    return AuthPolicy::CleanState(&path_service);
  }

 protected:
  void RegisterDBusObjectsAsync(
      brillo::dbus_utils::AsyncEventSequencer* sequencer) override {
    brillo::dbus_utils::AsyncEventSequencer::Handler handler =
        sequencer->GetHandler("AuthPolicy.RegisterAsync() failed.", true);
    authpolicy_.RegisterAsync(
        AuthPolicy::GetDBusObject(object_manager_.get()),
        base::BindOnce(&Daemon::OnAuthPolicyRegistered,
                       weak_ptr_factory_.GetWeakPtr(), std::move(handler)));
  }

 private:
  void OnAuthPolicyRegistered(
      brillo::dbus_utils::AsyncEventSequencer::Handler handler, bool success) {
    // If it wasn't successful, the sequencer handler should print an error and
    // exit.
    std::move(handler).Run(success);
    CHECK(success);
    LOG(INFO) << "authpolicyd started";

    // Initialize authpolicy here, so that stuff like the machine password check
    // happens after the daemon is registered.
    ErrorType error = authpolicy_.Initialize(device_is_locked_);
    if (error != ERROR_NONE) {
      LOG(ERROR) << "SambaInterface failed to initialize with error code "
                 << error;
      exit(kExitCodeStartupFailure);
    }
  }

  bool device_is_locked_;

  // Keep this order! |authpolicy_| must be last as it depends on the other two.
  AuthPolicyMetrics metrics_;
  PathService path_service_;
  AuthPolicy authpolicy_{&metrics_, &path_service_};

  base::WeakPtrFactory<Daemon> weak_ptr_factory_;
};

}  // namespace authpolicy

int main(int /* argc */, char* /* argv */[]) {
  brillo::OpenLog("authpolicyd", true);
  brillo::InitLog(brillo::kLogToSyslog);

  // Verify we're running as authpolicyd user.
  uid_t authpolicyd_uid;
  CHECK(
      brillo::userdb::GetUserInfo(kAuthPolicydUser, &authpolicyd_uid, nullptr));
  if (authpolicyd_uid != authpolicy::GetEffectiveUserId()) {
    LOG(ERROR) << "Failed to verify effective UID (must run as authpolicyd).";
    exit(kExitCodeStartupFailure);
  }

  // Make it possible to switch to authpolicyd-exec without caps and drop caps.
  uid_t authpolicyd_exec_uid;
  CHECK(brillo::userdb::GetUserInfo(kAuthPolicydExecUser, &authpolicyd_exec_uid,
                                    nullptr));
  if (!authpolicy::SetSavedUserAndDropCaps(authpolicyd_exec_uid)) {
    LOG(ERROR) << "Failed to establish user ids and drop caps.";
    exit(kExitCodeStartupFailure);
  }

  // Safety check to ensure that authpolicyd cannot run after the device has
  // been locked to a mode other than enterprise_ad.  (The lifetime management
  // of authpolicyd happens through upstart, this check only serves as a second
  // line of defense.)
  bool device_is_locked = false;
  InstallAttributesReader install_attributes_reader;
  if (install_attributes_reader.IsLocked()) {
    const std::string& mode = install_attributes_reader.GetAttribute(
        InstallAttributesReader::kAttrMode);
    if (mode != InstallAttributesReader::kDeviceModeEnterpriseAD) {
      LOG(ERROR) << "OOBE completed but device not in Active Directory "
                    "management mode. Cleaning state and exiting.";
      CHECK(authpolicy::Daemon::CleanState());
      exit(kExitCodeStartupFailure);
    } else {
      LOG(INFO) << "Install attributes locked to Active Directory mode.";

      // A configuration file should be present in this case.
      device_is_locked = true;
    }
  } else {
    LOG(INFO) << "No install attributes found. Cleaning state.";
    CHECK(authpolicy::Daemon::CleanState());
  }

  // Run daemon.
  LOG(INFO) << "authpolicyd starting";
  authpolicy::Daemon daemon(device_is_locked);
  int res = daemon.Run();
  LOG(INFO) << "authpolicyd stopping with exit code " << res;

  return res;
}
