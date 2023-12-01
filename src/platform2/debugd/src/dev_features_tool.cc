// Copyright 2014 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "debugd/src/dev_features_tool.h"

#include <functional>
#include <utility>

#include <base/check.h>
#include <base/functional/bind.h>
#include <base/functional/callback.h>
#include <chromeos/dbus/service_constants.h>

#include "debugd/src/error_utils.h"
#include "debugd/src/process_with_output.h"

namespace debugd {

namespace {

using ArgList = ProcessWithOutput::ArgList;

const char kDefaultRootPassword[] = "test0000";

const char kDevFeaturesErrorString[] = "org.chromium.debugd.error.DevFeatures";
const char kRootfsLockedErrorString[] =
    "Rootfs verification must be removed first";

// Executes a helper process with the expectation that any message printed to
// stderr indicates a failure that should be passed back over the D-Bus.
// Returns false if any errors launching the process occur. Returns true
// otherwise, and sets |exit_status| if it isn't null.
bool RunHelper(const std::string& command,
               const ArgList& arguments,
               bool requires_root,
               const std::string* stdin,
               int* exit_status,
               brillo::ErrorPtr* error) {
  std::string stderr;
  int result =
      ProcessWithOutput::RunHelper(command, arguments, requires_root, stdin,
                                   nullptr,  // Don't need stdout.
                                   &stderr, error);
  if (!stderr.empty()) {
    DEBUGD_ADD_ERROR(error, kDevFeaturesErrorString, stderr.c_str());
    return false;
  }

  if (exit_status)
    *exit_status = result;
  return true;
}

bool RemoveRootfsVerificationQuery(int* exit_status, brillo::ErrorPtr* error) {
  return RunHelper("dev_features_rootfs_verification", ArgList{"-q"},
                   true,     // requires root to check if / is writable by root.
                   nullptr,  // no stdin.
                   exit_status, error);
}

bool EnableBootFromUsbQuery(int* exit_status, brillo::ErrorPtr* error) {
  return RunHelper("dev_features_usb_boot", ArgList{"-q"},
                   true,     // requires root for crossystem queries.
                   nullptr,  // no stdin.
                   exit_status, error);
}

bool ConfigureSshServerQuery(int* exit_status, brillo::ErrorPtr* error) {
  return RunHelper("dev_features_ssh", ArgList{"-q"},
                   true,     // needs root to check for files in 700 folders.
                   nullptr,  // no stdin.
                   exit_status, error);
}

bool EnableChromeRemoteDebuggingQuery(int* exit_status,
                                      brillo::ErrorPtr* error) {
  return RunHelper("dev_features_chrome_remote_debugging", ArgList{"-q"}, false,
                   nullptr,  // no stdin.
                   exit_status, error);
}

bool SetUserPasswordQuery(const std::string& username,
                          bool system,
                          int* exit_status,
                          brillo::ErrorPtr* error) {
  ArgList args{"-q", "--user=" + username};
  if (system)
    args.push_back("--system");

  return RunHelper("dev_features_password", args,
                   true,     // requires root to read either password file.
                   nullptr,  // no stdin.
                   exit_status, error);
}

}  // namespace

bool DevFeaturesTool::RemoveRootfsVerification(brillo::ErrorPtr* error) const {
  return RunHelper("dev_features_rootfs_verification", ArgList{},
                   true,     // requires root for make_dev_ssd.sh script.
                   nullptr,  // no stdin.
                   nullptr,  // exit status doesn't matter.
                   error);
}

bool DevFeaturesTool::EnableBootFromUsb(brillo::ErrorPtr* error) const {
  return RunHelper("dev_features_usb_boot", ArgList{},
                   true,     // requires root for enable_dev_usb_boot script.
                   nullptr,  // no stdin.
                   nullptr,  // exit status doesn't matter.
                   error);
}

bool DevFeaturesTool::ConfigureSshServer(brillo::ErrorPtr* error) const {
  // SSH server configuration requires writing to rootfs.
  int exit_status;
  if (!RemoveRootfsVerificationQuery(&exit_status, error) || exit_status != 0) {
    DEBUGD_ADD_ERROR(error, kDevFeaturesErrorString, kRootfsLockedErrorString);
    return false;
  }

  return RunHelper("dev_features_ssh", ArgList{},
                   true,     // requires root to write to rootfs directories.
                   nullptr,  // no stdin.
                   nullptr,  // exit status doesn't matter.
                   error);
}

bool DevFeaturesTool::EnableChromeRemoteDebugging(
    brillo::ErrorPtr* error) const {
  int exit_status;
  if (!RemoveRootfsVerificationQuery(&exit_status, error) || exit_status != 0) {
    DEBUGD_ADD_ERROR(error, kDevFeaturesErrorString, kRootfsLockedErrorString);
    return false;
  }

  return RunHelper("dev_features_chrome_remote_debugging", ArgList{},
                   true,     // requires root to write to rootfs directories.
                   nullptr,  // no stdin.
                   nullptr,  // exit status doesn't matter.
                   error);
}

bool DevFeaturesTool::SetUserPassword(const std::string& username,
                                      const std::string& password,
                                      brillo::ErrorPtr* error) const {
  ArgList args{"--user=" + username};

  // Set the devmode password regardless of rootfs verification state.
  if (!RunHelper("dev_features_password", args,
                 true,       // requires root to write devmode password file.
                 &password,  // pipe the password through stdin.
                 nullptr,    // exit status doesn't matter.
                 error)) {
    return false;  // DEBUGD_ADD_ERROR is already called.
  }

  // If rootfs is locked, don't bother setting the system password.
  int exit_status;
  if (!RemoveRootfsVerificationQuery(&exit_status, error) || exit_status != 0)
    return true;

  args.push_back("--system");
  return RunHelper("dev_features_password", args,
                   true,       // requires root to write system password file.
                   &password,  // pipe the password through stdin.
                   nullptr,    // exit status doesn't matter.
                   error);
}

bool DevFeaturesTool::EnableChromeDevFeatures(const std::string& root_password,
                                              brillo::ErrorPtr* error) const {
  if (!EnableBootFromUsb(error))
    return false;  // DEBUGD_ADD_ERROR is already called.

  if (!ConfigureSshServer(error))
    return false;  // DEBUGD_ADD_ERROR is already called.

  return SetUserPassword(
      "root", root_password.empty() ? kDefaultRootPassword : root_password,
      error);
}

namespace {

struct Query {
  // The callback should launch the query program. If launching fails, return
  // false and set the error. If it succeeds, put the exit status in the
  // integer out-argument.
  using Function = base::OnceCallback<bool(int*, brillo::ErrorPtr*)>;

  Function function;
  DevFeatureFlag flag;
};

}  // namespace

bool DevFeaturesTool::QueryDevFeatures(int32_t* flags,
                                       brillo::ErrorPtr* error) const {
  DCHECK(flags);
  Query queries[] = {
      {base::BindOnce(&RemoveRootfsVerificationQuery),
       DEV_FEATURE_ROOTFS_VERIFICATION_REMOVED},
      {base::BindOnce(&EnableBootFromUsbQuery),
       DEV_FEATURE_BOOT_FROM_USB_ENABLED},
      {base::BindOnce(&EnableChromeRemoteDebuggingQuery),
       DEV_FEATURE_CHROME_REMOTE_DEBUGGING_ENABLED},
      {base::BindOnce(&ConfigureSshServerQuery),
       DEV_FEATURE_SSH_SERVER_CONFIGURED},
      {base::BindOnce(&SetUserPasswordQuery, "root", /* system = */ false),
       DEV_FEATURE_DEV_MODE_ROOT_PASSWORD_SET},
      {base::BindOnce(&SetUserPasswordQuery, "root", /* system = */ true),
       DEV_FEATURE_SYSTEM_ROOT_PASSWORD_SET}};

  int32_t result_flags = 0;
  for (auto& query : queries) {
    int exit_status;
    if (!std::move(query.function).Run(&exit_status, error)) {
      // D-Bus is only set up to handle a single error so exit as soon as we
      // hit one.
      return false;  // DEBUGD_ADD_ERROR is already called.
    }
    if (exit_status == 0)
      result_flags |= query.flag;
  }
  *flags = result_flags;
  return true;
}

}  // namespace debugd
