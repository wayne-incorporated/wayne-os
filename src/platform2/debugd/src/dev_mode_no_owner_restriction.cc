// Copyright 2014 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "debugd/src/dev_mode_no_owner_restriction.h"

#include <memory>
#include <string>
#include <vector>

#include <chromeos/dbus/service_constants.h>
#include <cryptohome/proto_bindings/UserDataAuth.pb.h>
#include <dbus/bus.h>
#include <dbus/message.h>
#include <dbus/object_path.h>
#include <dbus/object_proxy.h>
#include <google/protobuf/message_lite.h>
#include <user_data_auth-client/user_data_auth/dbus-proxies.h>

#include "debugd/src/error_utils.h"
#include "debugd/src/process_with_output.h"

#include "rpc.pb.h"  // NOLINT(build/include_directory)

namespace debugd {

namespace {

const char kAccessDeniedErrorString[] =
    "org.chromium.debugd.error.AccessDenied";
const char kDevModeAccessErrorString[] =
    "Use of this tool is restricted to dev mode.";
const char kOwnerAccessErrorString[] =
    "Unavailable after device has an owner or boot lockbox is finalized.";
const char kOwnerQueryErrorString[] =
    "Error encountered when querying D-Bus, cryptohome may be busy.";

// Queries the cryptohome GetLoginStatus D-Bus interface.
//
// Handles lower-level logic for dbus methods and the cryptohome protobuf
// classes. Cryptohome protobuf responses work by extending the BaseReply class,
// so if an error occurs it's possible to get a reply that does not contain the
// GetLoginStatusReply extension.
//
// |reply| will be filled if a response was received regardless of extension,
// but the function will only return true if reply is filled and has the
// correct GetLoginStatusReply extension.
bool CryptohomeGetLoginStatus(dbus::Bus* bus,
                              user_data_auth::GetLoginStatusReply* reply) {
  org::chromium::CryptohomeMiscInterfaceProxy proxy(bus);
  user_data_auth::GetLoginStatusRequest request;
  brillo::ErrorPtr error;
  bool success = proxy.GetLoginStatus(
      request, reply, &error, user_data_auth::kUserDataAuthServiceTimeoutInMs);
  if (!success || error) {
    return false;
  }

  return true;
}

}  // namespace

DevModeNoOwnerRestriction::DevModeNoOwnerRestriction(
    scoped_refptr<dbus::Bus> bus)
    : bus_(bus) {}

bool DevModeNoOwnerRestriction::AllowToolUse(brillo::ErrorPtr* error) {
  // Check dev mode first to avoid unnecessary cryptohome query delays.
  if (!InDevMode(error)) {
    return false;  // DEBUGD_ADD_ERROR is already called.
  }

  bool owner_exists, boot_lockbox_finalized;
  if (!GetOwnerAndLockboxStatus(&owner_exists, &boot_lockbox_finalized)) {
    // We want to specifically indicate when the query failed since it may
    // mean that cryptohome is busy and could be tried again later.
    DEBUGD_ADD_ERROR(error, kAccessDeniedErrorString, kOwnerQueryErrorString);
    return false;
  }

  if (owner_exists || boot_lockbox_finalized) {
    DEBUGD_ADD_ERROR(error, kAccessDeniedErrorString, kOwnerAccessErrorString);
    return false;
  }

  return true;
}

bool DevModeNoOwnerRestriction::InDevMode(brillo::ErrorPtr* error) const {
  // The is_developer_end_user script provides a common way to access this
  // information rather than duplicating logic here.
  if (ProcessWithOutput::RunProcess("/usr/sbin/is_developer_end_user",
                                    ProcessWithOutput::ArgList{},
                                    true,     // needs root to run properly.
                                    false,    // disable_sandbox.
                                    nullptr,  // no stdin.
                                    nullptr,  // no stdout.
                                    nullptr,  // no stderr.
                                    nullptr) != 0) {  // no D-Bus error.
    DEBUGD_ADD_ERROR(error, kAccessDeniedErrorString,
                     kDevModeAccessErrorString);
    return false;
  }
  return true;
}

// Checks for owner user and boot lockbox status.
//
// This function handles the high-level code of checking the cryptohome
// protocol buffer response. Lower-level details of sending the D-Bus function
// and parsing the protocol buffer are handled in CryptohomeGetLoginStatus().
//
// If cryptohome was queried successfully, returns true and |owner_user_exists|
// and |boot_lockbox_finalized| are updated.
bool DevModeNoOwnerRestriction::GetOwnerAndLockboxStatus(
    bool* owner_user_exists, bool* boot_lockbox_finalized) {
  user_data_auth::GetLoginStatusReply reply;
  if (CryptohomeGetLoginStatus(bus_.get(), &reply)) {
    *owner_user_exists = reply.owner_user_exists();
    // boot_lockbox_finalized is deprecated and always sets to false.
    // See definition of user_data_auth::GetLoginStatusReply for more
    // information.
    *boot_lockbox_finalized = false;
    return true;
  }
  return false;
}

}  // namespace debugd
