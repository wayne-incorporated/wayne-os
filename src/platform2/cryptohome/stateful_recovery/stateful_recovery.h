// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
#ifndef CRYPTOHOME_STATEFUL_RECOVERY_STATEFUL_RECOVERY_H_
#define CRYPTOHOME_STATEFUL_RECOVERY_STATEFUL_RECOVERY_H_

#include <string>

#include <base/files/file_path.h>
#include <base/functional/callback.h>
#include <brillo/dbus/dbus_method_response.h>
#include <cryptohome/proto_bindings/UserDataAuth.pb.h>
#include <cryptohome/proto_bindings/rpc.pb.h>
#include <policy/libpolicy.h>
#include <user_data_auth-client/user_data_auth/dbus-proxies.h>

#include "cryptohome/username.h"

namespace cryptohome {

class Platform;
class Service;

// This class handles recovery of encrypted data from the stateful partition.
// At present, it provides a simple way to export the encrypted data while the
// feature is maturing by checking for the existence of a file on the
// unencrypted portion of stateful.
//
// Once the feature has seen satisfactory airtime and all
// related tooling is robust, this class will implement a tighter mechanism
// for recovering the encrypted data in stateful that requires physical device
// modification or device owner modification:
//   http://crosbug.com/34219
//
class StatefulRecovery {
 public:
  explicit StatefulRecovery(
      Platform* platform,
      org::chromium::UserDataAuthInterfaceProxyInterface* userdataauth_proxy,
      policy::PolicyProvider* policy_provider,
      std::string flag_file);
  virtual ~StatefulRecovery() = default;

  // Returns true if recovery was requested by the device user.
  virtual bool Requested();
  // Returns true if it successfully recovered stateful contents.
  virtual bool Recover();

  static const char kRecoverSource[];
  static const char kRecoverDestination[];
  static const char kRecoverBlockUsage[];
  static const char kRecoverFilesystemDetails[];
  static const char kFlagFile[];

 private:
  // Returns true if a flag file indicating a recovery request exists and
  // contains the expected content.
  bool ParseFlagFile();

  // Copies encrypted partition details to recovery directory.
  bool CopyPartitionInfo();

  // Copies encrypted partition contents to recovery directory.
  bool CopyPartitionContents();

  // Copies the mounted user directory to recovery directory.
  bool CopyUserContents();

  // Versions of the recovery handler.
  bool RecoverV1();
  bool RecoverV2();

  // Mount mounts the cryptohome for the specified username and passkey.
  // If the mounting is successful, true is returned and out_home_path is set
  // to the home path for the home directory for the target user. Otherwise,
  // false is returned and out_home_path is unchanged.
  bool Mount(const Username& username,
             const std::string& passkey,
             base::FilePath* out_home_path);

  // InvalidateAuthSession invalidates an AuthSession given by the
  // |auth_session_id|.
  void InvalidateAuthSession(const std::string& auth_session_id);

  // Unmount unmounts all cryptohome. It returns true on success and false on
  // failure.
  bool Unmount();

  // IsOwnerFunction returns true if the given user is the owner.
  bool IsOwner(const std::string& username);

  bool requested_;
  Platform* platform_;
  org::chromium::UserDataAuthInterfaceProxyInterface* userdataauth_proxy_;
  policy::PolicyProvider* policy_provider_;
  base::FilePath flag_file_;
  int timeout_ms_;
  std::string version_;
  Username user_;
  std::string passkey_;
};

}  // namespace cryptohome

#endif  // CRYPTOHOME_STATEFUL_RECOVERY_STATEFUL_RECOVERY_H_
