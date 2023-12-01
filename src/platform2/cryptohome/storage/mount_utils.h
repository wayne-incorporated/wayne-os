// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_STORAGE_MOUNT_UTILS_H_
#define CRYPTOHOME_STORAGE_MOUNT_UTILS_H_

#include <string>

#include <cryptohome/proto_bindings/UserDataAuth.pb.h>
#include <dbus/cryptohome/dbus-constants.h>
#include <google/protobuf/message_lite.h>

#include "cryptohome/crypto_error.h"
#include "cryptohome/platform.h"

namespace cryptohome {

constexpr bool IsolateUserSession() {
  return USE_USER_SESSION_ISOLATION;
}

// Checks whether the user session mount namespace has been created and logs
// error message.
bool UserSessionMountNamespaceExists();

// Cryptohome uses protobufs to communicate with the out-of-process mount
// helper.
bool ReadProtobuf(int fd, google::protobuf::MessageLite* message);
bool WriteProtobuf(int fd, const google::protobuf::MessageLite& message);

// Forks a child process that immediately prints |message| and crashes.
// This is useful to report an error through crash reporting without taking
// down the entire process, therefore allowing it to clean up and exit
// normally.
void ForkAndCrash(const std::string& message);

// Converts CryptoError to CryptohomeErrorCode defined in the protos.
user_data_auth::CryptohomeErrorCode CryptoErrorToCryptohomeError(
    const CryptoError code);

// Converts a CryptoError returned from AuthBlocks or VaultKeysets to
// MountError.
MountError CryptoErrorToMountError(const CryptoError crypto_error);

// Converts MountError used by mount.cc to CryptohomeErrorCode defined in the
// protos.
user_data_auth::CryptohomeErrorCode MountErrorToCryptohomeError(
    const MountError code);

}  // namespace cryptohome

#endif  // CRYPTOHOME_STORAGE_MOUNT_UTILS_H_
