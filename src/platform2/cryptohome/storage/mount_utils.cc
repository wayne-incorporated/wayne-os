// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// This file contains assorted functions used in mount-related classed.

#include "cryptohome/storage/mount_utils.h"

#include <linux/magic.h>
#include <sys/types.h>
#include <sys/vfs.h>
#include <sys/wait.h>
#include <unistd.h>

#include <unordered_map>
#include <vector>

#include <base/files/file_util.h>
#include <base/logging.h>
#include <chromeos/constants/cryptohome.h>

#include "cryptohome/crypto_error.h"

namespace {
// Size of span when writing protobuf message size to file.
constexpr size_t kSpanSize = 1;

}  // namespace

namespace cryptohome {

bool UserSessionMountNamespaceExists() {
  struct statfs buff;
  if (statfs(kUserSessionMountNamespacePath, &buff) == 0) {
    if (static_cast<uint64_t>(buff.f_type) != NSFS_MAGIC) {
      LOG(ERROR) << kUserSessionMountNamespacePath
                 << " is not a namespace file, has the user session namespace "
                    "been created?";
      return false;
    }
  } else {
    PLOG(ERROR) << "statfs(" << kUserSessionMountNamespacePath << ") failed";
    return false;
  }
  return true;
}

bool ReadProtobuf(int in_fd, google::protobuf::MessageLite* message) {
  size_t proto_size = 0;
  if (!base::ReadFromFD(in_fd, reinterpret_cast<char*>(&proto_size),
                        sizeof(proto_size))) {
    PLOG(ERROR) << "Failed to read protobuf size";
    return false;
  }

  std::vector<char> buf(proto_size);
  if (!base::ReadFromFD(in_fd, buf.data(), buf.size())) {
    PLOG(ERROR) << "Failed to read protobuf";
    return false;
  }

  if (!message->ParseFromArray(buf.data(), buf.size())) {
    LOG(ERROR) << "Failed to parse protobuf";
    return false;
  }

  return true;
}

bool WriteProtobuf(int out_fd, const google::protobuf::MessageLite& message) {
  size_t size = message.ByteSizeLong();
  if (!base::WriteFileDescriptor(
          out_fd, base::as_bytes(base::make_span(&size, kSpanSize)))) {
    PLOG(ERROR) << "Failed to write protobuf size";
    return false;
  }

  if (!message.SerializeToFileDescriptor(out_fd)) {
    LOG(ERROR) << "Failed to serialize and write protobuf";
    return false;
  }

  return true;
}

void ForkAndCrash(const std::string& message) {
  // Fork-and-crashing would only add overhead when fuzzing, without any real
  // benefit.
#if !USE_FUZZER
  pid_t child_pid = fork();

  if (child_pid < 0) {
    PLOG(ERROR) << "fork() failed";
  } else if (child_pid == 0) {
    // Child process: crash with |message|.
    LOG(FATAL) << message;
  } else {
    // |child_pid| > 0
    // Parent process: reap the child process in a best-effort way and return
    // normally.
    waitpid(child_pid, nullptr, 0);
  }
#endif
}

user_data_auth::CryptohomeErrorCode CryptoErrorToCryptohomeError(
    const CryptoError code) {
  return MountErrorToCryptohomeError(CryptoErrorToMountError(code));
}

MountError CryptoErrorToMountError(CryptoError crypto_error) {
  MountError local_error = MOUNT_ERROR_NONE;
  switch (crypto_error) {
    case CryptoError::CE_TPM_FATAL:
    case CryptoError::CE_OTHER_FATAL:
      local_error = MOUNT_ERROR_VAULT_UNRECOVERABLE;
      break;
    case CryptoError::CE_TPM_COMM_ERROR:
      local_error = MOUNT_ERROR_TPM_COMM_ERROR;
      break;
    case CryptoError::CE_TPM_DEFEND_LOCK:
      local_error = MOUNT_ERROR_TPM_DEFEND_LOCK;
      break;
    case CryptoError::CE_TPM_REBOOT:
      local_error = MOUNT_ERROR_TPM_NEEDS_REBOOT;
      break;
    case CryptoError::CE_CREDENTIAL_LOCKED:
      local_error = MOUNT_ERROR_CREDENTIAL_LOCKED;
      break;
    case CryptoError::CE_RECOVERY_TRANSIENT:
      local_error = MOUNT_ERROR_RECOVERY_TRANSIENT;
      break;
    case CryptoError::CE_RECOVERY_FATAL:
      local_error = MOUNT_ERROR_RECOVERY_FATAL;
      break;
    case CryptoError::CE_LE_EXPIRED:
      local_error = MOUNT_ERROR_CREDENTIAL_EXPIRED;
      break;
    default:
      local_error = MOUNT_ERROR_KEY_FAILURE;
      break;
  }
  return local_error;
}

user_data_auth::CryptohomeErrorCode MountErrorToCryptohomeError(
    const MountError code) {
  switch (code) {
    case MOUNT_ERROR_NONE:
      return user_data_auth::CRYPTOHOME_ERROR_NOT_SET;
    case MOUNT_ERROR_FATAL:
      return user_data_auth::CRYPTOHOME_ERROR_MOUNT_FATAL;
    case MOUNT_ERROR_KEY_FAILURE:
      return user_data_auth::CRYPTOHOME_ERROR_AUTHORIZATION_KEY_FAILED;
    case MOUNT_ERROR_MOUNT_POINT_BUSY:
      return user_data_auth::CRYPTOHOME_ERROR_MOUNT_MOUNT_POINT_BUSY;
    case MOUNT_ERROR_TPM_COMM_ERROR:
      return user_data_auth::CRYPTOHOME_ERROR_TPM_COMM_ERROR;
    case MOUNT_ERROR_UNPRIVILEGED_KEY:
      return user_data_auth::CRYPTOHOME_ERROR_AUTHORIZATION_KEY_DENIED;
    case MOUNT_ERROR_TPM_DEFEND_LOCK:
      return user_data_auth::CRYPTOHOME_ERROR_TPM_DEFEND_LOCK;
    case MOUNT_ERROR_CREDENTIAL_LOCKED:
      return user_data_auth::CRYPTOHOME_ERROR_CREDENTIAL_LOCKED;
    case MOUNT_ERROR_CREDENTIAL_EXPIRED:
      return user_data_auth::CRYPTOHOME_ERROR_CREDENTIAL_EXPIRED;
    case MOUNT_ERROR_TPM_UPDATE_REQUIRED:
      return user_data_auth::CRYPTOHOME_ERROR_TPM_UPDATE_REQUIRED;
    case MOUNT_ERROR_USER_DOES_NOT_EXIST:
      return user_data_auth::CRYPTOHOME_ERROR_ACCOUNT_NOT_FOUND;
    case MOUNT_ERROR_TPM_NEEDS_REBOOT:
      return user_data_auth::CRYPTOHOME_ERROR_TPM_NEEDS_REBOOT;
    case MOUNT_ERROR_OLD_ENCRYPTION:
      return user_data_auth::CRYPTOHOME_ERROR_MOUNT_OLD_ENCRYPTION;
    case MOUNT_ERROR_PREVIOUS_MIGRATION_INCOMPLETE:
      return user_data_auth::
          CRYPTOHOME_ERROR_MOUNT_PREVIOUS_MIGRATION_INCOMPLETE;
    case MOUNT_ERROR_RECREATED:
      return user_data_auth::CRYPTOHOME_ERROR_NOT_SET;
    case MOUNT_ERROR_VAULT_UNRECOVERABLE:
      return user_data_auth::CRYPTOHOME_ERROR_VAULT_UNRECOVERABLE;
    case MOUNT_ERROR_RECOVERY_TRANSIENT:
      return user_data_auth::CRYPTOHOME_ERROR_RECOVERY_TRANSIENT;
    case MOUNT_ERROR_RECOVERY_FATAL:
      return user_data_auth::CRYPTOHOME_ERROR_RECOVERY_FATAL;
    default:
      return user_data_auth::CRYPTOHOME_ERROR_MOUNT_FATAL;
  }
}

}  // namespace cryptohome
