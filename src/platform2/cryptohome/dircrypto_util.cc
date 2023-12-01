// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/dircrypto_util.h"

#include <string>

#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <base/check_op.h>
#include <base/logging.h>

extern "C" {
#include <ext2fs/ext2_fs.h>
#include <keyutils.h>
}

#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/files/scoped_file.h>
#include <base/notreached.h>
#include <base/posix/eintr_wrapper.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_util.h>
#include <brillo/secure_blob.h>

// Add missing chromeos specific partition wide drop cache.
#define FS_IOC_DROP_CACHE _IO('f', 129)

namespace dircrypto {

namespace {

constexpr char kKeyType[] = "logon";
constexpr char kKeyNamePrefix[] = "ext4:";
constexpr char kKeyringName[] = "dircrypt";
constexpr char kStatefulPartitionPath[] = "/mnt/stateful_partition";

key_serial_t GetSessionKeyring() {
  key_serial_t keyring =
      keyctl_search(KEY_SPEC_SESSION_KEYRING, "keyring", kKeyringName, 0);
  if (keyring == kInvalidKeySerial) {
    PLOG(ERROR) << "keyctl_search failed";
    return kInvalidKeySerial;
  }

  return keyring;
}

key_serial_t KeyReferenceToKeySerial(const brillo::SecureBlob& key_reference) {
  std::string key_name =
      kKeyNamePrefix + base::ToLowerASCII(base::HexEncode(
                           key_reference.data(), key_reference.size()));

  key_serial_t key =
      keyctl_search(GetSessionKeyring(), "logon", key_name.c_str(), 0);

  return key;
}

base::ScopedFD GetStatefulPartitionScopedFd() {
  base::ScopedFD fd = base::ScopedFD(
      HANDLE_EINTR(open(kStatefulPartitionPath, O_RDONLY | O_DIRECTORY)));

  if (!fd.is_valid())
    PLOG(ERROR) << "Failed to open file descriptor " << kStatefulPartitionPath;

  return fd;
}

bool DropMountCaches() {
  base::ScopedFD fd = GetStatefulPartitionScopedFd();
  if (!fd.is_valid()) {
    PLOG(ERROR) << "Failed to open stateful partition";
    return false;
  }

  if (ioctl(fd.get(), FS_IOC_DROP_CACHE, nullptr) < 0) {
    PLOG(ERROR) << "Failed to drop cache for stateful partition";
    return false;
  }

  return true;
}

void BuildFscryptKeySpec(const KeyReference& key_reference,
                         struct fscrypt_key_specifier* key_spec) {
  switch (key_reference.policy_version) {
    case FSCRYPT_POLICY_V1:
      key_spec->type = FSCRYPT_KEY_SPEC_TYPE_DESCRIPTOR;
      DCHECK_EQ(FSCRYPT_KEY_DESCRIPTOR_SIZE, key_reference.reference.size());
      memcpy(key_spec->u.descriptor, key_reference.reference.char_data(),
             key_reference.reference.size());
      break;
    case FSCRYPT_POLICY_V2:
      key_spec->type = FSCRYPT_KEY_SPEC_TYPE_IDENTIFIER;
      break;
    default:
      NOTREACHED() << "Invalid policy version";
  }
}

}  // namespace

// Kernel versions before 5.4 do not support the fscrypt key management ioctls.
// In absence of these ioctls, we fall back to the legacy interface of adding
// removing keys.
namespace legacy {

static bool AddKeyToSessionKeyring(const brillo::SecureBlob& key,
                                   KeyReference* key_reference) {
  if (key.size() > FS_MAX_KEY_SIZE ||
      key_reference->reference.size() != FS_KEY_DESCRIPTOR_SIZE) {
    LOG(ERROR) << "Invalid arguments: key.size() = " << key.size()
               << "key_descriptor.size() = " << key_reference->reference.size();
    return false;
  }
  key_serial_t keyring = GetSessionKeyring();
  if (keyring == kInvalidKeySerial) {
    PLOG(ERROR) << "keyctl_search failed";
    return false;
  }
  struct fscrypt_key fs_key = {};
  fs_key.mode = FS_ENCRYPTION_MODE_AES_256_XTS;
  memcpy(fs_key.raw, key.char_data(), key.size());
  fs_key.size = key.size();
  std::string key_name = kKeyNamePrefix + base::ToLowerASCII(base::HexEncode(
                                              key_reference->reference.data(),
                                              key_reference->reference.size()));
  key_serial_t key_serial = add_key(kKeyType, key_name.c_str(), &fs_key,
                                    sizeof(fscrypt_key), keyring);
  brillo::SecureClearObject(fs_key);
  if (key_serial == kInvalidKeySerial) {
    PLOG(ERROR) << "Failed to insert key into keyring";
    return false;
  }

  /* Set the permission on the key.
   * Possessor: (everyone given the key is in a session keyring belonging to
   * init):
   * -- View, Search
   * User: (root)
   * -- View, Search, Write, Setattr
   * Group, Other:
   * -- None
   */
  const key_perm_t kPermissions = KEY_POS_VIEW | KEY_POS_SEARCH | KEY_USR_VIEW |
                                  KEY_USR_WRITE | KEY_USR_SEARCH |
                                  KEY_USR_SETATTR;
  if (keyctl_setperm(key_serial, kPermissions) != 0) {
    PLOG(ERROR) << "Could not change permission on key " << key_serial;
    return false;
  }
  return true;
}

static bool UnlinkSessionKey(const KeyReference& key_reference) {
  key_serial_t keyring = GetSessionKeyring();
  key_serial_t key = KeyReferenceToKeySerial(key_reference.reference);

  if (key == kInvalidKeySerial) {
    PLOG(ERROR) << "keyctl_search failed";
    return false;
  }

  if (keyring == kInvalidKeySerial)
    return false;

  if (keyctl_unlink(key, keyring) == -1) {
    PLOG(ERROR) << "Failed to unlink the key";
    return false;
  }
  return true;
}

static bool InvalidateSessionKey(const KeyReference& key_reference) {
  // First, attempt to selectively drop caches for the stateful partition.
  // This can fail if the directory does not support the operation or if
  // the process does not have the correct capabilities (CAP_SYS_ADMIN).
  if (!DropMountCaches()) {
    LOG(ERROR) << "Failed to drop cache for user mount.";
    // Use drop_caches to drop all clear cache. Otherwise, cached decrypted data
    // will stay visible. This should invalidate the key provided no one touches
    // the encrypted directories while this function is running.
    constexpr char kData = '3';
    if (base::WriteFile(base::FilePath("/proc/sys/vm/drop_caches"), &kData,
                        sizeof(kData)) != sizeof(kData)) {
      LOG(ERROR) << "Failed to drop all caches.";
      return false;
    }
  }

  // At this point, the key should be invalidated, but try to invalidate it just
  // in case.
  // If the key was already invalidated, this should fail with ENOKEY.
  key_serial_t key = KeyReferenceToKeySerial(key_reference.reference);
  if (key == kInvalidKeySerial) {
    if (errno != ENOKEY) {
      PLOG(ERROR) << "Failed to find key to invalidate";
    }
    return true;
  }

  if (keyctl_invalidate(key) == 0) {
    LOG(ERROR) << "We ended up invalidating key " << key;
  } else if (errno != ENOKEY) {
    PLOG(ERROR) << "Failed to invalidate key" << key;
  }
  return true;
}

static bool RemoveSessionKey(const KeyReference& key_reference) {
  // Unlink the key.
  // NOTE: Even after this, the key will still stay valid as long as the
  // encrypted contents are on the page cache.
  if (!UnlinkSessionKey(key_reference)) {
    LOG(ERROR) << "Failed to unlink the key.";
  }
  // Run Sync() to make all dirty cache clear.
  sync();

  return InvalidateSessionKey(key_reference);
}

}  // namespace legacy

// CheckFscryptKeyIoctlSupport is used to decide whether:
// (1) The filesystem-level keyring is supported.
// (2) Whether fscrypt v2 encryption policies can be used.
bool CheckFscryptKeyIoctlSupport() {
  base::ScopedFD fd = GetStatefulPartitionScopedFd();
  if (!fd.is_valid()) {
    PLOG(ERROR) << "Failed to open stateful partition";
    return false;
  }

  errno = 0;
  bool ret = false;

  ioctl(fd.get(), FS_IOC_ADD_ENCRYPTION_KEY, nullptr);
  if (errno != EOPNOTSUPP && errno != ENOTTY)
    ret = true;

  if (!ret)
    VLOG(3) << "fscrypt v2 encryption policies not supported; "
            << "falling back to v1 encryption policies.";

  return ret;
}

bool SetDirectoryKey(const base::FilePath& dir,
                     const KeyReference& key_reference) {
  base::ScopedFD fd(
      HANDLE_EINTR(open(dir.value().c_str(), O_RDONLY | O_DIRECTORY)));
  if (!fd.is_valid()) {
    PLOG(ERROR) << "Fscrypt: Invalid directory " << dir.value();
    return false;
  }

  union {
    struct fscrypt_policy_v1 v1;
    struct fscrypt_policy_v2 v2;
  } policy;

  memset(&policy, 0, sizeof(policy));

  switch (key_reference.policy_version) {
    case FSCRYPT_POLICY_V1:
      DCHECK_EQ(static_cast<size_t>(FSCRYPT_KEY_DESCRIPTOR_SIZE),
                key_reference.reference.size());
      policy.v1.version = FSCRYPT_POLICY_V1;
      policy.v1.contents_encryption_mode = FS_ENCRYPTION_MODE_AES_256_XTS;
      policy.v1.filenames_encryption_mode = FS_ENCRYPTION_MODE_AES_256_CTS;
      policy.v1.flags = 0;
      memcpy(policy.v1.master_key_descriptor,  // nocheck
             key_reference.reference.data(), key_reference.reference.size());
      break;
    case FSCRYPT_POLICY_V2:
      DCHECK_EQ(static_cast<size_t>(FSCRYPT_KEY_IDENTIFIER_SIZE),
                key_reference.reference.size());
      policy.v2.version = FSCRYPT_POLICY_V2;
      policy.v2.contents_encryption_mode = FS_ENCRYPTION_MODE_AES_256_XTS;
      policy.v2.filenames_encryption_mode = FS_ENCRYPTION_MODE_AES_256_CTS;
      policy.v2.flags = FSCRYPT_POLICY_FLAGS_PAD_16;
      memcpy(policy.v2.master_key_identifier,  // nocheck
             key_reference.reference.data(), key_reference.reference.size());
      break;
    default:
      NOTREACHED() << "Invalid encryption policy version";
  }

  if (ioctl(fd.get(), FS_IOC_SET_ENCRYPTION_POLICY, &policy) < 0) {
    PLOG(ERROR) << "Failed to set the encryption policy of " << dir.value();
    return false;
  }
  return true;
}

static int GetDirectoryPolicy(const base::FilePath& dir,
                              struct fscrypt_get_policy_ex_arg* arg) {
  base::ScopedFD fd(
      HANDLE_EINTR(open(dir.value().c_str(), O_RDONLY | O_DIRECTORY)));
  if (!fd.is_valid()) {
    PLOG(ERROR) << "Fscrypt: Invalid directory " << dir.value();
    errno = EINVAL;
    return -1;
  }

  int err = 0;
  // FS_IOC_GET_ENCRYPTION_POLICY only supports v1 policies.
  if (CheckFscryptKeyIoctlSupport())
    err = ioctl(fd.get(), FS_IOC_GET_ENCRYPTION_POLICY_EX, arg);
  else
    err = ioctl(fd.get(), FS_IOC_GET_ENCRYPTION_POLICY, &(arg->policy.v1));

  return err;
}

int GetDirectoryPolicyVersion(const base::FilePath& dir) {
  struct fscrypt_get_policy_ex_arg arg = {};
  memset(&arg, 0, sizeof(arg));
  arg.policy_size = sizeof(arg.policy);

  if (GetDirectoryPolicy(dir, &arg) < 0)
    return -1;

  return arg.policy.version;
}

KeyState GetDirectoryKeyState(const base::FilePath& dir) {
  struct fscrypt_get_policy_ex_arg arg = {};
  memset(&arg, 0, sizeof(arg));
  arg.policy_size = sizeof(arg.policy);

  if (GetDirectoryPolicy(dir, &arg) < 0) {
    switch (errno) {
      case ENODATA:
      case ENOENT:
        return KeyState::NO_KEY;
      case ENOTTY:
      case EOPNOTSUPP:
        return KeyState::NOT_SUPPORTED;
      default:
        PLOG(ERROR) << "Failed to get the encryption policy of " << dir.value();
        return KeyState::UNKNOWN;
    }
  }
  return KeyState::ENCRYPTED;
}

static bool AddFscryptKey(const brillo::SecureBlob& key,
                          KeyReference* key_reference) {
  brillo::SecureBlob add_key_arg(sizeof(struct fscrypt_add_key_arg) +
                                 key.size());
  struct fscrypt_add_key_arg* arg =
      (struct fscrypt_add_key_arg*)add_key_arg.data();

  BuildFscryptKeySpec(*key_reference, &(arg->key_spec));

  arg->raw_size = key.size();
  memcpy(arg->raw, key.char_data(), key.size());

  base::ScopedFD fd = GetStatefulPartitionScopedFd();
  if (!fd.is_valid())
    return false;

  if (ioctl(fd.get(), FS_IOC_ADD_ENCRYPTION_KEY, arg) < 0) {
    PLOG(ERROR) << "Failed to add encryption key";
    return false;
  }

  // For v2 policies, store the returned key identifier in the key reference.
  if (key_reference->policy_version == FSCRYPT_POLICY_V2) {
    key_reference->reference.resize(FSCRYPT_KEY_IDENTIFIER_SIZE);
    memcpy(key_reference->reference.char_data(), arg->key_spec.u.identifier,
           FSCRYPT_KEY_IDENTIFIER_SIZE);
  }

  return true;
}

static bool RemoveFscryptKey(const KeyReference& key_reference) {
  struct fscrypt_remove_key_arg arg;
  memset(&arg, 0, sizeof(fscrypt_remove_key_arg));

  BuildFscryptKeySpec(key_reference, &arg.key_spec);

  // Set the identifier for v2 policies.
  if (key_reference.policy_version == FSCRYPT_POLICY_V2) {
    memcpy(arg.key_spec.u.identifier, key_reference.reference.char_data(),
           FSCRYPT_KEY_IDENTIFIER_SIZE);
  }

  auto fd = GetStatefulPartitionScopedFd();
  if (!fd.is_valid())
    return false;

  if (ioctl(fd.get(), FS_IOC_REMOVE_ENCRYPTION_KEY, &arg) < 0) {
    PLOG(ERROR) << "Failed to remove encryption key";
    return false;
  }

  // Check removal status flags if there are files still open after removing the
  // encryption key.
  if (arg.removal_status_flags & FSCRYPT_KEY_REMOVAL_STATUS_FLAG_OTHER_USERS) {
    LOG(ERROR) << "Failed to remove fscrypt key: still used by other users.";
  } else if (arg.removal_status_flags &
             FSCRYPT_KEY_REMOVAL_STATUS_FLAG_FILES_BUSY) {
    LOG(ERROR)
        << "Some files are still in use after removing encryption key; these "
           "files were not locked.";
  }

  return true;
}

bool AddDirectoryKey(const brillo::SecureBlob& key,
                     KeyReference* key_reference) {
  return CheckFscryptKeyIoctlSupport()
             ? AddFscryptKey(key, key_reference)
             : legacy::AddKeyToSessionKeyring(key, key_reference);
}

bool RemoveDirectoryKey(const KeyReference& key_reference,
                        const base::FilePath& dir) {
  // If the key reference is empty (eg. after a crash), create
  // the key reference from the policy set on the directory.
  KeyReference ref;
  if (key_reference.reference.size() == 0) {
    struct fscrypt_get_policy_ex_arg arg;
    memset(&arg, 0, sizeof(fscrypt_get_policy_ex_arg));
    arg.policy_size = sizeof(arg.policy);

    LOG(INFO)
        << "Empty key reference; attempting to get policy from directory.";
    if (GetDirectoryPolicy(dir, &arg) < 0) {
      LOG(ERROR) << "Failed to get fscrypt policy from directory " << dir;
      return false;
    }

    switch (arg.policy.version) {
      case FSCRYPT_POLICY_V1:
        ref.reference.resize(FSCRYPT_KEY_DESCRIPTOR_SIZE);
        memcpy(ref.reference.char_data(),
               arg.policy.v1.master_key_descriptor,  // nocheck
               FSCRYPT_KEY_DESCRIPTOR_SIZE);
        ref.policy_version = FSCRYPT_POLICY_V1;
        break;
      case FSCRYPT_POLICY_V2:
        ref.reference.resize(FSCRYPT_KEY_IDENTIFIER_SIZE);
        memcpy(ref.reference.char_data(),
               arg.policy.v2.master_key_identifier,  // nocheck
               FSCRYPT_KEY_IDENTIFIER_SIZE);
        ref.policy_version = FSCRYPT_POLICY_V2;
        break;
      default:
        NOTREACHED() << "Invalid encryption policy version: "
                     << arg.policy.version;
        return false;
    }
  } else {
    ref = key_reference;
  }

  return CheckFscryptKeyIoctlSupport() ? RemoveFscryptKey(ref)
                                       : legacy::RemoveSessionKey(ref);
}

}  // namespace dircrypto
