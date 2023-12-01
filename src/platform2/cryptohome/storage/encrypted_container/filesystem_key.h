// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_STORAGE_ENCRYPTED_CONTAINER_FILESYSTEM_KEY_H_
#define CRYPTOHOME_STORAGE_ENCRYPTED_CONTAINER_FILESYSTEM_KEY_H_

#include <brillo/secure_blob.h>

namespace cryptohome {

struct FileSystemKey {
  brillo::SecureBlob fek;
  brillo::SecureBlob fnek;
  brillo::SecureBlob fek_salt;
  brillo::SecureBlob fnek_salt;
};

struct FileSystemKeyReference {
  brillo::SecureBlob fek_sig;
  brillo::SecureBlob fnek_sig;
};

// TODO(dlunev): those are inline since otherwise they cause symbol collision
// in mount_encrypted. Fix the hierarchy so that doesn't need to be inline.
inline bool operator==(const FileSystemKey& lhs, const FileSystemKey& rhs) {
  return (lhs.fek == rhs.fek && lhs.fnek == rhs.fnek &&
          lhs.fek_salt == rhs.fek_salt && lhs.fnek_salt == rhs.fnek_salt);
}

inline bool operator!=(const FileSystemKey& lhs, const FileSystemKey& rhs) {
  return !(lhs == rhs);
}

inline bool operator==(const FileSystemKeyReference& lhs,
                       const FileSystemKeyReference& rhs) {
  return (lhs.fek_sig == rhs.fek_sig && lhs.fnek_sig == rhs.fnek_sig);
}

inline bool operator!=(const FileSystemKeyReference& lhs,
                       const FileSystemKeyReference& rhs) {
  return !(lhs == rhs);
}

}  // namespace cryptohome

#endif  // CRYPTOHOME_STORAGE_ENCRYPTED_CONTAINER_FILESYSTEM_KEY_H_
