// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BOOTLOCKBOX_NVRAM_BOOT_LOCKBOX_H_
#define BOOTLOCKBOX_NVRAM_BOOT_LOCKBOX_H_

#include <map>
#include <string>

#include <base/files/file_path.h>
#include <brillo/secure_blob.h>
#include <gtest/gtest_prod.h>

#include "bootlockbox/hwsec_space.h"
#include "bootlockbox/key_value_map.pb.h"
#include "bootlockbox/proto_bindings/boot_lockbox_rpc.pb.h"

namespace bootlockbox {

// A map that stores key-value pairs.
using KeyValueMap = std::map<std::string, std::string>;

inline constexpr char kNVRamBootLockboxFilePath[] =
    "/var/lib/bootlockbox/nvram_boot_lockbox.pb";
// The max file file size for nvram_boot_lockbox.pb. Currently set
// to 1MB.
inline constexpr size_t kMaxFileSize = 1024 * 1024;
inline constexpr uint32_t kVersion = 1;

// NVRamBootLockbox is a key-value map that is stored on disk and its integrity
// is guaranteed by TPM NVRAM space. The key is usually an application defined
// string and the value is a SHA256 digest. The caller of NVRamBootLockbox is
// responsible for calculating the digest. NVRamBootLockbox is protected by the
// TPM and can only be updated before a user logs in after boot.
class NVRamBootLockbox {
 public:
  // Does not take ownership of |hwsec_space|.
  explicit NVRamBootLockbox(HwsecSpace* hwsec_space);
  NVRamBootLockbox(HwsecSpace* hwsec_space,
                   const base::FilePath& bootlockbox_file_path);
  virtual ~NVRamBootLockbox();

  // Stores |digest| in bootlockbox.
  virtual bool Store(const std::string& key,
                     const std::string& digest,
                     BootLockboxErrorCode* error);

  // Reads digest identified by key.
  virtual bool Read(const std::string& key,
                    std::string* digest,
                    BootLockboxErrorCode* error);

  // Locks bootlockbox. This function may change nvspace_state_.
  virtual bool Finalize();

  // Gets BootLockbox state.
  virtual SpaceState GetState();

  // Defines NVRAM space. This function may change nvspace_state_ to
  // kSpaceUninitialized.
  virtual bool DefineSpace();

  // Registers a callback to defines NVRAM space after the TPM ownership had
  // been taken. This function may change nvspace_state_ to
  // kSpaceUninitialized.
  virtual bool RegisterOwnershipCallback();

  // Reads the key value map from disk and verifies the digest against the
  // digest stored in NVRAM space. This function may update nvspace_state_.
  virtual bool Load();

 protected:
  // Set BootLockbox state.
  virtual void SetState(const SpaceState state);

 private:
  // Writes to file, updates the digest in NVRAM space and updates local
  // local key_value_store_.
  bool FlushAndUpdate(const KeyValueMap& keyvals);

  // The file that stores serialized key_value_store_ on disk.
  base::FilePath boot_lockbox_filepath_;

  KeyValueMap key_value_store_;

  // The digest of the key value storage. The digest is stored in NVRAM
  // space and locked for writing after users logs in.
  std::string root_digest_;

  HwsecSpace* hwsec_space_;

  bool ownership_callback_registered_ = false;

  // The state of nvspace. This is not the state of the service.
  SpaceState nvspace_state_{SpaceState::kSpaceError};

  FRIEND_TEST(NVRamBootLockboxTest, DefineSpace);
  FRIEND_TEST(NVRamBootLockboxTest, LoadFailDigestMisMatch);
  FRIEND_TEST(NVRamBootLockboxTest, StoreLoadReadSuccess);
  FRIEND_TEST(NVRamBootLockboxTest, FirstStoreReadSuccess);
};

}  // namespace bootlockbox

#endif  // BOOTLOCKBOX_NVRAM_BOOT_LOCKBOX_H_
