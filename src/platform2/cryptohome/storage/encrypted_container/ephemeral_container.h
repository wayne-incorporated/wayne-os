// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_STORAGE_ENCRYPTED_CONTAINER_EPHEMERAL_CONTAINER_H_
#define CRYPTOHOME_STORAGE_ENCRYPTED_CONTAINER_EPHEMERAL_CONTAINER_H_

#include <memory>

#include "cryptohome/platform.h"
#include "cryptohome/storage/encrypted_container/encrypted_container.h"
#include "cryptohome/storage/encrypted_container/fake_backing_device.h"
#include "cryptohome/storage/encrypted_container/filesystem_key.h"
#include "cryptohome/storage/encrypted_container/ramdisk_device.h"

namespace cryptohome {

// EphemeralContainer accepts a ramdisk backing device and ensures its purge
// upon container's teardown.
class EphemeralContainer final : public EncryptedContainer {
 public:
  // Unlike other containers, it forces a specific backing device type top
  // enforce that only ramdisk backed devices are used.
  EphemeralContainer(std::unique_ptr<RamdiskDevice> backing_device,
                     Platform* platform);

  ~EphemeralContainer() override;

  bool Exists() override;

  bool Purge() override;

  bool Setup(const FileSystemKey& encryption_key) override;

  bool Reset() override;

  bool Teardown() override;

  EncryptedContainerType GetType() const override {
    return EncryptedContainerType::kEphemeral;
  }

  base::FilePath GetBackingLocation() const override;

 private:
  // A private constructor with FakeBackingDevice for tests.
  EphemeralContainer(std::unique_ptr<FakeBackingDevice> backing_device,
                     Platform* platform);

  const std::unique_ptr<BackingDevice> backing_device_;
  Platform* platform_;

  friend class EphemeralContainerTest;
};

}  // namespace cryptohome

#endif  // CRYPTOHOME_STORAGE_ENCRYPTED_CONTAINER_EPHEMERAL_CONTAINER_H_
