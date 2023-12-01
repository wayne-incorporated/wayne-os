// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_STORAGE_ENCRYPTED_CONTAINER_FAKE_BACKING_DEVICE_H_
#define CRYPTOHOME_STORAGE_ENCRYPTED_CONTAINER_FAKE_BACKING_DEVICE_H_

#include "cryptohome/storage/encrypted_container/backing_device.h"

#include <memory>
#include <optional>

#include <gmock/gmock.h>

#include "cryptohome/storage/encrypted_container/backing_device_factory.h"

namespace cryptohome {

class FakeBackingDevice : public BackingDevice {
 public:
  FakeBackingDevice(BackingDeviceType type, const base::FilePath& device_path)
      : exists_(false),
        attached_(false),
        type_(type),
        backing_device_path_(device_path) {}

  ~FakeBackingDevice() {}

  bool Create() override {
    if (exists_) {
      return false;
    }
    exists_ = true;
    return true;
  };

  bool Purge() override {
    if (!exists_ || attached_) {
      return false;
    }
    exists_ = false;
    return true;
  }

  bool Setup() override {
    if (!exists_ || attached_) {
      return false;
    }

    attached_ = true;
    return true;
  }

  bool Teardown() override {
    if (!exists_ || !attached_) {
      return false;
    }
    attached_ = false;
    return true;
  }

  bool Exists() override { return exists_; }

  BackingDeviceType GetType() override { return type_; }

  std::optional<base::FilePath> GetPath() override {
    if (!attached_) {
      return std::nullopt;
    }
    return backing_device_path_;
  }

 private:
  bool exists_;
  bool attached_;
  BackingDeviceType type_;
  base::FilePath backing_device_path_;
};

class FakeBackingDeviceFactory : public BackingDeviceFactory {
 public:
  explicit FakeBackingDeviceFactory(Platform* platform)
      : BackingDeviceFactory(platform) {}
  ~FakeBackingDeviceFactory() {}

  std::unique_ptr<BackingDevice> Generate(
      const BackingDeviceConfig& config) override {
    return std::make_unique<FakeBackingDevice>(
        config.type, base::FilePath("/dev").Append(config.name));
  }
};

}  // namespace cryptohome

#endif  // CRYPTOHOME_STORAGE_ENCRYPTED_CONTAINER_FAKE_BACKING_DEVICE_H_
