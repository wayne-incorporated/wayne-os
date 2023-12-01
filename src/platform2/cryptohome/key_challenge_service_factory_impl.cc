// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/key_challenge_service_factory_impl.h"

#include <memory>
#include <string>

#include <base/logging.h>
#include <base/memory/ref_counted.h>
#include <dbus/bus.h>

#include "cryptohome/key_challenge_service_impl.h"

namespace cryptohome {

KeyChallengeServiceFactoryImpl::KeyChallengeServiceFactoryImpl() = default;

KeyChallengeServiceFactoryImpl::~KeyChallengeServiceFactoryImpl() = default;

void KeyChallengeServiceFactoryImpl::SetMountThreadBus(
    scoped_refptr<::dbus::Bus> bus) {
  if (mount_thread_bus_) {
    LOG(WARNING)
        << "MountThreadBus already initialized in KeyChallengeServiceFactory.";
  }
  mount_thread_bus_ = bus;
}

std::unique_ptr<KeyChallengeService> KeyChallengeServiceFactoryImpl::New(
    const std::string& key_delegate_dbus_service_name) {
  if (!mount_thread_bus_) {
    LOG(ERROR) << "Cannot do challenge-response authentication without system "
                  "D-Bus bus";
    return nullptr;
  }
  return std::make_unique<KeyChallengeServiceImpl>(
      mount_thread_bus_, key_delegate_dbus_service_name);
}

}  // namespace cryptohome
