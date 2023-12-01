// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_MOCK_KEY_CHALLENGE_SERVICE_FACTORY_H_
#define CRYPTOHOME_MOCK_KEY_CHALLENGE_SERVICE_FACTORY_H_

#include <memory>
#include <string>

#include <base/memory/ref_counted.h>
#include <dbus/bus.h>
#include <gmock/gmock.h>

#include "cryptohome/key_challenge_service.h"
#include "cryptohome/key_challenge_service_factory.h"

namespace cryptohome {

class MockKeyChallengeServiceFactory : public KeyChallengeServiceFactory {
 public:
  MockKeyChallengeServiceFactory() = default;
  ~MockKeyChallengeServiceFactory() override = default;

  MOCK_METHOD(void, SetMountThreadBus, (scoped_refptr<::dbus::Bus> bus));
  MOCK_METHOD(std::unique_ptr<KeyChallengeService>, New, (const std::string&));
};

}  // namespace cryptohome

#endif  // CRYPTOHOME_MOCK_KEY_CHALLENGE_SERVICE_FACTORY_H_
