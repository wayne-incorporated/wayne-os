// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BOOTLOCKBOX_FAKE_HWSEC_SPACE_H_
#define BOOTLOCKBOX_FAKE_HWSEC_SPACE_H_

#include <string>

#include "bootlockbox/hwsec_space.h"

namespace bootlockbox {

class FakeTpmSpace : public HwsecSpace {
 public:
  FakeTpmSpace() {}

  SpaceState DefineSpace() override;

  bool WriteSpace(const std::string& digest) override;

  SpaceState ReadSpace(std::string* digest) override;

  bool LockSpace() override;

  void RegisterOwnershipTakenCallback(base::OnceClosure callback) override;

  void SetDigest(const std::string& digest);

 private:
  std::string digest_;
};

}  // namespace bootlockbox

#endif  // BOOTLOCKBOX_FAKE_HWSEC_SPACE_H_
