// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BOOTLOCKBOX_HWSEC_SPACE_H_
#define BOOTLOCKBOX_HWSEC_SPACE_H_

#include <string>

#include <base/functional/callback.h>

namespace bootlockbox {

enum class SpaceState {
  kSpaceNormal = 0,
  kSpaceError = 1,          // General errors.
  kSpaceUninitialized = 2,  // Space is uninitialized.
  kSpaceUndefined = 3,      // Space is not defined.
  kSpaceWriteLocked = 4,    // Space is write locked.
  kSpaceNeedPowerwash = 5,  // Space needs powerwash to define.
};

class HwsecSpace {
 public:
  virtual ~HwsecSpace() = default;

  // This method defines a non-volatile storage area in Hwsec for bootlocboxd.
  virtual SpaceState DefineSpace() = 0;

  // This method writes |digest| to nvram space for bootlockboxd
  virtual bool WriteSpace(const std::string& digest) = 0;

  // Read nv space to nvram_data. If space is defined and initialized,
  // digest contains the digest and returns true. Otherwise, returns false and
  // |state| contains the error information.
  virtual SpaceState ReadSpace(std::string* digest) = 0;

  // Lock the bootlockbox space for writing.
  virtual bool LockSpace() = 0;

  // Register the callback that would be called when Hwsec ownership had been
  // taken.
  virtual void RegisterOwnershipTakenCallback(base::OnceClosure callback) = 0;
};

}  // namespace bootlockbox

#endif  // BOOTLOCKBOX_HWSEC_SPACE_H_
