// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BIOD_BIOD_SYSTEM_H_
#define BIOD_BIOD_SYSTEM_H_

#include <string>

namespace biod {

class BiodSystem {
 public:
  BiodSystem() = default;
  // Disable copy and assign.
  BiodSystem(const BiodSystem&) = delete;
  BiodSystem& operator=(const BiodSystem&) = delete;
  virtual ~BiodSystem() = default;

  virtual bool HardwareWriteProtectIsEnabled() const;
  virtual bool OnlyBootSignedKernel() const;

 protected:
  virtual int VbGetSystemPropertyInt(const std::string& name) const;
};

}  // namespace biod

#endif  // BIOD_BIOD_SYSTEM_H_
