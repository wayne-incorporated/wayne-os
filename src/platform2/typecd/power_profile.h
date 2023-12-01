// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TYPECD_POWER_PROFILE_H_
#define TYPECD_POWER_PROFILE_H_

#include <map>
#include <memory>

#include <base/files/file_path.h>
#include <gtest/gtest_prod.h>

#include "typecd/pdo.h"

namespace typecd {

// This class represents a set of power source and sink capabilities supported
// by a Type-C peripheral. The Linux kernel Type-C subsystem groups these Power
// Delivery Objects (PDOs) together in a "usb_power_delivery" object; we can
// take that to represent a "power profile".
// Currently, only Partner PowerProfiles are supported.
//
// Why add a PowerProfile class instead of embedding the PDOs directly into the
// Peripheral class? This is because Ports can have more than 1 PowerProfile.
// So, it is beneficial to maintain a similar abstraction here.
//
// TODO(b/245608929): Add Port support for PowerProfile objects.
class PowerProfile {
 public:
  explicit PowerProfile(const base::FilePath& syspath);
  PowerProfile() = default;
  virtual ~PowerProfile() = default;

  PowerProfile(const PowerProfile&) = delete;
  PowerProfile& operator=(const PowerProfile&) = delete;

 protected:
  // Manually set syspath (to help facilitate unit tests).
  void SetSyspath(const base::FilePath path) { syspath_ = path; }

 private:
  friend class PowerProfileTest;
  FRIEND_TEST(PowerProfileTest, ParseDirs);

  // Parse and register the sink caps for the power profile.
  void ParseSinkCaps();

  // Parse and register the source caps for the power profile.
  void ParseSourceCaps();

  // Wrapper function which creates a Pdo and returns a pointer to it.
  // Created mainly for unit test purposes (in unit tests, we override
  // this function with a custom stub, since we don't want to check the actual
  // PDO parsing, which is handled by PdoTest).
  virtual std::unique_ptr<Pdo> CreatePdo(const base::FilePath& path);

  // Sysfs path used to access power delivery directory.
  base::FilePath syspath_;

  // A map of all the Sink Cap PDOs advertised in this PowerProfile.
  // The key is the index of the PDO (in the Get Sink Capabilities PDO message).
  std::map<int, std::unique_ptr<Pdo>> sink_caps_;

  // A map of all the Source Cap PDOs advertised in this PowerProfile.
  // The key is the index of the PDO (in the Get Source Capabilities PDO
  // message).
  std::map<int, std::unique_ptr<Pdo>> source_caps_;
};

}  // namespace typecd

#endif  // TYPECD_POWER_PROFILE_H_
