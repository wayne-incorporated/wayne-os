// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef INIT_CROSSYSTEM_H_
#define INIT_CROSSYSTEM_H_

#include <string>

// Light-weight interface to crossystem with std::string semantics.
class CrosSystem {
 public:
  virtual ~CrosSystem() {}

  // Name of property containing the position of the Developer Switch when the
  // device booted.
  static constexpr char kDevSwitchBoot[] = "devsw_boot";

  // Name of property containing the active main firmware.
  static constexpr char kMainFirmwareActive[] = "mainfw_act";

  // Name of property that signals a request to clear TPM owner on next reboot.
  static constexpr char kClearTpmOwnerRequest[] = "clear_tpm_owner_request";

  // Name of property that indicates if the current build is a debug build.
  static constexpr char kDebugBuild[] = "debug_build";

  // Reads a system property integer into `value_out`.
  //
  // Returns true on sucess
  virtual bool GetInt(const std::string& name, int* value_out) = 0;

  // Sets the system property integer `name` to `value`.
  //
  // Returns true on success.
  virtual bool SetInt(const std::string& name, int value) = 0;

  // Reads a system property string and stores it in `value_out`.
  //
  // Returns true on success.
  virtual bool GetString(const std::string& name, std::string* value_out) = 0;

  // Sets a system property string.
  //
  // The maximum length of the value accepted depends on the specific property.
  //
  // Returns true on success.
  virtual bool SetString(const std::string& name, const std::string& value) = 0;
};

#endif  // INIT_CROSSYSTEM_H_
