// Copyright 2016 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LOGIN_MANAGER_CROSSYSTEM_H_
#define LOGIN_MANAGER_CROSSYSTEM_H_

#include <cstddef>

// Light-weight interface to crossystem keeping the original char* semantics to
// make it an easy drop-in replacement.  (std::string semantics may be added in
// the future.)
class Crossystem {
 public:
  virtual ~Crossystem() {}

  // Recommended size for string property buffers used with
  // VbGetSystemPropertyString().
  static const std::size_t kVbMaxStringProperty = 8192;

  // The name of the flag that indicates whether dev mode must be blocked.
  static const char kBlockDevmode[];

  // The name of the flag that indicates whether enrollment check must be run.
  static const char kCheckEnrollment[];

  // The name of the flag that indicates whether NVRAM has been cleared (eg. due
  // to loss of power).
  static const char kNvramCleared[];

  // Crossystem property indicating firmware type.
  static const char kMainfwType[];

  // Firmware type string returned when there is no Chrome OS firmware present.
  static const char kMainfwTypeNonchrome[];

  // Name of the flag that signals a request to clear the TPM owner on next
  // reboot.
  static const char kClearTpmOwnerRequest[];

  // Reads a system property integer.
  //
  // Returns the property value, or -1 if error.
  virtual int VbGetSystemPropertyInt(const char* name) = 0;

  // Sets a system property integer.
  //
  // Returns 0 if success, -1 if error.
  virtual int VbSetSystemPropertyInt(const char* name, int value) = 0;

  // Reads a system property string into a destination buffer of the specified
  // size.  Returned string will be null-terminated.  If the buffer is too
  // small, the returned string will be truncated.
  //
  // The caller can expect an un-truncated value if the size provided is at
  // least kVbMaxStringProperty.
  //
  // Returns the passed buffer, or nullptr if error.
  virtual const char* VbGetSystemPropertyString(const char* name,
                                                char* dest,
                                                std::size_t size) = 0;

  // Sets a system property string.
  //
  // The maximum length of the value accepted depends on the specific
  // property, not on kVbMaxStringProperty.
  //
  // Returns 0 if success, -1 if error.
  virtual int VbSetSystemPropertyString(const char* name,
                                        const char* value) = 0;
};

#endif  // LOGIN_MANAGER_CROSSYSTEM_H_
