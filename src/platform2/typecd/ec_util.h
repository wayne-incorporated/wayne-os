// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TYPECD_EC_UTIL_H_
#define TYPECD_EC_UTIL_H_

namespace typecd {

// List of possible Type C Operating modes. These are selected by typecd based
// on connected peripheral(s) and device policy.
//
// NOTE:
// These values are set according to the values used by the ectool command which
// triggers USB Type-C mode entry (see "cmd_typec_control()" inside
// https://chromium.googlesource.com/chromiumos/platform/ec/+/refs/heads/main/util/ectool.c)
// As such, these values should only be changed if the corresponding ectool
// values do.
enum class TypeCMode {
  kNone = -1,
  kDP = 0,
  kTBT = 1,
  kUSB4 = 2,
};

// Interface used by Type C daemon to communicate with Chrome EC for
// controlling specific Type C behaviour. Depending on the running environment
// (e.g production Chromebook, unit tests) this interface can be implemented by
// a variety of back-ends (e.g D-BUS calls to an entity controlling the Chrome
// OS EC, ioctls directly to the Chrome OS EC, calls to Linux kernel sysfs,
// Mock implementation etc.).
class ECUtil {
 public:
  // Returns whether the system supports Type C Mode Entry from the Application
  // Processor.
  virtual bool ModeEntrySupported() = 0;

  // Instruct the system to enter mode |mode| on port with index |port|.
  virtual bool EnterMode(int port, TypeCMode mode) = 0;

  // Instruct the system to exit the current operating mode on port with index
  // |port|.
  virtual bool ExitMode(int port) = 0;

  // Provides DP alternate mode state on port with index |port|.
  // Returns false if the EcUtil command could not be executed, otherwise
  // returns true.
  virtual bool DpState(int port, bool* entered) = 0;

  // Provides HPD GPIO state for port with index |port|.
  // Returns true on systems that use HPD GPIO signalling from the EC (i.e AMD),
  // otherwise returns false.
  virtual bool HpdState(int port, bool* hpd) = 0;

  virtual ~ECUtil() = default;
};

}  // namespace typecd

#endif  // TYPECD_EC_UTIL_H_
