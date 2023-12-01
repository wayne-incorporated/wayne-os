// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_SYSTEM_FAKE_SYSTEM_UTILITIES_H_
#define DIAGNOSTICS_CROS_HEALTHD_SYSTEM_FAKE_SYSTEM_UTILITIES_H_

#include <sys/utsname.h>

#include <optional>
#include <string>

#include "diagnostics/cros_healthd/system/system_utilities.h"
#include "diagnostics/cros_healthd/system/system_utilities_constants.h"

namespace diagnostics {

// Fake implementation of the SystemUtilities interface.
class FakeSystemUtilities final : public SystemUtilities {
 public:
  FakeSystemUtilities();
  FakeSystemUtilities(const FakeSystemUtilities&) = delete;
  FakeSystemUtilities& operator=(const FakeSystemUtilities&) = delete;
  ~FakeSystemUtilities() override;

  // SystemUtilities overrides:
  int Uname(struct utsname* buf) override;

  // Sets the response to any Uname() calls. If specified, |machine| will be
  // used to populate the Uname() call's |buf|.machine output parameter. The
  // other fields of |buf| will be left empty.
  void SetUnameResponse(int ret_code,
                        const std::optional<std::string>& machine);

 private:
  // Used as the return value for any Uname() calls received. Defaults to
  // success.
  int uname_ret_code_ = 0;
  // When |uname_ret_code_| is set to success, any received Uname() calls will
  // set the |buf|.machine output parameter to this value.
  std::string uname_machine_ = kUnameMachineX86_64;
};

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_SYSTEM_FAKE_SYSTEM_UTILITIES_H_
