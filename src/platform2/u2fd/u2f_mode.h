// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef U2FD_U2F_MODE_H_
#define U2FD_U2F_MODE_H_

#include <bindings/chrome_device_policy.pb.h>

namespace u2f {

namespace em = enterprise_management;

enum class U2fMode : uint8_t {
  kUnset = em::DeviceSecondFactorAuthenticationProto_U2fMode_UNSET,
  kDisabled = em::DeviceSecondFactorAuthenticationProto_U2fMode_DISABLED,
  kU2f = em::DeviceSecondFactorAuthenticationProto_U2fMode_U2F,
  kU2fExtended = em::DeviceSecondFactorAuthenticationProto_U2fMode_U2F_EXTENDED,
};

}  // namespace u2f

#endif  // U2FD_U2F_MODE_H_
