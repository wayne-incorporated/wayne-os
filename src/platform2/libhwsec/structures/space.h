// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_STRUCTURES_SPACE_H_
#define LIBHWSEC_STRUCTURES_SPACE_H_

namespace hwsec {

enum class Space {
  kFirmwareManagementParameters,
  kPlatformFirmwareManagementParameters,
  kInstallAttributes,
  kBootlockbox,
  kEnterpriseRollback,
};

enum class RoSpace {
  kEndorsementRsaCert,
  kEndorsementEccCert,
  kBoardId,
  kSNData,
  kG2fCert,
  kRsuDeviceId,
  kRmaBytes,
};

}  // namespace hwsec

#endif  // LIBHWSEC_STRUCTURES_SPACE_H_
