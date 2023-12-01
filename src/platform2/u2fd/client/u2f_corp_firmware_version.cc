// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "u2fd/client/u2f_corp_firmware_version.h"

#include <string>

#include <libhwsec/frontend/u2fd/vendor_frontend.h>

#include "u2fd/client/u2f_client_export.h"

namespace u2f {

U2fCorpFirmwareVersion U2fCorpFirmwareVersion::FromRwVersion(
    const hwsec::U2fVendorFrontend::RwVersion& rw_version) {
  // In b/232715968, we decided to use the following transformation to transform
  // the 12-byte TPM RW version into the 3-byte firmware version expected in U2F
  // Corp. In practice this won't overflow.
  uint32_t epoch = rw_version.epoch * 100 + rw_version.major;
  uint32_t major = rw_version.minor / 10;
  uint32_t minor = rw_version.minor % 10;

  return U2fCorpFirmwareVersion(static_cast<uint8_t>(epoch),
                                static_cast<uint8_t>(major),
                                static_cast<uint8_t>(minor));
}

std::string U2fCorpFirmwareVersion::ToString() const {
  return std::string({static_cast<char>(epoch_), static_cast<char>(major_),
                      static_cast<char>(minor_)});
}

U2fCorpFirmwareVersion::U2fCorpFirmwareVersion(uint8_t epoch,
                                               uint8_t major,
                                               uint8_t minor)
    : epoch_(epoch), major_(major), minor_(minor) {}

}  // namespace u2f
