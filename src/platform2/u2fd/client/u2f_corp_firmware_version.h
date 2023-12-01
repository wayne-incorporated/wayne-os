// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef U2FD_CLIENT_U2F_CORP_FIRMWARE_VERSION_H_
#define U2FD_CLIENT_U2F_CORP_FIRMWARE_VERSION_H_

#include <string>

#include <libhwsec/frontend/u2fd/vendor_frontend.h>

#include "u2fd/client/u2f_client_export.h"

namespace u2f {

class U2F_CLIENT_EXPORT U2fCorpFirmwareVersion {
 public:
  U2fCorpFirmwareVersion() = default;
  ~U2fCorpFirmwareVersion() = default;

  static U2fCorpFirmwareVersion FromRwVersion(
      const hwsec::U2fVendorFrontend::RwVersion& rw_version);

  std::string ToString() const;

 private:
  U2fCorpFirmwareVersion(uint8_t epoch, uint8_t major, uint8_t minor);

  uint8_t epoch_;
  uint8_t major_;
  uint8_t minor_;
};

}  // namespace u2f

#endif  // U2FD_CLIENT_U2F_CORP_FIRMWARE_VERSION_H_
