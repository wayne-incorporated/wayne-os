// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef HERMES_MODEM_CONTROL_INTERFACE_H_
#define HERMES_MODEM_CONTROL_INTERFACE_H_

#include <vector>

#include <google-lpa/lpa/data/proto/euicc_info_1.pb.h>

#include "hermes/euicc_event.h"
#include "hermes/hermes_common.h"

namespace hermes {

class ModemControlInterface {
 public:
  // Switch to the slot value before the last hermes operation
  virtual void RestoreActiveSlot(ResultCallback cb) = 0;

  virtual void ProcessEuiccEvent(EuiccEvent event, ResultCallback cb) = 0;

  virtual void SetCardVersion(
      const lpa::proto::EuiccSpecVersion& spec_version) = 0;

  virtual void OpenConnection(
      const std::vector<uint8_t>& aid,
      base::OnceCallback<void(std::vector<uint8_t>)> cb) = 0;
  virtual void TransmitApdu(
      const std::vector<uint8_t>& apduCommand,
      base::OnceCallback<void(std::vector<uint8_t>)> cb) = 0;

  virtual ~ModemControlInterface() = default;
};

}  // namespace hermes

#endif  // HERMES_MODEM_CONTROL_INTERFACE_H_
