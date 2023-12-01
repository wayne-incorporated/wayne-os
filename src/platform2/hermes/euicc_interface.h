// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef HERMES_EUICC_INTERFACE_H_
#define HERMES_EUICC_INTERFACE_H_

#include <string>
#include <vector>

#include <google-lpa/lpa/card/euicc_card.h>

#include "hermes/modem_control_interface.h"

namespace hermes {

class EuiccManagerInterface;

class EuiccInterface : public lpa::card::EuiccCard,
                       public ModemControlInterface {
 public:
  using ResponseCallback =
      std::function<void(std::vector<std::vector<uint8_t>>&
                             responses,  // NOLINT(runtime/references)
                         int err)>;

  virtual void Initialize(EuiccManagerInterface* euicc_manager,
                          ResultCallback cb) = 0;

  //
  // Below methods from parent classes for documentation purpose
  //

  // from ModemControlInterface
  virtual void ProcessEuiccEvent(EuiccEvent event, ResultCallback cb) = 0;
  virtual void RestoreActiveSlot(ResultCallback cb) = 0;
  virtual void SetCardVersion(
      const lpa::proto::EuiccSpecVersion& spec_version) = 0;

  // from lpa::card::EuiccCard
  virtual void SendApdus(std::vector<lpa::card::Apdu> apdus,
                         ResponseCallback cb) = 0;
  virtual bool IsSimValidAfterEnable() = 0;
  virtual bool IsSimValidAfterDisable() = 0;
  virtual std::string GetImei() = 0;
  virtual lpa::util::EuiccLog* logger() = 0;
  virtual const lpa::proto::EuiccSpecVersion& GetCardVersion() = 0;
  virtual lpa::util::Executor* executor() = 0;

  virtual std::vector<uint8_t> GetUtranSupportedRelease() = 0;
  virtual std::vector<uint8_t> GetEutranSupportedRelease() = 0;
};

}  // namespace hermes

#endif  // HERMES_EUICC_INTERFACE_H_
