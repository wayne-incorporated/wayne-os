// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TPM_MANAGER_CLIENT_TPM_OWNERSHIP_SIGNAL_HANDLER_H_
#define TPM_MANAGER_CLIENT_TPM_OWNERSHIP_SIGNAL_HANDLER_H_

#include <string>

#include "tpm_manager/proto_bindings/tpm_manager.pb.h"

namespace tpm_manager {

// |TpmOwnershipTakenSignalHandler| declares the abstract interfaces for users
// to implement the behavior upon receiving the ownership taken signal from
// |tpm_managerd|.
class TpmOwnershipTakenSignalHandler {
 public:
  TpmOwnershipTakenSignalHandler() = default;
  virtual ~TpmOwnershipTakenSignalHandler() = default;

  // By design, this function is supposed to be called upon the signal is
  // received. |signal| is the data sent along with the signal.
  virtual void OnOwnershipTaken(const OwnershipTakenSignal& signal) = 0;

  // By design, this function is supposed to be called upon the dbus connection
  // is connected, where |is_successful| indicates if the signal connection is
  // successful. |interface_name| and the |signal_name| identify which signal
  // connection triggers this callback. Currently they always refer to ownership
  // taken signal.
  virtual void OnSignalConnected(const std::string& interface_name,
                                 const std::string& signal_name,
                                 bool is_successful) = 0;
};

}  // namespace tpm_manager

#endif  //  TPM_MANAGER_CLIENT_TPM_OWNERSHIP_SIGNAL_HANDLER_H_
