// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_SUPPLICANT_SUPPLICANT_EAP_STATE_HANDLER_H_
#define SHILL_SUPPLICANT_SUPPLICANT_EAP_STATE_HANDLER_H_

#include <string>

#include "shill/service.h"

namespace shill {

// This object tracks the state of wpa_supplicant's EAP association.
// It parses events from wpa_supplicant and can notify callers when
// wpa_supplicant succeeds or fails authentication.  In the latter
// case it can explain the failure in detail based on the course of
// events leading up to it.
class SupplicantEAPStateHandler {
 public:
  SupplicantEAPStateHandler();
  virtual ~SupplicantEAPStateHandler();

  // Receive the |status| and |parameter| from an EAP event and returns
  // true if this state transition indicates that the EAP authentication
  // process has succeeded.  If instead the EAP authentication has failed,
  // |failure| will be set to reflect the type of failure that occurred,
  // false will be returned.  If this EAP event has no direct outcome,
  // this function returns false without changing |failure|.
  virtual bool ParseStatus(const std::string& status,
                           const std::string& parameter,
                           Service::ConnectFailure* failure);

  // Resets the internal state of the handler.
  virtual void Reset();

  virtual bool is_eap_in_progress() const { return is_eap_in_progress_; }

 private:
  friend class SupplicantEAPStateHandlerTest;

  // The stored TLS error type which may lead to an EAP failure.
  std::string tls_error_;

  // Whether or not an EAP authentication is in progress.  Note
  // specifically that an EAP failure in wpa_supplicant does not
  // automatically cause the EAP process to stop, while success does.
  bool is_eap_in_progress_;
};

}  // namespace shill

#endif  // SHILL_SUPPLICANT_SUPPLICANT_EAP_STATE_HANDLER_H_
