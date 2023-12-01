// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TRUNKS_CSME_MEI_CLIENT_H_
#define TRUNKS_CSME_MEI_CLIENT_H_

#include <string>

#include "trunks/trunks_export.h"

namespace trunks {
namespace csme {

// `MeiClient` provides the interfaces that communicate with MEI. It is meant
// to handle the connection and I/O of MEI.
class TRUNKS_EXPORT MeiClient {
 public:
  virtual ~MeiClient() = default;
  // Returns true when the device has MEI interface.
  virtual bool IsSupport() = 0;
  // Initializes the connection to the device (or socket). Returns `true` iff
  // the reuired operations succeeds.
  virtual bool Initialize() = 0;
  // Sends `data` to the connected MEI device. if `wait_for_response_ready` is
  // set to `true`, also checks readiness of MEI device after sending `data`.
  virtual bool Send(const std::string& data, bool wait_for_response_ready) = 0;
  // Waits for data sent from MEI and stores them in `data`.
  virtual bool Receive(std::string* data) = 0;
};

}  // namespace csme
}  // namespace trunks

#endif  // TRUNKS_CSME_MEI_CLIENT_H_
