// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TRUNKS_CSME_MEI_CLIENT_SOCKET_H_
#define TRUNKS_CSME_MEI_CLIENT_SOCKET_H_

#include "trunks/csme/mei_client.h"

#include <string>

#include <linux/uuid.h>

#include "trunks/trunks_export.h"

namespace trunks {
namespace csme {

// `MeiClientSocket` communicate with MEI using socket connection.
class TRUNKS_EXPORT MeiClientSocket : public MeiClient {
 public:
  MeiClientSocket(const std::string& mei_path, const uuid_le& guid);
  ~MeiClientSocket() override;
  bool IsSupport() override;
  bool Initialize() override;
  bool Send(const std::string& data, bool wait_for_response_ready) override;
  bool Receive(std::string* data) override;

 private:
  // Performs the main task of `Initialize()`.
  bool InitializeInternal();
  // Closes `fd_` if necessary, and set the status as "uninitialized".
  void Uninitialize();

  // Socket path the client connects to.
  const std::string mei_path_;
  // The GUID of the MEI.
  uuid_le guid_;
  bool initialized_ = false;
  int fd_ = -1;
};

}  // namespace csme
}  // namespace trunks

#endif  // TRUNKS_CSME_MEI_CLIENT_SOCKET_H_
