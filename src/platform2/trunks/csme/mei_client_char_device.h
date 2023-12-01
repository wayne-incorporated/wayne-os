// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TRUNKS_CSME_MEI_CLIENT_CHAR_DEVICE_H_
#define TRUNKS_CSME_MEI_CLIENT_CHAR_DEVICE_H_

#include "trunks/csme/mei_client.h"

#include <linux/uuid.h>

#include <memory>
#include <string>
#include <vector>

#include <libhwsec-foundation/syscaller/syscaller.h>
#include <libhwsec-foundation/syscaller/syscaller_impl.h>

#include "trunks/trunks_export.h"

namespace trunks {
namespace csme {

class TRUNKS_EXPORT MeiClientCharDevice : public MeiClient {
 public:
  MeiClientCharDevice(const std::string& mei_path, const uuid_le& guid);
  MeiClientCharDevice(const std::string& mei_path,
                      const uuid_le& guid,
                      hwsec_foundation::Syscaller* syscaller);
  ~MeiClientCharDevice() override;
  bool IsSupport() override;
  bool Initialize() override;
  // TODO(b/190621192): Avoid indefinite timeout for `Send()` and `Receive()`.
  bool Send(const std::string& data, bool wait_for_response_ready) override;
  bool Receive(std::string* data) override;

 private:
  // Performs the main task of `Initialize()`.
  bool InitializeInternal();
  // Closes `fd_` if necessary, and set the status as "uninitialized".
  void Uninitialize();
  // Checks the write operation succeeds.
  bool EnsureWriteSuccess();

  hwsec_foundation::SyscallerImpl default_syscaller_;
  hwsec_foundation::Syscaller* syscaller_ = &default_syscaller_;
  // The device driver path.
  const std::string mei_path_;
  // The GUID of the MEI.
  uuid_le guid_;
  bool initialized_ = false;
  int fd_ = -1;
  int max_message_size_ = -1;
  std::vector<char> message_buffer_;
};

}  // namespace csme
}  // namespace trunks

#endif  // TRUNKS_CSME_MEI_CLIENT_CHAR_DEVICE_H_
