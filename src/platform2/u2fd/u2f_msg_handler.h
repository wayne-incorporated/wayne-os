// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef U2FD_U2F_MSG_HANDLER_H_
#define U2FD_U2F_MSG_HANDLER_H_

#include <functional>
#include <memory>
#include <string>
#include <vector>

#include <attestation/proto_bindings/interface.pb.h>
#include <libhwsec/frontend/u2fd/vendor_frontend.h>
#include <metrics/metrics_library.h>

#include "u2fd/allowlisting_util.h"
#include "u2fd/client/u2f_apdu.h"
#include "u2fd/client/user_state.h"
#include "u2fd/u2f_corp_processor_interface.h"
#include "u2fd/u2f_msg_handler_interface.h"

namespace u2f {

// Processes incoming U2F messages, and produces corresponding responses.
class U2fMessageHandler : public U2fMessageHandlerInterface {
 public:
  // Constructs a new message handler. Does not take ownership of proxy or
  // metrics, both of which must outlive this instance.
  U2fMessageHandler(std::unique_ptr<AllowlistingUtil> allowlisting_util,
                    std::function<void()> request_user_presence,
                    UserState* user_state,
                    const hwsec::U2fVendorFrontend* u2f_frontend,
                    org::chromium::SessionManagerInterfaceProxy* sm_proxy,
                    MetricsLibraryInterface* metrics,
                    bool allow_g2f_attestation,
                    U2fCorpProcessorInterface* u2f_corp_processor);

  // Processes the APDU and builds a response locally, making using of cr50
  // vendor commands where necessary.
  U2fResponseApdu ProcessMsg(const std::string& request) override;

 private:
  // Process a U2F_REGISTER APDU.
  U2fResponseApdu ProcessU2fRegister(const U2fRegisterRequestApdu& request);
  // Process a U2F_AUTHENTICATE APDU.
  U2fResponseApdu ProcessU2fAuthenticate(
      const U2fAuthenticateRequestApdu& request);

  // Builds an empty U2F response with the specified status code.
  U2fResponseApdu BuildEmptyResponse(uint16_t sw);

  std::unique_ptr<AllowlistingUtil> allowlisting_util_;
  std::function<void()> request_user_presence_;
  UserState* user_state_;
  const hwsec::U2fVendorFrontend* u2f_frontend_;
  MetricsLibraryInterface* metrics_;

  const bool allow_g2f_attestation_;

  U2fCorpProcessorInterface* u2f_corp_processor_;
};

}  // namespace u2f

#endif  // U2FD_U2F_MSG_HANDLER_H_
