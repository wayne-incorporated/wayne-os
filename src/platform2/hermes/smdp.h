// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef HERMES_SMDP_H_
#define HERMES_SMDP_H_

#include <memory>
#include <string>

#include <brillo/http/http_request.h>
#include <brillo/http/http_transport.h>
#include <google-lpa/lpa/smdx/smdp_client.h>
#include <google-lpa/lpa/smdx/smdp_client_factory.h>

#include "hermes/executor.h"
#include "hermes/logger.h"

namespace hermes {

class SmdpFactory : public lpa::smdp::SmdpClientFactory {
 public:
  SmdpFactory(Logger* logger, Executor* executor);

  std::unique_ptr<lpa::smdp::SmdpClient> NewSmdpClient(
      std::string tls_certs_dir,
      std::string smdp_addr,
      const lpa::proto::EuiccSpecVersion& card_verison) override;

 private:
  // Objects owned by the Daemon instance.
  Logger* logger_;
  Executor* executor_;
};

// Class to facilitate communication between the LPD and SM-DP+
// server. Responsible for opening, maintaining, and closing an
// HTTPS connection with the SM-DP+ server.
class Smdp : public lpa::smdp::SmdpClient {
 public:
  using LpaCallback =
      std::function<void(int code, std::string& http_resp, int err)>;

  Smdp(std::string server_addr,
       const std::string& certs_dir,
       const lpa::proto::EuiccSpecVersion& card_version,
       Logger* logger,
       Executor* executor);

  // lpa::smdp::SmdpClient override.
  lpa::util::EuiccLog* logger() override;

 protected:
  // lpa::smdp::SmdpClient overrides.
  lpa::util::Executor* executor() override;
  void SendHttps(const std::string& path,
                 const std::string& request,
                 LpaCallback cb) override;

 private:
  std::shared_ptr<brillo::http::Transport> server_transport_;

  std::string card_version_;

  // Objects owned by the Daemon instance.
  Logger* logger_;
  Executor* executor_;
};

}  // namespace hermes

#endif  // HERMES_SMDP_H_
