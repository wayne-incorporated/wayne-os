// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "hermes/smdp.h"

#include <algorithm>
#include <string>
#include <utility>

#include <base/base64.h>
#include <base/check.h>
#include <base/files/file_path.h>
#include <base/functional/bind.h>
#include <base/json/json_reader.h>
#include <base/json/json_writer.h>
#include <base/logging.h>
#include <base/strings/string_util.h>
#include <base/values.h>

namespace {

constexpr auto kSmdxTimeout = base::Minutes(3);
constexpr auto kSendNotificationsTimeout = base::Seconds(15);
constexpr std::string_view kHandleNotification = "handleNotification";

void OnHttpsResponse(hermes::Smdp::LpaCallback cb,
                     brillo::http::RequestID /*request_id*/,
                     std::unique_ptr<brillo::http::Response> response) {
  LOG(INFO) << __func__;
  std::string raw_data;
  if (!response) {
    cb(0, raw_data, lpa::smdp::SmdpClient::kMalformedResponse);
    return;
  }

  raw_data = response->ExtractDataAsString();
  VLOG(1) << __func__ << ": Response raw_data : " << raw_data;

  cb(response->GetStatusCode(), raw_data, lpa::smdp::SmdpClient::kNoError);
}

void OnHttpsError(hermes::Smdp::LpaCallback cb,
                  brillo::http::RequestID /*request_id*/,
                  const brillo::Error* error) {
  LOG(WARNING) << "HTTPS request failed (brillo error code " << error->GetCode()
               << "): " << error->GetMessage();
  std::string empty;
  cb(0, empty, lpa::smdp::SmdpClient::kSendHttpsError);
}

}  // namespace

namespace hermes {

SmdpFactory::SmdpFactory(Logger* logger, Executor* executor)
    : logger_(logger), executor_(executor) {}

std::unique_ptr<lpa::smdp::SmdpClient> SmdpFactory::NewSmdpClient(
    std::string tls_certs_dir,
    std::string smdp_addr,
    const lpa::proto::EuiccSpecVersion& card_verison) {
  return std::make_unique<Smdp>(std::move(smdp_addr), std::move(tls_certs_dir),
                                card_verison, logger_, executor_);
}

Smdp::Smdp(std::string server_addr,
           const std::string& certs_dir,
           const lpa::proto::EuiccSpecVersion& card_version,
           Logger* logger,
           Executor* executor)
    : server_transport_(brillo::http::Transport::CreateDefault()),
      logger_(logger),
      executor_(executor) {
  if (certs_dir.find("/test/") != std::string::npos) {
    LOG(INFO) << "Using SSL certificates for GSMA test servers";
    server_transport_->UseCustomCertificate(
        brillo::http::Transport::Certificate::kHermesTest);
  } else {
    LOG(INFO) << "Using SSL certificates for GSMA production servers";
    server_transport_->UseCustomCertificate(
        brillo::http::Transport::Certificate::kHermesProd);
  }
  // QR codes from certain vendors have SMDP address in uppercase but reject
  // initiateAuthenticate if the domain name isn't lowercase. b/183032912
  smdp_addr_ = base::ToLowerASCII(server_addr);
  // Ensure |smdp_addr_| does not begin with a scheme (e.g. "https://"), as this
  // variable will be used for the smdpAddress field in SM-DP+ communications.
  size_t found = smdp_addr_.find("://");
  if (found != std::string::npos) {
    smdp_addr_.erase(0, found + 3);
  }
  std::ostringstream stringStream;
  stringStream << card_version.major() << "." << card_version.minor() << "."
               << card_version.revision();
  card_version_ = stringStream.str();
}

lpa::util::EuiccLog* Smdp::logger() {
  return logger_;
}

lpa::util::Executor* Smdp::executor() {
  return executor_;
}

void Smdp::SendHttps(const std::string& path,
                     const std::string& request,
                     LpaCallback cb) {
  // path is hardcoded by the LPA. There is no PII.
  LOG(INFO) << __func__ << " path:" << path;
  brillo::ErrorPtr error = nullptr;
  std::string url = "https://" + smdp_addr_ + path;

  if (path.find(kHandleNotification) != std::string::npos)
    server_transport_->SetDefaultTimeout(kSendNotificationsTimeout);
  else
    server_transport_->SetDefaultTimeout(kSmdxTimeout);

  VLOG(1) << __func__ << ": sending data to " << url << ": " << request;
  brillo::http::Request http_request(url, brillo::http::request_type::kPost,
                                     server_transport_);
  http_request.SetContentType("application/json");
  http_request.SetUserAgent("gsma-rsp-lpad");
  http_request.AddHeader("X-Admin-Protocol", "gsma/rsp/v2.2.2");
  http_request.AddRequestBody(&request[0], request.size(), &error);
  CHECK(!error);

  http_request.GetResponse(base::BindOnce(&OnHttpsResponse, cb),
                           base::BindOnce(&OnHttpsError, cb));
}

}  // namespace hermes
