// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "attestation/pca_agent/server/pca_request.h"

#include <utility>

#include <base/check.h>
#include <base/logging.h>
#include <brillo/http/http_transport.h>
#include <brillo/mime_utils.h>

namespace attestation {
namespace pca_agent {

template <typename ReplyType>
PcaRequest<ReplyType>::PcaRequest(const std::string& name,
                                  const std::string& url,
                                  const std::string& request,
                                  std::unique_ptr<DBusResponseType> response)
    : name_(name),
      url_(url),
      request_(request),
      response_(std::move(response)) {}

template <typename ReplyType>
void PcaRequest<ReplyType>::SendRequest() {
  http_utils_->GetChromeProxyServersAsync(
      url_,
      base::BindOnce(&PcaRequest::OnGetProxyServers, base::RetainedRef(this)));
}

template <typename ReplyType>
void PcaRequest<ReplyType>::OnGetProxyServers(
    bool success, const std::vector<std::string>& servers) {
  // In case of failure, also tries direct connection.
  if (!success || servers.empty()) {
    proxy_servers_ = {brillo::http::kDirectProxy};
  } else {
    // Reverses the vector so we can just pop back afterwards.
    proxy_servers_.assign(servers.rbegin(), servers.rend());
  }
  // From the logic above, this should be always true.
  CHECK(SendRequestWithProxySetting());
}

template <typename ReplyType>
bool PcaRequest<ReplyType>::SendRequestWithProxySetting() {
  if (proxy_servers_.empty()) {
    return false;
  }
  auto transport = transport_factory_->CreateWithProxy(proxy_servers_.back());
  proxy_servers_.pop_back();
  PostText(url_, request_, brillo::mime::application::kOctet_stream, {},
           transport,
           base::BindOnce(&PcaRequest::OnSuccess, base::RetainedRef(this)),
           base::BindOnce(&PcaRequest::OnError, base::RetainedRef(this)));
  return true;
}

template <typename ReplyType>
void PcaRequest<ReplyType>::GetChromeProxyServersAsync(
    const std::string& url,
    brillo::http::GetChromeProxyServersCallback callback) {
  scoped_refptr<dbus::Bus> bus = connection_.Connect();
  if (!bus) {
    LOG(ERROR) << "Failed to connect to system bus through libbrillo.";
    std::move(callback).Run(false, {});
    return;
  }
  return brillo::http::GetChromeProxyServersAsync(bus, url,
                                                  std::move(callback));
}

template <typename ReplyType>
void PcaRequest<ReplyType>::OnError(brillo::http::RequestID /*not used*/,
                                    const brillo::Error* err) {
  ReplyType reply;
  LOG(ERROR) << name_
             << ": Failed to talk to PCA server: " << err->GetMessage();
  if (!SendRequestWithProxySetting()) {
    reply.set_status(STATUS_CA_NOT_AVAILABLE);
    response_->Return(reply);
  }
}

template <typename ReplyType>
void PcaRequest<ReplyType>::OnSuccess(
    brillo::http::RequestID,
    std::unique_ptr<brillo::http::Response> pca_response) {
  ReplyType reply;
  if (pca_response->IsSuccessful()) {
    if (pca_response->GetStatusCode() == 200) {
      reply.set_status(STATUS_SUCCESS);
      *reply.mutable_response() = pca_response->ExtractDataAsString();
    } else {
      LOG(ERROR) << name_
                 << ": |pca_agent| doesn't support any other status code other "
                    "than 200 even if it's a successful call. Status code = "
                 << pca_response->GetStatusCode();
      reply.set_status(STATUS_NOT_SUPPORTED);
    }
    return response_->Return(reply);
  }
  LOG(ERROR) << name_ << ": Bad status code: " << pca_response->GetStatusCode();
  if (!SendRequestWithProxySetting()) {
    reply.set_status(STATUS_CA_NOT_AVAILABLE);
    response_->Return(reply);
  }
}

// Explicit instantiation.
template class PcaRequest<EnrollReply>;
template class PcaRequest<GetCertificateReply>;

}  // namespace pca_agent
}  // namespace attestation
