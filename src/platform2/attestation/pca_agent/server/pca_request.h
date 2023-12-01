// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ATTESTATION_PCA_AGENT_SERVER_PCA_REQUEST_H_
#define ATTESTATION_PCA_AGENT_SERVER_PCA_REQUEST_H_

#include "attestation/pca_agent/server/pca_agent_service.h"

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <attestation/proto_bindings/interface.pb.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/memory/ref_counted.h>
#include <brillo/dbus/dbus_connection.h>
#include <brillo/dbus/dbus_method_response.h>
#include <brillo/http/http_request.h>
#include <dbus/bus.h>

#include "attestation/pca_agent/server/default_transport_factory.h"
#include "attestation/pca_agent/server/pca_http_utils.h"

namespace attestation {
namespace pca_agent {

// A class that is designed for handling the pca response. To achieve its
// purpose, this class implements 2 functions, |OnError| and |OnSuccess|, to
// handle the situations as their names suggest respectively.
// Note that this class is |base::RefCounted| so the caller can bind them into 2
// callbacks at the same time.
template <typename ReplyType>
class PcaRequest final : public base::RefCounted<PcaRequest<ReplyType>>,
                         private DefaultTransportFactory,
                         private PcaHttpUtils {
  using DBusResponseType = brillo::dbus_utils::DBusMethodResponse<ReplyType>;

 public:
  // Constructs a new instance with |name| as its name, and |response| as the
  // dbus response callback. |url| and |request| represents what their names
  // suggest. It is intended that this constructor takes ownership of what
  // |response| has.
  PcaRequest(const std::string& name,
             const std::string& url,
             const std::string& request,
             std::unique_ptr<DBusResponseType> response);

  // Not copyable or movable.
  PcaRequest(const PcaRequest&) = delete;
  PcaRequest(PcaRequest&&) = delete;
  PcaRequest& operator=(const PcaRequest&) = delete;
  PcaRequest& operator=(PcaRequest&&) = delete;

  // Sends |request_| to the PCA server at |url_|. The detailed flows are as
  // follows:
  // 1. Gets the proxy information from Chrome. If failed, continues assuming no
  // proxy server, i.e., "direct://" would be the only attempt we are gonna try.
  // 2. Gets the first proxy server from the list and pop it. Sends |request_|
  // to |url_| with the popped proxy server.
  // 3. In case of connection error or bad HTTP status code, goes back to 2.
  // until running out of all proxy options.
  // Despite of the flow described above, the processes are broken down to
  // tasks and invoked in async manner.
  void SendRequest();

  void set_transport_factory_for_testing(TransportFactory* factory) {
    transport_factory_ = factory;
  }

  void set_pca_http_utils_for_testing(PcaHttpUtils* utils) {
    http_utils_ = utils;
  }

 private:
  // The name of the response it is handling; used for logging.
  const std::string name_;
  // The URL of the PCA server.
  const std::string url_;
  // The request to be sent to |url_|
  const std::string request_;
  // A |TransportFactory| used to create |brillo::http::Transport| instance;
  // alternated during unittest for testability.
  TransportFactory* transport_factory_{this};

  // The list of proxy servers used to try to send the request with.
  std::vector<std::string> proxy_servers_;
  //
  // The dbus response callback, which is called when either |OnError| or
  // |OnSuccess| is called.
  std::unique_ptr<DBusResponseType> response_;

  // The callback of |GetChromeProxyServersAsync|; triggers
  // |SendRequestWithProxySetting| after storing the proxy servers into
  // |proxy_servers_|. In case of |!success|, inserts an identifier of direct
  // connection.
  void OnGetProxyServers(bool success, const std::vector<std::string>& servers);

  // Reads and pops a proxy server from |proxy_servers_| and sends |request_| to
  // |url_| with that proxy server. In case of error/success, invokes |OnError|
  // and |Onsuccess|, respectively.
  bool SendRequestWithProxySetting();

  // Logs the error and tries sends the request with next proxy server if any;
  // otherwise, invokes |response_| with a proper status code. Designed to be
  // called when errors occur during sending HTTP request.
  void OnError(brillo::http::RequestID /*not used*/, const brillo::Error* err);

  // Invokes |response_| if the HTTP status code is successful; in case of
  // unsupported successful status code, e.g., "Partial", the returned status is
  // set to |STATUS_NOT_SUPPORT|. In case of unsuccessful HTTP status code,
  // sends the request with next proxy server if any; otherwise, invokes
  // |response_| with a proper status code. Designed to be called when sending
  // HTTP request successfully.
  void OnSuccess(brillo::http::RequestID,
                 std::unique_ptr<brillo::http::Response> pca_response);

  // |PcaRequestHttpUtils| overrides.
  void GetChromeProxyServersAsync(
      const std::string& url,
      brillo::http::GetChromeProxyServersCallback callback) override;

  // A |PcaRequestHttpUtils| used to perform HTTP related functions;
  // alternated during unittest for testability.
  PcaHttpUtils* http_utils_{this};

  // Used to retrieve proxy servers from Chrome.
  brillo::DBusConnection connection_;
};

}  // namespace pca_agent
}  // namespace attestation

#endif  // ATTESTATION_PCA_AGENT_SERVER_PCA_REQUEST_H_
