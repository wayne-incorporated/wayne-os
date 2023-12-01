// Copyright 2014 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBBRILLO_BRILLO_HTTP_HTTP_TRANSPORT_H_
#define LIBBRILLO_BRILLO_HTTP_HTTP_TRANSPORT_H_

#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <base/files/file_path.h>
#include <base/functional/callback_forward.h>
#include <base/location.h>
#include <base/time/time.h>
#include <brillo/brillo_export.h>
#include <brillo/errors/error.h>

namespace brillo {
namespace http {

BRILLO_EXPORT extern const char kErrorDomain[];
// Constant referring to 'direct' proxy which implies no proxy server.
BRILLO_EXPORT extern const char kDirectProxy[];  // direct://

class Request;
class Response;
class Connection;

using RequestID = int;

using HeaderList = std::vector<std::pair<std::string, std::string>>;
using SuccessCallback =
    base::OnceCallback<void(RequestID, std::unique_ptr<Response>)>;
using ErrorCallback = base::OnceCallback<void(RequestID, const brillo::Error*)>;

///////////////////////////////////////////////////////////////////////////////
// Transport is a base class for specific implementation of HTTP communication.
// This class (and its underlying implementation) is used by http::Request and
// http::Response classes to provide HTTP functionality to the clients. By
// default, this interface will use CA certificates that only allow secure
// (HTTPS) communication with Google services.
///////////////////////////////////////////////////////////////////////////////
class BRILLO_EXPORT Transport : public std::enable_shared_from_this<Transport> {
 public:
  enum class Certificate {
    // Default certificate; only allows communication with Google services.
    kDefault,
    // Certificates for communicating only with production SM-DP+ and SM-DS
    // servers.
    kHermesProd,
    // Certificates for communicating only with test SM-DP+ and SM-DS servers.
    kHermesTest,
    // The NSS certificate store, which the curl command-line tool and libcurl
    // library use by default. This set of certificates does not restrict
    // secure communication to only Google services.
    kNss,
  };

  Transport() = default;
  Transport(const Transport&) = delete;
  Transport& operator=(const Transport&) = delete;

  virtual ~Transport() = default;

  // Creates a connection object and initializes it with the specified data.
  // |transport| is a shared pointer to this transport object instance,
  // used to maintain the object alive as long as the connection exists.
  // The |url| here is the full URL specified in the request. It is passed
  // to the underlying transport (e.g. CURL) to establish the connection.
  virtual std::shared_ptr<Connection> CreateConnection(
      const std::string& url,
      const std::string& method,
      const HeaderList& headers,
      const std::string& user_agent,
      const std::string& referer,
      brillo::ErrorPtr* error) = 0;

  // Runs |callback| on the task runner (message loop) associated with the
  // transport. For transports that do not contain references to real message
  // loops (e.g. a fake transport), calls the callback immediately.
  virtual void RunCallbackAsync(const base::Location& from_here,
                                base::OnceClosure callback) = 0;

  // Initiates an asynchronous transfer on the given |connection|.
  // The actual implementation of an async I/O is transport-specific.
  // Returns a request ID which can be used to cancel the request.
  virtual RequestID StartAsyncTransfer(Connection* connection,
                                       SuccessCallback success_callback,
                                       ErrorCallback error_callback) = 0;

  // Cancels a pending asynchronous request. This will cancel a pending request
  // scheduled by the transport while the I/O operations are still in progress.
  // As soon as all I/O completes for the request/response, or when an error
  // occurs, the success/error callbacks are invoked and the request is
  // considered complete and can no longer be canceled.
  // Returns false if pending request with |request_id| is not found (e.g. it
  // has already completed/its callbacks are dispatched).
  virtual bool CancelRequest(RequestID request_id) = 0;

  // Set the default timeout of requests made.
  virtual void SetDefaultTimeout(base::TimeDelta timeout) = 0;

  // Set the local IP address of requests
  virtual void SetLocalIpAddress(const std::string& ip_address) = 0;

  // Set the list of DNS servers to be used instead of the system default.
  virtual void SetDnsServers(const std::vector<std::string>& dns_servers) = 0;

  // Set the name of the network interface that the DNS resolver should bind to.
  // Note: this method needs CAP_NET_ADMIN permission or root because it
  // eventually calls setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE).
  virtual void SetDnsInterface(const std::string& dns_interface) = 0;

  // Set the local IPv4 address that the DNS resolver should bind to.
  virtual void SetDnsLocalIPv4Address(const std::string& dns_ipv4_addr) = 0;

  // Set the local IPv6 address that the DNS resolver should bind to.
  virtual void SetDnsLocalIPv6Address(const std::string& dns_ipv6_addr) = 0;

  // Use the default CA certificate for certificate verification. This
  // means that clients are only allowed to communicate with Google services.
  virtual void UseDefaultCertificate() {}

  // Set the CA certificate to use for certificate verification.
  //
  // This call can allow a client to securly communicate with a different subset
  // of services than it can otherwise. However, setting a custom certificate
  // should be done only when necessary, and should be done with careful control
  // over the certificates that are contained in the relevant path. See
  // https://chromium.googlesource.com/chromiumos/docs/+/HEAD/ca_certs.md for
  // more information on certificates in Chrome OS.
  virtual void UseCustomCertificate(Transport::Certificate cert) {}

  // Appends host entry to DNS cache. curl can only do HTTPS request to a custom
  // IP if it resolves an HTTPS hostname to that IP. This is useful in
  // forcing a particular mapping for an HTTPS host. See CURLOPT_RESOLVE for
  // more details.
  virtual void ResolveHostToIp(const std::string& host,
                               uint16_t port,
                               const std::string& ip_address) {}

  // Sets the receive buffer size.
  virtual void SetBufferSize(std::optional<int> buffer_size) {}

  // Sets the send buffer size.
  virtual void SetUploadBufferSize(std::optional<int> buffer_size) {}

  // Creates a default http::Transport (currently, using http::curl::Transport).
  static std::shared_ptr<Transport> CreateDefault();

  // Creates a default http::Transport that will utilize the passed in proxy
  // server (currently, using a http::curl::Transport). |proxy| should be of the
  // form scheme://[user:pass@]host:port or may be the empty string or the
  // string kDirectProxy (i.e. direct://) to indicate no proxy.
  static std::shared_ptr<Transport> CreateDefaultWithProxy(
      const std::string& proxy);

 protected:
  // Clears the forced DNS mappings created by ResolveHostToIp.
  virtual void ClearHost() {}

  static base::FilePath CertificateToPath(Certificate cert);
};

}  // namespace http
}  // namespace brillo

#endif  // LIBBRILLO_BRILLO_HTTP_HTTP_TRANSPORT_H_
