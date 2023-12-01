// Copyright 2014 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <base/check.h>
#include <brillo/http/http_transport.h>

#include <brillo/http/http_transport_curl.h>

namespace brillo {
namespace http {

const char kErrorDomain[] = "http_transport";
const char kDirectProxy[] = "direct://";

std::shared_ptr<Transport> Transport::CreateDefault() {
  return std::make_shared<http::curl::Transport>(std::make_shared<CurlApi>());
}

std::shared_ptr<Transport> Transport::CreateDefaultWithProxy(
    const std::string& proxy) {
  if (proxy.empty() || proxy == kDirectProxy) {
    return CreateDefault();
  } else {
    return std::make_shared<http::curl::Transport>(std::make_shared<CurlApi>(),
                                                   proxy);
  }
}

base::FilePath Transport::CertificateToPath(Transport::Certificate cert) {
  const char* str;
  switch (cert) {
    case Certificate::kDefault:
      str =
#ifdef __ANDROID__
          "/system/etc/security/cacerts_google";
#else
          "/usr/share/chromeos-ca-certificates";
#endif
      break;
    case Certificate::kHermesProd:
      str = "/usr/share/hermes-ca-certificates/prod";
      break;
    case Certificate::kHermesTest:
      str = "/usr/share/hermes-ca-certificates/test";
      break;
    case Certificate::kNss:
      str = "/etc/ssl/certs";
      break;
    default:
      CHECK(false) << "Invalid certificate";
      break;
  }
  return base::FilePath(str);
}

}  // namespace http
}  // namespace brillo
