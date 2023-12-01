// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBBRILLO_BRILLO_HTTP_HTTP_PROXY_H_
#define LIBBRILLO_BRILLO_HTTP_HTTP_PROXY_H_

#include <string>
#include <vector>

#include <base/functional/callback_forward.h>
#include <base/memory/ref_counted.h>
#include <brillo/brillo_export.h>

namespace dbus {
class Bus;
}  // namespace dbus

namespace brillo {
namespace http {

// Options to override the default behaviour of the proxy resolution service in
// Chrome regarding system-proxy. System-proxy is a local daemon which does
// proxy authentication to a remote HTTP proxy, on behalf of Chrome OS system
// services. The default behaviour is to return the address of system-proxy as
// the first entry in the PAC-style list of resolved proxy list only if the
// device policy SystemProxySettings is enabled.
enum BRILLO_EXPORT SystemProxyOverride {
  // Default behaviour. System-proxy will be prepended to the list of returned
  // proxies only if enabled by policy.
  kDefault = 0,
  // System-proxy will be prepended to the list of returned proxies only if
  // enabled by policy or feature flag SystemProxyForSystemServices.
  kOptIn = 1,
  // System-proxy will not be added to the list of returned proxies, even if
  // enabled by policy.
  kOptOut = 2,
};

using GetChromeProxyServersCallback = base::OnceCallback<void(
    bool success, const std::vector<std::string>& proxies)>;

// Gets the list of proxy servers that are configured in Chrome by sending a
// D-Bus message to Chrome. The list will always be at least one in size, with
// the last element always being the direct option. The target URL should be
// passed in for the |url| parameter. The proxy servers are set in
// |proxies_out|. The format of the strings in |proxies_out| is
// scheme://[[user:pass@]host:port] with the last element being "direct://".
// Valid schemes it will return are socks4, socks5, http, https or direct.
// Even if this function returns false, it will still set |proxies_out| to be
// just the direct proxy. This function will only return false if there is an
// error in the D-Bus communication itself.
BRILLO_EXPORT bool GetChromeProxyServers(scoped_refptr<::dbus::Bus> bus,
                                         const std::string& url,
                                         std::vector<std::string>* proxies_out);

// Async version of GetChromeProxyServers.
BRILLO_EXPORT void GetChromeProxyServersAsync(
    scoped_refptr<::dbus::Bus> bus,
    const std::string& url,
    GetChromeProxyServersCallback callback);

// Async version of `GetChromeProxyServers` which allows the caller to
// explicitly opt-in and -out of using the system-proxy daemon, which
// authenticates the caller to a remote HTTP proxy.
BRILLO_EXPORT void GetChromeProxyServersWithOverrideAsync(
    scoped_refptr<::dbus::Bus> bus,
    const std::string& url,
    const SystemProxyOverride system_proxy_override,
    GetChromeProxyServersCallback callback);

}  // namespace http
}  // namespace brillo

#endif  // LIBBRILLO_BRILLO_HTTP_HTTP_PROXY_H_
