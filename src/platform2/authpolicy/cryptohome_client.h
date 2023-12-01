// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef AUTHPOLICY_CRYPTOHOME_CLIENT_H_
#define AUTHPOLICY_CRYPTOHOME_CLIENT_H_

#include <memory>
#include <string>
#include <utility>

#include <cryptohome/proto_bindings/UserDataAuth.pb.h>
#include <user_data_auth-client/user_data_auth/dbus-proxies.h>

namespace dbus {
class ObjectProxy;
}

namespace brillo {
namespace dbus_utils {
class DBusObject;
}
}  // namespace brillo

namespace authpolicy {

// Exposes methods from the Cryptohome daemon.
class CryptohomeClient {
 public:
  explicit CryptohomeClient(brillo::dbus_utils::DBusObject* dbus_object);
  CryptohomeClient(const CryptohomeClient&) = delete;
  CryptohomeClient& operator=(const CryptohomeClient&) = delete;

  virtual ~CryptohomeClient();

  // Exposes Cryptohome's GetSanitizedUsername(). This is a 32-byte lowercase
  // hex string that is also used as user directory. Returns an empty string on
  // error.
  std::string GetSanitizedUsername(const std::string& account_id_key);

  // Testing method for overriding the dbus proxy.
  void set_cryptohome_misc_proxy_for_testing(
      std::unique_ptr<org::chromium::CryptohomeMiscInterfaceProxyInterface>
          proxy) {
    cryptohome_misc_proxy_ = std::move(proxy);
  }

 private:
  // DBus proxy for contacting cryptohome.
  std::unique_ptr<org::chromium::CryptohomeMiscInterfaceProxyInterface>
      cryptohome_misc_proxy_;
};

}  // namespace authpolicy

#endif  // AUTHPOLICY_CRYPTOHOME_CLIENT_H_
