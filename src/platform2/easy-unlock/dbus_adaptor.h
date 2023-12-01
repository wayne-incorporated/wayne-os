// Copyright 2014 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef EASY_UNLOCK_DBUS_ADAPTOR_H_
#define EASY_UNLOCK_DBUS_ADAPTOR_H_

#include <stdint.h>

#include <string>
#include <vector>

#include <brillo/dbus/dbus_object.h>
#include <brillo/dbus/async_event_sequencer.h>

namespace dbus {
class MethodCall;
}  // namespace dbus

namespace easy_unlock {
class Service;
}  // namespace easy_unlock

namespace easy_unlock {

// DBus adaptor for EasyUnlock dbus service.
class DBusAdaptor {
 public:
  using CompletionAction =
      brillo::dbus_utils::AsyncEventSequencer::CompletionAction;

  DBusAdaptor(const scoped_refptr<dbus::Bus>& bus,
              easy_unlock::Service* service);
  DBusAdaptor(const DBusAdaptor&) = delete;
  DBusAdaptor& operator=(const DBusAdaptor&) = delete;

  ~DBusAdaptor();

  // Registers handlers for EasyUnlock service method calls.
  void Register(CompletionAction callback);

 private:
  // Handlers for DBus method calls exported in |ExportDBusMethods|.
  // See service_impl.h in easy-unlock-crypto repo for more info on specific
  // methods.
  void GenerateEcP256KeyPair(std::vector<uint8_t>* private_key,
                             std::vector<uint8_t>* public_key);
  std::vector<uint8_t> WrapPublicKey(const std::string& algorithm_str,
                                     const std::vector<uint8_t>& public_key);
  std::vector<uint8_t> PerformECDHKeyAgreement(
      const std::vector<uint8_t>& private_key,
      const std::vector<uint8_t>& public_key);
  std::vector<uint8_t> CreateSecureMessage(
      const std::vector<uint8_t>& payload,
      const std::vector<uint8_t>& key,
      const std::vector<uint8_t>& associated_data,
      const std::vector<uint8_t>& public_metadata,
      const std::vector<uint8_t>& verification_key_id,
      const std::vector<uint8_t>& decryption_key_id,
      const std::string& encryption_type_str,
      const std::string& signature_type_str);
  std::vector<uint8_t> UnwrapSecureMessage(
      const std::vector<uint8_t>& message,
      const std::vector<uint8_t>& key,
      const std::vector<uint8_t>& associated_data,
      const std::string& encryption_type_str,
      const std::string& signature_type_str);

  // The EasyUnlock service implementation to which DBus method calls
  // are forwarded.
  easy_unlock::Service* const service_impl_;
  brillo::dbus_utils::DBusObject dbus_object_;
};

}  // namespace easy_unlock

#endif  // EASY_UNLOCK_DBUS_ADAPTOR_H_
