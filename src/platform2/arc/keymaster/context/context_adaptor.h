// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ARC_KEYMASTER_CONTEXT_CONTEXT_ADAPTOR_H_
#define ARC_KEYMASTER_CONTEXT_CONTEXT_ADAPTOR_H_

#include <memory>
#include <optional>
#include <string>

#include <base/memory/scoped_refptr.h>
#include <base/memory/weak_ptr.h>
#include <brillo/secure_blob.h>
#include <chaps/pkcs11/cryptoki.h>
#include <cryptohome/proto_bindings/UserDataAuth.pb.h>
#include <dbus/bus.h>
#include <user_data_auth-client/user_data_auth/dbus-proxies.h>

namespace arc {
namespace keymaster {
namespace context {

// Helper class for general utilities in the context. It serves two main
// purposes:
// * Implement DBus methods to communicate with other daemons.
// * Offer a simple cache for commonly used data so it doesn't have to be
//   fetched multiple times.
class ContextAdaptor {
 public:
  // The chaps slots this context is aware of. Note this must be in sync with
  // the enum definitions in mojo/cert_store.mojom and proto/key_data.proto.
  enum class Slot {
    kUser,
    kSystem,
  };

  ContextAdaptor();
  // Not copyable nor assignable.
  ContextAdaptor(const ContextAdaptor&) = delete;
  ContextAdaptor& operator=(const ContextAdaptor&) = delete;
  ~ContextAdaptor();

  base::WeakPtr<ContextAdaptor> GetWeakPtr() {
    return weak_ptr_factory_.GetWeakPtr();
  }

  // Returns the slot id of the security token for the given |slot|, or
  // std::nullopt if there's an error in the DBus call.
  std::optional<CK_SLOT_ID> FetchSlotId(Slot slot);

  const std::optional<brillo::SecureBlob>& encryption_key() {
    return cached_encryption_key_;
  }

  void set_encryption_key(const std::optional<brillo::SecureBlob>& key) {
    cached_encryption_key_ = key;
  }

  void set_user_slot_for_tests(CK_SLOT_ID slot) { cached_user_slot_ = slot; }

  void set_system_slot_for_tests(CK_SLOT_ID slot) {
    cached_system_slot_ = slot;
  }

 private:
  // Returns the slot id of the security token for the primary user, or
  // std::nullopt if there's an error in the DBus call.
  std::optional<CK_SLOT_ID> FetchPrimaryUserSlotId();

  // Returns the slot id of the system security token, or std::nullopt if
  // there's an error in the DBus call.
  std::optional<CK_SLOT_ID> FetchSystemSlotId();

  // Returns the email of the primary signed in user, or std::nullopt if
  // there's an error in the DBus call
  std::optional<std::string> FetchPrimaryUserEmail();

  std::optional<CK_SLOT_ID> FetchSlotIdFromTpmTokenInfo(
      std::optional<std::string> user_email);

  scoped_refptr<::dbus::Bus> GetBus();

  scoped_refptr<::dbus::Bus> bus_;
  // Initially nullopt, then populated in the corresponding fetch operation.
  std::optional<CK_SLOT_ID> cached_user_slot_;
  std::optional<CK_SLOT_ID> cached_system_slot_;
  std::optional<std::string> cached_email_;
  // Initially nullopt, then populated in the corresponding setter.
  std::optional<brillo::SecureBlob> cached_encryption_key_;

  // DBus proxy for contacting cryptohome.
  std::unique_ptr<org::chromium::CryptohomePkcs11InterfaceProxyInterface>
      pkcs11_proxy_;

  // Must be last member to ensure weak pointers are invalidated first.
  base::WeakPtrFactory<ContextAdaptor> weak_ptr_factory_;
};

}  // namespace context
}  // namespace keymaster
}  // namespace arc

#endif  // ARC_KEYMASTER_CONTEXT_CONTEXT_ADAPTOR_H_
