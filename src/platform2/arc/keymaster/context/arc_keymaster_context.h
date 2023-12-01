// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ARC_KEYMASTER_CONTEXT_ARC_KEYMASTER_CONTEXT_H_
#define ARC_KEYMASTER_CONTEXT_ARC_KEYMASTER_CONTEXT_H_

#include <optional>
#include <utility>
#include <vector>

#include <base/memory/scoped_refptr.h>
#include <brillo/secure_blob.h>
#include <hardware/keymaster_defs.h>
#include <keymaster/authorization_set.h>
#include <keymaster/contexts/pure_soft_keymaster_context.h>
#include <keymaster/key.h>
#include <keymaster/key_factory.h>
#include <keymaster/UniquePtr.h>
#include <mojo/cert_store.mojom.h>

#include "arc/keymaster/context/context_adaptor.h"
#include "arc/keymaster/context/cros_key.h"
#include "arc/keymaster/key_data.pb.h"

namespace arc {
namespace keymaster {
namespace context {

// Defines specific behavior for ARC Keymaster in Chrome OS.
class ArcKeymasterContext : public ::keymaster::PureSoftKeymasterContext {
 public:
  ArcKeymasterContext();
  ~ArcKeymasterContext() override;
  // Not copyable nor assignable.
  ArcKeymasterContext(const ArcKeymasterContext&) = delete;
  ArcKeymasterContext& operator=(const ArcKeymasterContext&) = delete;

  // Replaces the list of placeholders for Chrome OS keys.
  void set_placeholder_keys(std::vector<mojom::ChromeOsKeyPtr> keys) {
    placeholder_keys_ = std::move(keys);
  }

  // Returns the Chrome OS key correspponding to the given key blob, if any.
  std::optional<mojom::ChromeOsKeyPtr> FindPlaceholderKey(
      const ::keymaster::KeymasterKeyBlob& key_material) const;

  // PureSoftKeymasterContext overrides.
  keymaster_error_t CreateKeyBlob(
      const ::keymaster::AuthorizationSet& key_description,
      keymaster_key_origin_t origin,
      const ::keymaster::KeymasterKeyBlob& key_material,
      ::keymaster::KeymasterKeyBlob* key_blob,
      ::keymaster::AuthorizationSet* hw_enforced,
      ::keymaster::AuthorizationSet* sw_enforced) const override;
  keymaster_error_t ParseKeyBlob(
      const ::keymaster::KeymasterKeyBlob& key_blob,
      const ::keymaster::AuthorizationSet& additional_params,
      ::keymaster::UniquePtr<::keymaster::Key>* key) const override;
  keymaster_error_t UpgradeKeyBlob(
      const ::keymaster::KeymasterKeyBlob& key_to_upgrade,
      const ::keymaster::AuthorizationSet& upgrade_params,
      ::keymaster::KeymasterKeyBlob* upgraded_key) const override;

 private:
  // If |key_blob| contains an ARC owned key, deserialize it into |key_material|
  // and auth sets. Otherwise it is a CrOS owned key, deserialized into |key|.
  //
  // Can also deserialize insecure blobs.
  keymaster_error_t DeserializeBlob(
      const ::keymaster::KeymasterKeyBlob& key_blob,
      const ::keymaster::AuthorizationSet& hidden,
      ::keymaster::KeymasterKeyBlob* key_material,
      ::keymaster::AuthorizationSet* hw_enforced,
      ::keymaster::AuthorizationSet* sw_enforced,
      ::keymaster::UniquePtr<::keymaster::Key>* key) const;

  // Serialize the given key data info the output |key_blob|.
  keymaster_error_t SerializeKeyDataBlob(
      const ::keymaster::KeymasterKeyBlob& key_material,
      const ::keymaster::AuthorizationSet& hidden,
      const ::keymaster::AuthorizationSet& hw_enforced,
      const ::keymaster::AuthorizationSet& sw_enforced,
      ::keymaster::KeymasterKeyBlob* key_blob) const;

  // If |key_blob| contains an ARC owned key, deserialize it into |key_material|
  // and auth sets. Otherwise it is a CrOS owned key, deserialized into |key|.
  //
  // Only handles key blobs serialized by |SerializeKeyDataBlob|.
  keymaster_error_t DeserializeKeyDataBlob(
      const ::keymaster::KeymasterKeyBlob& key_blob,
      const ::keymaster::AuthorizationSet& hidden,
      ::keymaster::KeymasterKeyBlob* key_material,
      ::keymaster::AuthorizationSet* hw_enforced,
      ::keymaster::AuthorizationSet* sw_enforced,
      ::keymaster::UniquePtr<::keymaster::Key>* key) const;

  // Constructs a new Chrome OS |key|.
  keymaster_error_t LoadKey(
      KeyData&& key_data,
      ::keymaster::AuthorizationSet&& hw_enforced,
      ::keymaster::AuthorizationSet&& sw_enforced,
      ::keymaster::UniquePtr<::keymaster::Key>* key) const;

  // Serializes |key_data| into |key_blob|.
  bool SerializeKeyData(const KeyData& key_data,
                        const ::keymaster::AuthorizationSet& hidden,
                        ::keymaster::KeymasterKeyBlob* key_blob) const;

  // Deserializes the contents of |key_blob| into |key_data|.
  std::optional<KeyData> DeserializeKeyData(
      const ::keymaster::KeymasterKeyBlob& key_blob,
      const ::keymaster::AuthorizationSet& hidden) const;

  // Parses the given parameter into an instance of KeyData.
  //
  // May return |std::nullopt| when the placeholder key correspponding to this
  // |key_material| is invalid.
  std::optional<KeyData> PackToKeyData(
      const ::keymaster::KeymasterKeyBlob& key_material,
      const ::keymaster::AuthorizationSet& hw_enforced,
      const ::keymaster::AuthorizationSet& sw_enforced) const;

  // Removes the given |key| from the list of |placeholder_keys_|.
  void DeletePlaceholderKey(const mojom::ChromeOsKeyPtr& key) const;

  mutable ContextAdaptor context_adaptor_;

  mutable CrosKeyFactory rsa_key_factory_;

  // Holds placeholder keys that will be installed by ARC.
  //
  // Placeholders maintain information about keys owned by Chrome OS. When ARC
  // tries to install a new key, arc-keymasterd checks if it is a placeholder,
  // and if so, replaces it with a handle to the original Chrome OS key instead.
  //
  // From that point on, operation on that key will be executed on the original
  // Chrome OS key.
  mutable std::vector<mojom::ChromeOsKeyPtr> placeholder_keys_;

  // Friend class for testing.
  friend class ContextTestPeer;
};

namespace internal {

// Expose SerializeAuthorizationSetToBlob for tests.
brillo::Blob TestSerializeAuthorizationSetToBlob(
    const ::keymaster::AuthorizationSet& authorization_set);

}  // namespace internal

}  // namespace context
}  // namespace keymaster
}  // namespace arc

#endif  // ARC_KEYMASTER_CONTEXT_ARC_KEYMASTER_CONTEXT_H_
