// Copyright 2015 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ATTESTATION_SERVER_KEY_STORE_H_
#define ATTESTATION_SERVER_KEY_STORE_H_

#include <string>

#include <attestation/proto_bindings/keystore.pb.h>

namespace attestation {

// A mock-able key storage interface.
class KeyStore {
 public:
  KeyStore() {}
  KeyStore(const KeyStore&) = delete;
  KeyStore& operator=(const KeyStore&) = delete;
  virtual ~KeyStore() {}

  // Reads key data from the store for the key identified by |key_label| and by
  // |username|. On success true is returned and |key_data| is populated.
  virtual bool Read(const std::string& username,
                    const std::string& key_label,
                    std::string* key_data) = 0;

  // Writes key data to the store for the key identified by |key_label| and by
  // |username|. If such a key already exists the existing data will be
  // overwritten.
  virtual bool Write(const std::string& username,
                     const std::string& key_label,
                     const std::string& key_data) = 0;

  // Deletes key data for the key identified by |key_label| and by |username|.
  // Returns false if key data exists but could not be deleted.
  virtual bool Delete(const std::string& username,
                      const std::string& key_label) = 0;

  // Deletes key data for all keys identified by |key_prefix| and by |username|
  // Returns false if key data exists but could not be deleted.
  virtual bool DeleteByPrefix(const std::string& username,
                              const std::string& key_prefix) = 0;

  // Registers a key to be associated with |username|.
  // The provided |label| will be associated with all registered objects.
  // |private_key_blob| holds the private key in some opaque format and
  // |public_key_der| holds the public key in PKCS #1 RSAPublicKey format.
  // If a non-empty |certificate| is provided it will be registered along with
  // the key. Returns true on success.
  virtual bool Register(const std::string& username,
                        const std::string& label,
                        KeyType key_type,
                        KeyUsage key_usage,
                        const std::string& private_key_blob,
                        const std::string& public_key_der,
                        const std::string& certificate) = 0;

  // Registers a |certificate| that is not associated to a registered key. The
  // certificate will be associated with |username|.
  virtual bool RegisterCertificate(const std::string& username,
                                   const std::string& certificate) = 0;
};

}  // namespace attestation

#endif  // ATTESTATION_SERVER_KEY_STORE_H_
