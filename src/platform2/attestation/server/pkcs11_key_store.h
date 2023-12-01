// Copyright 2015 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ATTESTATION_SERVER_PKCS11_KEY_STORE_H_
#define ATTESTATION_SERVER_PKCS11_KEY_STORE_H_

#include "attestation/server/key_store.h"

#include <string>

#include <base/functional/callback_forward.h>
#include <chaps/pkcs11/cryptoki.h>
#include <chaps/token_manager_client.h>

namespace attestation {

// This class uses a PKCS #11 token as storage for key data.  The key data is
// stored in data objects with the following attributes:
// CKA_CLASS - CKO_DATA
// CKA_LABEL - A key name.
// CKA_VALUE - Binary key data (opaque to this class and the PKCS #11 token).
// CKA_APPLICATION - A constant value associated with this class.
// CKA_TOKEN - True
// CKA_PRIVATE - True
// CKA_MODIFIABLE - False
// There is no barrier between the objects created by this class and any other
// objects residing in the same token.  In practice, this means that any
// component with access to the PKCS #11 token also has access to read or delete
// key data.
class Pkcs11KeyStore : public KeyStore {
 public:
  // Does not take ownership of pointers.
  explicit Pkcs11KeyStore(chaps::TokenManagerClient* token_manager);
  Pkcs11KeyStore(const Pkcs11KeyStore&) = delete;
  Pkcs11KeyStore& operator=(const Pkcs11KeyStore&) = delete;

  ~Pkcs11KeyStore() override;

  // KeyStore interface.
  bool Read(const std::string& username,
            const std::string& key_name,
            std::string* key_data) override;
  bool Write(const std::string& username,
             const std::string& key_name,
             const std::string& key_data) override;
  bool Delete(const std::string& username,
              const std::string& key_name) override;
  bool DeleteByPrefix(const std::string& username,
                      const std::string& key_prefix) override;
  bool Register(const std::string& username,
                const std::string& label,
                KeyType key_type,
                KeyUsage key_usage,
                const std::string& private_key_blob,
                const std::string& public_key_der,
                const std::string& certificate) override;
  bool RegisterCertificate(const std::string& username,
                           const std::string& certificate) override;

 private:
  using EnumObjectsCallback = base::RepeatingCallback<bool(
      const std::string& key_name, CK_OBJECT_HANDLE object_handle)>;

  // Searches for a PKCS #11 object for a given key name.  If one exists, the
  // object handle is returned, otherwise CK_INVALID_HANDLE is returned.
  CK_OBJECT_HANDLE FindObject(CK_SESSION_HANDLE session_handle,
                              const std::string& key_name);

  // Gets a slot for the given |username| if |is_user_specific| or the system
  // slot otherwise. Returns false if no appropriate slot is found.
  bool GetUserSlot(const std::string& username, CK_SLOT_ID_PTR slot);

  // Enumerates all PKCS #11 objects associated with keys.  The |callback| is
  // called once for each object.
  bool EnumObjects(CK_SESSION_HANDLE session_handle,
                   const EnumObjectsCallback& callback);

  // Looks up the key name for the given |object_handle| which is associated
  // with a key.  Returns true on success.
  bool GetKeyName(CK_SESSION_HANDLE session_handle,
                  CK_OBJECT_HANDLE object_handle,
                  std::string* key_name);

  // An EnumObjectsCallback for use with DeleteByPrefix.  Destroys the key
  // object identified by |object_handle| if |key_name| matches |key_prefix|.
  // Returns true on success.
  bool DeleteIfMatchesPrefix(CK_SESSION_HANDLE session_handle,
                             const std::string& key_prefix,
                             const std::string& key_name,
                             CK_OBJECT_HANDLE object_handle);

  // Extracts the |subject|, |issuer|, and |serial_number| information from an
  // X.509 |certificate|. Returns false if the value cannot be determined.
  bool GetCertificateFields(const std::string& certificate,
                            std::string* subject,
                            std::string* issuer,
                            std::string* serial_number);

  // Returns true iff the given certificate already exists in the token.
  bool DoesCertificateExist(CK_SESSION_HANDLE session_handle,
                            const std::string& certificate);

  chaps::TokenManagerClient* token_manager_;
};

}  // namespace attestation

#endif  // ATTESTATION_SERVER_PKCS11_KEY_STORE_H_
