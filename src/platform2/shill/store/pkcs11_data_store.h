// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// A PKCS #11 backed KeyStore implementation.

#ifndef SHILL_STORE_PKCS11_DATA_STORE_H_
#define SHILL_STORE_PKCS11_DATA_STORE_H_

#include <memory>
#include <string>

#include <base/functional/callback.h>
#include <chaps/pkcs11/cryptoki.h>

namespace shill {

// This class uses a PKCS #11 token as storage for data.  The data is stored
// in data objects with the following attributes:
// CKA_CLASS - CKO_DATA
// CKA_LABEL - A data key.
// CKA_VALUE - Binary data (opaque to this class and the PKCS #11 token).
// CKA_APPLICATION - A constant value associated with this class.
// CKA_TOKEN - True
// CKA_PRIVATE - True
// CKA_MODIFIABLE - False
// There is no barrier between the objects created by this class and any other
// objects residing in the same token.  In practice, this means that any
// component with access to the PKCS #11 token also has access to read or delete
// key data.
class Pkcs11DataStore {
 public:
  Pkcs11DataStore();
  Pkcs11DataStore(const Pkcs11DataStore&) = delete;
  Pkcs11DataStore& operator=(const Pkcs11DataStore&) = delete;

  virtual ~Pkcs11DataStore();

  // Reads a data object from PKCS#11 token storage. Returns false if not found.
  bool Read(CK_SLOT_ID slot,
            const std::string& data_key,
            std::string* data_value);
  // Writes a data object into PKCS#11 token storage. Overwrites existing data
  // if one with |data_key| already exists.
  bool Write(CK_SLOT_ID slot,
             const std::string& data_key,
             const std::string& data_value);
  // Deletes a data object from PKCS#11 token storage. Returns true if the
  // object does not exist or is deleted successfully, false upon failure.
  bool Delete(CK_SLOT_ID slot, const std::string& data_key);
  // Deletes all data objects with a certain key prefix. Return false upon
  // operation failure.
  bool DeleteByPrefix(CK_SLOT_ID slot, const std::string& key_prefix);

 private:
  using EnumObjectsCallback = base::RepeatingCallback<bool(
      const std::string& key_name, CK_OBJECT_HANDLE object_handle)>;

  // Searches for a PKCS #11 object for a given key name.  If one exists, the
  // object handle is returned, otherwise CK_INVALID_HANDLE is returned.
  CK_OBJECT_HANDLE FindObject(CK_SESSION_HANDLE session_handle,
                              const std::string& key_name);

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
};

}  // namespace shill

#endif  // SHILL_STORE_PKCS11_DATA_STORE_H_
