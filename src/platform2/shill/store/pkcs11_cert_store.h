// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_STORE_PKCS11_CERT_STORE_H_
#define SHILL_STORE_PKCS11_CERT_STORE_H_

#include <chaps/pkcs11/cryptoki.h>

#include <string>

namespace shill {

// This class handles certificates-related PKCS #11 operations.
class Pkcs11CertStore {
 public:
  Pkcs11CertStore() = default;
  Pkcs11CertStore(const Pkcs11CertStore&) = delete;
  Pkcs11CertStore& operator=(const Pkcs11CertStore&) = delete;

  virtual ~Pkcs11CertStore() = default;

  // Deletes all certificates and private keys with a CKA_ID attribute that
  // matches the given |cka_id| from PKCS#11 token storage. Returns true if all
  // matching objects are deleted successfully or if nothing matches, false
  // upon failure.
  bool Delete(CK_SLOT_ID slot, const std::string& cka_id);

 private:
  // Searches for a PKCS#11 objects matching |cka_id|. Upon success,
  // |object_handles| and |out_count| will be populated and the method will
  // return true.
  bool FindObjects(CK_SESSION_HANDLE session_handle,
                   const std::string& cka_id,
                   CK_ULONG max_object_count,
                   CK_OBJECT_HANDLE_PTR object_handles,
                   CK_ULONG& out_count);

  // Get the PKCS#11 class of an object.
  bool GetObjectClass(CK_SESSION_HANDLE session_handle,
                      CK_OBJECT_HANDLE object_handle,
                      CK_OBJECT_CLASS_PTR object_class);
};

}  // namespace shill

#endif  // SHILL_STORE_PKCS11_CERT_STORE_H_
