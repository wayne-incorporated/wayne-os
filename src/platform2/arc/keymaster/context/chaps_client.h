// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ARC_KEYMASTER_CONTEXT_CHAPS_CLIENT_H_
#define ARC_KEYMASTER_CONTEXT_CHAPS_CLIENT_H_

#include <memory>
#include <optional>
#include <string>

#include <base/memory/weak_ptr.h>
#include <brillo/secure_blob.h>
#include <chaps/pkcs11/cryptoki.h>

#include "arc/keymaster/context/context_adaptor.h"

namespace arc {
namespace keymaster {
namespace context {

namespace internal {

class ScopedSession;

}  // namespace internal

// Exposes chaps functionality through an API that is relevant to the ARC
// Keymaster context.
class ChapsClient {
 public:
  ChapsClient(base::WeakPtr<ContextAdaptor> context_adaptor,
              ContextAdaptor::Slot slot);
  // Not copyable nor assignable.
  ChapsClient(const ChapsClient&) = delete;
  ChapsClient& operator=(const ChapsClient&) = delete;
  ~ChapsClient();

  // Returns a handle to the chaps object with given |label| and |id|.
  std::optional<CK_OBJECT_HANDLE> FindObject(CK_OBJECT_CLASS object_class,
                                             const std::string& label,
                                             const brillo::Blob& id);

  // Returns the SPKI of a certificate identified by the given |label| and |id|.
  std::optional<brillo::Blob> ExportSubjectPublicKeyInfo(
      const std::string& label, const brillo::Blob& id);

  // Initializes a new signature operation.
  //
  // Mechanism types known to work are (though others may work too):
  // * CKM_RSA_PKCS
  // * CKM_SHA256_RSA_PKCS
  bool InitializeSignature(CK_MECHANISM_TYPE mechanism_type,
                           CK_OBJECT_HANDLE key_handle);

  // Updates an ongoing signature operation with |input|.
  bool UpdateSignature(const brillo::Blob& input);

  // Finishes an ongoing signature operation, returning the final signature.
  std::optional<brillo::Blob> FinalizeSignature();

  // Returns the ARC Keymaster AES-256 encryption key material. If the key does
  // not exist yet it will be generated. Returns std::nullopt if there's an
  // error in the PKCS #11 operation.
  std::optional<brillo::SecureBlob> ExportOrGenerateEncryptionKey();

  // Retrieves an identifier for this client's session. Used to identify
  // simultaneously existing clients and operations. Returns std::nullopt if
  // there's an error in the PKCS #11 operation opening the session.
  std::optional<CK_SESSION_HANDLE> session_handle();

 private:
  // Returns a handle to the key with the given |label|. Returns std::nullopt
  // if there's an error in the PKCS #11 operation.
  std::optional<CK_OBJECT_HANDLE> FindKey(const std::string& label);

  // Exports the secret material of a key, given its PKCS #11 |key_handle|. For
  // this to work the key needs to have been created with CKA_EXTRACTABLE true
  // and CKA_SENSITIVE false.
  //
  // When this function returns CKR_OK the pointer |exported_key| is set with
  // the key material corresponding to |key_handle|.
  //
  // When this function returns CKR_SESSION_HANDLE_INVALID the |key_handle|
  // given has become invalid, and callers should retry in a new session.
  //
  // For any other return value, some error happened.
  CK_RV ExportKey(CK_OBJECT_HANDLE key_handle,
                  brillo::SecureBlob* exported_key);

  // Generates the ARC Keymaster AES-256 encryption key material and returns its
  // handle. Returns std::nullopt if there's an error in the PKCS #11
  // operation.
  std::optional<CK_OBJECT_HANDLE> GenerateEncryptionKey();

  // Retrieves the PKCS #11 byte array CKA_VALUE corresponding to
  // |attribute_type| of |object_handle|.
  //
  // When this function returns CKR_OK the pointer |attribute_value| is set with
  // the CKA_VALUE byte array.
  //
  // When this function returns CKR_SESSION_HANDLE_INVALID the |object_handle|
  // given has become invalid, and callers should retry in a new session.
  //
  // For any other return value, some error happened.
  CK_RV GetBytesAttribute(CK_OBJECT_HANDLE object_handle,
                          CK_ATTRIBUTE_TYPE attribute_type,
                          brillo::SecureBlob* attribute_value);

  // Verifies ARC has permissions to access the chaps key identified by
  // |key_handle|.
  //
  // ARC permissions are managed by Chrome based on whether the KeyPermissions
  // policy includes ARC applications.
  bool VerifyArcPermissionForKey(CK_OBJECT_HANDLE key_handle);

  std::unique_ptr<internal::ScopedSession> session_;

  base::WeakPtr<ContextAdaptor> context_adaptor_;

  const ContextAdaptor::Slot slot_;
};

}  // namespace context
}  // namespace keymaster
}  // namespace arc

#endif  // ARC_KEYMASTER_CONTEXT_CHAPS_CLIENT_H_
