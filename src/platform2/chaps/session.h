// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHAPS_SESSION_H_
#define CHAPS_SESSION_H_

#include <string>
#include <vector>

#include "pkcs11/cryptoki.h"

namespace chaps {

class Object;

enum OperationType {
  kEncrypt,
  kDecrypt,
  kDigest,
  kSign,
  kVerify,
  kNumOperationTypes
};

// Session is the interface for a PKCS #11 session.  This component is
// responsible for maintaining session state including the state of any multi-
// part operations and any session objects.  It is also responsible for
// executing all session-specific operations.
class Session {
 public:
  virtual ~Session() {}
  // General state management (see PKCS #11 v2.20: 11.6 C_GetSessionInfo).
  virtual int GetSlot() const = 0;
  virtual CK_STATE GetState() const = 0;
  virtual bool IsReadOnly() const = 0;
  virtual bool IsOperationActive(OperationType type) const = 0;
  // Object management (see PKCS #11 v2.20: 11.7).
  virtual CK_RV CreateObject(const CK_ATTRIBUTE_PTR attributes,
                             int num_attributes,
                             int* new_object_handle) = 0;
  virtual CK_RV CopyObject(const CK_ATTRIBUTE_PTR attributes,
                           int num_attributes,
                           int object_handle,
                           int* new_object_handle) = 0;
  virtual CK_RV DestroyObject(int object_handle) = 0;
  virtual bool GetObject(int object_handle, const Object** object) = 0;
  virtual bool GetModifiableObject(int object_handle, Object** object) = 0;
  virtual CK_RV FlushModifiableObject(Object* object) = 0;
  virtual CK_RV FindObjectsInit(const CK_ATTRIBUTE_PTR attributes,
                                int num_attributes) = 0;
  virtual CK_RV FindObjects(int max_object_count,
                            std::vector<int>* object_handles) = 0;
  virtual CK_RV FindObjectsFinal() = 0;
  // Cryptographic operations (encrypt, decrypt, digest, sign, verify). See
  // PKCS #11 v2.20: 11.8 through 11.12 for details on these operations. See
  // section 11.2 for a description of PKCS #11 operation output semantics.
  //   All methods providing output use the following parameters:
  //     required_out_length - Provides the maximum output receivable on input
  //                           and is populated with the required output length.
  //     data_out - Is populated with output data if the required output length
  //                is not greater than the maximum receivable length.
  //                Otherwise, the method must be called again with an
  //                appropriate maximum in order to receive the output. All
  //                input will be ignored until the output has been received by
  //                the caller.
  //
  // OperationInit - Initializes a cryptographic operation for this session
  //                 (like C_EncryptInit for an encrypt operation).
  //   operation - The operation type to be initialized. Only one operation of a
  //               given type may be active at a given time (like PKCS #11).
  //   mechanism - The PKCS #11 mechanism to be executed.
  //   key - The key to use for the operation (may be NULL only if the operation
  //         does not use a key (e.g. Digest).
  virtual CK_RV OperationInit(OperationType operation,
                              CK_MECHANISM_TYPE mechanism,
                              const std::string& mechanism_parameter,
                              const Object* key) = 0;
  // Continues an operation that is already active (like C_EncryptUpdate). If
  // the operation does not provide output (e.g. C_DigestUpdate),
  // required_out_length and data_out may be NULL. If the operation does produce
  // output then these parameters must not be NULL (even if none is expected
  // this iteration).
  virtual CK_RV OperationUpdate(OperationType operation,
                                const std::string& data_in,
                                int* required_out_length,
                                std::string* data_out) = 0;
  // Finalizes an operation for which all input has been provided (like
  // C_EncryptFinal. The required_out_length and data_out parameters must not be
  // NULL. Verify operations must use VerifyFinal.
  virtual CK_RV OperationFinal(OperationType operation,
                               int* required_out_length,
                               std::string* data_out) = 0;
  // Cancels an operation that is already active (like C_EncryptUpdate).
  virtual void OperationCancel(OperationType operation) = 0;
  // Finalizes a signature verification operation (like C_VerifyFinal).
  virtual CK_RV VerifyFinal(const std::string& signature) = 0;
  // Performs an entire operation in a single step (like C_Encrypt). This is
  // like calling OperationUpdate followed by OperationFinal but with combined
  // output semantics (i.e. buffer-too-small case will return total output size
  // for both steps).
  virtual CK_RV OperationSinglePart(OperationType operation,
                                    const std::string& data_in,
                                    int* required_out_length,
                                    std::string* data_out) = 0;
  // Key generation (see PKCS #11 v2.20: 11.14).
  virtual CK_RV GenerateKey(CK_MECHANISM_TYPE mechanism,
                            const std::string& mechanism_parameter,
                            const CK_ATTRIBUTE_PTR attributes,
                            int num_attributes,
                            int* new_key_handle) = 0;
  virtual CK_RV GenerateKeyPair(CK_MECHANISM_TYPE mechanism,
                                const std::string& mechanism_parameter,
                                const CK_ATTRIBUTE_PTR public_attributes,
                                int num_public_attributes,
                                const CK_ATTRIBUTE_PTR private_attributes,
                                int num_private_attributes,
                                int* new_public_key_handle,
                                int* new_private_key_handle) = 0;
  // Random number generation (see PKCS #11 v2.20: 11.15).
  virtual CK_RV SeedRandom(const std::string& seed) = 0;
  virtual CK_RV GenerateRandom(int num_bytes, std::string* random_data) = 0;
  // Returns true if private objects are loaded and the session is ready for
  // operations with them without blocking.
  virtual bool IsPrivateLoaded() = 0;
};

}  // namespace chaps

#endif  // CHAPS_SESSION_H_
