// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHAPS_SESSION_IMPL_H_
#define CHAPS_SESSION_IMPL_H_

#include "chaps/session.h"

#include <map>
#include <memory>
#include <string>
#include <vector>

#include <base/functional/callback_helpers.h>
#include <crypto/scoped_openssl_types.h>
#include <libhwsec/frontend/chaps/frontend.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

#include "chaps/chaps_factory.h"
#include "chaps/chaps_metrics.h"
#include "chaps/object.h"
#include "chaps/object_pool.h"
#include "pkcs11/cryptoki.h"

namespace chaps {

class ChapsFactory;
class ObjectPool;

// SessionImpl is the interface for a PKCS #11 session.  This component is
// responsible for maintaining session state including the state of any multi-
// part operations and any session objects.  It is also responsible for
// executing all session-specific operations.
class SessionImpl : public Session {
 public:
  // This stores the state of an operation.
  // This is public because RSASignerVerifier helper uses it.
  struct OperationContext {
    bool is_valid_;        // Whether the contents of this structure are valid.
    bool is_cipher_;       // Set to true when cipher_context_ is valid.
    bool is_digest_;       // Set to true when digest_context_ is valid.
    bool is_hmac_;         // Set to true when hmac_context_ is valid.
    bool is_incremental_;  // Set when an incremental operation is performed.
    bool is_finished_;     // Set to true when the operation completes.
    crypto::ScopedEVP_CIPHER_CTX cipher_context_;
    crypto::ScopedEVP_MD_CTX digest_context_;
    crypto::ScopedHMAC_CTX hmac_context_;
    std::string data_;  // This can be used to queue input or output.
    const Object* key_;
    CK_MECHANISM_TYPE mechanism_;
    std::string parameter_;  // The mechanism parameter (if any).
    base::ScopedClosureRunner cleanup_;  // The extra closure for cleanup.

    OperationContext();
    ~OperationContext();

    void Clear();
  };

  // The ownership and management of the pointers provided here are outside the
  // scope of this class. Typically, the object pool will be managed by the slot
  // manager and will be shared by all sessions associated with the same slot.
  // The hwsec and factory objects are typically singletons and shared across
  // all sessions and slots.
  SessionImpl(int slot_id,
              ObjectPool* token_object_pool,
              const hwsec::ChapsFrontend* hwsec,
              ChapsFactory* factory,
              HandleGenerator* handle_generator,
              bool is_read_only,
              ChapsMetrics* chaps_metrics);
  SessionImpl(const SessionImpl&) = delete;
  SessionImpl& operator=(const SessionImpl&) = delete;

  ~SessionImpl() override;

  // General state management.
  int GetSlot() const override;
  CK_STATE GetState() const override;
  bool IsReadOnly() const override;
  bool IsOperationActive(OperationType type) const override;

  // Object management.
  CK_RV CreateObject(const CK_ATTRIBUTE_PTR attributes,
                     int num_attributes,
                     int* new_object_handle) override;
  CK_RV CopyObject(const CK_ATTRIBUTE_PTR attributes,
                   int num_attributes,
                   int object_handle,
                   int* new_object_handle) override;
  CK_RV DestroyObject(int object_handle) override;
  bool GetObject(int object_handle, const Object** object) override;
  bool GetModifiableObject(int object_handle, Object** object) override;
  CK_RV FlushModifiableObject(Object* object) override;
  CK_RV FindObjectsInit(const CK_ATTRIBUTE_PTR attributes,
                        int num_attributes) override;
  CK_RV FindObjects(int max_object_count,
                    std::vector<int>* object_handles) override;
  CK_RV FindObjectsFinal() override;

  // Cryptographic operations (encrypt, decrypt, digest, sign, verify).
  CK_RV OperationInit(OperationType operation,
                      CK_MECHANISM_TYPE mechanism,
                      const std::string& mechanism_parameter,
                      const Object* key) override;
  CK_RV OperationUpdate(OperationType operation,
                        const std::string& data_in,
                        int* required_out_length,
                        std::string* data_out) override;
  CK_RV OperationFinal(OperationType operation,
                       int* required_out_length,
                       std::string* data_out) override;
  void OperationCancel(OperationType operation) override;
  CK_RV VerifyFinal(const std::string& signature) override;
  CK_RV OperationSinglePart(OperationType operation,
                            const std::string& data_in,
                            int* required_out_length,
                            std::string* data_out) override;

  // Key generation.
  CK_RV GenerateKey(CK_MECHANISM_TYPE mechanism,
                    const std::string& mechanism_parameter,
                    const CK_ATTRIBUTE_PTR attributes,
                    int num_attributes,
                    int* new_key_handle) override;
  CK_RV GenerateKeyPair(CK_MECHANISM_TYPE mechanism,
                        const std::string& mechanism_parameter,
                        const CK_ATTRIBUTE_PTR public_attributes,
                        int num_public_attributes,
                        const CK_ATTRIBUTE_PTR private_attributes,
                        int num_private_attributes,
                        int* new_public_key_handle,
                        int* new_private_key_handle) override;

  // Random number generation.
  CK_RV SeedRandom(const std::string& seed) override;
  CK_RV GenerateRandom(int num_bytes, std::string* random_data) override;
  bool IsPrivateLoaded() override;

  size_t get_object_key_map_size_for_testing() {
    return object_key_map_.size();
  }

 private:
  CK_RV OperationUpdateInternal(OperationType operation,
                                const std::string& data_in,
                                int* required_out_length,
                                std::string* data_out);
  CK_RV OperationFinalInternal(OperationType operation,
                               int* required_out_length,
                               std::string* data_out,
                               bool clear_context = true);
  // An extra layer of raw functions are added to simplify the  UMA report code.
  // These raw functions should not call ReportChapsSessionStatus(), otherwise
  // the status will be double counted.
  CK_RV OperationInitRaw(OperationType operation,
                         CK_MECHANISM_TYPE mechanism,
                         const std::string& mechanism_parameter,
                         const Object* key);
  CK_RV OperationUpdateRaw(OperationType operation,
                           const std::string& data_in,
                           int* required_out_length,
                           std::string* data_out);
  CK_RV OperationFinalRaw(OperationType operation,
                          int* required_out_length,
                          std::string* data_out,
                          bool clear_context = true);
  CK_RV OperationSinglePartRaw(OperationType operation,
                               const std::string& data_in,
                               int* required_out_length,
                               std::string* data_out);
  CK_RV CipherInit(bool is_encrypt,
                   CK_MECHANISM_TYPE mechanism,
                   const std::string& mechanism_parameter,
                   const Object* key);
  CK_RV CipherUpdate(OperationContext* context,
                     const std::string& data_in,
                     int* required_out_length,
                     std::string* data_out);
  CK_RV CipherFinal(OperationContext* context);
  CK_RV CreateObjectInternal(const CK_ATTRIBUTE_PTR attributes,
                             int num_attributes,
                             const Object* copy_from_object,
                             int* new_object_handle);
  bool GenerateDESKey(std::string* key_material);

  CK_RV GenerateRSAKeyPair(Object* public_object, Object* private_object);
  bool GenerateRSAKeyPairSoftware(int modulus_bits,
                                  const std::string& public_exponent,
                                  Object* public_object,
                                  Object* private_object);
  bool GenerateRSAKeyPairHwsec(int modulus_bits,
                               const std::string& public_exponent,
                               Object* public_object,
                               Object* private_object);

  CK_RV GenerateECCKeyPair(Object* public_object, Object* private_object);
  bool GenerateECCKeyPairSoftware(const crypto::ScopedEC_KEY& key,
                                  Object* public_object,
                                  Object* private_object);
  bool GenerateECCKeyPairHwsec(const crypto::ScopedEC_KEY& key,
                               int curve_nid,
                               Object* public_object,
                               Object* private_object);

  // Provides operation output and handles the buffer-too-small case.
  // The output data must be in context->data_.
  // required_out_length - In: The maximum number of bytes that can be received.
  //                       Out: The actual number of bytes to be received.
  // data_out - Receives the output data if maximum >= actual.
  CK_RV GetOperationOutput(OperationContext* context,
                           int* required_out_length,
                           std::string* data_out);
  // Returns the key usage flag that must be set in order to perform the given
  // operation (e.g. kEncrypt requires CKA_ENCRYPT to be TRUE).
  CK_ATTRIBUTE_TYPE GetRequiredKeyUsage(OperationType operation);
  hwsec::StatusOr<hwsec::Key> GetHwsecKey(const Object* key);
  void UpdateObjectCount(OperationContext* context);
  void IncreaseObjectCount(const Object* key);
  void DecreaseObjectCount(const Object* key);

  // RSA operations
  bool RSAEncrypt(OperationContext* context);
  bool RSADecrypt(OperationContext* context);
  bool RSASign(OperationContext* context);
  CK_RV RSAVerify(OperationContext* context,
                  const std::string& digest,
                  const std::string& signature);

  // ECC operations
  bool ECCSign(OperationContext* context);
  bool ECCSignHwsec(const std::string& input,
                    CK_MECHANISM_TYPE signing_mechanism,
                    const Object* key_object,
                    std::string* signature);
  bool ECCSignSoftware(const std::string& input,
                       const Object* key_object,
                       std::string* signature);
  CK_RV ECCVerify(OperationContext* context,
                  const std::string& signed_data,
                  const std::string& signature);

  // Wraps the given private key using the HWSec and deletes all sensitive
  // attributes. This is called when a private key is imported. On success,
  // the private key can only be accessed by the HWSec.
  CK_RV WrapPrivateKey(Object* object);
  CK_RV WrapRSAPrivateKey(Object* object);
  CK_RV WrapECCPrivateKey(Object* object);

  ChapsFactory* factory_;
  std::vector<int> find_results_;
  size_t find_results_offset_;
  bool find_results_valid_;
  bool is_read_only_;
  std::map<const Object*, hwsec::ScopedKey> object_key_map_;
  std::map<const Object*, uint32_t> object_count_map_;

  // The context operations should be destruct before the object maps.
  OperationContext operation_context_[kNumOperationTypes];
  int slot_id_;
  std::unique_ptr<ObjectPool> session_object_pool_;
  ObjectPool* token_object_pool_;
  const hwsec::ChapsFrontend* hwsec_;
  ChapsMetrics* chaps_metrics_;
};

}  // namespace chaps

#endif  // CHAPS_SESSION_IMPL_H_
