// Copyright 2011 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHAPS_CHAPS_SERVICE_H_
#define CHAPS_CHAPS_SERVICE_H_

#include <string>
#include <vector>

#include <chaps/proto_bindings/ck_structs.pb.h>

#include "chaps/chaps_interface.h"
#include "chaps/slot_manager.h"
#include "pkcs11/cryptoki.h"

namespace chaps {

// ChapsServiceImpl implements the Chaps IPC interface.  This class effectively
// serves as the entry point to the Chaps daemon and is called directly by
// ChapsAdaptor.
class ChapsServiceImpl : public ChapsInterface {
 public:
  // ChapsServiceImpl does not take ownership of slot_manager and will not
  // delete it.
  explicit ChapsServiceImpl(SlotManager* slot_manager);
  ChapsServiceImpl(const ChapsServiceImpl&) = delete;
  ChapsServiceImpl& operator=(const ChapsServiceImpl&) = delete;

  ~ChapsServiceImpl() override = default;

  // ChapsInterface methods
  uint32_t GetSlotList(const brillo::SecureBlob& isolate_credential,
                       bool token_present,
                       std::vector<uint64_t>* slot_list) override;
  uint32_t GetSlotInfo(const brillo::SecureBlob& isolate_credential,
                       uint64_t slot_id,
                       SlotInfo* slot_info) override;
  uint32_t GetTokenInfo(const brillo::SecureBlob& isolate_credential,
                        uint64_t slot_id,
                        TokenInfo* token_info) override;
  uint32_t GetMechanismList(const brillo::SecureBlob& isolate_credential,
                            uint64_t slot_id,
                            std::vector<uint64_t>* mechanism_list) override;
  uint32_t GetMechanismInfo(const brillo::SecureBlob& isolate_credential,
                            uint64_t slot_id,
                            uint64_t mechanism_type,
                            MechanismInfo* mechanism_info) override;
  uint32_t InitToken(const brillo::SecureBlob& isolate_credential,
                     uint64_t slot_id,
                     const std::string* so_pin,
                     const std::vector<uint8_t>& label) override;
  uint32_t InitPIN(const brillo::SecureBlob& isolate_credential,
                   uint64_t session_id,
                   const std::string* pin) override;
  uint32_t SetPIN(const brillo::SecureBlob& isolate_credential,
                  uint64_t session_id,
                  const std::string* old_pin,
                  const std::string* new_pin) override;
  uint32_t OpenSession(const brillo::SecureBlob& isolate_credential,
                       uint64_t slot_id,
                       uint64_t flags,
                       uint64_t* session_id) override;
  uint32_t CloseSession(const brillo::SecureBlob& isolate_credential,
                        uint64_t session_id) override;
  uint32_t GetSessionInfo(const brillo::SecureBlob& isolate_credential,
                          uint64_t session_id,
                          SessionInfo* session_info) override;
  uint32_t GetOperationState(const brillo::SecureBlob& isolate_credential,
                             uint64_t session_id,
                             std::vector<uint8_t>* operation_state) override;
  uint32_t SetOperationState(const brillo::SecureBlob& isolate_credential,
                             uint64_t session_id,
                             const std::vector<uint8_t>& operation_state,
                             uint64_t encryption_key_handle,
                             uint64_t authentication_key_handle) override;
  uint32_t Login(const brillo::SecureBlob& isolate_credential,
                 uint64_t session_id,
                 uint64_t user_type,
                 const std::string* pin) override;
  uint32_t Logout(const brillo::SecureBlob& isolate_credential,
                  uint64_t session_id) override;
  uint32_t CreateObject(const brillo::SecureBlob& isolate_credential,
                        uint64_t session_id,
                        const std::vector<uint8_t>& attributes,
                        uint64_t* new_object_handle) override;
  uint32_t CopyObject(const brillo::SecureBlob& isolate_credential,
                      uint64_t session_id,
                      uint64_t object_handle,
                      const std::vector<uint8_t>& attributes,
                      uint64_t* new_object_handle) override;
  uint32_t DestroyObject(const brillo::SecureBlob& isolate_credential,
                         uint64_t session_id,
                         uint64_t object_handle) override;
  uint32_t GetObjectSize(const brillo::SecureBlob& isolate_credential,
                         uint64_t session_id,
                         uint64_t object_handle,
                         uint64_t* object_size) override;
  uint32_t GetAttributeValue(const brillo::SecureBlob& isolate_credential,
                             uint64_t session_id,
                             uint64_t object_handle,
                             const std::vector<uint8_t>& attributes_in,
                             std::vector<uint8_t>* attributes_out) override;
  uint32_t SetAttributeValue(const brillo::SecureBlob& isolate_credential,
                             uint64_t session_id,
                             uint64_t object_handle,
                             const std::vector<uint8_t>& attributes) override;
  uint32_t FindObjectsInit(const brillo::SecureBlob& isolate_credential,
                           uint64_t session_id,
                           const std::vector<uint8_t>& attributes) override;
  uint32_t FindObjects(const brillo::SecureBlob& isolate_credential,
                       uint64_t session_id,
                       uint64_t max_object_count,
                       std::vector<uint64_t>* object_list) override;
  uint32_t FindObjectsFinal(const brillo::SecureBlob& isolate_credential,
                            uint64_t session_id) override;
  uint32_t EncryptInit(const brillo::SecureBlob& isolate_credential,
                       uint64_t session_id,
                       uint64_t mechanism_type,
                       const std::vector<uint8_t>& mechanism_parameter,
                       uint64_t key_handle) override;
  uint32_t Encrypt(const brillo::SecureBlob& isolate_credential,
                   uint64_t session_id,
                   const std::vector<uint8_t>& data_in,
                   uint64_t max_out_length,
                   uint64_t* actual_out_length,
                   std::vector<uint8_t>* data_out) override;
  uint32_t EncryptUpdate(const brillo::SecureBlob& isolate_credential,
                         uint64_t session_id,
                         const std::vector<uint8_t>& data_in,
                         uint64_t max_out_length,
                         uint64_t* actual_out_length,
                         std::vector<uint8_t>* data_out) override;
  uint32_t EncryptFinal(const brillo::SecureBlob& isolate_credential,
                        uint64_t session_id,
                        uint64_t max_out_length,
                        uint64_t* actual_out_length,
                        std::vector<uint8_t>* data_out) override;
  void EncryptCancel(const brillo::SecureBlob& isolate_credential,
                     uint64_t session_id) override;
  uint32_t DecryptInit(const brillo::SecureBlob& isolate_credential,
                       uint64_t session_id,
                       uint64_t mechanism_type,
                       const std::vector<uint8_t>& mechanism_parameter,
                       uint64_t key_handle) override;
  uint32_t Decrypt(const brillo::SecureBlob& isolate_credential,
                   uint64_t session_id,
                   const std::vector<uint8_t>& data_in,
                   uint64_t max_out_length,
                   uint64_t* actual_out_length,
                   std::vector<uint8_t>* data_out) override;
  uint32_t DecryptUpdate(const brillo::SecureBlob& isolate_credential,
                         uint64_t session_id,
                         const std::vector<uint8_t>& data_in,
                         uint64_t max_out_length,
                         uint64_t* actual_out_length,
                         std::vector<uint8_t>* data_out) override;
  uint32_t DecryptFinal(const brillo::SecureBlob& isolate_credential,
                        uint64_t session_id,
                        uint64_t max_out_length,
                        uint64_t* actual_out_length,
                        std::vector<uint8_t>* data_out) override;
  void DecryptCancel(const brillo::SecureBlob& isolate_credential,
                     uint64_t session_id) override;
  uint32_t DigestInit(const brillo::SecureBlob& isolate_credential,
                      uint64_t session_id,
                      uint64_t mechanism_type,
                      const std::vector<uint8_t>& mechanism_parameter) override;
  uint32_t Digest(const brillo::SecureBlob& isolate_credential,
                  uint64_t session_id,
                  const std::vector<uint8_t>& data_in,
                  uint64_t max_out_length,
                  uint64_t* actual_out_length,
                  std::vector<uint8_t>* digest) override;
  uint32_t DigestUpdate(const brillo::SecureBlob& isolate_credential,
                        uint64_t session_id,
                        const std::vector<uint8_t>& data_in) override;
  uint32_t DigestKey(const brillo::SecureBlob& isolate_credential,
                     uint64_t session_id,
                     uint64_t key_handle) override;
  uint32_t DigestFinal(const brillo::SecureBlob& isolate_credential,
                       uint64_t session_id,
                       uint64_t max_out_length,
                       uint64_t* actual_out_length,
                       std::vector<uint8_t>* digest) override;
  void DigestCancel(const brillo::SecureBlob& isolate_credential,
                    uint64_t session_id) override;
  uint32_t SignInit(const brillo::SecureBlob& isolate_credential,
                    uint64_t session_id,
                    uint64_t mechanism_type,
                    const std::vector<uint8_t>& mechanism_parameter,
                    uint64_t key_handle) override;
  uint32_t Sign(const brillo::SecureBlob& isolate_credential,
                uint64_t session_id,
                const std::vector<uint8_t>& data,
                uint64_t max_out_length,
                uint64_t* actual_out_length,
                std::vector<uint8_t>* signature) override;
  uint32_t SignUpdate(const brillo::SecureBlob& isolate_credential,
                      uint64_t session_id,
                      const std::vector<uint8_t>& data_part) override;
  uint32_t SignFinal(const brillo::SecureBlob& isolate_credential,
                     uint64_t session_id,
                     uint64_t max_out_length,
                     uint64_t* actual_out_length,
                     std::vector<uint8_t>* signature) override;
  void SignCancel(const brillo::SecureBlob& isolate_credential,
                  uint64_t session_id) override;
  uint32_t SignRecoverInit(const brillo::SecureBlob& isolate_credential,
                           uint64_t session_id,
                           uint64_t mechanism_type,
                           const std::vector<uint8_t>& mechanism_parameter,
                           uint64_t key_handle) override;
  uint32_t SignRecover(const brillo::SecureBlob& isolate_credential,
                       uint64_t session_id,
                       const std::vector<uint8_t>& data,
                       uint64_t max_out_length,
                       uint64_t* actual_out_length,
                       std::vector<uint8_t>* signature) override;
  uint32_t VerifyInit(const brillo::SecureBlob& isolate_credential,
                      uint64_t session_id,
                      uint64_t mechanism_type,
                      const std::vector<uint8_t>& mechanism_parameter,
                      uint64_t key_handle) override;
  uint32_t Verify(const brillo::SecureBlob& isolate_credential,
                  uint64_t session_id,
                  const std::vector<uint8_t>& data,
                  const std::vector<uint8_t>& signature) override;
  uint32_t VerifyUpdate(const brillo::SecureBlob& isolate_credential,
                        uint64_t session_id,
                        const std::vector<uint8_t>& data_part) override;
  uint32_t VerifyFinal(const brillo::SecureBlob& isolate_credential,
                       uint64_t session_id,
                       const std::vector<uint8_t>& signature) override;
  void VerifyCancel(const brillo::SecureBlob& isolate_credential,
                    uint64_t session_id) override;
  uint32_t VerifyRecoverInit(const brillo::SecureBlob& isolate_credential,
                             uint64_t session_id,
                             uint64_t mechanism_type,
                             const std::vector<uint8_t>& mechanism_parameter,
                             uint64_t key_handle) override;
  uint32_t VerifyRecover(const brillo::SecureBlob& isolate_credential,
                         uint64_t session_id,
                         const std::vector<uint8_t>& signature,
                         uint64_t max_out_length,
                         uint64_t* actual_out_length,
                         std::vector<uint8_t>* data) override;
  uint32_t DigestEncryptUpdate(const brillo::SecureBlob& isolate_credential,
                               uint64_t session_id,
                               const std::vector<uint8_t>& data_in,
                               uint64_t max_out_length,
                               uint64_t* actual_out_length,
                               std::vector<uint8_t>* data_out) override;
  uint32_t DecryptDigestUpdate(const brillo::SecureBlob& isolate_credential,
                               uint64_t session_id,
                               const std::vector<uint8_t>& data_in,
                               uint64_t max_out_length,
                               uint64_t* actual_out_length,
                               std::vector<uint8_t>* data_out) override;
  uint32_t SignEncryptUpdate(const brillo::SecureBlob& isolate_credential,
                             uint64_t session_id,
                             const std::vector<uint8_t>& data_in,
                             uint64_t max_out_length,
                             uint64_t* actual_out_length,
                             std::vector<uint8_t>* data_out) override;
  uint32_t DecryptVerifyUpdate(const brillo::SecureBlob& isolate_credential,
                               uint64_t session_id,
                               const std::vector<uint8_t>& data_in,
                               uint64_t max_out_length,
                               uint64_t* actual_out_length,
                               std::vector<uint8_t>* data_out) override;
  uint32_t GenerateKey(const brillo::SecureBlob& isolate_credential,
                       uint64_t session_id,
                       uint64_t mechanism_type,
                       const std::vector<uint8_t>& mechanism_parameter,
                       const std::vector<uint8_t>& attributes,
                       uint64_t* key_handle) override;
  uint32_t GenerateKeyPair(const brillo::SecureBlob& isolate_credential,
                           uint64_t session_id,
                           uint64_t mechanism_type,
                           const std::vector<uint8_t>& mechanism_parameter,
                           const std::vector<uint8_t>& public_attributes,
                           const std::vector<uint8_t>& private_attributes,
                           uint64_t* public_key_handle,
                           uint64_t* private_key_handle) override;
  uint32_t WrapKey(const brillo::SecureBlob& isolate_credential,
                   uint64_t session_id,
                   uint64_t mechanism_type,
                   const std::vector<uint8_t>& mechanism_parameter,
                   uint64_t wrapping_key_handle,
                   uint64_t key_handle,
                   uint64_t max_out_length,
                   uint64_t* actual_out_length,
                   std::vector<uint8_t>* wrapped_key) override;
  uint32_t UnwrapKey(const brillo::SecureBlob& isolate_credential,
                     uint64_t session_id,
                     uint64_t mechanism_type,
                     const std::vector<uint8_t>& mechanism_parameter,
                     uint64_t wrapping_key_handle,
                     const std::vector<uint8_t>& wrapped_key,
                     const std::vector<uint8_t>& attributes,
                     uint64_t* key_handle) override;
  uint32_t DeriveKey(const brillo::SecureBlob& isolate_credential,
                     uint64_t session_id,
                     uint64_t mechanism_type,
                     const std::vector<uint8_t>& mechanism_parameter,
                     uint64_t base_key_handle,
                     const std::vector<uint8_t>& attributes,
                     uint64_t* key_handle) override;
  uint32_t SeedRandom(const brillo::SecureBlob& isolate_credential,
                      uint64_t session_id,
                      const std::vector<uint8_t>& seed) override;
  uint32_t GenerateRandom(const brillo::SecureBlob& isolate_credential,
                          uint64_t session_id,
                          uint64_t num_bytes,
                          std::vector<uint8_t>* random_data) override;

 private:
  SlotManager* slot_manager_;
};

}  // namespace chaps
#endif  // CHAPS_CHAPS_SERVICE_H_
