// Copyright 2011 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHAPS_CHAPS_ADAPTOR_H_
#define CHAPS_CHAPS_ADAPTOR_H_

#include <string>
#include <vector>

#include <brillo/dbus/async_event_sequencer.h>
#include <brillo/dbus/dbus_object.h>
#include <brillo/secure_blob.h>
#include <dbus/bus.h>
#include <chaps/proto_bindings/ck_structs.pb.h>

namespace chaps {

inline constexpr char kPersistentLogLevelPath[] = "/var/lib/chaps/.loglevel";

class ChapsInterface;
class TokenManagerInterface;

// The ChapsAdaptor class implements the D-Bus interface and redirects IPC
// calls to a ChapsInterface or TokenManagerInterface.
class ChapsAdaptor {
 public:
  ChapsAdaptor(scoped_refptr<dbus::Bus> bus,
               ChapsInterface* service,
               TokenManagerInterface* token_manager);
  ChapsAdaptor(const ChapsAdaptor&) = delete;
  ChapsAdaptor& operator=(const ChapsAdaptor&) = delete;

  virtual ~ChapsAdaptor();

  void RegisterAsync(
      brillo::dbus_utils::AsyncEventSequencer::CompletionAction cb);

  // Chaps D-Bus interface methods.
  void OpenIsolate(const brillo::SecureVector& isolate_credential_in,
                   brillo::SecureVector* isolate_credential_out,
                   bool* new_isolate_created,
                   bool* result);
  void CloseIsolate(const brillo::SecureVector& isolate_credential);
  void LoadToken(const brillo::SecureVector& isolate_credential,
                 const std::string& path,
                 const brillo::SecureVector& auth_data,
                 const std::string& label,
                 uint64_t* slot_id,
                 bool* result);
  void UnloadToken(const brillo::SecureVector& isolate_credential,
                   const std::string& path,
                   bool* result);
  void GetTokenPath(const brillo::SecureVector& isolate_credential,
                    uint64_t slot_id,
                    std::string* path,
                    bool* result);
  void SetLogLevel(const int32_t& level);
  void GetSlotList(const brillo::SecureVector& isolate_credential,
                   bool token_present,
                   std::vector<uint64_t>* slot_list,
                   uint32_t* result);
  void GetSlotInfo(const brillo::SecureVector& isolate_credential,
                   uint64_t slot_id,
                   SlotInfo* slot_info,
                   uint32_t* result);
  void GetTokenInfo(const brillo::SecureVector& isolate_credential,
                    uint64_t slot_id,
                    TokenInfo* token_info,
                    uint32_t* result);
  void GetMechanismList(const brillo::SecureVector& isolate_credential,
                        uint64_t slot_id,
                        std::vector<uint64_t>* mechanism_list,
                        uint32_t* result);
  void GetMechanismInfo(const brillo::SecureVector& isolate_credential,
                        uint64_t slot_id,
                        uint64_t mechanism_type,
                        MechanismInfo* mechanism_info,
                        uint32_t* result);
  uint32_t InitToken(const brillo::SecureVector& isolate_credential,
                     uint64_t slot_id,
                     bool use_null_pin,
                     const std::string& optional_so_pin,
                     const std::vector<uint8_t>& new_token_label);
  uint32_t InitPIN(const brillo::SecureVector& isolate_credential,
                   uint64_t session_id,
                   bool use_null_pin,
                   const std::string& optional_user_pin);
  uint32_t SetPIN(const brillo::SecureVector& isolate_credential,
                  uint64_t session_id,
                  bool use_null_old_pin,
                  const std::string& optional_old_pin,
                  bool use_null_new_pin,
                  const std::string& optional_new_pin);
  void OpenSession(const brillo::SecureVector& isolate_credential,
                   uint64_t slot_id,
                   uint64_t flags,
                   uint64_t* session_id,
                   uint32_t* result);
  uint32_t CloseSession(const brillo::SecureVector& isolate_credential,
                        uint64_t session_id);
  void GetSessionInfo(const brillo::SecureVector& isolate_credential,
                      uint64_t session_id,
                      SessionInfo* session_info,
                      uint32_t* result);
  void GetOperationState(const brillo::SecureVector& isolate_credential,
                         uint64_t session_id,
                         std::vector<uint8_t>* operation_state,
                         uint32_t* result);
  uint32_t SetOperationState(const brillo::SecureVector& isolate_credential,
                             uint64_t session_id,
                             const std::vector<uint8_t>& operation_state,
                             uint64_t encryption_key_handle,
                             uint64_t authentication_key_handle);
  uint32_t Login(const brillo::SecureVector& isolate_credential,
                 uint64_t session_id,
                 uint64_t user_type,
                 bool use_null_pin,
                 const std::string& optional_pin);
  uint32_t Logout(const brillo::SecureVector& isolate_credential,
                  uint64_t session_id);
  void CreateObject(const brillo::SecureVector& isolate_credential,
                    uint64_t session_id,
                    const std::vector<uint8_t>& attributes,
                    uint64_t* new_object_handle,
                    uint32_t* result);
  void CopyObject(const brillo::SecureVector& isolate_credential,
                  uint64_t session_id,
                  uint64_t object_handle,
                  const std::vector<uint8_t>& attributes,
                  uint64_t* new_object_handle,
                  uint32_t* result);
  uint32_t DestroyObject(const brillo::SecureVector& isolate_credential,
                         uint64_t session_id,
                         uint64_t object_handle);
  void GetObjectSize(const brillo::SecureVector& isolate_credential,
                     uint64_t session_id,
                     uint64_t object_handle,
                     uint64_t* object_size,
                     uint32_t* result);
  void GetAttributeValue(const brillo::SecureVector& isolate_credential,
                         uint64_t session_id,
                         uint64_t object_handle,
                         const std::vector<uint8_t>& attributes_in,
                         std::vector<uint8_t>* attributes_out,
                         uint32_t* result);
  uint32_t SetAttributeValue(const brillo::SecureVector& isolate_credential,
                             uint64_t session_id,
                             uint64_t object_handle,
                             const std::vector<uint8_t>& attributes);
  uint32_t FindObjectsInit(const brillo::SecureVector& isolate_credential,
                           uint64_t session_id,
                           const std::vector<uint8_t>& attributes);
  void FindObjects(const brillo::SecureVector& isolate_credential,
                   uint64_t session_id,
                   uint64_t max_object_count,
                   std::vector<uint64_t>* object_list,
                   uint32_t* result);
  uint32_t FindObjectsFinal(const brillo::SecureVector& isolate_credential,
                            uint64_t session_id);
  uint32_t EncryptInit(const brillo::SecureVector& isolate_credential,
                       uint64_t session_id,
                       uint64_t mechanism_type,
                       const std::vector<uint8_t>& mechanism_parameter,
                       uint64_t key_handle);
  void Encrypt(const brillo::SecureVector& isolate_credential,
               uint64_t session_id,
               const std::vector<uint8_t>& data_in,
               uint64_t max_out_length,
               uint64_t* actual_out_length,
               std::vector<uint8_t>* data_out,
               uint32_t* result);
  void EncryptUpdate(const brillo::SecureVector& isolate_credential,
                     uint64_t session_id,
                     const std::vector<uint8_t>& data_in,
                     uint64_t max_out_length,
                     uint64_t* actual_out_length,
                     std::vector<uint8_t>* data_out,
                     uint32_t* result);
  void EncryptFinal(const brillo::SecureVector& isolate_credential,
                    uint64_t session_id,
                    uint64_t max_out_length,
                    uint64_t* actual_out_length,
                    std::vector<uint8_t>* data_out,
                    uint32_t* result);
  void EncryptCancel(const brillo::SecureVector& isolate_credential,
                     uint64_t session_id);
  uint32_t DecryptInit(const brillo::SecureVector& isolate_credential,
                       uint64_t session_id,
                       uint64_t mechanism_type,
                       const std::vector<uint8_t>& mechanism_parameter,
                       uint64_t key_handle);
  void Decrypt(const brillo::SecureVector& isolate_credential,
               uint64_t session_id,
               const std::vector<uint8_t>& data_in,
               uint64_t max_out_length,
               uint64_t* actual_out_length,
               std::vector<uint8_t>* data_out,
               uint32_t* result);
  void DecryptUpdate(const brillo::SecureVector& isolate_credential,
                     uint64_t session_id,
                     const std::vector<uint8_t>& data_in,
                     uint64_t max_out_length,
                     uint64_t* actual_out_length,
                     std::vector<uint8_t>* data_out,
                     uint32_t* result);
  void DecryptFinal(const brillo::SecureVector& isolate_credential,
                    uint64_t session_id,
                    uint64_t max_out_length,
                    uint64_t* actual_out_length,
                    std::vector<uint8_t>* data_out,
                    uint32_t* result);
  void DecryptCancel(const brillo::SecureVector& isolate_credential,
                     uint64_t session_id);
  uint32_t DigestInit(const brillo::SecureVector& isolate_credential,
                      uint64_t session_id,
                      uint64_t mechanism_type,
                      const std::vector<uint8_t>& mechanism_parameter);
  void Digest(const brillo::SecureVector& isolate_credential,
              uint64_t session_id,
              const std::vector<uint8_t>& data_in,
              uint64_t max_out_length,
              uint64_t* actual_out_length,
              std::vector<uint8_t>* digest,
              uint32_t* result);
  uint32_t DigestUpdate(const brillo::SecureVector& isolate_credential,
                        uint64_t session_id,
                        const std::vector<uint8_t>& data_in);
  uint32_t DigestKey(const brillo::SecureVector& isolate_credential,
                     uint64_t session_id,
                     uint64_t key_handle);
  void DigestFinal(const brillo::SecureVector& isolate_credential,
                   uint64_t session_id,
                   uint64_t max_out_length,
                   uint64_t* actual_out_length,
                   std::vector<uint8_t>* digest,
                   uint32_t* result);
  void DigestCancel(const brillo::SecureVector& isolate_credential,
                    uint64_t session_id);
  uint32_t SignInit(const brillo::SecureVector& isolate_credential,
                    uint64_t session_id,
                    uint64_t mechanism_type,
                    const std::vector<uint8_t>& mechanism_parameter,
                    uint64_t key_handle);
  void Sign(const brillo::SecureVector& isolate_credential,
            uint64_t session_id,
            const std::vector<uint8_t>& data,
            uint64_t max_out_length,
            uint64_t* actual_out_length,
            std::vector<uint8_t>* signature,
            uint32_t* result);
  uint32_t SignUpdate(const brillo::SecureVector& isolate_credential,
                      uint64_t session_id,
                      const std::vector<uint8_t>& data_part);
  void SignFinal(const brillo::SecureVector& isolate_credential,
                 uint64_t session_id,
                 uint64_t max_out_length,
                 uint64_t* actual_out_length,
                 std::vector<uint8_t>* signature,
                 uint32_t* result);
  void SignCancel(const brillo::SecureVector& isolate_credential,
                  uint64_t session_id);
  uint32_t SignRecoverInit(const brillo::SecureVector& isolate_credential,
                           uint64_t session_id,
                           uint64_t mechanism_type,
                           const std::vector<uint8_t>& mechanism_parameter,
                           uint64_t key_handle);
  void SignRecover(const brillo::SecureVector& isolate_credential,
                   uint64_t session_id,
                   const std::vector<uint8_t>& data,
                   uint64_t max_out_length,
                   uint64_t* actual_out_length,
                   std::vector<uint8_t>* signature,
                   uint32_t* result);
  uint32_t VerifyInit(const brillo::SecureVector& isolate_credential,
                      uint64_t session_id,
                      uint64_t mechanism_type,
                      const std::vector<uint8_t>& mechanism_parameter,
                      uint64_t key_handle);
  uint32_t Verify(const brillo::SecureVector& isolate_credential,
                  uint64_t session_id,
                  const std::vector<uint8_t>& data,
                  const std::vector<uint8_t>& signature);
  uint32_t VerifyUpdate(const brillo::SecureVector& isolate_credential,
                        uint64_t session_id,
                        const std::vector<uint8_t>& data_part);
  uint32_t VerifyFinal(const brillo::SecureVector& isolate_credential,
                       uint64_t session_id,
                       const std::vector<uint8_t>& signature);
  void VerifyCancel(const brillo::SecureVector& isolate_credential,
                    uint64_t session_id);
  uint32_t VerifyRecoverInit(const brillo::SecureVector& isolate_credential,
                             uint64_t session_id,
                             uint64_t mechanism_type,
                             const std::vector<uint8_t>& mechanism_parameter,
                             uint64_t key_handle);
  void VerifyRecover(const brillo::SecureVector& isolate_credential,
                     uint64_t session_id,
                     const std::vector<uint8_t>& signature,
                     uint64_t max_out_length,
                     uint64_t* actual_out_length,
                     std::vector<uint8_t>* data,
                     uint32_t* result);
  void DigestEncryptUpdate(const brillo::SecureVector& isolate_credential,
                           uint64_t session_id,
                           const std::vector<uint8_t>& data_in,
                           uint64_t max_out_length,
                           uint64_t* actual_out_length,
                           std::vector<uint8_t>* data_out,
                           uint32_t* result);
  void DecryptDigestUpdate(const brillo::SecureVector& isolate_credential,
                           uint64_t session_id,
                           const std::vector<uint8_t>& data_in,
                           uint64_t max_out_length,
                           uint64_t* actual_out_length,
                           std::vector<uint8_t>* data_out,
                           uint32_t* result);
  void SignEncryptUpdate(const brillo::SecureVector& isolate_credential,
                         uint64_t session_id,
                         const std::vector<uint8_t>& data_in,
                         uint64_t max_out_length,
                         uint64_t* actual_out_length,
                         std::vector<uint8_t>* data_out,
                         uint32_t* result);
  void DecryptVerifyUpdate(const brillo::SecureVector& isolate_credential,
                           uint64_t session_id,
                           const std::vector<uint8_t>& data_in,
                           uint64_t max_out_length,
                           uint64_t* actual_out_length,
                           std::vector<uint8_t>* data_out,
                           uint32_t* result);
  void GenerateKey(const brillo::SecureVector& isolate_credential,
                   uint64_t session_id,
                   uint64_t mechanism_type,
                   const std::vector<uint8_t>& mechanism_parameter,
                   const std::vector<uint8_t>& attributes,
                   uint64_t* key_handle,
                   uint32_t* result);
  void GenerateKeyPair(const brillo::SecureVector& isolate_credential,
                       uint64_t session_id,
                       uint64_t mechanism_type,
                       const std::vector<uint8_t>& mechanism_parameter,
                       const std::vector<uint8_t>& public_attributes,
                       const std::vector<uint8_t>& private_attributes,
                       uint64_t* public_key_handle,
                       uint64_t* private_key_handle,
                       uint32_t* result);
  void WrapKey(const brillo::SecureVector& isolate_credential,
               uint64_t session_id,
               uint64_t mechanism_type,
               const std::vector<uint8_t>& mechanism_parameter,
               uint64_t wrapping_key_handle,
               uint64_t key_handle,
               uint64_t max_out_length,
               uint64_t* actual_out_length,
               std::vector<uint8_t>* wrapped_key,
               uint32_t* result);
  void UnwrapKey(const brillo::SecureVector& isolate_credential,
                 uint64_t session_id,
                 uint64_t mechanism_type,
                 const std::vector<uint8_t>& mechanism_parameter,
                 uint64_t wrapping_key_handle,
                 const std::vector<uint8_t>& wrapped_key,
                 const std::vector<uint8_t>& attributes,
                 uint64_t* key_handle,
                 uint32_t* result);
  void DeriveKey(const brillo::SecureVector& isolate_credential,
                 uint64_t session_id,
                 uint64_t mechanism_type,
                 const std::vector<uint8_t>& mechanism_parameter,
                 uint64_t base_key_handle,
                 const std::vector<uint8_t>& attributes,
                 uint64_t* key_handle,
                 uint32_t* result);
  uint32_t SeedRandom(const brillo::SecureVector& isolate_credential,
                      uint64_t session_id,
                      const std::vector<uint8_t>& seed);
  void GenerateRandom(const brillo::SecureVector& isolate_credential,
                      uint64_t session_id,
                      uint64_t num_bytes,
                      std::vector<uint8_t>* random_data,
                      uint32_t* result);

 private:
  brillo::dbus_utils::DBusObject dbus_object_;

  ChapsInterface* service_;
  TokenManagerInterface* token_manager_;
};

}  // namespace chaps

#endif  // CHAPS_CHAPS_ADAPTOR_H_
