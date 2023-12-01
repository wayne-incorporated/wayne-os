// Copyright 2011 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chaps/chaps_adaptor.h"

#include <utility>

#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <dbus/object_path.h>

#include "chaps/chaps.h"
#include "chaps/chaps_interface.h"
#include "chaps/chaps_utility.h"
#include "chaps/dbus_bindings/constants.h"
#include "chaps/token_manager_interface.h"

using base::FilePath;
using brillo::SecureBlob;
using std::string;
using std::vector;

namespace chaps {

ChapsAdaptor::ChapsAdaptor(scoped_refptr<dbus::Bus> bus,
                           ChapsInterface* service,
                           TokenManagerInterface* token_manager)
    : dbus_object_(nullptr, bus, dbus::ObjectPath(kChapsServicePath)),
      service_(service),
      token_manager_(token_manager) {
  CHECK(service_);
  CHECK(token_manager_);
}

ChapsAdaptor::~ChapsAdaptor() {}

void ChapsAdaptor::RegisterAsync(
    brillo::dbus_utils::AsyncEventSequencer::CompletionAction cb) {
  brillo::dbus_utils::DBusInterface* interface =
      dbus_object_.AddOrGetInterface(kChapsInterface);
  interface->AddSimpleMethodHandler(kOpenIsolateMethod, base::Unretained(this),
                                    &ChapsAdaptor::OpenIsolate);
  interface->AddSimpleMethodHandler(kCloseIsolateMethod, base::Unretained(this),
                                    &ChapsAdaptor::CloseIsolate);
  interface->AddSimpleMethodHandler(kLoadTokenMethod, base::Unretained(this),
                                    &ChapsAdaptor::LoadToken);
  interface->AddSimpleMethodHandler(kUnloadTokenMethod, base::Unretained(this),
                                    &ChapsAdaptor::UnloadToken);
  interface->AddSimpleMethodHandler(kGetTokenPathMethod, base::Unretained(this),
                                    &ChapsAdaptor::GetTokenPath);
  interface->AddSimpleMethodHandler(kSetLogLevelMethod, base::Unretained(this),
                                    &ChapsAdaptor::SetLogLevel);
  interface->AddSimpleMethodHandler(kGetSlotListMethod, base::Unretained(this),
                                    &ChapsAdaptor::GetSlotList);
  interface->AddSimpleMethodHandler(kGetSlotInfoMethod, base::Unretained(this),
                                    &ChapsAdaptor::GetSlotInfo);
  interface->AddSimpleMethodHandler(kGetTokenInfoMethod, base::Unretained(this),
                                    &ChapsAdaptor::GetTokenInfo);
  interface->AddSimpleMethodHandler(kGetMechanismListMethod,
                                    base::Unretained(this),
                                    &ChapsAdaptor::GetMechanismList);
  interface->AddSimpleMethodHandler(kGetMechanismInfoMethod,
                                    base::Unretained(this),
                                    &ChapsAdaptor::GetMechanismInfo);
  interface->AddSimpleMethodHandler(kInitTokenMethod, base::Unretained(this),
                                    &ChapsAdaptor::InitToken);
  interface->AddSimpleMethodHandler(kInitPINMethod, base::Unretained(this),
                                    &ChapsAdaptor::InitPIN);
  interface->AddSimpleMethodHandler(kSetPINMethod, base::Unretained(this),
                                    &ChapsAdaptor::SetPIN);
  interface->AddSimpleMethodHandler(kOpenSessionMethod, base::Unretained(this),
                                    &ChapsAdaptor::OpenSession);
  interface->AddSimpleMethodHandler(kCloseSessionMethod, base::Unretained(this),
                                    &ChapsAdaptor::CloseSession);
  interface->AddSimpleMethodHandler(kGetSessionInfoMethod,
                                    base::Unretained(this),
                                    &ChapsAdaptor::GetSessionInfo);
  interface->AddSimpleMethodHandler(kGetOperationStateMethod,
                                    base::Unretained(this),
                                    &ChapsAdaptor::GetOperationState);
  interface->AddSimpleMethodHandler(kSetOperationStateMethod,
                                    base::Unretained(this),
                                    &ChapsAdaptor::SetOperationState);
  interface->AddSimpleMethodHandler(kLoginMethod, base::Unretained(this),
                                    &ChapsAdaptor::Login);
  interface->AddSimpleMethodHandler(kLogoutMethod, base::Unretained(this),
                                    &ChapsAdaptor::Logout);
  interface->AddSimpleMethodHandler(kCreateObjectMethod, base::Unretained(this),
                                    &ChapsAdaptor::CreateObject);
  interface->AddSimpleMethodHandler(kCopyObjectMethod, base::Unretained(this),
                                    &ChapsAdaptor::CopyObject);
  interface->AddSimpleMethodHandler(kDestroyObjectMethod,
                                    base::Unretained(this),
                                    &ChapsAdaptor::DestroyObject);
  interface->AddSimpleMethodHandler(kGetObjectSizeMethod,
                                    base::Unretained(this),
                                    &ChapsAdaptor::GetObjectSize);
  interface->AddSimpleMethodHandler(kGetAttributeValueMethod,
                                    base::Unretained(this),
                                    &ChapsAdaptor::GetAttributeValue);
  interface->AddSimpleMethodHandler(kSetAttributeValueMethod,
                                    base::Unretained(this),
                                    &ChapsAdaptor::SetAttributeValue);
  interface->AddSimpleMethodHandler(kFindObjectsInitMethod,
                                    base::Unretained(this),
                                    &ChapsAdaptor::FindObjectsInit);
  interface->AddSimpleMethodHandler(kFindObjectsMethod, base::Unretained(this),
                                    &ChapsAdaptor::FindObjects);
  interface->AddSimpleMethodHandler(kFindObjectsFinalMethod,
                                    base::Unretained(this),
                                    &ChapsAdaptor::FindObjectsFinal);
  interface->AddSimpleMethodHandler(kEncryptInitMethod, base::Unretained(this),
                                    &ChapsAdaptor::EncryptInit);
  interface->AddSimpleMethodHandler(kEncryptMethod, base::Unretained(this),
                                    &ChapsAdaptor::Encrypt);
  interface->AddSimpleMethodHandler(kEncryptUpdateMethod,
                                    base::Unretained(this),
                                    &ChapsAdaptor::EncryptUpdate);
  interface->AddSimpleMethodHandler(kEncryptFinalMethod, base::Unretained(this),
                                    &ChapsAdaptor::EncryptFinal);
  interface->AddSimpleMethodHandler(kEncryptCancelMethod,
                                    base::Unretained(this),
                                    &ChapsAdaptor::EncryptCancel);
  interface->AddSimpleMethodHandler(kDecryptInitMethod, base::Unretained(this),
                                    &ChapsAdaptor::DecryptInit);
  interface->AddSimpleMethodHandler(kDecryptMethod, base::Unretained(this),
                                    &ChapsAdaptor::Decrypt);
  interface->AddSimpleMethodHandler(kDecryptUpdateMethod,
                                    base::Unretained(this),
                                    &ChapsAdaptor::DecryptUpdate);
  interface->AddSimpleMethodHandler(kDecryptFinalMethod, base::Unretained(this),
                                    &ChapsAdaptor::DecryptFinal);
  interface->AddSimpleMethodHandler(kDecryptCancelMethod,
                                    base::Unretained(this),
                                    &ChapsAdaptor::DecryptCancel);
  interface->AddSimpleMethodHandler(kDigestInitMethod, base::Unretained(this),
                                    &ChapsAdaptor::DigestInit);
  interface->AddSimpleMethodHandler(kDigestMethod, base::Unretained(this),
                                    &ChapsAdaptor::Digest);
  interface->AddSimpleMethodHandler(kDigestUpdateMethod, base::Unretained(this),
                                    &ChapsAdaptor::DigestUpdate);
  interface->AddSimpleMethodHandler(kDigestKeyMethod, base::Unretained(this),
                                    &ChapsAdaptor::DigestKey);
  interface->AddSimpleMethodHandler(kDigestFinalMethod, base::Unretained(this),
                                    &ChapsAdaptor::DigestFinal);
  interface->AddSimpleMethodHandler(kDigestCancelMethod, base::Unretained(this),
                                    &ChapsAdaptor::DigestCancel);
  interface->AddSimpleMethodHandler(kSignInitMethod, base::Unretained(this),
                                    &ChapsAdaptor::SignInit);
  interface->AddSimpleMethodHandler(kSignMethod, base::Unretained(this),
                                    &ChapsAdaptor::Sign);
  interface->AddSimpleMethodHandler(kSignUpdateMethod, base::Unretained(this),
                                    &ChapsAdaptor::SignUpdate);
  interface->AddSimpleMethodHandler(kSignFinalMethod, base::Unretained(this),
                                    &ChapsAdaptor::SignFinal);
  interface->AddSimpleMethodHandler(kSignCancelMethod, base::Unretained(this),
                                    &ChapsAdaptor::SignCancel);
  interface->AddSimpleMethodHandler(kSignRecoverInitMethod,
                                    base::Unretained(this),
                                    &ChapsAdaptor::SignRecoverInit);
  interface->AddSimpleMethodHandler(kSignRecoverMethod, base::Unretained(this),
                                    &ChapsAdaptor::SignRecover);
  interface->AddSimpleMethodHandler(kVerifyInitMethod, base::Unretained(this),
                                    &ChapsAdaptor::VerifyInit);
  interface->AddSimpleMethodHandler(kVerifyMethod, base::Unretained(this),
                                    &ChapsAdaptor::Verify);
  interface->AddSimpleMethodHandler(kVerifyUpdateMethod, base::Unretained(this),
                                    &ChapsAdaptor::VerifyUpdate);
  interface->AddSimpleMethodHandler(kVerifyFinalMethod, base::Unretained(this),
                                    &ChapsAdaptor::VerifyFinal);
  interface->AddSimpleMethodHandler(kVerifyCancelMethod, base::Unretained(this),
                                    &ChapsAdaptor::VerifyCancel);
  interface->AddSimpleMethodHandler(kVerifyRecoverInitMethod,
                                    base::Unretained(this),
                                    &ChapsAdaptor::VerifyRecoverInit);
  interface->AddSimpleMethodHandler(kVerifyRecoverMethod,
                                    base::Unretained(this),
                                    &ChapsAdaptor::VerifyRecover);
  interface->AddSimpleMethodHandler(kDigestEncryptUpdateMethod,
                                    base::Unretained(this),
                                    &ChapsAdaptor::DigestEncryptUpdate);
  interface->AddSimpleMethodHandler(kDecryptDigestUpdateMethod,
                                    base::Unretained(this),
                                    &ChapsAdaptor::DecryptDigestUpdate);
  interface->AddSimpleMethodHandler(kSignEncryptUpdateMethod,
                                    base::Unretained(this),
                                    &ChapsAdaptor::SignEncryptUpdate);
  interface->AddSimpleMethodHandler(kDecryptVerifyUpdateMethod,
                                    base::Unretained(this),
                                    &ChapsAdaptor::DecryptVerifyUpdate);
  interface->AddSimpleMethodHandler(kGenerateKeyMethod, base::Unretained(this),
                                    &ChapsAdaptor::GenerateKey);
  interface->AddSimpleMethodHandler(kGenerateKeyPairMethod,
                                    base::Unretained(this),
                                    &ChapsAdaptor::GenerateKeyPair);
  interface->AddSimpleMethodHandler(kWrapKeyMethod, base::Unretained(this),
                                    &ChapsAdaptor::WrapKey);
  interface->AddSimpleMethodHandler(kUnwrapKeyMethod, base::Unretained(this),
                                    &ChapsAdaptor::UnwrapKey);
  interface->AddSimpleMethodHandler(kDeriveKeyMethod, base::Unretained(this),
                                    &ChapsAdaptor::DeriveKey);
  interface->AddSimpleMethodHandler(kSeedRandomMethod, base::Unretained(this),
                                    &ChapsAdaptor::SeedRandom);
  interface->AddSimpleMethodHandler(kGenerateRandomMethod,
                                    base::Unretained(this),
                                    &ChapsAdaptor::GenerateRandom);
  dbus_object_.RegisterAsync(std::move(cb));
}

void ChapsAdaptor::OpenIsolate(
    const brillo::SecureVector& isolate_credential_in,
    brillo::SecureVector* isolate_credential_out,
    bool* new_isolate_created,
    bool* result) {
  VLOG(1) << "CALL: " << __func__;
  *result = false;
  SecureBlob isolate_credential(isolate_credential_in.begin(),
                                isolate_credential_in.end());
    *result =
        token_manager_->OpenIsolate(&isolate_credential, new_isolate_created);
  isolate_credential_out->swap(isolate_credential);
}

void ChapsAdaptor::CloseIsolate(
    const brillo::SecureVector& isolate_credential) {
  VLOG(1) << "CALL: " << __func__;
  SecureBlob isolate_credential_blob(isolate_credential.begin(),
                                     isolate_credential.end());

    token_manager_->CloseIsolate(isolate_credential_blob);
}

void ChapsAdaptor::LoadToken(const brillo::SecureVector& isolate_credential,
                             const string& path,
                             const brillo::SecureVector& auth_data,
                             const string& label,
                             uint64_t* slot_id,
                             bool* result) {
  VLOG(1) << "CALL: " << __func__;
  SecureBlob isolate_credential_blob(isolate_credential.begin(),
                                     isolate_credential.end());
  SecureBlob auth_data_blob(auth_data.begin(), auth_data.end());
  *result = token_manager_->LoadToken(isolate_credential_blob, FilePath(path),
                                      auth_data_blob, label,
                                      PreservedValue<uint64_t, int>(slot_id));
}

void ChapsAdaptor::UnloadToken(const brillo::SecureVector& isolate_credential,
                               const string& path,
                               bool* result) {
  VLOG(1) << "CALL: " << __func__;
  SecureBlob isolate_credential_blob(isolate_credential.begin(),
                                     isolate_credential.end());

  *result =
      token_manager_->UnloadToken(isolate_credential_blob, FilePath(path));
}

void ChapsAdaptor::GetTokenPath(const brillo::SecureVector& isolate_credential,
                                uint64_t slot_id,
                                std::string* path,
                                bool* result) {
  VLOG(1) << "CALL: " << __func__;
  SecureBlob isolate_credential_blob(isolate_credential.begin(),
                                     isolate_credential.end());
  FilePath tmp;
  *result =
      token_manager_->GetTokenPath(isolate_credential_blob, slot_id, &tmp);
  *path = tmp.value();
}

void ChapsAdaptor::SetLogLevel(const int32_t& level) {
  logging::SetMinLogLevel(level);
  string level_str = base::NumberToString(level);
  int writeResult = base::WriteFile(FilePath(kPersistentLogLevelPath),
                                    level_str.data(), level_str.length());
  VLOG_IF(2, writeResult < 0) << "Failed to save loglevel to file.";
}

void ChapsAdaptor::GetSlotList(const brillo::SecureVector& isolate_credential,
                               bool token_present,
                               vector<uint64_t>* slot_list,
                               uint32_t* result) {
  VLOG(1) << "CALL: " << __func__;
  VLOG(2) << "IN: "
          << "token_present=" << token_present;
  SecureBlob isolate_credential_blob(isolate_credential.begin(),
                                     isolate_credential.end());

  *result =
      service_->GetSlotList(isolate_credential_blob, token_present, slot_list);
  VLOG_IF(2, *result == CKR_OK) << "OUT: "
                                << "slot_list=" << PrintIntVector(*slot_list);
}

void ChapsAdaptor::GetSlotInfo(const brillo::SecureVector& isolate_credential,
                               uint64_t slot_id,
                               SlotInfo* slot_info,
                               uint32_t* result) {
  VLOG(1) << "CALL: " << __func__;
  VLOG(2) << "IN: "
          << "slot_id=" << slot_id;
  SecureBlob isolate_credential_blob(isolate_credential.begin(),
                                     isolate_credential.end());

  *result = service_->GetSlotInfo(isolate_credential_blob, slot_id, slot_info);
  VLOG_IF(2, *result == CKR_OK)
      << "OUT: "
      << "slot_description=" << slot_info->slot_description();
}

void ChapsAdaptor::GetTokenInfo(const brillo::SecureVector& isolate_credential,
                                uint64_t slot_id,
                                TokenInfo* token_info,
                                uint32_t* result) {
  VLOG(1) << "CALL: " << __func__;
  VLOG(2) << "IN: "
          << "slot_id=" << slot_id;
  SecureBlob isolate_credential_blob(isolate_credential.begin(),
                                     isolate_credential.end());

  *result =
      service_->GetTokenInfo(isolate_credential_blob, slot_id, token_info);
  VLOG_IF(2, *result == CKR_OK) << "OUT: "
                                << "label=" << token_info->label();
}

void ChapsAdaptor::GetMechanismList(
    const brillo::SecureVector& isolate_credential,
    uint64_t slot_id,
    vector<uint64_t>* mechanism_list,
    uint32_t* result) {
  VLOG(1) << "CALL: " << __func__;
  VLOG(2) << "IN: "
          << "slot_id=" << slot_id;
  SecureBlob isolate_credential_blob(isolate_credential.begin(),
                                     isolate_credential.end());

  *result = service_->GetMechanismList(isolate_credential_blob, slot_id,
                                       mechanism_list);
  VLOG_IF(2, *result == CKR_OK)
      << "OUT: "
      << "mechanism_list=" << PrintIntVector(*mechanism_list);
}

void ChapsAdaptor::GetMechanismInfo(
    const brillo::SecureVector& isolate_credential,
    uint64_t slot_id,
    uint64_t mechanism_type,
    MechanismInfo* mechanism_info,
    uint32_t* result) {
  VLOG(1) << "CALL: " << __func__;
  VLOG(2) << "IN: "
          << "slot_id=" << slot_id;
  VLOG(2) << "IN: "
          << "mechanism_type=" << mechanism_type;
  SecureBlob isolate_credential_blob(isolate_credential.begin(),
                                     isolate_credential.end());

  *result = service_->GetMechanismInfo(isolate_credential_blob, slot_id,
                                       mechanism_type, mechanism_info);
  VLOG_IF(2, *result == CKR_OK)
      << "OUT: "
      << "min_key_size=" << mechanism_info->min_key_size();
  VLOG_IF(2, *result == CKR_OK)
      << "OUT: "
      << "max_key_size=" << mechanism_info->max_key_size();
  VLOG_IF(2, *result == CKR_OK) << "OUT: "
                                << "flags=" << mechanism_info->flags();
}

uint32_t ChapsAdaptor::InitToken(const brillo::SecureVector& isolate_credential,
                                 uint64_t slot_id,
                                 bool use_null_pin,
                                 const string& optional_so_pin,
                                 const vector<uint8_t>& new_token_label) {
  VLOG(1) << "CALL: " << __func__;
  VLOG(2) << "IN: "
          << "slot_id=" << slot_id;
  VLOG(2) << "IN: "
          << "new_token_label=" << ConvertByteVectorToString(new_token_label);
  const string* tmp_pin = use_null_pin ? NULL : &optional_so_pin;
  SecureBlob isolate_credential_blob(isolate_credential.begin(),
                                     isolate_credential.end());

  return service_->InitToken(isolate_credential_blob, slot_id, tmp_pin,
                             new_token_label);
}

uint32_t ChapsAdaptor::InitPIN(const brillo::SecureVector& isolate_credential,
                               uint64_t session_id,
                               bool use_null_pin,
                               const string& optional_user_pin) {
  VLOG(1) << "CALL: " << __func__;
  VLOG(2) << "IN: "
          << "session_id=" << session_id;
  VLOG(2) << "IN: "
          << "use_null_pin=" << use_null_pin;
  const string* tmp_pin = use_null_pin ? NULL : &optional_user_pin;
  SecureBlob isolate_credential_blob(isolate_credential.begin(),
                                     isolate_credential.end());

  return service_->InitPIN(isolate_credential_blob, session_id, tmp_pin);
}

uint32_t ChapsAdaptor::SetPIN(const brillo::SecureVector& isolate_credential,
                              uint64_t session_id,
                              bool use_null_old_pin,
                              const string& optional_old_pin,
                              bool use_null_new_pin,
                              const string& optional_new_pin) {
  VLOG(1) << "CALL: " << __func__;
  VLOG(2) << "IN: "
          << "session_id=" << session_id;
  VLOG(2) << "IN: "
          << "use_null_old_pin=" << use_null_old_pin;
  VLOG(2) << "IN: "
          << "use_null_new_pin=" << use_null_new_pin;
  const string* tmp_old_pin = use_null_old_pin ? NULL : &optional_old_pin;
  const string* tmp_new_pin = use_null_new_pin ? NULL : &optional_new_pin;
  SecureBlob isolate_credential_blob(isolate_credential.begin(),
                                     isolate_credential.end());

  return service_->SetPIN(isolate_credential_blob, session_id, tmp_old_pin,
                          tmp_new_pin);
}

void ChapsAdaptor::OpenSession(const brillo::SecureVector& isolate_credential,
                               uint64_t slot_id,
                               uint64_t flags,
                               uint64_t* session_id,
                               uint32_t* result) {
  VLOG(1) << "CALL: " << __func__;
  VLOG(2) << "IN: "
          << "slot_id=" << slot_id;
  VLOG(2) << "IN: "
          << "flags=" << flags;
  SecureBlob isolate_credential_blob(isolate_credential.begin(),
                                     isolate_credential.end());

  *result = service_->OpenSession(isolate_credential_blob, slot_id, flags,
                                  session_id);
  VLOG_IF(2, *result == CKR_OK) << "OUT: "
                                << "session_id=" << *session_id;
}

uint32_t ChapsAdaptor::CloseSession(
    const brillo::SecureVector& isolate_credential, uint64_t session_id) {
  VLOG(1) << "CALL: " << __func__;
  VLOG(2) << "IN: "
          << "session_id=" << session_id;
  SecureBlob isolate_credential_blob(isolate_credential.begin(),
                                     isolate_credential.end());

  return service_->CloseSession(isolate_credential_blob, session_id);
}

void ChapsAdaptor::GetSessionInfo(
    const brillo::SecureVector& isolate_credential,
    uint64_t session_id,
    SessionInfo* session_info,
    uint32_t* result) {
  VLOG(1) << "CALL: " << __func__;
  VLOG(2) << "IN: "
          << "session_id=" << session_id;
  SecureBlob isolate_credential_blob(isolate_credential.begin(),
                                     isolate_credential.end());

  *result = service_->GetSessionInfo(isolate_credential_blob, session_id,
                                     session_info);
  VLOG_IF(2, *result == CKR_OK) << "OUT: "
                                << "slot_id=" << session_info->slot_id();
  VLOG_IF(2, *result == CKR_OK) << "OUT: "
                                << "state=" << session_info->state();
  VLOG_IF(2, *result == CKR_OK) << "OUT: "
                                << "flags=" << session_info->flags();
  VLOG_IF(2, *result == CKR_OK)
      << "OUT: "
      << "device_error=" << session_info->device_error();
}

void ChapsAdaptor::GetOperationState(
    const brillo::SecureVector& isolate_credential,
    uint64_t session_id,
    vector<uint8_t>* operation_state,
    uint32_t* result) {
  VLOG(1) << "CALL: " << __func__;
  SecureBlob isolate_credential_blob(isolate_credential.begin(),
                                     isolate_credential.end());

  *result = service_->GetOperationState(isolate_credential_blob, session_id,
                                        operation_state);
}

uint32_t ChapsAdaptor::SetOperationState(
    const brillo::SecureVector& isolate_credential,
    uint64_t session_id,
    const vector<uint8_t>& operation_state,
    uint64_t encryption_key_handle,
    uint64_t authentication_key_handle) {
  VLOG(1) << "CALL: " << __func__;
  SecureBlob isolate_credential_blob(isolate_credential.begin(),
                                     isolate_credential.end());

  return service_->SetOperationState(isolate_credential_blob, session_id,
                                     operation_state, encryption_key_handle,
                                     authentication_key_handle);
}

uint32_t ChapsAdaptor::Login(const brillo::SecureVector& isolate_credential,
                             uint64_t session_id,
                             uint64_t user_type,
                             bool use_null_pin,
                             const string& optional_pin) {
  VLOG(1) << "CALL: " << __func__;
  VLOG(2) << "IN: "
          << "session_id=" << session_id;
  VLOG(2) << "IN: "
          << "user_type=" << user_type;
  VLOG(2) << "IN: "
          << "use_null_pin=" << use_null_pin;
  const string* pin = use_null_pin ? NULL : &optional_pin;
  SecureBlob isolate_credential_blob(isolate_credential.begin(),
                                     isolate_credential.end());

  return service_->Login(isolate_credential_blob, session_id, user_type, pin);
}

uint32_t ChapsAdaptor::Logout(const brillo::SecureVector& isolate_credential,
                              uint64_t session_id) {
  VLOG(1) << "CALL: " << __func__;
  VLOG(2) << "IN: "
          << "session_id=" << session_id;
  SecureBlob isolate_credential_blob(isolate_credential.begin(),
                                     isolate_credential.end());

  return service_->Logout(isolate_credential_blob, session_id);
}

void ChapsAdaptor::CreateObject(const brillo::SecureVector& isolate_credential,
                                uint64_t session_id,
                                const vector<uint8_t>& attributes,
                                uint64_t* new_object_handle,
                                uint32_t* result) {
  VLOG(1) << "CALL: " << __func__;
  VLOG(2) << "IN: "
          << "session_id=" << session_id;
  VLOG(2) << "IN: "
          << "attributes=" << PrintAttributes(attributes, true);
  SecureBlob isolate_credential_blob(isolate_credential.begin(),
                                     isolate_credential.end());

  *result = service_->CreateObject(isolate_credential_blob, session_id,
                                   attributes, new_object_handle);
  VLOG_IF(2, *result == CKR_OK) << "OUT: "
                                << "new_object_handle=" << *new_object_handle;
}

void ChapsAdaptor::CopyObject(const brillo::SecureVector& isolate_credential,
                              uint64_t session_id,
                              uint64_t object_handle,
                              const vector<uint8_t>& attributes,
                              uint64_t* new_object_handle,
                              uint32_t* result) {
  VLOG(1) << "CALL: " << __func__;
  VLOG(2) << "IN: "
          << "session_id=" << session_id;
  VLOG(2) << "IN: "
          << "object_handle=" << object_handle;
  VLOG(2) << "IN: "
          << "attributes=" << PrintAttributes(attributes, true);
  SecureBlob isolate_credential_blob(isolate_credential.begin(),
                                     isolate_credential.end());

  *result = service_->CopyObject(isolate_credential_blob, session_id,
                                 object_handle, attributes, new_object_handle);
  VLOG_IF(2, *result == CKR_OK) << "OUT: "
                                << "new_object_handle=" << *new_object_handle;
}

uint32_t ChapsAdaptor::DestroyObject(
    const brillo::SecureVector& isolate_credential,
    uint64_t session_id,
    uint64_t object_handle) {
  VLOG(1) << "CALL: " << __func__;
  VLOG(2) << "IN: "
          << "session_id=" << session_id;
  VLOG(2) << "IN: "
          << "object_handle=" << object_handle;
  SecureBlob isolate_credential_blob(isolate_credential.begin(),
                                     isolate_credential.end());

  return service_->DestroyObject(isolate_credential_blob, session_id,
                                 object_handle);
}

void ChapsAdaptor::GetObjectSize(const brillo::SecureVector& isolate_credential,
                                 uint64_t session_id,
                                 uint64_t object_handle,
                                 uint64_t* object_size,
                                 uint32_t* result) {
  VLOG(1) << "CALL: " << __func__;
  VLOG(2) << "IN: "
          << "session_id=" << session_id;
  VLOG(2) << "IN: "
          << "object_handle=" << object_handle;
  SecureBlob isolate_credential_blob(isolate_credential.begin(),
                                     isolate_credential.end());

  *result = service_->GetObjectSize(isolate_credential_blob, session_id,
                                    object_handle, object_size);
  VLOG_IF(2, *result == CKR_OK) << "OUT: "
                                << "object_size=" << *object_size;
}

void ChapsAdaptor::GetAttributeValue(
    const brillo::SecureVector& isolate_credential,
    uint64_t session_id,
    uint64_t object_handle,
    const vector<uint8_t>& attributes_in,
    vector<uint8_t>* attributes_out,
    uint32_t* result) {
  VLOG(1) << "CALL: " << __func__;
  VLOG(2) << "IN: "
          << "session_id=" << session_id;
  VLOG(2) << "IN: "
          << "object_handle=" << object_handle;
  VLOG(2) << "IN: "
          << "attributes_in=" << PrintAttributes(attributes_in, false);
  SecureBlob isolate_credential_blob(isolate_credential.begin(),
                                     isolate_credential.end());

  *result =
      service_->GetAttributeValue(isolate_credential_blob, session_id,
                                  object_handle, attributes_in, attributes_out);
  VLOG_IF(2, *result == CKR_OK || *result == CKR_ATTRIBUTE_TYPE_INVALID)
      << "OUT: "
      << "attributes_out=" << PrintAttributes(*attributes_out, true);
}

uint32_t ChapsAdaptor::SetAttributeValue(
    const brillo::SecureVector& isolate_credential,
    uint64_t session_id,
    uint64_t object_handle,
    const vector<uint8_t>& attributes) {
  VLOG(1) << "CALL: " << __func__;
  VLOG(2) << "IN: "
          << "session_id=" << session_id;
  VLOG(2) << "IN: "
          << "object_handle=" << object_handle;
  VLOG(2) << "IN: "
          << "attributes=" << PrintAttributes(attributes, true);
  SecureBlob isolate_credential_blob(isolate_credential.begin(),
                                     isolate_credential.end());

  return service_->SetAttributeValue(isolate_credential_blob, session_id,
                                     object_handle, attributes);
}

uint32_t ChapsAdaptor::FindObjectsInit(
    const brillo::SecureVector& isolate_credential,
    uint64_t session_id,
    const vector<uint8_t>& attributes) {
  VLOG(1) << "CALL: " << __func__;
  VLOG(2) << "IN: "
          << "session_id=" << session_id;
  VLOG(2) << "IN: "
          << "attributes=" << PrintAttributes(attributes, true);
  SecureBlob isolate_credential_blob(isolate_credential.begin(),
                                     isolate_credential.end());

  return service_->FindObjectsInit(isolate_credential_blob, session_id,
                                   attributes);
}

void ChapsAdaptor::FindObjects(const brillo::SecureVector& isolate_credential,
                               uint64_t session_id,
                               uint64_t max_object_count,
                               vector<uint64_t>* object_list,
                               uint32_t* result) {
  VLOG(1) << "CALL: " << __func__;
  VLOG(2) << "IN: "
          << "session_id=" << session_id;
  VLOG(2) << "IN: "
          << "max_object_count=" << max_object_count;
  SecureBlob isolate_credential_blob(isolate_credential.begin(),
                                     isolate_credential.end());

  *result = service_->FindObjects(isolate_credential_blob, session_id,
                                  max_object_count, object_list);
  VLOG_IF(2, *result == CKR_OK)
      << "OUT: "
      << "object_list=" << PrintIntVector(*object_list);
}

uint32_t ChapsAdaptor::FindObjectsFinal(
    const brillo::SecureVector& isolate_credential, uint64_t session_id) {
  VLOG(1) << "CALL: " << __func__;
  VLOG(2) << "IN: "
          << "session_id=" << session_id;
  SecureBlob isolate_credential_blob(isolate_credential.begin(),
                                     isolate_credential.end());

  return service_->FindObjectsFinal(isolate_credential_blob, session_id);
}

uint32_t ChapsAdaptor::EncryptInit(
    const brillo::SecureVector& isolate_credential,
    uint64_t session_id,
    uint64_t mechanism_type,
    const vector<uint8_t>& mechanism_parameter,
    uint64_t key_handle) {
  VLOG(1) << "CALL: " << __func__;
  VLOG(2) << "IN: "
          << "session_id=" << session_id;
  VLOG(2) << "IN: "
          << "mechanism_type=" << mechanism_type;
  VLOG(2) << "IN: "
          << "mechanism_parameter=" << PrintIntVector(mechanism_parameter);
  VLOG(2) << "IN: "
          << "key_handle=" << key_handle;
  SecureBlob isolate_credential_blob(isolate_credential.begin(),
                                     isolate_credential.end());

  return service_->EncryptInit(isolate_credential_blob, session_id,
                               mechanism_type, mechanism_parameter, key_handle);
}

void ChapsAdaptor::Encrypt(const brillo::SecureVector& isolate_credential,
                           uint64_t session_id,
                           const vector<uint8_t>& data_in,
                           uint64_t max_out_length,
                           uint64_t* actual_out_length,
                           vector<uint8_t>* data_out,
                           uint32_t* result) {
  VLOG(1) << "CALL: " << __func__;
  VLOG(2) << "IN: "
          << "session_id=" << session_id;
  VLOG(2) << "IN: "
          << "max_out_length=" << max_out_length;
  SecureBlob isolate_credential_blob(isolate_credential.begin(),
                                     isolate_credential.end());

  *result = service_->Encrypt(isolate_credential_blob, session_id, data_in,
                              max_out_length, actual_out_length, data_out);
  VLOG_IF(2, *result == CKR_OK) << "OUT: "
                                << "actual_out_length=" << *actual_out_length;
}

void ChapsAdaptor::EncryptUpdate(const brillo::SecureVector& isolate_credential,
                                 uint64_t session_id,
                                 const vector<uint8_t>& data_in,
                                 uint64_t max_out_length,
                                 uint64_t* actual_out_length,
                                 vector<uint8_t>* data_out,
                                 uint32_t* result) {
  VLOG(1) << "CALL: " << __func__;
  VLOG(2) << "IN: "
          << "session_id=" << session_id;
  VLOG(2) << "IN: "
          << "max_out_length=" << max_out_length;
  SecureBlob isolate_credential_blob(isolate_credential.begin(),
                                     isolate_credential.end());

  *result =
      service_->EncryptUpdate(isolate_credential_blob, session_id, data_in,
                              max_out_length, actual_out_length, data_out);
  VLOG_IF(2, *result == CKR_OK) << "OUT: "
                                << "actual_out_length=" << *actual_out_length;
}

void ChapsAdaptor::EncryptFinal(const brillo::SecureVector& isolate_credential,
                                uint64_t session_id,
                                uint64_t max_out_length,
                                uint64_t* actual_out_length,
                                vector<uint8_t>* data_out,
                                uint32_t* result) {
  VLOG(1) << "CALL: " << __func__;
  VLOG(2) << "IN: "
          << "session_id=" << session_id;
  VLOG(2) << "IN: "
          << "max_out_length=" << max_out_length;
  SecureBlob isolate_credential_blob(isolate_credential.begin(),
                                     isolate_credential.end());

  *result = service_->EncryptFinal(isolate_credential_blob, session_id,
                                   max_out_length, actual_out_length, data_out);
  VLOG_IF(2, *result == CKR_OK) << "OUT: "
                                << "actual_out_length=" << *actual_out_length;
}

void ChapsAdaptor::EncryptCancel(const brillo::SecureVector& isolate_credential,
                                 uint64_t session_id) {
  VLOG(1) << "CALL: " << __func__;
  SecureBlob isolate_credential_blob(isolate_credential.begin(),
                                     isolate_credential.end());

  service_->EncryptCancel(isolate_credential_blob, session_id);
}

uint32_t ChapsAdaptor::DecryptInit(
    const brillo::SecureVector& isolate_credential,
    uint64_t session_id,
    uint64_t mechanism_type,
    const vector<uint8_t>& mechanism_parameter,
    uint64_t key_handle) {
  VLOG(1) << "CALL: " << __func__;
  VLOG(2) << "IN: "
          << "session_id=" << session_id;
  VLOG(2) << "IN: "
          << "mechanism_type=" << mechanism_type;
  VLOG(2) << "IN: "
          << "mechanism_parameter=" << PrintIntVector(mechanism_parameter);
  VLOG(2) << "IN: "
          << "key_handle=" << key_handle;
  SecureBlob isolate_credential_blob(isolate_credential.begin(),
                                     isolate_credential.end());

  return service_->DecryptInit(isolate_credential_blob, session_id,
                               mechanism_type, mechanism_parameter, key_handle);
}

void ChapsAdaptor::Decrypt(const brillo::SecureVector& isolate_credential,
                           uint64_t session_id,
                           const vector<uint8_t>& data_in,
                           uint64_t max_out_length,
                           uint64_t* actual_out_length,
                           vector<uint8_t>* data_out,
                           uint32_t* result) {
  VLOG(1) << "CALL: " << __func__;
  VLOG(2) << "IN: "
          << "session_id=" << session_id;
  VLOG(2) << "IN: "
          << "max_out_length=" << max_out_length;
  SecureBlob isolate_credential_blob(isolate_credential.begin(),
                                     isolate_credential.end());

  *result = service_->Decrypt(isolate_credential_blob, session_id, data_in,
                              max_out_length, actual_out_length, data_out);
  VLOG_IF(2, *result == CKR_OK) << "OUT: "
                                << "actual_out_length=" << *actual_out_length;
}

void ChapsAdaptor::DecryptUpdate(const brillo::SecureVector& isolate_credential,
                                 uint64_t session_id,
                                 const vector<uint8_t>& data_in,
                                 uint64_t max_out_length,
                                 uint64_t* actual_out_length,
                                 vector<uint8_t>* data_out,
                                 uint32_t* result) {
  VLOG(1) << "CALL: " << __func__;
  VLOG(2) << "IN: "
          << "session_id=" << session_id;
  VLOG(2) << "IN: "
          << "max_out_length=" << max_out_length;
  SecureBlob isolate_credential_blob(isolate_credential.begin(),
                                     isolate_credential.end());

  *result =
      service_->DecryptUpdate(isolate_credential_blob, session_id, data_in,
                              max_out_length, actual_out_length, data_out);
  VLOG_IF(2, *result == CKR_OK) << "OUT: "
                                << "actual_out_length=" << *actual_out_length;
}

void ChapsAdaptor::DecryptFinal(const brillo::SecureVector& isolate_credential,
                                uint64_t session_id,
                                uint64_t max_out_length,
                                uint64_t* actual_out_length,
                                vector<uint8_t>* data_out,
                                uint32_t* result) {
  VLOG(1) << "CALL: " << __func__;
  VLOG(2) << "IN: "
          << "session_id=" << session_id;
  VLOG(2) << "IN: "
          << "max_out_length=" << max_out_length;
  SecureBlob isolate_credential_blob(isolate_credential.begin(),
                                     isolate_credential.end());

  *result = service_->DecryptFinal(isolate_credential_blob, session_id,
                                   max_out_length, actual_out_length, data_out);
  VLOG_IF(2, *result == CKR_OK) << "OUT: "
                                << "actual_out_length=" << *actual_out_length;
}

void ChapsAdaptor::DecryptCancel(const brillo::SecureVector& isolate_credential,
                                 uint64_t session_id) {
  VLOG(1) << "CALL: " << __func__;
  SecureBlob isolate_credential_blob(isolate_credential.begin(),
                                     isolate_credential.end());

  service_->DecryptCancel(isolate_credential_blob, session_id);
}

uint32_t ChapsAdaptor::DigestInit(
    const brillo::SecureVector& isolate_credential,
    uint64_t session_id,
    uint64_t mechanism_type,
    const vector<uint8_t>& mechanism_parameter) {
  VLOG(1) << "CALL: " << __func__;
  VLOG(2) << "IN: "
          << "session_id=" << session_id;
  VLOG(2) << "IN: "
          << "mechanism_type=" << mechanism_type;
  VLOG(2) << "IN: "
          << "mechanism_parameter=" << PrintIntVector(mechanism_parameter);
  SecureBlob isolate_credential_blob(isolate_credential.begin(),
                                     isolate_credential.end());

  return service_->DigestInit(isolate_credential_blob, session_id,
                              mechanism_type, mechanism_parameter);
}

void ChapsAdaptor::Digest(const brillo::SecureVector& isolate_credential,
                          uint64_t session_id,
                          const vector<uint8_t>& data_in,
                          uint64_t max_out_length,
                          uint64_t* actual_out_length,
                          vector<uint8_t>* digest,
                          uint32_t* result) {
  VLOG(1) << "CALL: " << __func__;
  VLOG(2) << "IN: "
          << "session_id=" << session_id;
  VLOG(2) << "IN: "
          << "max_out_length=" << max_out_length;
  SecureBlob isolate_credential_blob(isolate_credential.begin(),
                                     isolate_credential.end());

  *result = service_->Digest(isolate_credential_blob, session_id, data_in,
                             max_out_length, actual_out_length, digest);
  VLOG_IF(2, *result == CKR_OK) << "OUT: "
                                << "actual_out_length=" << *actual_out_length;
}

uint32_t ChapsAdaptor::DigestUpdate(
    const brillo::SecureVector& isolate_credential,
    uint64_t session_id,
    const vector<uint8_t>& data_in) {
  VLOG(1) << "CALL: " << __func__;
  VLOG(2) << "IN: "
          << "session_id=" << session_id;
  SecureBlob isolate_credential_blob(isolate_credential.begin(),
                                     isolate_credential.end());

  return service_->DigestUpdate(isolate_credential_blob, session_id, data_in);
}

uint32_t ChapsAdaptor::DigestKey(const brillo::SecureVector& isolate_credential,
                                 uint64_t session_id,
                                 uint64_t key_handle) {
  VLOG(1) << "CALL: " << __func__;
  VLOG(2) << "IN: "
          << "session_id=" << session_id;
  VLOG(2) << "IN: "
          << "key_handle=" << key_handle;
  SecureBlob isolate_credential_blob(isolate_credential.begin(),
                                     isolate_credential.end());

  return service_->DigestKey(isolate_credential_blob, session_id, key_handle);
}

void ChapsAdaptor::DigestFinal(const brillo::SecureVector& isolate_credential,
                               uint64_t session_id,
                               uint64_t max_out_length,
                               uint64_t* actual_out_length,
                               vector<uint8_t>* digest,
                               uint32_t* result) {
  VLOG(1) << "CALL: " << __func__;
  VLOG(2) << "IN: "
          << "session_id=" << session_id;
  VLOG(2) << "IN: "
          << "max_out_length=" << max_out_length;
  SecureBlob isolate_credential_blob(isolate_credential.begin(),
                                     isolate_credential.end());

  *result = service_->DigestFinal(isolate_credential_blob, session_id,
                                  max_out_length, actual_out_length, digest);
  VLOG_IF(2, *result == CKR_OK) << "OUT: "
                                << "actual_out_length=" << *actual_out_length;
}

void ChapsAdaptor::DigestCancel(const brillo::SecureVector& isolate_credential,
                                uint64_t session_id) {
  VLOG(1) << "CALL: " << __func__;
  SecureBlob isolate_credential_blob(isolate_credential.begin(),
                                     isolate_credential.end());

  service_->DigestCancel(isolate_credential_blob, session_id);
}

uint32_t ChapsAdaptor::SignInit(const brillo::SecureVector& isolate_credential,
                                uint64_t session_id,
                                uint64_t mechanism_type,
                                const vector<uint8_t>& mechanism_parameter,
                                uint64_t key_handle) {
  VLOG(1) << "CALL: " << __func__;
  VLOG(2) << "IN: "
          << "session_id=" << session_id;
  VLOG(2) << "IN: "
          << "mechanism_type=" << mechanism_type;
  VLOG(2) << "IN: "
          << "mechanism_parameter=" << PrintIntVector(mechanism_parameter);
  VLOG(2) << "IN: "
          << "key_handle=" << key_handle;
  SecureBlob isolate_credential_blob(isolate_credential.begin(),
                                     isolate_credential.end());

  return service_->SignInit(isolate_credential_blob, session_id, mechanism_type,
                            mechanism_parameter, key_handle);
}

void ChapsAdaptor::Sign(const brillo::SecureVector& isolate_credential,
                        uint64_t session_id,
                        const vector<uint8_t>& data,
                        uint64_t max_out_length,
                        uint64_t* actual_out_length,
                        vector<uint8_t>* signature,
                        uint32_t* result) {
  VLOG(1) << "CALL: " << __func__;
  VLOG(2) << "IN: "
          << "session_id=" << session_id;
  VLOG(2) << "IN: "
          << "max_out_length=" << max_out_length;
  SecureBlob isolate_credential_blob(isolate_credential.begin(),
                                     isolate_credential.end());

  *result = service_->Sign(isolate_credential_blob, session_id, data,
                           max_out_length, actual_out_length, signature);
  VLOG_IF(2, *result == CKR_OK) << "OUT: "
                                << "actual_out_length=" << *actual_out_length;
}

uint32_t ChapsAdaptor::SignUpdate(
    const brillo::SecureVector& isolate_credential,
    uint64_t session_id,
    const vector<uint8_t>& data_part) {
  VLOG(1) << "CALL: " << __func__;
  VLOG(2) << "IN: "
          << "session_id=" << session_id;
  SecureBlob isolate_credential_blob(isolate_credential.begin(),
                                     isolate_credential.end());

  return service_->SignUpdate(isolate_credential_blob, session_id, data_part);
}

void ChapsAdaptor::SignFinal(const brillo::SecureVector& isolate_credential,
                             uint64_t session_id,
                             uint64_t max_out_length,
                             uint64_t* actual_out_length,
                             vector<uint8_t>* signature,
                             uint32_t* result) {
  VLOG(1) << "CALL: " << __func__;
  VLOG(2) << "IN: "
          << "session_id=" << session_id;
  VLOG(2) << "IN: "
          << "max_out_length=" << max_out_length;
  SecureBlob isolate_credential_blob(isolate_credential.begin(),
                                     isolate_credential.end());

  *result = service_->SignFinal(isolate_credential_blob, session_id,
                                max_out_length, actual_out_length, signature);
  VLOG_IF(2, *result == CKR_OK) << "OUT: "
                                << "actual_out_length=" << *actual_out_length;
}

void ChapsAdaptor::SignCancel(const brillo::SecureVector& isolate_credential,
                              uint64_t session_id) {
  VLOG(1) << "CALL: " << __func__;
  SecureBlob isolate_credential_blob(isolate_credential.begin(),
                                     isolate_credential.end());

  service_->SignCancel(isolate_credential_blob, session_id);
}

uint32_t ChapsAdaptor::SignRecoverInit(
    const brillo::SecureVector& isolate_credential,
    uint64_t session_id,
    uint64_t mechanism_type,
    const vector<uint8_t>& mechanism_parameter,
    uint64_t key_handle) {
  VLOG(1) << "CALL: " << __func__;
  VLOG(2) << "IN: "
          << "session_id=" << session_id;
  VLOG(2) << "IN: "
          << "mechanism_type=" << mechanism_type;
  VLOG(2) << "IN: "
          << "mechanism_parameter=" << PrintIntVector(mechanism_parameter);
  VLOG(2) << "IN: "
          << "key_handle=" << key_handle;
  SecureBlob isolate_credential_blob(isolate_credential.begin(),
                                     isolate_credential.end());

  return service_->SignRecoverInit(isolate_credential_blob, session_id,
                                   mechanism_type, mechanism_parameter,
                                   key_handle);
}

void ChapsAdaptor::SignRecover(const brillo::SecureVector& isolate_credential,
                               uint64_t session_id,
                               const vector<uint8_t>& data,
                               uint64_t max_out_length,
                               uint64_t* actual_out_length,
                               vector<uint8_t>* signature,
                               uint32_t* result) {
  VLOG(1) << "CALL: " << __func__;
  VLOG(2) << "IN: "
          << "session_id=" << session_id;
  VLOG(2) << "IN: "
          << "max_out_length=" << max_out_length;
  SecureBlob isolate_credential_blob(isolate_credential.begin(),
                                     isolate_credential.end());

  *result = service_->SignRecover(isolate_credential_blob, session_id, data,
                                  max_out_length, actual_out_length, signature);
  VLOG_IF(2, *result == CKR_OK) << "OUT: "
                                << "actual_out_length=" << *actual_out_length;
}

uint32_t ChapsAdaptor::VerifyInit(
    const brillo::SecureVector& isolate_credential,
    uint64_t session_id,
    uint64_t mechanism_type,
    const vector<uint8_t>& mechanism_parameter,
    uint64_t key_handle) {
  VLOG(1) << "CALL: " << __func__;
  VLOG(2) << "IN: "
          << "session_id=" << session_id;
  VLOG(2) << "IN: "
          << "mechanism_type=" << mechanism_type;
  VLOG(2) << "IN: "
          << "mechanism_parameter=" << PrintIntVector(mechanism_parameter);
  VLOG(2) << "IN: "
          << "key_handle=" << key_handle;
  SecureBlob isolate_credential_blob(isolate_credential.begin(),
                                     isolate_credential.end());

  return service_->VerifyInit(isolate_credential_blob, session_id,
                              mechanism_type, mechanism_parameter, key_handle);
}

uint32_t ChapsAdaptor::Verify(const brillo::SecureVector& isolate_credential,
                              uint64_t session_id,
                              const vector<uint8_t>& data,
                              const vector<uint8_t>& signature) {
  VLOG(1) << "CALL: " << __func__;
  VLOG(2) << "IN: "
          << "session_id=" << session_id;
  SecureBlob isolate_credential_blob(isolate_credential.begin(),
                                     isolate_credential.end());

  return service_->Verify(isolate_credential_blob, session_id, data, signature);
}

uint32_t ChapsAdaptor::VerifyUpdate(
    const brillo::SecureVector& isolate_credential,
    uint64_t session_id,
    const vector<uint8_t>& data_part) {
  VLOG(1) << "CALL: " << __func__;
  VLOG(2) << "IN: "
          << "session_id=" << session_id;
  SecureBlob isolate_credential_blob(isolate_credential.begin(),
                                     isolate_credential.end());

  return service_->VerifyUpdate(isolate_credential_blob, session_id, data_part);
}

uint32_t ChapsAdaptor::VerifyFinal(
    const brillo::SecureVector& isolate_credential,
    uint64_t session_id,
    const vector<uint8_t>& signature) {
  VLOG(1) << "CALL: " << __func__;
  VLOG(2) << "IN: "
          << "session_id=" << session_id;
  SecureBlob isolate_credential_blob(isolate_credential.begin(),
                                     isolate_credential.end());

  return service_->VerifyFinal(isolate_credential_blob, session_id, signature);
}

void ChapsAdaptor::VerifyCancel(const brillo::SecureVector& isolate_credential,
                                uint64_t session_id) {
  VLOG(1) << "CALL: " << __func__;
  SecureBlob isolate_credential_blob(isolate_credential.begin(),
                                     isolate_credential.end());

  service_->VerifyCancel(isolate_credential_blob, session_id);
}

uint32_t ChapsAdaptor::VerifyRecoverInit(
    const brillo::SecureVector& isolate_credential,
    uint64_t session_id,
    uint64_t mechanism_type,
    const vector<uint8_t>& mechanism_parameter,
    uint64_t key_handle) {
  VLOG(1) << "CALL: " << __func__;
  VLOG(2) << "IN: "
          << "session_id=" << session_id;
  VLOG(2) << "IN: "
          << "mechanism_type=" << mechanism_type;
  VLOG(2) << "IN: "
          << "mechanism_parameter=" << PrintIntVector(mechanism_parameter);
  VLOG(2) << "IN: "
          << "key_handle=" << key_handle;
  SecureBlob isolate_credential_blob(isolate_credential.begin(),
                                     isolate_credential.end());

  return service_->VerifyRecoverInit(isolate_credential_blob, session_id,
                                     mechanism_type, mechanism_parameter,
                                     key_handle);
}

void ChapsAdaptor::VerifyRecover(const brillo::SecureVector& isolate_credential,
                                 uint64_t session_id,
                                 const vector<uint8_t>& signature,
                                 uint64_t max_out_length,
                                 uint64_t* actual_out_length,
                                 vector<uint8_t>* data,
                                 uint32_t* result) {
  VLOG(1) << "CALL: " << __func__;
  VLOG(2) << "IN: "
          << "session_id=" << session_id;
  VLOG(2) << "IN: "
          << "max_out_length=" << max_out_length;
  SecureBlob isolate_credential_blob(isolate_credential.begin(),
                                     isolate_credential.end());

  *result =
      service_->VerifyRecover(isolate_credential_blob, session_id, signature,
                              max_out_length, actual_out_length, data);
  VLOG_IF(2, *result == CKR_OK) << "OUT: "
                                << "actual_out_length=" << *actual_out_length;
}

void ChapsAdaptor::DigestEncryptUpdate(
    const brillo::SecureVector& isolate_credential,
    uint64_t session_id,
    const vector<uint8_t>& data_in,
    uint64_t max_out_length,
    uint64_t* actual_out_length,
    vector<uint8_t>* data_out,
    uint32_t* result) {
  VLOG(1) << "CALL: " << __func__;
  VLOG(2) << "IN: "
          << "session_id=" << session_id;
  VLOG(2) << "IN: "
          << "max_out_length=" << max_out_length;
  SecureBlob isolate_credential_blob(isolate_credential.begin(),
                                     isolate_credential.end());

  *result = service_->DigestEncryptUpdate(isolate_credential_blob, session_id,
                                          data_in, max_out_length,
                                          actual_out_length, data_out);
  VLOG_IF(2, *result == CKR_OK) << "OUT: "
                                << "actual_out_length=" << *actual_out_length;
}

void ChapsAdaptor::DecryptDigestUpdate(
    const brillo::SecureVector& isolate_credential,
    uint64_t session_id,
    const vector<uint8_t>& data_in,
    uint64_t max_out_length,
    uint64_t* actual_out_length,
    vector<uint8_t>* data_out,
    uint32_t* result) {
  VLOG(1) << "CALL: " << __func__;
  VLOG(2) << "IN: "
          << "session_id=" << session_id;
  VLOG(2) << "IN: "
          << "max_out_length=" << max_out_length;
  SecureBlob isolate_credential_blob(isolate_credential.begin(),
                                     isolate_credential.end());

  *result = service_->DecryptDigestUpdate(isolate_credential_blob, session_id,
                                          data_in, max_out_length,
                                          actual_out_length, data_out);
  VLOG_IF(2, *result == CKR_OK) << "OUT: "
                                << "actual_out_length=" << *actual_out_length;
}

void ChapsAdaptor::SignEncryptUpdate(
    const brillo::SecureVector& isolate_credential,
    uint64_t session_id,
    const vector<uint8_t>& data_in,
    uint64_t max_out_length,
    uint64_t* actual_out_length,
    vector<uint8_t>* data_out,
    uint32_t* result) {
  VLOG(1) << "CALL: " << __func__;
  VLOG(2) << "IN: "
          << "session_id=" << session_id;
  VLOG(2) << "IN: "
          << "max_out_length=" << max_out_length;
  SecureBlob isolate_credential_blob(isolate_credential.begin(),
                                     isolate_credential.end());

  *result =
      service_->SignEncryptUpdate(isolate_credential_blob, session_id, data_in,
                                  max_out_length, actual_out_length, data_out);
  VLOG_IF(2, *result == CKR_OK) << "OUT: "
                                << "actual_out_length=" << *actual_out_length;
}

void ChapsAdaptor::DecryptVerifyUpdate(
    const brillo::SecureVector& isolate_credential,
    uint64_t session_id,
    const vector<uint8_t>& data_in,
    uint64_t max_out_length,
    uint64_t* actual_out_length,
    vector<uint8_t>* data_out,
    uint32_t* result) {
  VLOG(1) << "CALL: " << __func__;
  VLOG(2) << "IN: "
          << "session_id=" << session_id;
  VLOG(2) << "IN: "
          << "max_out_length=" << max_out_length;
  SecureBlob isolate_credential_blob(isolate_credential.begin(),
                                     isolate_credential.end());

  *result = service_->DecryptVerifyUpdate(isolate_credential_blob, session_id,
                                          data_in, max_out_length,
                                          actual_out_length, data_out);
  VLOG_IF(2, *result == CKR_OK) << "OUT: "
                                << "actual_out_length=" << *actual_out_length;
}

void ChapsAdaptor::GenerateKey(const brillo::SecureVector& isolate_credential,
                               uint64_t session_id,
                               uint64_t mechanism_type,
                               const vector<uint8_t>& mechanism_parameter,
                               const vector<uint8_t>& attributes,
                               uint64_t* key_handle,
                               uint32_t* result) {
  VLOG(1) << "CALL: " << __func__;
  VLOG(2) << "IN: "
          << "session_id=" << session_id;
  VLOG(2) << "IN: "
          << "mechanism_type=" << mechanism_type;
  VLOG(2) << "IN: "
          << "mechanism_parameter=" << PrintIntVector(mechanism_parameter);
  VLOG(2) << "IN: "
          << "attributes=" << PrintAttributes(attributes, true);
  SecureBlob isolate_credential_blob(isolate_credential.begin(),
                                     isolate_credential.end());

  *result =
      service_->GenerateKey(isolate_credential_blob, session_id, mechanism_type,
                            mechanism_parameter, attributes, key_handle);
  VLOG_IF(2, *result == CKR_OK) << "OUT: "
                                << "key_handle=" << *key_handle;
}

void ChapsAdaptor::GenerateKeyPair(
    const brillo::SecureVector& isolate_credential,
    uint64_t session_id,
    uint64_t mechanism_type,
    const vector<uint8_t>& mechanism_parameter,
    const vector<uint8_t>& public_attributes,
    const vector<uint8_t>& private_attributes,
    uint64_t* public_key_handle,
    uint64_t* private_key_handle,
    uint32_t* result) {
  VLOG(1) << "CALL: " << __func__;
  VLOG(2) << "IN: "
          << "session_id=" << session_id;
  VLOG(2) << "IN: "
          << "mechanism_type=" << mechanism_type;
  VLOG(2) << "IN: "
          << "mechanism_parameter=" << PrintIntVector(mechanism_parameter);
  VLOG(2) << "IN: "
          << "public_attributes=" << PrintAttributes(public_attributes, true);
  VLOG(2) << "IN: "
          << "private_attributes=" << PrintAttributes(private_attributes, true);
  SecureBlob isolate_credential_blob(isolate_credential.begin(),
                                     isolate_credential.end());

  *result = service_->GenerateKeyPair(isolate_credential_blob, session_id,
                                      mechanism_type, mechanism_parameter,
                                      public_attributes, private_attributes,
                                      public_key_handle, private_key_handle);
  VLOG_IF(2, *result == CKR_OK) << "OUT: "
                                << "public_key_handle=" << *public_key_handle;
  VLOG_IF(2, *result == CKR_OK) << "OUT: "
                                << "private_key_handle=" << *private_key_handle;
}

void ChapsAdaptor::WrapKey(const brillo::SecureVector& isolate_credential,
                           uint64_t session_id,
                           uint64_t mechanism_type,
                           const vector<uint8_t>& mechanism_parameter,
                           uint64_t wrapping_key_handle,
                           uint64_t key_handle,
                           uint64_t max_out_length,
                           uint64_t* actual_out_length,
                           vector<uint8_t>* wrapped_key,
                           uint32_t* result) {
  VLOG(1) << "CALL: " << __func__;
  VLOG(2) << "IN: "
          << "session_id=" << session_id;
  VLOG(2) << "IN: "
          << "mechanism_type=" << mechanism_type;
  VLOG(2) << "IN: "
          << "mechanism_parameter=" << PrintIntVector(mechanism_parameter);
  VLOG(2) << "IN: "
          << "wrapping_key_handle=" << wrapping_key_handle;
  VLOG(2) << "IN: "
          << "key_handle=" << key_handle;
  VLOG(2) << "IN: "
          << "max_out_length=" << max_out_length;
  SecureBlob isolate_credential_blob(isolate_credential.begin(),
                                     isolate_credential.end());

  *result =
      service_->WrapKey(isolate_credential_blob, session_id, mechanism_type,
                        mechanism_parameter, wrapping_key_handle, key_handle,
                        max_out_length, actual_out_length, wrapped_key);
  VLOG_IF(2, *result == CKR_OK) << "OUT: "
                                << "actual_out_length=" << *actual_out_length;
}

void ChapsAdaptor::UnwrapKey(const brillo::SecureVector& isolate_credential,
                             uint64_t session_id,
                             uint64_t mechanism_type,
                             const vector<uint8_t>& mechanism_parameter,
                             uint64_t wrapping_key_handle,
                             const vector<uint8_t>& wrapped_key,
                             const vector<uint8_t>& attributes,
                             uint64_t* key_handle,
                             uint32_t* result) {
  VLOG(1) << "CALL: " << __func__;
  VLOG(2) << "IN: "
          << "session_id=" << session_id;
  VLOG(2) << "IN: "
          << "mechanism_type=" << mechanism_type;
  VLOG(2) << "IN: "
          << "mechanism_parameter=" << PrintIntVector(mechanism_parameter);
  VLOG(2) << "IN: "
          << "wrapping_key_handle=" << wrapping_key_handle;
  VLOG(2) << "IN: "
          << "attributes=" << PrintAttributes(attributes, true);
  SecureBlob isolate_credential_blob(isolate_credential.begin(),
                                     isolate_credential.end());

  *result = service_->UnwrapKey(
      isolate_credential_blob, session_id, mechanism_type, mechanism_parameter,
      wrapping_key_handle, wrapped_key, attributes, key_handle);
  VLOG_IF(2, *result == CKR_OK) << "OUT: "
                                << "key_handle=" << *key_handle;
}

void ChapsAdaptor::DeriveKey(const brillo::SecureVector& isolate_credential,
                             uint64_t session_id,
                             uint64_t mechanism_type,
                             const vector<uint8_t>& mechanism_parameter,
                             uint64_t base_key_handle,
                             const vector<uint8_t>& attributes,
                             uint64_t* key_handle,
                             uint32_t* result) {
  VLOG(1) << "CALL: " << __func__;
  VLOG(2) << "IN: "
          << "session_id=" << session_id;
  VLOG(2) << "IN: "
          << "mechanism_type=" << mechanism_type;
  VLOG(2) << "IN: "
          << "mechanism_parameter=" << PrintIntVector(mechanism_parameter);
  VLOG(2) << "IN: "
          << "base_key_handle=" << base_key_handle;
  VLOG(2) << "IN: "
          << "attributes=" << PrintAttributes(attributes, true);
  SecureBlob isolate_credential_blob(isolate_credential.begin(),
                                     isolate_credential.end());

  *result = service_->DeriveKey(isolate_credential_blob, session_id,
                                mechanism_type, mechanism_parameter,
                                base_key_handle, attributes, key_handle);
  VLOG_IF(2, *result == CKR_OK) << "OUT: "
                                << "key_handle=" << *key_handle;
}

uint32_t ChapsAdaptor::SeedRandom(
    const brillo::SecureVector& isolate_credential,
    uint64_t session_id,
    const vector<uint8_t>& seed) {
  VLOG(1) << "CALL: " << __func__;
  VLOG(2) << "IN: "
          << "session_id=" << session_id;
  VLOG(2) << "IN: "
          << "num_bytes=" << seed.size();
  SecureBlob isolate_credential_blob(isolate_credential.begin(),
                                     isolate_credential.end());

  return service_->SeedRandom(isolate_credential_blob, session_id, seed);
}

void ChapsAdaptor::GenerateRandom(
    const brillo::SecureVector& isolate_credential,
    uint64_t session_id,
    uint64_t num_bytes,
    vector<uint8_t>* random_data,
    uint32_t* result) {
  VLOG(1) << "CALL: " << __func__;
  VLOG(2) << "IN: "
          << "session_id=" << session_id;
  VLOG(2) << "IN: "
          << "num_bytes=" << num_bytes;
  SecureBlob isolate_credential_blob(isolate_credential.begin(),
                                     isolate_credential.end());

  *result = service_->GenerateRandom(isolate_credential_blob, session_id,
                                     num_bytes, random_data);
}

}  // namespace chaps
