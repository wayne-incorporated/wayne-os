// Copyright 2011 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chaps/chaps_proxy.h"

#include <utility>

#include <base/logging.h>
#include <base/memory/ptr_util.h>
#include <base/memory/ref_counted.h>
#include <brillo/dbus/dbus_method_invoker.h>
#include <dbus/message.h>
#include <dbus/object_path.h>

#include "base/functional/callback_helpers.h"
#include "chaps/chaps.h"
#include "chaps/chaps_utility.h"
#include "chaps/isolate.h"
#include "pkcs11/cryptoki.h"

using brillo::Blob;
using brillo::SecureBlob;
using brillo::dbus_utils::ExtractMethodCallResults;
using std::string;
using std::vector;

namespace {

// 5 minutes, since some security element operations can take a while.
constexpr base::TimeDelta kDBusTimeout = base::Minutes(5);

// TODO(yich): We should remove this after chromeos-dbus-binding support
// SecureBlob.
inline const Blob ToBlob(const SecureBlob& blob) {
  return Blob(blob.begin(), blob.end());
}

// We need to be able to shadow AtExitManagers because we don't know if the
// caller has an AtExitManager already or not (on Chrome it might, but on Linux
// it probably won't).
class ProxyAtExitManager : public base::AtExitManager {
 public:
  ProxyAtExitManager() : AtExitManager(true) {}
  ProxyAtExitManager(const ProxyAtExitManager&) = delete;
  ProxyAtExitManager& operator=(const ProxyAtExitManager&) = delete;
};

}  // namespace

namespace chaps {

// Below is the real implementation.

ChapsProxyImpl::ChapsProxyImpl(std::unique_ptr<base::AtExitManager> at_exit)
    : at_exit_(std::move(at_exit)) {}

ChapsProxyImpl::~ChapsProxyImpl() {}

// static
std::unique_ptr<ChapsProxyImpl> ChapsProxyImpl::Create(bool shadow_at_exit,
                                                       ThreadingMode mode) {
  std::unique_ptr<base::AtExitManager> at_exit;
  if (shadow_at_exit) {
    at_exit = std::make_unique<ProxyAtExitManager>();
  }

  auto chaps_proxy_impl =
      base::WrapUnique(new ChapsProxyImpl(std::move(at_exit)));

  bool connected = false;

  if (mode == ThreadingMode::kStandaloneWorkerThread) {
    base::Thread::Options options(base::MessagePumpType::IO, 0);
    chaps_proxy_impl->dbus_thread_ =
        std::make_unique<ChapsProxyThread>(chaps_proxy_impl.get());
    chaps_proxy_impl->dbus_thread_->StartWithOptions(std::move(options));

    base::WaitableEvent event(base::WaitableEvent::ResetPolicy::MANUAL,
                              base::WaitableEvent::InitialState::NOT_SIGNALED);
    chaps_proxy_impl->dbus_thread_->task_runner()->PostTask(
        FROM_HERE, base::BindOnce(&ChapsProxyImpl::InitializationTask,
                                  base::Unretained(chaps_proxy_impl.get()),
                                  base::BindOnce(&base::WaitableEvent::Signal,
                                                 base::Unretained(&event)),
                                  &connected));
    event.Wait();
  } else {
    chaps_proxy_impl->InitializationTask(base::DoNothing(), &connected);
  }

  if (!connected) {
    // We should return nullptr when failed to connect to system D-Bus, and let
    // C_Initialize return CKR_GENERAL_ERROR.
    LOG(ERROR) << "Failed to connect to system D-Bus";
    return nullptr;
  }

  return chaps_proxy_impl;
}

void ChapsProxyImpl::InitializationTask(base::OnceClosure callback,
                                        bool* connected) {
  dbus::Bus::Options options;
  options.bus_type = dbus::Bus::SYSTEM;
  bus_ = base::MakeRefCounted<dbus::Bus>(options);

  *connected = bus_->Connect();

  default_proxy_ = std::make_unique<org::chromium::ChapsProxy>(bus_);

  proxy_ = default_proxy_.get();

  std::move(callback).Run();
}

void ChapsProxyImpl::ShutdownTask() {
  default_proxy_.reset();
  bus_->ShutdownAndBlock();
  bus_.reset();
}

template <typename MethodType, typename... Args>
bool ChapsProxyImpl::SendRequestAndWait(const MethodType& method,
                                        Args... args) {
  bool success = true;
  if (dbus_thread_) {
    base::WaitableEvent event(base::WaitableEvent::ResetPolicy::MANUAL,
                              base::WaitableEvent::InitialState::NOT_SIGNALED);
    dbus_thread_->task_runner()->PostTask(
        FROM_HERE, base::BindOnce(
                       [](org::chromium::ChapsProxyInterface* proxy,
                          base::WaitableEvent* completion, bool* success,
                          const MethodType& method, Args... args) {
                         brillo::ErrorPtr error = nullptr;
                         if (!(proxy->*method)(args..., &error,
                                               kDBusTimeout.InMilliseconds()) ||
                             error) {
                           *success = false;
                         }
                         completion->Signal();
                       },
                       proxy_, &event, &success, method, args...));

    event.Wait();
  } else {
    brillo::ErrorPtr error = nullptr;
    if (!(proxy_->*method)(args..., &error, kDBusTimeout.InMilliseconds()) ||
        error) {
      success = false;
    }
  }
  return success;
}

bool ChapsProxyImpl::OpenIsolate(SecureBlob* isolate_credential,
                                 bool* new_isolate_created) {
  Blob isolate_credential_out;
  bool result = false;
  bool success =
      SendRequestAndWait(&org::chromium::ChapsProxyInterface::OpenIsolate,
                         ToBlob(*isolate_credential), &isolate_credential_out,
                         new_isolate_created, &result);
  *isolate_credential = SecureBlob(isolate_credential_out);
  return success && result;
}

void ChapsProxyImpl::CloseIsolate(const SecureBlob& isolate_credential) {
  SendRequestAndWait(&org::chromium::ChapsProxyInterface::CloseIsolate,
                     ToBlob(isolate_credential));
}

bool ChapsProxyImpl::LoadToken(const SecureBlob& isolate_credential,
                               const string& path,
                               const SecureBlob& auth_data,
                               const string& label,
                               uint64_t* slot_id) {
  bool result = false;
  bool success =
      SendRequestAndWait(&org::chromium::ChapsProxyInterface::LoadToken,
                         ToBlob(isolate_credential), path, ToBlob(auth_data),
                         label, slot_id, &result);
  return success && result;
}

bool ChapsProxyImpl::UnloadToken(const SecureBlob& isolate_credential,
                                 const string& path) {
  bool result = false;
  bool success =
      SendRequestAndWait(&org::chromium::ChapsProxyInterface::UnloadToken,
                         ToBlob(isolate_credential), path, &result);
  return success && result;
}

bool ChapsProxyImpl::GetTokenPath(const SecureBlob& isolate_credential,
                                  uint64_t slot_id,
                                  string* path) {
  bool result = false;
  bool success =
      SendRequestAndWait(&org::chromium::ChapsProxyInterface::GetTokenPath,
                         ToBlob(isolate_credential), slot_id, path, &result);
  return success && result;
}

void ChapsProxyImpl::SetLogLevel(const int32_t& level) {
  SendRequestAndWait(&org::chromium::ChapsProxyInterface::SetLogLevel, level);
}

uint32_t ChapsProxyImpl::GetSlotList(const SecureBlob& isolate_credential,
                                     bool token_present,
                                     vector<uint64_t>* slot_list) {
  LOG_CK_RV_AND_RETURN_IF(!slot_list, CKR_ARGUMENTS_BAD);
  uint32_t result = CKR_GENERAL_ERROR;

  SendRequestAndWait(&org::chromium::ChapsProxyInterface::GetSlotList,
                     ToBlob(isolate_credential), token_present, slot_list,
                     &result);
  return result;
}

uint32_t ChapsProxyImpl::GetSlotInfo(const SecureBlob& isolate_credential,
                                     uint64_t slot_id,
                                     SlotInfo* slot_info) {
  LOG_CK_RV_AND_RETURN_IF(!slot_info, CKR_ARGUMENTS_BAD);
  uint32_t result = CKR_GENERAL_ERROR;
  SendRequestAndWait(&org::chromium::ChapsProxyInterface::GetSlotInfo,
                     ToBlob(isolate_credential), slot_id, slot_info, &result);
  return result;
}

uint32_t ChapsProxyImpl::GetTokenInfo(const SecureBlob& isolate_credential,
                                      uint64_t slot_id,
                                      TokenInfo* token_info) {
  LOG_CK_RV_AND_RETURN_IF(!token_info, CKR_ARGUMENTS_BAD);
  uint32_t result = CKR_GENERAL_ERROR;
  SendRequestAndWait(&org::chromium::ChapsProxyInterface::GetTokenInfo,
                     ToBlob(isolate_credential), slot_id, token_info, &result);
  return result;
}

uint32_t ChapsProxyImpl::GetMechanismList(const SecureBlob& isolate_credential,
                                          uint64_t slot_id,
                                          vector<uint64_t>* mechanism_list) {
  LOG_CK_RV_AND_RETURN_IF(!mechanism_list, CKR_ARGUMENTS_BAD);
  uint32_t result = CKR_GENERAL_ERROR;
  SendRequestAndWait(&org::chromium::ChapsProxyInterface::GetMechanismList,
                     ToBlob(isolate_credential), slot_id, mechanism_list,
                     &result);
  return result;
}

uint32_t ChapsProxyImpl::GetMechanismInfo(const SecureBlob& isolate_credential,
                                          uint64_t slot_id,
                                          uint64_t mechanism_type,
                                          MechanismInfo* mechanism_info) {
  LOG_CK_RV_AND_RETURN_IF(!mechanism_info, CKR_ARGUMENTS_BAD);
  uint32_t result = CKR_GENERAL_ERROR;
  SendRequestAndWait(&org::chromium::ChapsProxyInterface::GetMechanismInfo,
                     ToBlob(isolate_credential), slot_id, mechanism_type,
                     mechanism_info, &result);
  return result;
}

uint32_t ChapsProxyImpl::InitToken(const SecureBlob& isolate_credential,
                                   uint64_t slot_id,
                                   const string* so_pin,
                                   const vector<uint8_t>& label) {
  uint32_t result = CKR_GENERAL_ERROR;
  string tmp_pin;
  if (so_pin)
    tmp_pin = *so_pin;
  SendRequestAndWait(&org::chromium::ChapsProxyInterface::InitToken,
                     ToBlob(isolate_credential), slot_id, (so_pin == nullptr),
                     tmp_pin, label, &result);
  return result;
}

uint32_t ChapsProxyImpl::InitPIN(const SecureBlob& isolate_credential,
                                 uint64_t session_id,
                                 const string* pin) {
  uint32_t result = CKR_GENERAL_ERROR;
  string tmp_pin;
  if (pin)
    tmp_pin = *pin;
  SendRequestAndWait(&org::chromium::ChapsProxyInterface::InitPIN,
                     ToBlob(isolate_credential), session_id, (pin == nullptr),
                     tmp_pin, &result);
  return result;
}

uint32_t ChapsProxyImpl::SetPIN(const SecureBlob& isolate_credential,
                                uint64_t session_id,
                                const string* old_pin,
                                const string* new_pin) {
  uint32_t result = CKR_GENERAL_ERROR;
  string tmp_old_pin;
  if (old_pin)
    tmp_old_pin = *old_pin;
  string tmp_new_pin;
  if (new_pin)
    tmp_new_pin = *new_pin;
  SendRequestAndWait(&org::chromium::ChapsProxyInterface::SetPIN,
                     ToBlob(isolate_credential), session_id,
                     (old_pin == nullptr), tmp_old_pin, (new_pin == nullptr),
                     tmp_new_pin, &result);
  return result;
}

uint32_t ChapsProxyImpl::OpenSession(const SecureBlob& isolate_credential,
                                     uint64_t slot_id,
                                     uint64_t flags,
                                     uint64_t* session_id) {
  LOG_CK_RV_AND_RETURN_IF(!session_id, CKR_ARGUMENTS_BAD);
  uint32_t result = CKR_GENERAL_ERROR;
  SendRequestAndWait(&org::chromium::ChapsProxyInterface::OpenSession,
                     ToBlob(isolate_credential), slot_id, flags, session_id,
                     &result);
  return result;
}

uint32_t ChapsProxyImpl::CloseSession(const SecureBlob& isolate_credential,
                                      uint64_t session_id) {
  uint32_t result = CKR_GENERAL_ERROR;
  SendRequestAndWait(&org::chromium::ChapsProxyInterface::CloseSession,
                     ToBlob(isolate_credential), session_id, &result);
  return result;
}

uint32_t ChapsProxyImpl::GetSessionInfo(const SecureBlob& isolate_credential,
                                        uint64_t session_id,
                                        SessionInfo* session_info) {
  LOG_CK_RV_AND_RETURN_IF(!session_info, CKR_ARGUMENTS_BAD);
  uint32_t result = CKR_GENERAL_ERROR;
  SendRequestAndWait(&org::chromium::ChapsProxyInterface::GetSessionInfo,
                     ToBlob(isolate_credential), session_id, session_info,
                     &result);
  return result;
}

uint32_t ChapsProxyImpl::GetOperationState(const SecureBlob& isolate_credential,
                                           uint64_t session_id,
                                           vector<uint8_t>* operation_state) {
  LOG_CK_RV_AND_RETURN_IF(!operation_state, CKR_ARGUMENTS_BAD);
  uint32_t result = CKR_GENERAL_ERROR;
  SendRequestAndWait(&org::chromium::ChapsProxyInterface::GetOperationState,
                     ToBlob(isolate_credential), session_id, operation_state,
                     &result);
  return result;
}

uint32_t ChapsProxyImpl::SetOperationState(
    const SecureBlob& isolate_credential,
    uint64_t session_id,
    const vector<uint8_t>& operation_state,
    uint64_t encryption_key_handle,
    uint64_t authentication_key_handle) {
  uint32_t result = CKR_GENERAL_ERROR;
  SendRequestAndWait(&org::chromium::ChapsProxyInterface::SetOperationState,
                     ToBlob(isolate_credential), session_id, operation_state,
                     encryption_key_handle, authentication_key_handle, &result);
  return result;
}

uint32_t ChapsProxyImpl::Login(const SecureBlob& isolate_credential,
                               uint64_t session_id,
                               uint64_t user_type,
                               const string* pin) {
  uint32_t result = CKR_GENERAL_ERROR;
  string tmp_pin;
  if (pin)
    tmp_pin = *pin;
  SendRequestAndWait(&org::chromium::ChapsProxyInterface::Login,
                     ToBlob(isolate_credential), session_id, user_type,
                     (pin == nullptr), tmp_pin, &result);
  return result;
}

uint32_t ChapsProxyImpl::Logout(const SecureBlob& isolate_credential,
                                uint64_t session_id) {
  uint32_t result = CKR_GENERAL_ERROR;
  SendRequestAndWait(&org::chromium::ChapsProxyInterface::Logout,
                     ToBlob(isolate_credential), session_id, &result);
  return result;
}

uint32_t ChapsProxyImpl::CreateObject(const SecureBlob& isolate_credential,
                                      uint64_t session_id,
                                      const vector<uint8_t>& attributes,
                                      uint64_t* new_object_handle) {
  LOG_CK_RV_AND_RETURN_IF(!new_object_handle, CKR_ARGUMENTS_BAD);
  uint32_t result = CKR_GENERAL_ERROR;
  SendRequestAndWait(&org::chromium::ChapsProxyInterface::CreateObject,
                     ToBlob(isolate_credential), session_id, attributes,
                     new_object_handle, &result);
  return result;
}

uint32_t ChapsProxyImpl::CopyObject(const SecureBlob& isolate_credential,
                                    uint64_t session_id,
                                    uint64_t object_handle,
                                    const vector<uint8_t>& attributes,
                                    uint64_t* new_object_handle) {
  LOG_CK_RV_AND_RETURN_IF(!new_object_handle, CKR_ARGUMENTS_BAD);
  uint32_t result = CKR_GENERAL_ERROR;
  SendRequestAndWait(&org::chromium::ChapsProxyInterface::CopyObject,
                     ToBlob(isolate_credential), session_id, object_handle,
                     attributes, new_object_handle, &result);
  return result;
}

uint32_t ChapsProxyImpl::DestroyObject(const SecureBlob& isolate_credential,
                                       uint64_t session_id,
                                       uint64_t object_handle) {
  uint32_t result = CKR_GENERAL_ERROR;
  SendRequestAndWait(&org::chromium::ChapsProxyInterface::DestroyObject,
                     ToBlob(isolate_credential), session_id, object_handle,
                     &result);
  return result;
}

uint32_t ChapsProxyImpl::GetObjectSize(const SecureBlob& isolate_credential,
                                       uint64_t session_id,
                                       uint64_t object_handle,
                                       uint64_t* object_size) {
  LOG_CK_RV_AND_RETURN_IF(!object_size, CKR_ARGUMENTS_BAD);
  uint32_t result = CKR_GENERAL_ERROR;
  SendRequestAndWait(&org::chromium::ChapsProxyInterface::GetObjectSize,
                     ToBlob(isolate_credential), session_id, object_handle,
                     object_size, &result);
  return result;
}

uint32_t ChapsProxyImpl::GetAttributeValue(const SecureBlob& isolate_credential,
                                           uint64_t session_id,
                                           uint64_t object_handle,
                                           const vector<uint8_t>& attributes_in,
                                           vector<uint8_t>* attributes_out) {
  LOG_CK_RV_AND_RETURN_IF(!attributes_out, CKR_ARGUMENTS_BAD);
  uint32_t result = CKR_GENERAL_ERROR;
  SendRequestAndWait(&org::chromium::ChapsProxyInterface::GetAttributeValue,
                     ToBlob(isolate_credential), session_id, object_handle,
                     attributes_in, attributes_out, &result);
  return result;
}

uint32_t ChapsProxyImpl::SetAttributeValue(const SecureBlob& isolate_credential,
                                           uint64_t session_id,
                                           uint64_t object_handle,
                                           const vector<uint8_t>& attributes) {
  uint32_t result = CKR_GENERAL_ERROR;
  SendRequestAndWait(&org::chromium::ChapsProxyInterface::SetAttributeValue,
                     ToBlob(isolate_credential), session_id, object_handle,
                     attributes, &result);
  return result;
}

uint32_t ChapsProxyImpl::FindObjectsInit(const SecureBlob& isolate_credential,
                                         uint64_t session_id,
                                         const vector<uint8_t>& attributes) {
  uint32_t result = CKR_GENERAL_ERROR;
  SendRequestAndWait(&org::chromium::ChapsProxyInterface::FindObjectsInit,
                     ToBlob(isolate_credential), session_id, attributes,
                     &result);
  return result;
}

uint32_t ChapsProxyImpl::FindObjects(const SecureBlob& isolate_credential,
                                     uint64_t session_id,
                                     uint64_t max_object_count,
                                     vector<uint64_t>* object_list) {
  if (!object_list || object_list->size() > 0)
    LOG_CK_RV_AND_RETURN(CKR_ARGUMENTS_BAD);
  uint32_t result = CKR_GENERAL_ERROR;
  SendRequestAndWait(&org::chromium::ChapsProxyInterface::FindObjects,
                     ToBlob(isolate_credential), session_id, max_object_count,
                     object_list, &result);
  return result;
}

uint32_t ChapsProxyImpl::FindObjectsFinal(const SecureBlob& isolate_credential,
                                          uint64_t session_id) {
  uint32_t result = CKR_GENERAL_ERROR;
  SendRequestAndWait(&org::chromium::ChapsProxyInterface::FindObjectsFinal,
                     ToBlob(isolate_credential), session_id, &result);
  return result;
}

uint32_t ChapsProxyImpl::EncryptInit(const SecureBlob& isolate_credential,
                                     uint64_t session_id,
                                     uint64_t mechanism_type,
                                     const vector<uint8_t>& mechanism_parameter,
                                     uint64_t key_handle) {
  uint32_t result = CKR_GENERAL_ERROR;
  SendRequestAndWait(&org::chromium::ChapsProxyInterface::EncryptInit,
                     ToBlob(isolate_credential), session_id, mechanism_type,
                     mechanism_parameter, key_handle, &result);
  return result;
}

uint32_t ChapsProxyImpl::Encrypt(const SecureBlob& isolate_credential,
                                 uint64_t session_id,
                                 const vector<uint8_t>& data_in,
                                 uint64_t max_out_length,
                                 uint64_t* actual_out_length,
                                 vector<uint8_t>* data_out) {
  LOG_CK_RV_AND_RETURN_IF(!actual_out_length || !data_out, CKR_ARGUMENTS_BAD);
  uint32_t result = CKR_GENERAL_ERROR;
  SendRequestAndWait(&org::chromium::ChapsProxyInterface::Encrypt,
                     ToBlob(isolate_credential), session_id, data_in,
                     max_out_length, actual_out_length, data_out, &result);
  return result;
}

uint32_t ChapsProxyImpl::EncryptUpdate(const SecureBlob& isolate_credential,
                                       uint64_t session_id,
                                       const vector<uint8_t>& data_in,
                                       uint64_t max_out_length,
                                       uint64_t* actual_out_length,
                                       vector<uint8_t>* data_out) {
  LOG_CK_RV_AND_RETURN_IF(!actual_out_length || !data_out, CKR_ARGUMENTS_BAD);
  uint32_t result = CKR_GENERAL_ERROR;
  SendRequestAndWait(&org::chromium::ChapsProxyInterface::EncryptUpdate,
                     ToBlob(isolate_credential), session_id, data_in,
                     max_out_length, actual_out_length, data_out, &result);
  return result;
}

uint32_t ChapsProxyImpl::EncryptFinal(const SecureBlob& isolate_credential,
                                      uint64_t session_id,
                                      uint64_t max_out_length,
                                      uint64_t* actual_out_length,
                                      vector<uint8_t>* data_out) {
  LOG_CK_RV_AND_RETURN_IF(!actual_out_length || !data_out, CKR_ARGUMENTS_BAD);
  uint32_t result = CKR_GENERAL_ERROR;
  SendRequestAndWait(&org::chromium::ChapsProxyInterface::EncryptFinal,
                     ToBlob(isolate_credential), session_id, max_out_length,
                     actual_out_length, data_out, &result);
  return result;
}

void ChapsProxyImpl::EncryptCancel(const SecureBlob& isolate_credential,
                                   uint64_t session_id) {
  SendRequestAndWait(&org::chromium::ChapsProxyInterface::EncryptCancel,
                     ToBlob(isolate_credential), session_id);
}

uint32_t ChapsProxyImpl::DecryptInit(const SecureBlob& isolate_credential,
                                     uint64_t session_id,
                                     uint64_t mechanism_type,
                                     const vector<uint8_t>& mechanism_parameter,
                                     uint64_t key_handle) {
  uint32_t result = CKR_GENERAL_ERROR;
  SendRequestAndWait(&org::chromium::ChapsProxyInterface::DecryptInit,
                     ToBlob(isolate_credential), session_id, mechanism_type,
                     mechanism_parameter, key_handle, &result);
  return result;
}

uint32_t ChapsProxyImpl::Decrypt(const SecureBlob& isolate_credential,
                                 uint64_t session_id,
                                 const vector<uint8_t>& data_in,
                                 uint64_t max_out_length,
                                 uint64_t* actual_out_length,
                                 vector<uint8_t>* data_out) {
  LOG_CK_RV_AND_RETURN_IF(!actual_out_length || !data_out, CKR_ARGUMENTS_BAD);
  uint32_t result = CKR_GENERAL_ERROR;
  SendRequestAndWait(&org::chromium::ChapsProxyInterface::Decrypt,
                     ToBlob(isolate_credential), session_id, data_in,
                     max_out_length, actual_out_length, data_out, &result);
  return result;
}

uint32_t ChapsProxyImpl::DecryptUpdate(const SecureBlob& isolate_credential,
                                       uint64_t session_id,
                                       const vector<uint8_t>& data_in,
                                       uint64_t max_out_length,
                                       uint64_t* actual_out_length,
                                       vector<uint8_t>* data_out) {
  LOG_CK_RV_AND_RETURN_IF(!actual_out_length || !data_out, CKR_ARGUMENTS_BAD);
  uint32_t result = CKR_GENERAL_ERROR;
  SendRequestAndWait(&org::chromium::ChapsProxyInterface::DecryptUpdate,
                     ToBlob(isolate_credential), session_id, data_in,
                     max_out_length, actual_out_length, data_out, &result);
  return result;
}

uint32_t ChapsProxyImpl::DecryptFinal(const SecureBlob& isolate_credential,
                                      uint64_t session_id,
                                      uint64_t max_out_length,
                                      uint64_t* actual_out_length,
                                      vector<uint8_t>* data_out) {
  LOG_CK_RV_AND_RETURN_IF(!actual_out_length || !data_out, CKR_ARGUMENTS_BAD);
  uint32_t result = CKR_GENERAL_ERROR;
  SendRequestAndWait(&org::chromium::ChapsProxyInterface::DecryptFinal,
                     ToBlob(isolate_credential), session_id, max_out_length,
                     actual_out_length, data_out, &result);
  return result;
}

void ChapsProxyImpl::DecryptCancel(const SecureBlob& isolate_credential,
                                   uint64_t session_id) {
  SendRequestAndWait(&org::chromium::ChapsProxyInterface::DecryptCancel,
                     ToBlob(isolate_credential), session_id);
}

uint32_t ChapsProxyImpl::DigestInit(
    const SecureBlob& isolate_credential,
    uint64_t session_id,
    uint64_t mechanism_type,
    const vector<uint8_t>& mechanism_parameter) {
  uint32_t result = CKR_GENERAL_ERROR;
  SendRequestAndWait(&org::chromium::ChapsProxyInterface::DigestInit,
                     ToBlob(isolate_credential), session_id, mechanism_type,
                     mechanism_parameter, &result);
  return result;
}

uint32_t ChapsProxyImpl::Digest(const SecureBlob& isolate_credential,
                                uint64_t session_id,
                                const vector<uint8_t>& data_in,
                                uint64_t max_out_length,
                                uint64_t* actual_out_length,
                                vector<uint8_t>* digest) {
  uint32_t result = CKR_GENERAL_ERROR;
  SendRequestAndWait(&org::chromium::ChapsProxyInterface::Digest,
                     ToBlob(isolate_credential), session_id, data_in,
                     max_out_length, actual_out_length, digest, &result);
  return result;
}

uint32_t ChapsProxyImpl::DigestUpdate(const SecureBlob& isolate_credential,
                                      uint64_t session_id,
                                      const vector<uint8_t>& data_in) {
  uint32_t result = CKR_GENERAL_ERROR;
  SendRequestAndWait(&org::chromium::ChapsProxyInterface::DigestUpdate,
                     ToBlob(isolate_credential), session_id, data_in, &result);
  return result;
}

uint32_t ChapsProxyImpl::DigestKey(const SecureBlob& isolate_credential,
                                   uint64_t session_id,
                                   uint64_t key_handle) {
  uint32_t result = CKR_GENERAL_ERROR;
  SendRequestAndWait(&org::chromium::ChapsProxyInterface::DigestKey,
                     ToBlob(isolate_credential), session_id, key_handle,
                     &result);
  return result;
}

uint32_t ChapsProxyImpl::DigestFinal(const SecureBlob& isolate_credential,
                                     uint64_t session_id,
                                     uint64_t max_out_length,
                                     uint64_t* actual_out_length,
                                     vector<uint8_t>* digest) {
  uint32_t result = CKR_GENERAL_ERROR;
  SendRequestAndWait(&org::chromium::ChapsProxyInterface::DigestFinal,
                     ToBlob(isolate_credential), session_id, max_out_length,
                     actual_out_length, digest, &result);
  return result;
}

void ChapsProxyImpl::DigestCancel(const SecureBlob& isolate_credential,
                                  uint64_t session_id) {
  SendRequestAndWait(&org::chromium::ChapsProxyInterface::DigestCancel,
                     ToBlob(isolate_credential), session_id);
}

uint32_t ChapsProxyImpl::SignInit(const SecureBlob& isolate_credential,
                                  uint64_t session_id,
                                  uint64_t mechanism_type,
                                  const vector<uint8_t>& mechanism_parameter,
                                  uint64_t key_handle) {
  uint32_t result = CKR_GENERAL_ERROR;
  SendRequestAndWait(&org::chromium::ChapsProxyInterface::SignInit,
                     ToBlob(isolate_credential), session_id, mechanism_type,
                     mechanism_parameter, key_handle, &result);
  return result;
}

uint32_t ChapsProxyImpl::Sign(const SecureBlob& isolate_credential,
                              uint64_t session_id,
                              const vector<uint8_t>& data,
                              uint64_t max_out_length,
                              uint64_t* actual_out_length,
                              vector<uint8_t>* signature) {
  uint32_t result = CKR_GENERAL_ERROR;
  SendRequestAndWait(&org::chromium::ChapsProxyInterface::Sign,
                     ToBlob(isolate_credential), session_id, data,
                     max_out_length, actual_out_length, signature, &result);
  return result;
}

uint32_t ChapsProxyImpl::SignUpdate(const SecureBlob& isolate_credential,
                                    uint64_t session_id,
                                    const vector<uint8_t>& data_part) {
  uint32_t result = CKR_GENERAL_ERROR;
  SendRequestAndWait(&org::chromium::ChapsProxyInterface::SignUpdate,
                     ToBlob(isolate_credential), session_id, data_part,
                     &result);
  return result;
}

uint32_t ChapsProxyImpl::SignFinal(const SecureBlob& isolate_credential,
                                   uint64_t session_id,
                                   uint64_t max_out_length,
                                   uint64_t* actual_out_length,
                                   vector<uint8_t>* signature) {
  uint32_t result = CKR_GENERAL_ERROR;
  SendRequestAndWait(&org::chromium::ChapsProxyInterface::SignFinal,
                     ToBlob(isolate_credential), session_id, max_out_length,
                     actual_out_length, signature, &result);
  return result;
}

void ChapsProxyImpl::SignCancel(const SecureBlob& isolate_credential,
                                uint64_t session_id) {
  SendRequestAndWait(&org::chromium::ChapsProxyInterface::SignCancel,
                     ToBlob(isolate_credential), session_id);
}

uint32_t ChapsProxyImpl::SignRecoverInit(
    const SecureBlob& isolate_credential,
    uint64_t session_id,
    uint64_t mechanism_type,
    const vector<uint8_t>& mechanism_parameter,
    uint64_t key_handle) {
  uint32_t result = CKR_GENERAL_ERROR;
  SendRequestAndWait(&org::chromium::ChapsProxyInterface::SignRecoverInit,
                     ToBlob(isolate_credential), session_id, mechanism_type,
                     mechanism_parameter, key_handle, &result);
  return result;
}

uint32_t ChapsProxyImpl::SignRecover(const SecureBlob& isolate_credential,
                                     uint64_t session_id,
                                     const vector<uint8_t>& data,
                                     uint64_t max_out_length,
                                     uint64_t* actual_out_length,
                                     vector<uint8_t>* signature) {
  uint32_t result = CKR_GENERAL_ERROR;
  SendRequestAndWait(&org::chromium::ChapsProxyInterface::SignRecover,
                     ToBlob(isolate_credential), session_id, data,
                     max_out_length, actual_out_length, signature, &result);
  return result;
}

uint32_t ChapsProxyImpl::VerifyInit(const SecureBlob& isolate_credential,
                                    uint64_t session_id,
                                    uint64_t mechanism_type,
                                    const vector<uint8_t>& mechanism_parameter,
                                    uint64_t key_handle) {
  uint32_t result = CKR_GENERAL_ERROR;
  SendRequestAndWait(&org::chromium::ChapsProxyInterface::VerifyInit,
                     ToBlob(isolate_credential), session_id, mechanism_type,
                     mechanism_parameter, key_handle, &result);
  return result;
}

uint32_t ChapsProxyImpl::Verify(const SecureBlob& isolate_credential,
                                uint64_t session_id,
                                const vector<uint8_t>& data,
                                const vector<uint8_t>& signature) {
  uint32_t result = CKR_GENERAL_ERROR;
  SendRequestAndWait(&org::chromium::ChapsProxyInterface::Verify,
                     ToBlob(isolate_credential), session_id, data, signature,
                     &result);
  return result;
}

uint32_t ChapsProxyImpl::VerifyUpdate(const SecureBlob& isolate_credential,
                                      uint64_t session_id,
                                      const vector<uint8_t>& data_part) {
  uint32_t result = CKR_GENERAL_ERROR;
  SendRequestAndWait(&org::chromium::ChapsProxyInterface::VerifyUpdate,
                     ToBlob(isolate_credential), session_id, data_part,
                     &result);
  return result;
}

uint32_t ChapsProxyImpl::VerifyFinal(const SecureBlob& isolate_credential,
                                     uint64_t session_id,
                                     const vector<uint8_t>& signature) {
  uint32_t result = CKR_GENERAL_ERROR;
  SendRequestAndWait(&org::chromium::ChapsProxyInterface::VerifyFinal,
                     ToBlob(isolate_credential), session_id, signature,
                     &result);
  return result;
}

void ChapsProxyImpl::VerifyCancel(const SecureBlob& isolate_credential,
                                  uint64_t session_id) {
  SendRequestAndWait(&org::chromium::ChapsProxyInterface::VerifyCancel,
                     ToBlob(isolate_credential), session_id);
}

uint32_t ChapsProxyImpl::VerifyRecoverInit(
    const SecureBlob& isolate_credential,
    uint64_t session_id,
    uint64_t mechanism_type,
    const vector<uint8_t>& mechanism_parameter,
    uint64_t key_handle) {
  uint32_t result = CKR_GENERAL_ERROR;
  SendRequestAndWait(&org::chromium::ChapsProxyInterface::VerifyRecoverInit,
                     ToBlob(isolate_credential), session_id, mechanism_type,
                     mechanism_parameter, key_handle, &result);
  return result;
}

uint32_t ChapsProxyImpl::VerifyRecover(const SecureBlob& isolate_credential,
                                       uint64_t session_id,
                                       const vector<uint8_t>& signature,
                                       uint64_t max_out_length,
                                       uint64_t* actual_out_length,
                                       vector<uint8_t>* data) {
  uint32_t result = CKR_GENERAL_ERROR;
  SendRequestAndWait(&org::chromium::ChapsProxyInterface::VerifyRecover,
                     ToBlob(isolate_credential), session_id, signature,
                     max_out_length, actual_out_length, data, &result);
  return result;
}

uint32_t ChapsProxyImpl::DigestEncryptUpdate(
    const SecureBlob& isolate_credential,
    uint64_t session_id,
    const vector<uint8_t>& data_in,
    uint64_t max_out_length,
    uint64_t* actual_out_length,
    vector<uint8_t>* data_out) {
  LOG_CK_RV_AND_RETURN_IF(!actual_out_length || !data_out, CKR_ARGUMENTS_BAD);
  uint32_t result = CKR_GENERAL_ERROR;
  SendRequestAndWait(&org::chromium::ChapsProxyInterface::DigestEncryptUpdate,
                     ToBlob(isolate_credential), session_id, data_in,
                     max_out_length, actual_out_length, data_out, &result);
  return result;
}

uint32_t ChapsProxyImpl::DecryptDigestUpdate(
    const SecureBlob& isolate_credential,
    uint64_t session_id,
    const vector<uint8_t>& data_in,
    uint64_t max_out_length,
    uint64_t* actual_out_length,
    vector<uint8_t>* data_out) {
  LOG_CK_RV_AND_RETURN_IF(!actual_out_length || !data_out, CKR_ARGUMENTS_BAD);
  uint32_t result = CKR_GENERAL_ERROR;
  SendRequestAndWait(&org::chromium::ChapsProxyInterface::DecryptDigestUpdate,
                     ToBlob(isolate_credential), session_id, data_in,
                     max_out_length, actual_out_length, data_out, &result);
  return result;
}

uint32_t ChapsProxyImpl::SignEncryptUpdate(const SecureBlob& isolate_credential,
                                           uint64_t session_id,
                                           const vector<uint8_t>& data_in,
                                           uint64_t max_out_length,
                                           uint64_t* actual_out_length,
                                           vector<uint8_t>* data_out) {
  LOG_CK_RV_AND_RETURN_IF(!actual_out_length || !data_out, CKR_ARGUMENTS_BAD);
  uint32_t result = CKR_GENERAL_ERROR;
  SendRequestAndWait(&org::chromium::ChapsProxyInterface::SignEncryptUpdate,
                     ToBlob(isolate_credential), session_id, data_in,
                     max_out_length, actual_out_length, data_out, &result);
  return result;
}

uint32_t ChapsProxyImpl::DecryptVerifyUpdate(
    const SecureBlob& isolate_credential,
    uint64_t session_id,
    const vector<uint8_t>& data_in,
    uint64_t max_out_length,
    uint64_t* actual_out_length,
    vector<uint8_t>* data_out) {
  LOG_CK_RV_AND_RETURN_IF(!actual_out_length || !data_out, CKR_ARGUMENTS_BAD);
  uint32_t result = CKR_GENERAL_ERROR;
  SendRequestAndWait(&org::chromium::ChapsProxyInterface::DecryptVerifyUpdate,
                     ToBlob(isolate_credential), session_id, data_in,
                     max_out_length, actual_out_length, data_out, &result);
  return result;
}

uint32_t ChapsProxyImpl::GenerateKey(const SecureBlob& isolate_credential,
                                     uint64_t session_id,
                                     uint64_t mechanism_type,
                                     const vector<uint8_t>& mechanism_parameter,
                                     const vector<uint8_t>& attributes,
                                     uint64_t* key_handle) {
  LOG_CK_RV_AND_RETURN_IF(!key_handle, CKR_ARGUMENTS_BAD);
  uint32_t result = CKR_GENERAL_ERROR;
  SendRequestAndWait(&org::chromium::ChapsProxyInterface::GenerateKey,
                     ToBlob(isolate_credential), session_id, mechanism_type,
                     mechanism_parameter, attributes, key_handle, &result);
  return result;
}

uint32_t ChapsProxyImpl::GenerateKeyPair(
    const SecureBlob& isolate_credential,
    uint64_t session_id,
    uint64_t mechanism_type,
    const vector<uint8_t>& mechanism_parameter,
    const vector<uint8_t>& public_attributes,
    const vector<uint8_t>& private_attributes,
    uint64_t* public_key_handle,
    uint64_t* private_key_handle) {
  LOG_CK_RV_AND_RETURN_IF(!public_key_handle || !private_key_handle,
                          CKR_ARGUMENTS_BAD);
  uint32_t result = CKR_GENERAL_ERROR;
  SendRequestAndWait(&org::chromium::ChapsProxyInterface::GenerateKeyPair,
                     ToBlob(isolate_credential), session_id, mechanism_type,
                     mechanism_parameter, public_attributes, private_attributes,
                     public_key_handle, private_key_handle, &result);
  return result;
}

uint32_t ChapsProxyImpl::WrapKey(const SecureBlob& isolate_credential,
                                 uint64_t session_id,
                                 uint64_t mechanism_type,
                                 const vector<uint8_t>& mechanism_parameter,
                                 uint64_t wrapping_key_handle,
                                 uint64_t key_handle,
                                 uint64_t max_out_length,
                                 uint64_t* actual_out_length,
                                 vector<uint8_t>* wrapped_key) {
  LOG_CK_RV_AND_RETURN_IF(!actual_out_length || !wrapped_key,
                          CKR_ARGUMENTS_BAD);
  uint32_t result = CKR_GENERAL_ERROR;
  SendRequestAndWait(&org::chromium::ChapsProxyInterface::WrapKey,
                     ToBlob(isolate_credential), session_id, mechanism_type,
                     mechanism_parameter, wrapping_key_handle, key_handle,
                     max_out_length, actual_out_length, wrapped_key, &result);
  return result;
}

uint32_t ChapsProxyImpl::UnwrapKey(const SecureBlob& isolate_credential,
                                   uint64_t session_id,
                                   uint64_t mechanism_type,
                                   const vector<uint8_t>& mechanism_parameter,
                                   uint64_t wrapping_key_handle,
                                   const vector<uint8_t>& wrapped_key,
                                   const vector<uint8_t>& attributes,
                                   uint64_t* key_handle) {
  LOG_CK_RV_AND_RETURN_IF(!key_handle, CKR_ARGUMENTS_BAD);
  uint32_t result = CKR_GENERAL_ERROR;
  SendRequestAndWait(&org::chromium::ChapsProxyInterface::UnwrapKey,
                     ToBlob(isolate_credential), session_id, mechanism_type,
                     mechanism_parameter, wrapping_key_handle, wrapped_key,
                     attributes, key_handle, &result);
  return result;
}

uint32_t ChapsProxyImpl::DeriveKey(const SecureBlob& isolate_credential,
                                   uint64_t session_id,
                                   uint64_t mechanism_type,
                                   const vector<uint8_t>& mechanism_parameter,
                                   uint64_t base_key_handle,
                                   const vector<uint8_t>& attributes,
                                   uint64_t* key_handle) {
  LOG_CK_RV_AND_RETURN_IF(!key_handle, CKR_ARGUMENTS_BAD);
  uint32_t result = CKR_GENERAL_ERROR;
  SendRequestAndWait(&org::chromium::ChapsProxyInterface::DeriveKey,
                     ToBlob(isolate_credential), session_id, mechanism_type,
                     mechanism_parameter, base_key_handle, attributes,
                     key_handle, &result);
  return result;
}

uint32_t ChapsProxyImpl::SeedRandom(const SecureBlob& isolate_credential,
                                    uint64_t session_id,
                                    const vector<uint8_t>& seed) {
  LOG_CK_RV_AND_RETURN_IF(seed.size() == 0, CKR_ARGUMENTS_BAD);
  uint32_t result = CKR_GENERAL_ERROR;
  SendRequestAndWait(&org::chromium::ChapsProxyInterface::SeedRandom,
                     ToBlob(isolate_credential), session_id, seed, &result);
  return result;
}

uint32_t ChapsProxyImpl::GenerateRandom(const SecureBlob& isolate_credential,
                                        uint64_t session_id,
                                        uint64_t num_bytes,
                                        vector<uint8_t>* random_data) {
  LOG_CK_RV_AND_RETURN_IF(!random_data || num_bytes == 0, CKR_ARGUMENTS_BAD);
  uint32_t result = CKR_GENERAL_ERROR;
  SendRequestAndWait(&org::chromium::ChapsProxyInterface::GenerateRandom,
                     ToBlob(isolate_credential), session_id, num_bytes,
                     random_data, &result);
  return result;
}

}  // namespace chaps
