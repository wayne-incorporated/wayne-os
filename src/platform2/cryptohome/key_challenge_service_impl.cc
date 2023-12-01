// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/key_challenge_service_impl.h"

#include <cstdint>
#include <memory>
#include <optional>
#include <utility>
#include <vector>

#include <base/check.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/time/time.h>
#include <brillo/errors/error.h>
#include <dbus/bus.h>
#include <google/protobuf/message_lite.h>

#include "cryptohome/error/location_utils.h"

using cryptohome::error::CryptohomeCryptoError;
using cryptohome::error::CryptohomeTPMError;
using cryptohome::error::ErrorActionSet;
using cryptohome::error::PossibleAction;
using cryptohome::error::PrimaryAction;
using hwsec::TPMRetryAction;
using hwsec_foundation::status::MakeStatus;
using hwsec_foundation::status::OkStatus;
using hwsec_foundation::status::StatusChain;

namespace cryptohome {

namespace {

// This is currently equal to the timeout used by the Chrome when making
// MountEx/CheckKeyEx calls to cryptohomed. (These timeouts are not technically
// required to be equal, but it's good from the UX perspective).
constexpr base::TimeDelta kDbusCallTimeout = base::Minutes(2);

// Used for holding OnceCallback when multiple callback function needs it, but
// only one of them will run. Note: This is not thread safe.
template <typename T>
class OnceCallbackHolder {
 public:
  explicit OnceCallbackHolder(T obj) : obj_(std::move(obj)) {}

  T get() {
    DCHECK(obj_.has_value());
    std::optional<T> res;
    std::swap(res, obj_);
    return std::move(res.value());
  }

 private:
  // The object that we are holding
  std::optional<T> obj_;
};

std::vector<uint8_t> SerializeProto(
    const google::protobuf::MessageLite& proto) {
  std::vector<uint8_t> serialized_proto(proto.ByteSizeLong());
  CHECK(
      proto.SerializeToArray(serialized_proto.data(), serialized_proto.size()));
  return serialized_proto;
}

bool DeserializeProto(const std::vector<uint8_t>& raw_buf,
                      google::protobuf::MessageLite* proto) {
  return proto->ParseFromArray(raw_buf.data(), raw_buf.size());
}

void OnDBusChallengeKeySuccess(
    std::shared_ptr<OnceCallbackHolder<KeyChallengeService::ResponseCallback>>
        callback_holder,
    const std::vector<uint8_t>& challenge_response) {
  KeyChallengeService::ResponseCallback original_callback =
      callback_holder->get();
  if (challenge_response.empty()) {
    // TODO(crbug.com/1046860): Remove the logging after stabilizing the
    // feature.
    LOG(INFO) << "Signature key challenge failed: empty response";
    std::move(original_callback)
        .Run(MakeStatus<CryptohomeCryptoError>(
            CRYPTOHOME_ERR_LOC(
                kLocKeyChallengeServiceEmptyResponseInChallengeKey),
            ErrorActionSet({PossibleAction::kDevCheckUnexpectedState,
                            PossibleAction::kReboot}),
            CryptoError::CE_OTHER_FATAL));
    return;
  }
  auto response_proto = std::make_unique<KeyChallengeResponse>();
  if (!DeserializeProto(challenge_response, response_proto.get())) {
    LOG(ERROR)
        << "Failed to parse KeyChallengeResponse from ChallengeKey D-Bus call";
    std::move(original_callback)
        .Run(MakeStatus<CryptohomeCryptoError>(
            CRYPTOHOME_ERR_LOC(
                kLocKeyChallengeServiceParseFailedInChallengeKey),
            ErrorActionSet({PossibleAction::kDevCheckUnexpectedState}),
            CryptoError::CE_OTHER_FATAL));
    return;
  }
  // TODO(crbug.com/1046860): Remove the logging after stabilizing the feature.
  if (response_proto->has_signature_response_data()) {
    LOG(INFO) << "Signature key challenge succeeded: signature size "
              << response_proto->signature_response_data().signature().size();
  } else {
    LOG(INFO) << "Key challenge completed with no signature";
  }
  std::move(original_callback).Run(std::move(response_proto));
}

void OnDBusChallengeKeyFailure(
    std::shared_ptr<OnceCallbackHolder<KeyChallengeService::ResponseCallback>>
        callback_holder,
    brillo::Error* error) {
  // TODO(crbug.com/1046860): Remove the logging after stabilizing the feature.
  CryptoStatus status;
  if (error) {
    LOG(INFO) << "Signature key challenge failed: dbus error code "
              << error->GetCode() << ", message " << error->GetMessage();
    // TODO(b/230326115): Distinguish between user cancellation and actual
    // error.
    status = MakeStatus<CryptohomeCryptoError>(
        CRYPTOHOME_ERR_LOC(kLocKeyChallengeServiceKnownDBusErrorInChallengeKey),
        ErrorActionSet(PrimaryAction::kIncorrectAuth),
        CryptoError::CE_OTHER_CRYPTO);
  } else {
    LOG(INFO) << "Key challenge failed: unknown dbus error";
    status = MakeStatus<CryptohomeCryptoError>(
        CRYPTOHOME_ERR_LOC(
            kLocKeyChallengeServiceUnknownDBusErrorInChallengeKey),
        ErrorActionSet({PossibleAction::kDevCheckUnexpectedState,
                        PossibleAction::kReboot}),
        CryptoError::CE_OTHER_FATAL);
  }
  KeyChallengeService::ResponseCallback original_callback =
      callback_holder->get();
  std::move(original_callback).Run(std::move(status));
}

void OnDBusFidoMakeCredentialSuccess(
    std::shared_ptr<OnceCallbackHolder<
        KeyChallengeService::MakeCredentialCallback>> callback_holder,
    const std::vector<uint8_t>& make_credential_response) {
  KeyChallengeService::MakeCredentialCallback original_callback =
      callback_holder->get();

  if (make_credential_response.empty()) {
    std::move(original_callback).Run(nullptr /* response */);
    return;
  }
  auto response =
      std::make_unique<cryptohome::fido::MakeCredentialAuthenticatorResponse>();
  if (!DeserializeProto(make_credential_response, response.get())) {
    LOG(ERROR) << "Failed to parse MakeCredentialAuthenticatorResponse from "
               << "FidoMakeCredential D-Bus call";
    return;
  }
  std::move(original_callback).Run(std::move(response));
}

void OnDBusFidoMakeCredentialFailure(
    std::shared_ptr<OnceCallbackHolder<
        KeyChallengeService::MakeCredentialCallback>> callback_holder,
    brillo::Error* error) {
  LOG(ERROR) << error->GetMessage();
  KeyChallengeService::MakeCredentialCallback original_callback =
      callback_holder->get();
  std::move(original_callback).Run(nullptr /* response */);
}

void OnDBusFidoGetAssertionSuccess(
    std::shared_ptr<OnceCallbackHolder<
        KeyChallengeService::GetAssertionCallback>> callback_holder,
    const std::vector<uint8_t>& get_assertion_response) {
  KeyChallengeService::GetAssertionCallback original_callback =
      callback_holder->get();

  if (get_assertion_response.empty()) {
    std::move(original_callback).Run(nullptr /* response */);
    return;
  }

  auto response =
      std::make_unique<cryptohome::fido::GetAssertionAuthenticatorResponse>();
  if (!DeserializeProto(get_assertion_response, response.get())) {
    LOG(ERROR) << "Failed to parse GetAssertionAuthenticatorResponse from "
               << "FidoGetAssertion D-Bus call";
    return;
  }
  std::move(original_callback).Run(std::move(response));
}

void OnDBusFidoGetAssertionFailure(
    std::shared_ptr<OnceCallbackHolder<
        KeyChallengeService::GetAssertionCallback>> callback_holder,
    brillo::Error* error) {
  LOG(ERROR) << error->GetMessage();
  KeyChallengeService::GetAssertionCallback original_callback =
      callback_holder->get();
  std::move(original_callback).Run(nullptr /* response */);
}

}  // namespace

KeyChallengeServiceImpl::KeyChallengeServiceImpl(
    scoped_refptr<dbus::Bus> dbus_bus,
    const std::string& key_delegate_dbus_service_name)
    : key_delegate_dbus_service_name_(key_delegate_dbus_service_name),
      dbus_proxy_(dbus_bus, key_delegate_dbus_service_name_) {
  DCHECK(dbus_bus);
  DCHECK(!key_delegate_dbus_service_name_.empty());
}

KeyChallengeServiceImpl::~KeyChallengeServiceImpl() = default;

void KeyChallengeServiceImpl::ChallengeKey(
    const AccountIdentifier& account_id,
    const KeyChallengeRequest& key_challenge_request,
    ResponseCallback response_callback) {
  if (!dbus_validate_bus_name(key_delegate_dbus_service_name_.c_str(),
                              nullptr /* error */)) {
    // Bail out to avoid crashing inside the D-Bus library.
    // TODO(emaxx): Remove this special handling once libchrome is uprev'ed to
    // include the fix from crbug.com/927196.
    LOG(ERROR) << "Invalid key challenge service name "
               << key_delegate_dbus_service_name_;
    std::move(response_callback)
        .Run(MakeStatus<CryptohomeCryptoError>(
            CRYPTOHOME_ERR_LOC(
                kLocKeyChallengeServiceInvalidDBusNameInChallengeKey),
            ErrorActionSet({PossibleAction::kDevCheckUnexpectedState}),
            CryptoError::CE_OTHER_FATAL));
    return;
  }
  std::shared_ptr<OnceCallbackHolder<ResponseCallback>> callback_holder(
      new OnceCallbackHolder<ResponseCallback>(std::move(response_callback)));
  // TODO(crbug.com/1046860): Remove the logging after stabilizing the feature.
  if (key_challenge_request.has_signature_request_data()) {
    LOG(INFO)
        << "Starting signature key challenge request, size "
        << key_challenge_request.signature_request_data().data_to_sign().size()
        << ", spki size "
        << key_challenge_request.signature_request_data()
               .public_key_spki_der()
               .size()
        << ", algorithm "
        << key_challenge_request.signature_request_data().signature_algorithm();
  }
  dbus_proxy_.ChallengeKeyAsync(
      SerializeProto(account_id), SerializeProto(key_challenge_request),
      base::BindOnce(&OnDBusChallengeKeySuccess, callback_holder),
      base::BindOnce(&OnDBusChallengeKeyFailure, callback_holder),
      /*timeout_ms=*/kDbusCallTimeout.InMilliseconds());
}

void KeyChallengeServiceImpl::FidoMakeCredential(
    const std::string& client_data_json,
    const cryptohome::fido::PublicKeyCredentialCreationOptions& request,
    MakeCredentialCallback response_callback) {
  if (!dbus_validate_bus_name(key_delegate_dbus_service_name_.c_str(),
                              nullptr /* error */)) {
    LOG(ERROR) << "Invalid key challenge service name "
               << key_delegate_dbus_service_name_;
    std::move(response_callback).Run(nullptr /* response */);
    return;
  }

  std::shared_ptr<OnceCallbackHolder<MakeCredentialCallback>> callback_holder(
      new OnceCallbackHolder<MakeCredentialCallback>(
          std::move(response_callback)));
  dbus_proxy_.FidoMakeCredentialAsync(
      client_data_json, SerializeProto(request),
      base::BindOnce(&OnDBusFidoMakeCredentialSuccess, callback_holder),
      base::BindOnce(&OnDBusFidoMakeCredentialFailure, callback_holder));
}

void KeyChallengeServiceImpl::FidoGetAssertion(
    const std::string& client_data_json,
    const cryptohome::fido::PublicKeyCredentialRequestOptions& request,
    GetAssertionCallback response_callback) {
  if (!dbus_validate_bus_name(key_delegate_dbus_service_name_.c_str(),
                              nullptr)) {
    LOG(ERROR) << "Invalid key challenge service name "
               << key_delegate_dbus_service_name_;
    std::move(response_callback).Run(nullptr /* response */);
    return;
  }

  std::shared_ptr<OnceCallbackHolder<GetAssertionCallback>> callback_holder(
      new OnceCallbackHolder<GetAssertionCallback>(
          std::move(response_callback)));
  dbus_proxy_.FidoGetAssertionAsync(
      client_data_json, SerializeProto(request),
      base::BindOnce(&OnDBusFidoGetAssertionSuccess, callback_holder),
      base::BindOnce(&OnDBusFidoGetAssertionFailure, callback_holder));
}

}  // namespace cryptohome
