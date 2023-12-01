// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "u2fd/webauthn_handler.h"

#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <base/check.h>
#include <base/check_op.h>
#include <base/functional/callback_helpers.h>
#include <base/logging.h>
#include <base/notreached.h>
#include <base/time/time.h>
#include <chromeos/cbor/values.h>
#include <chromeos/cbor/writer.h>
#include <chromeos/dbus/service_constants.h>
#include <cryptohome/proto_bindings/UserDataAuth.pb.h>
#include <cryptohome/proto_bindings/auth_factor.pb.h>
#include <openssl/rand.h>
#include <u2f/proto_bindings/u2f_interface.pb.h>

#include "u2fd/client/util.h"
#include "u2fd/u2f_command_processor.h"

namespace u2f {

namespace {

// User a big timeout for cryptohome. See b/172945202.
constexpr base::TimeDelta kCryptohomeTimeout = base::Minutes(2);

constexpr int kCancelUVFlowTimeoutMs = 5000;

constexpr char kAttestationFormatNone[] = "none";
// \xa0 is empty map in CBOR
constexpr char kAttestationStatementNone = '\xa0';
constexpr char kAttestationFormatU2f[] = "fido-u2f";
// Keys for attestation statement CBOR map.
constexpr char kSignatureKey[] = "sig";
constexpr char kX509CertKey[] = "x5c";

// The AAGUID for none-attestation (for platform-authenticator). For u2f/g2f
// attestation, empty AAGUID should be used.
const std::vector<uint8_t> kAaguid = {0x84, 0x03, 0x98, 0x77, 0xa5, 0x4b,
                                      0xdf, 0xbb, 0x04, 0xa8, 0x2d, 0xf2,
                                      0xfa, 0x2a, 0x11, 0x6e};

// AuthenticatorData flags are defined in
// https://www.w3.org/TR/webauthn-2/#sctn-authenticator-data
enum class AuthenticatorDataFlag : uint8_t {
  kTestOfUserPresence = 1u << 0,
  kTestOfUserVerification = 1u << 2,
  kAttestedCredentialData = 1u << 6,
  kExtensionDataIncluded = 1u << 7,
};

// Relative DBus object path for fingerprint manager in biod.
const char kCrosFpBiometricsManagerRelativePath[] = "/CrosFpBiometricsManager";

std::vector<uint8_t> Uint16ToByteVector(uint16_t value) {
  return std::vector<uint8_t>({static_cast<uint8_t>((value >> 8) & 0xff),
                               static_cast<uint8_t>(value & 0xff)});
}

void AppendToString(const std::vector<uint8_t>& vect, std::string* str) {
  str->append(reinterpret_cast<const char*>(vect.data()), vect.size());
}

void AppendAttestedCredential(const std::vector<uint8_t>& credential_id,
                              const std::vector<uint8_t>& credential_public_key,
                              std::vector<uint8_t>* authenticator_data) {
  util::AppendToVector(credential_id, authenticator_data);
  util::AppendToVector(credential_public_key, authenticator_data);
}

// Returns the current time in seconds since epoch as a privacy-preserving
// signature counter. Because of the conversion to a 32-bit unsigned integer,
// the counter will overflow in the year 2108.
std::vector<uint8_t> GetTimestampSignatureCounter() {
  uint32_t sign_counter = static_cast<uint32_t>(base::Time::Now().ToDoubleT());
  return std::vector<uint8_t>{
      static_cast<uint8_t>((sign_counter >> 24) & 0xff),
      static_cast<uint8_t>((sign_counter >> 16) & 0xff),
      static_cast<uint8_t>((sign_counter >> 8) & 0xff),
      static_cast<uint8_t>(sign_counter & 0xff),
  };
}

std::vector<uint8_t> EncodeU2fAttestationStatementInCBOR(
    const std::vector<uint8_t>& signature, const std::vector<uint8_t>& cert) {
  cbor::Value::MapValue attestation_statement_map;
  attestation_statement_map[cbor::Value(kSignatureKey)] =
      cbor::Value(signature);
  // The "x5c" field is an array of just one cert.
  std::vector<cbor::Value> certificate_array;
  certificate_array.push_back(cbor::Value(cert));
  attestation_statement_map[cbor::Value(kX509CertKey)] =
      cbor::Value(std::move(certificate_array));
  return *cbor::Writer::Write(
      cbor::Value(std::move(attestation_statement_map)));
}

}  // namespace

WebAuthnHandler::WebAuthnHandler()
    : user_state_(nullptr),
      webauthn_storage_(std::make_unique<WebAuthnStorage>()),
      u2f_command_processor_(std::unique_ptr<U2fCommandProcessor>()) {}

WebAuthnHandler::~WebAuthnHandler() {}

void WebAuthnHandler::Initialize(
    dbus::Bus* bus,
    UserState* user_state,
    U2fMode u2f_mode,
    std::unique_ptr<U2fCommandProcessor> u2f_command_processor,
    std::unique_ptr<AllowlistingUtil> allowlisting_util,
    MetricsLibraryInterface* metrics) {
  if (Initialized()) {
    VLOG(1) << "WebAuthn handler already initialized, doing nothing.";
    return;
  }

  metrics_ = metrics;
  user_state_ = user_state;
  user_state_->SetSessionStartedCallback(base::BindRepeating(
      &WebAuthnHandler::OnSessionStarted, base::Unretained(this)));
  user_state_->SetSessionStoppedCallback(base::BindRepeating(
      &WebAuthnHandler::OnSessionStopped, base::Unretained(this)));
  u2f_mode_ = u2f_mode;
  allowlisting_util_ = std::move(allowlisting_util);
  bus_ = bus;
  auth_dialog_dbus_proxy_ = bus_->GetObjectProxy(
      chromeos::kUserAuthenticationServiceName,
      dbus::ObjectPath(chromeos::kUserAuthenticationServicePath));
  // Testing can inject a mock.
  if (!cryptohome_proxy_)
    cryptohome_proxy_ =
        std::make_unique<org::chromium::UserDataAuthInterfaceProxy>(bus_);
  DCHECK(auth_dialog_dbus_proxy_);

  u2f_command_processor_ = std::move(u2f_command_processor);

  if (user_state_->HasUser()) {
    // WebAuthnHandler should normally initialize on boot, before any user has
    // logged in. If there's already a user, then we have crashed during a user
    // session, so catch up on the state.
    std::optional<std::string> user = user_state_->GetUser();
    DCHECK(user);
    OnSessionStarted(*user);
  }
}

bool WebAuthnHandler::Initialized() {
  return u2f_command_processor_ && user_state_;
}

bool WebAuthnHandler::AllowPresenceMode() {
  return u2f_mode_ == U2fMode::kU2f || u2f_mode_ == U2fMode::kU2fExtended;
}

void WebAuthnHandler::OnSessionStarted(const std::string& account_id) {
  // Do this first because there's a timeout for reading the secret.
  GetWebAuthnSecretHashAsync(account_id);

  webauthn_storage_->set_allow_access(true);
  std::optional<std::string> sanitized_user = user_state_->GetSanitizedUser();
  DCHECK(sanitized_user);
  webauthn_storage_->set_sanitized_user(*sanitized_user);

  if (!webauthn_storage_->LoadRecords()) {
    LOG(ERROR) << "Did not load all records for user " << *sanitized_user;
    return;
  }
  webauthn_storage_->SendRecordCountToUMA(metrics_);
}

void WebAuthnHandler::OnSessionStopped() {
  auth_time_secret_hash_.reset();
  webauthn_storage_->Reset();
}

void WebAuthnHandler::GetWebAuthnSecretHashAsync(
    const std::string& account_id) {
  user_data_auth::GetWebAuthnSecretHashRequest request;
  request.mutable_account_id()->set_account_id(account_id);

  cryptohome_proxy_->GetWebAuthnSecretHashAsync(
      request,
      base::BindOnce(&WebAuthnHandler::OnGetWebAuthnSecretHashResp,
                     base::Unretained(this)),
      base::BindOnce(&WebAuthnHandler::OnGetWebAuthnSecretHashCallFailed,
                     base::Unretained(this)),
      kCryptohomeTimeout.InMilliseconds());
}

void WebAuthnHandler::OnGetWebAuthnSecretHashCallFailed(brillo::Error* error) {
  LOG(ERROR) << "Failed to call GetWebAuthnSecretHash on cryptohome, error: "
             << error->GetMessage();
}

void WebAuthnHandler::OnGetWebAuthnSecretHashResp(
    const user_data_auth::GetWebAuthnSecretHashReply& reply) {
  if (reply.error() !=
      user_data_auth::CryptohomeErrorCode::CRYPTOHOME_ERROR_NOT_SET) {
    LOG(ERROR) << "GetWebAuthnSecretHash reply has error " << reply.error();
    return;
  }

  brillo::Blob secret_hash =
      brillo::BlobFromString(reply.webauthn_secret_hash());
  if (secret_hash.size() != SHA256_DIGEST_LENGTH) {
    LOG(ERROR) << "WebAuthn auth time secret hash size is wrong.";
    return;
  }

  auth_time_secret_hash_ =
      std::make_unique<brillo::Blob>(std::move(secret_hash));
}

void WebAuthnHandler::MakeCredential(
    std::unique_ptr<MakeCredentialMethodResponse> method_response,
    const MakeCredentialRequest& request) {
  MakeCredentialResponse response;
  VLOG(1) << "Received a MakeCredential request.";

  if (!Initialized()) {
    LOG(WARNING) << "MakeCredential: WebAuthnHandler not initialized.";
    response.set_status(MakeCredentialResponse::INTERNAL_ERROR);
    method_response->Return(response);
    return;
  }

  if (pending_uv_make_credential_session_ ||
      pending_uv_get_assertion_session_) {
    LOG(WARNING) << "MakeCredential: There is a pending session.";
    response.set_status(MakeCredentialResponse::REQUEST_PENDING);
    method_response->Return(response);
    return;
  }

  if (request.rp_id().empty()) {
    LOG(ERROR) << "MakeCredential: Invalid request format: no rp_id.";
    response.set_status(MakeCredentialResponse::INVALID_REQUEST);
    method_response->Return(response);
    return;
  }

  if (request.verification_type() == VerificationType::VERIFICATION_UNKNOWN) {
    LOG(ERROR) << "MakeCredential: Unknown verification type.";
    response.set_status(MakeCredentialResponse::VERIFICATION_FAILED);
    method_response->Return(response);
    return;
  }

  struct MakeCredentialSession session = {
      static_cast<uint64_t>(base::Time::Now().ToTimeT()), request,
      std::move(method_response)};

  if (!AllowPresenceMode()) {
    // Upgrade UP requests to UV.
    session.request.set_verification_type(
        VerificationType::VERIFICATION_USER_VERIFICATION);
  }

  if (session.request.verification_type() ==
      VerificationType::VERIFICATION_USER_VERIFICATION) {
    dbus::MethodCall call(
        chromeos::kUserAuthenticationServiceInterface,
        chromeos::kUserAuthenticationServiceShowAuthDialogV2Method);
    dbus::MessageWriter writer(&call);
    writer.AppendString(session.request.rp_id());
    writer.AppendInt32(session.request.verification_type());
    writer.AppendString(session.request.request_id_str());

    pending_uv_make_credential_session_ = std::move(session);
    auth_dialog_dbus_proxy_->CallMethod(
        &call, dbus::ObjectProxy::TIMEOUT_INFINITE,
        base::BindOnce(&WebAuthnHandler::HandleUVFlowResultMakeCredential,
                       base::Unretained(this)));
    return;
  }

  DoMakeCredential(std::move(session), PresenceRequirement::kPowerButton);
}

CancelWebAuthnFlowResponse WebAuthnHandler::Cancel(
    const CancelWebAuthnFlowRequest& request) {
  CancelWebAuthnFlowResponse response;
  if (!pending_uv_make_credential_session_ &&
      !pending_uv_get_assertion_session_) {
    VLOG(1) << "No pending session to cancel.";
    response.set_canceled(false);
    return response;
  }

  if (pending_uv_make_credential_session_) {
    if (pending_uv_make_credential_session_->request.request_id_str() !=
        request.request_id_str()) {
      LOG(ERROR) << "MakeCredential session has a different request_id, not "
                    "cancelling.";
      response.set_canceled(false);
      return response;
    }
  }

  if (pending_uv_get_assertion_session_) {
    if (pending_uv_get_assertion_session_->request.request_id_str() !=
        request.request_id_str()) {
      LOG(ERROR) << "GetAssertion session has a different request_id, not "
                    "cancelling.";
      response.set_canceled(false);
      return response;
    }
  }

  dbus::MethodCall call(chromeos::kUserAuthenticationServiceInterface,
                        chromeos::kUserAuthenticationServiceCancelMethod);
  std::unique_ptr<dbus::Response> cancel_ui_resp =
      auth_dialog_dbus_proxy_->CallMethodAndBlock(&call,
                                                  kCancelUVFlowTimeoutMs);

  if (!cancel_ui_resp) {
    LOG(ERROR) << "Failed to dismiss WebAuthn user verification UI.";
    response.set_canceled(false);
    return response;
  }

  // We do not reset |pending_uv_make_credential_session_| or
  // |pending_uv_get_assertion_session_| here because UI will still respond
  // to the cancelled request through these, though the response will be
  // ignored by Chrome.
  if (pending_uv_make_credential_session_) {
    pending_uv_make_credential_session_->canceled = true;
  } else {
    pending_uv_get_assertion_session_->canceled = true;
  }
  response.set_canceled(true);
  return response;
}

void WebAuthnHandler::HandleUVFlowResultMakeCredential(
    dbus::Response* flow_response) {
  MakeCredentialResponse response;

  DCHECK(pending_uv_make_credential_session_);

  if (!flow_response) {
    LOG(ERROR) << "User auth flow had no response.";
    response.set_status(MakeCredentialResponse::INTERNAL_ERROR);
    pending_uv_make_credential_session_->response->Return(response);
    pending_uv_make_credential_session_.reset();
    return;
  }

  dbus::MessageReader response_reader(flow_response);
  bool success;
  if (!response_reader.PopBool(&success)) {
    LOG(ERROR) << "Failed to parse user auth flow result.";
    response.set_status(MakeCredentialResponse::INTERNAL_ERROR);
    pending_uv_make_credential_session_->response->Return(response);
    pending_uv_make_credential_session_.reset();
    return;
  }

  if (!success) {
    if (pending_uv_make_credential_session_->canceled) {
      VLOG(1) << "WebAuthn MakeCredential operation canceled.";
      response.set_status(MakeCredentialResponse::CANCELED);
    } else {
      LOG(ERROR) << "User auth flow failed. Aborting MakeCredential.";
      response.set_status(MakeCredentialResponse::VERIFICATION_FAILED);
    }
    pending_uv_make_credential_session_->response->Return(response);
    pending_uv_make_credential_session_.reset();
    return;
  }

  DoMakeCredential(std::move(*pending_uv_make_credential_session_),
                   PresenceRequirement::kNone);
  pending_uv_make_credential_session_.reset();
}

void WebAuthnHandler::HandleUVFlowResultGetAssertion(
    dbus::Response* flow_response) {
  GetAssertionResponse response;

  DCHECK(pending_uv_get_assertion_session_);

  if (!flow_response) {
    LOG(ERROR) << "User auth flow had no response.";
    response.set_status(GetAssertionResponse::INTERNAL_ERROR);
    pending_uv_get_assertion_session_->response->Return(response);
    pending_uv_get_assertion_session_.reset();
    return;
  }

  dbus::MessageReader response_reader(flow_response);
  bool success;
  if (!response_reader.PopBool(&success)) {
    LOG(ERROR) << "Failed to parse user auth flow result.";
    response.set_status(GetAssertionResponse::INTERNAL_ERROR);
    pending_uv_get_assertion_session_->response->Return(response);
    pending_uv_get_assertion_session_.reset();
    return;
  }

  if (!success) {
    if (pending_uv_get_assertion_session_->canceled) {
      VLOG(1) << "WebAuthn GetAssertion operation canceled.";
      response.set_status(GetAssertionResponse::CANCELED);
    } else {
      LOG(ERROR) << "User auth flow failed. Aborting GetAssertion.";
      response.set_status(GetAssertionResponse::VERIFICATION_FAILED);
    }
    pending_uv_get_assertion_session_->response->Return(response);
    pending_uv_get_assertion_session_.reset();
    return;
  }

  DoGetAssertion(std::move(*pending_uv_get_assertion_session_),
                 PresenceRequirement::kAuthorizationSecret);
  pending_uv_get_assertion_session_.reset();
}

void WebAuthnHandler::DoMakeCredential(
    struct MakeCredentialSession session,
    PresenceRequirement presence_requirement) {
  MakeCredentialResponse response;
  const std::vector<uint8_t> rp_id_hash = util::Sha256(session.request.rp_id());
  std::vector<uint8_t> credential_id;
  CredentialPublicKey credential_public_key;
  std::vector<uint8_t> credential_key_blob;

  // If we are in u2f or g2f mode, and the request says it wants presence only,
  // make a non-versioned (i.e. non-uv-compatible) credential.
  bool uv_compatible = !(AllowPresenceMode() &&
                         session.request.verification_type() ==
                             VerificationType::VERIFICATION_USER_PRESENCE);

  brillo::SecureBlob credential_secret(kCredentialSecretSize);
  if (uv_compatible) {
    if (RAND_bytes(credential_secret.data(), credential_secret.size()) != 1) {
      LOG(ERROR)
          << "MakeCredential: Failed to generate secret for new credential.";
      response.set_status(MakeCredentialResponse::INTERNAL_ERROR);
      session.response->Return(response);
      return;
    }
  } else {
    // We are creating a credential that can only be signed with power button
    // press, and can be signed by u2f/g2f, so we must use the legacy secret.
    std::optional<brillo::SecureBlob> legacy_secret =
        user_state_->GetUserSecret();
    if (!legacy_secret) {
      LOG(ERROR) << "MakeCredential: Cannot find user secret when trying to "
                    "create u2f/g2f credential.";
      response.set_status(MakeCredentialResponse::INTERNAL_ERROR);
      session.response->Return(response);
      return;
    }
    credential_secret = std::move(*legacy_secret);
  }

  MakeCredentialResponse::MakeCredentialStatus generate_status =
      u2f_command_processor_->U2fGenerate(
          rp_id_hash, credential_secret, presence_requirement, uv_compatible,
          auth_time_secret_hash_.get(), &credential_id, &credential_public_key,
          &credential_key_blob);

  if (generate_status != MakeCredentialResponse::SUCCESS) {
    LOG(ERROR) << "MakeCredential: U2fGenerate failed with status "
               << static_cast<int>(generate_status) << ".";
    response.set_status(generate_status);
    session.response->Return(response);
    return;
  }

  if (credential_id.empty() || credential_public_key.cbor.empty()) {
    LOG(ERROR) << "MakeCredential: Returned credential is empty.";
    response.set_status(MakeCredentialResponse::INTERNAL_ERROR);
    session.response->Return(response);
    return;
  }

  auto ret = HasExcludedCredentials(session.request);
  if (ret == HasCredentialsResponse::INTERNAL_ERROR) {
    LOG(ERROR) << "MakeCredential: HasExcludedCredentials failed with an "
                  "internal error.";
    response.set_status(MakeCredentialResponse::INTERNAL_ERROR);
    session.response->Return(response);
    return;
  } else if (ret == HasCredentialsResponse::SUCCESS) {
    LOG(ERROR) << "MakeCredential: Credential is excluded in the request.";
    response.set_status(MakeCredentialResponse::EXCLUDED_CREDENTIAL_ID);
    session.response->Return(response);
    return;
  }

  const std::optional<std::vector<uint8_t>> authenticator_data =
      MakeAuthenticatorData(
          rp_id_hash, credential_id, credential_public_key.cbor,
          /* user_verified = */ session.request.verification_type() ==
              VerificationType::VERIFICATION_USER_VERIFICATION,
          /* include_attested_credential_data = */ true,
          /* is_u2f_authenticator_credential = */ !uv_compatible);
  if (!authenticator_data) {
    LOG(ERROR) << "MakeCredential: MakeAuthenticatorData failed";
    response.set_status(MakeCredentialResponse::INTERNAL_ERROR);
    session.response->Return(response);
    return;
  }
  AppendToString(*authenticator_data, response.mutable_authenticator_data());

  // If a credential is not UV-compatible, it is a legacy U2F/G2F credential
  // and should come with U2F/G2F attestation for backward compatibility.
  if (uv_compatible) {
    AppendNoneAttestation(&response);
  } else {
    if (credential_public_key.raw.empty()) {
      LOG(ERROR) << "MakeCredential: Authenticator doesn't support FIDO U2F "
                    "attestation statement format.";
      response.set_status(MakeCredentialResponse::INTERNAL_ERROR);
      session.response->Return(response);
      return;
    }
    std::optional<std::vector<uint8_t>> attestation_statement =
        MakeFidoU2fAttestationStatement(
            rp_id_hash, util::ToVector(session.request.client_data_hash()),
            credential_public_key.raw, credential_id,
            session.request.attestation_conveyance_preference());
    if (!attestation_statement) {
      LOG(ERROR)
          << "MakeCredential: Failed to make FIDO attestation statement.";
      response.set_status(MakeCredentialResponse::INTERNAL_ERROR);
      session.response->Return(response);
      return;
    }
    response.set_attestation_format(kAttestationFormatU2f);
    AppendToString(*attestation_statement,
                   response.mutable_attestation_statement());
  }

  // u2f/g2f credentials should not be written to record.
  if (uv_compatible) {
    // All steps succeeded, so write to record.
    WebAuthnRecord record;
    AppendToString(credential_id, &record.credential_id);
    // Because the credential secret is more like a salt in the protocol
    // and loading too much secure blob might cause RLIMIT_MEMLOCK, the
    // underlying storage class use blob to handle it. Logically it's still
    // a secret so we don't want to change interfaces elsewhere to take a blob,
    // instead just perform the conversion here.
    record.secret =
        brillo::Blob(credential_secret.begin(), credential_secret.end());
    record.key_blob = std::move(credential_key_blob);
    record.rp_id = session.request.rp_id();
    record.rp_display_name = session.request.rp_display_name();
    record.user_id = session.request.user_id();
    record.user_display_name = session.request.user_display_name();
    record.timestamp = base::Time::Now().ToDoubleT();
    record.is_resident_key = session.request.resident_key_required();
    if (!webauthn_storage_->WriteRecord(std::move(record))) {
      LOG(ERROR)
          << "MakeCredential: Failed to write record into WebAuthn storage.";
      response.set_status(MakeCredentialResponse::INTERNAL_ERROR);
      session.response->Return(response);
      return;
    }
  }

  VLOG(1) << "Finished processing MakeCredential request.";
  response.set_status(MakeCredentialResponse::SUCCESS);
  session.response->Return(response);
}

// AuthenticatorData layout:
// (See https://www.w3.org/TR/webauthn-2/#table-authData)
// -----------------------------------------------------------------------
// | RP ID hash:       32 bytes
// | Flags:             1 byte
// | Signature counter: 4 bytes
// |                           -------------------------------------------
// |                           | AAGUID:                  16 bytes
// | Attested Credential Data: | Credential ID length (L): 2 bytes
// | (if present)              | Credential ID:            L bytes
// |                           | Credential public key:    variable length
std::optional<std::vector<uint8_t>> WebAuthnHandler::MakeAuthenticatorData(
    const std::vector<uint8_t>& rp_id_hash,
    const std::vector<uint8_t>& credential_id,
    const std::vector<uint8_t>& credential_public_key,
    bool user_verified,
    bool include_attested_credential_data,
    bool is_u2f_authenticator_credential) {
  std::vector<uint8_t> authenticator_data(rp_id_hash);
  uint8_t flags =
      static_cast<uint8_t>(AuthenticatorDataFlag::kTestOfUserPresence);
  if (user_verified)
    flags |=
        static_cast<uint8_t>(AuthenticatorDataFlag::kTestOfUserVerification);
  if (include_attested_credential_data)
    flags |=
        static_cast<uint8_t>(AuthenticatorDataFlag::kAttestedCredentialData);
  authenticator_data.emplace_back(flags);

  // The U2F authenticator keeps a user-global signature counter in UserState.
  // For platform authenticator credentials, we derive a counter from a
  // timestamp instead.
  if (is_u2f_authenticator_credential) {
    std::optional<std::vector<uint8_t>> counter = user_state_->GetCounter();
    if (!counter || !user_state_->IncrementCounter()) {
      // UserState logs an error in this case.
      return std::nullopt;
    }
    util::AppendToVector(*counter, &authenticator_data);
  } else {
    util::AppendToVector(GetTimestampSignatureCounter(), &authenticator_data);
  }

  if (include_attested_credential_data) {
    util::AppendToVector(is_u2f_authenticator_credential
                             ? std::vector<uint8_t>(kAaguid.size(), 0)
                             : kAaguid,
                         &authenticator_data);
    uint16_t length = credential_id.size();
    util::AppendToVector(Uint16ToByteVector(length), &authenticator_data);

    AppendAttestedCredential(credential_id, credential_public_key,
                             &authenticator_data);
  }

  return authenticator_data;
}

void WebAuthnHandler::AppendNoneAttestation(MakeCredentialResponse* response) {
  response->set_attestation_format(kAttestationFormatNone);
  response->mutable_attestation_statement()->push_back(
      kAttestationStatementNone);
}

std::optional<std::vector<uint8_t>>
WebAuthnHandler::MakeFidoU2fAttestationStatement(
    const std::vector<uint8_t>& app_id,
    const std::vector<uint8_t>& challenge,
    const std::vector<uint8_t>& pub_key,
    const std::vector<uint8_t>& key_handle,
    const MakeCredentialRequest::AttestationConveyancePreference
        attestation_conveyance_preference) {
  std::vector<uint8_t> attestation_cert;
  std::vector<uint8_t> signature;
  if (attestation_conveyance_preference == MakeCredentialRequest::G2F &&
      u2f_mode_ == U2fMode::kU2fExtended) {
    std::optional<brillo::SecureBlob> user_secret =
        user_state_->GetUserSecret();
    if (!user_secret.has_value()) {
      LOG(ERROR) << "No user secret.";
      return std::nullopt;
    }

    MakeCredentialResponse::MakeCredentialStatus attest_status =
        u2f_command_processor_->G2fAttest(app_id, *user_secret, challenge,
                                          pub_key, key_handle,
                                          &attestation_cert, &signature);

    if (attest_status != MakeCredentialResponse::SUCCESS) {
      LOG(ERROR) << "Failed to do G2f attestation for MakeCredential";
      return std::nullopt;
    }

    if (allowlisting_util_ != nullptr &&
        !allowlisting_util_->AppendDataToCert(&attestation_cert)) {
      LOG(ERROR) << "Failed to get allowlisting data for G2F Enroll Request";
      return std::nullopt;
    }
  } else {
    if (!u2f_command_processor_->G2fSoftwareAttest(
            app_id, challenge, pub_key, key_handle, &attestation_cert,
            &signature)) {
      LOG(ERROR) << "Failed to do software attestation for MakeCredential";
      return std::nullopt;
    }
  }

  return EncodeU2fAttestationStatementInCBOR(signature, attestation_cert);
}

HasCredentialsResponse::HasCredentialsStatus
WebAuthnHandler::HasExcludedCredentials(const MakeCredentialRequest& request) {
  MatchedCredentials matched =
      FindMatchedCredentials(request.excluded_credential_id(), request.rp_id(),
                             request.app_id_exclude());
  if (matched.has_internal_error) {
    return HasCredentialsResponse::INTERNAL_ERROR;
  }

  if (matched.platform_credentials.empty() &&
      matched.legacy_credentials_for_rp_id.empty() &&
      matched.legacy_credentials_for_app_id.empty()) {
    return HasCredentialsResponse::UNKNOWN_CREDENTIAL_ID;
  }
  return HasCredentialsResponse::SUCCESS;
}

void WebAuthnHandler::GetAssertion(
    std::unique_ptr<GetAssertionMethodResponse> method_response,
    const GetAssertionRequest& request) {
  VLOG(1) << "Received a GetAssertion request.";
  GetAssertionResponse response;

  if (!Initialized()) {
    LOG(WARNING) << "GetAssertion: WebAuthnHandler not initialized.";
    response.set_status(GetAssertionResponse::INTERNAL_ERROR);
    method_response->Return(response);
    return;
  }

  if (pending_uv_make_credential_session_ ||
      pending_uv_get_assertion_session_) {
    LOG(WARNING) << "GetAssertion: There is a pending session.";
    response.set_status(GetAssertionResponse::REQUEST_PENDING);
    method_response->Return(response);
    return;
  }

  if (request.rp_id().empty() ||
      request.client_data_hash().size() != SHA256_DIGEST_LENGTH) {
    LOG(ERROR) << "GetAssertion: Invalid request format: no rp_id or incorrect "
                  "hash length.";
    response.set_status(GetAssertionResponse::INVALID_REQUEST);
    method_response->Return(response);
    return;
  }

  if (request.verification_type() == VerificationType::VERIFICATION_UNKNOWN) {
    LOG(ERROR) << "GetAssertion: Unknown verification type.";
    response.set_status(GetAssertionResponse::VERIFICATION_FAILED);
    method_response->Return(response);
    return;
  }

  // TODO(b/180502218): Support resident credentials.

  std::string* credential_to_use;
  bool is_legacy_credential = false;
  bool use_app_id = false;

  MatchedCredentials matched = FindMatchedCredentials(
      request.allowed_credential_id(), request.rp_id(), request.app_id());
  if (matched.has_internal_error) {
    LOG(ERROR) << "GetAssertion: FindMatchedCredentials failed with an "
                  "internal error.";
    response.set_status(GetAssertionResponse::INTERNAL_ERROR);
    method_response->Return(response);
    return;
  }

  if (!matched.platform_credentials.empty()) {
    credential_to_use = &matched.platform_credentials[0];
  } else if (!matched.legacy_credentials_for_rp_id.empty()) {
    credential_to_use = &matched.legacy_credentials_for_rp_id[0];
    is_legacy_credential = true;
  } else if (!matched.legacy_credentials_for_app_id.empty()) {
    credential_to_use = &matched.legacy_credentials_for_app_id[0];
    is_legacy_credential = true;
    use_app_id = true;
  } else {
    LOG(ERROR) << "GetAssertion: Failed to find matched credentials";
    response.set_status(GetAssertionResponse::UNKNOWN_CREDENTIAL_ID);
    method_response->Return(response);
    return;
  }

  struct GetAssertionSession session = {
      static_cast<uint64_t>(base::Time::Now().ToTimeT()), request,
      *credential_to_use, std::move(method_response)};
  if (use_app_id) {
    // App id was matched instead of rp id, so discard rp id.
    session.request.set_rp_id(request.app_id());
  }

  if (!AllowPresenceMode()) {
    // Upgrade UP requests to UV.
    session.request.set_verification_type(
        VerificationType::VERIFICATION_USER_VERIFICATION);
  }

  // Legacy credentials should go through power button, not UV.
  if (session.request.verification_type() ==
          VerificationType::VERIFICATION_USER_VERIFICATION &&
      !is_legacy_credential) {
    dbus::MethodCall call(
        chromeos::kUserAuthenticationServiceInterface,
        chromeos::kUserAuthenticationServiceShowAuthDialogV2Method);
    dbus::MessageWriter writer(&call);
    writer.AppendString(session.request.rp_id());
    writer.AppendInt32(session.request.verification_type());
    writer.AppendString(session.request.request_id_str());

    pending_uv_get_assertion_session_ = std::move(session);
    auth_dialog_dbus_proxy_->CallMethod(
        &call, dbus::ObjectProxy::TIMEOUT_INFINITE,
        base::BindOnce(&WebAuthnHandler::HandleUVFlowResultGetAssertion,
                       base::Unretained(this)));
    return;
  }

  DoGetAssertion(std::move(session), PresenceRequirement::kPowerButton);
}

// If already seeing failure, then no need to get user secret. This means
// in the fingerprint case, this signal should ideally come from UI instead of
// biod because only UI knows about retry.
void WebAuthnHandler::DoGetAssertion(struct GetAssertionSession session,
                                     PresenceRequirement presence_requirement) {
  GetAssertionResponse response;

  bool is_u2f_authenticator_credential = false;
  brillo::SecureBlob credential_secret;
  std::vector<uint8_t> credential_key_blob;
  if (!webauthn_storage_->GetSecretAndKeyBlobByCredentialId(
          session.credential_id, &credential_secret, &credential_key_blob)) {
    if (!AllowPresenceMode()) {
      LOG(ERROR) << "GetAssertion: No credential secret for credential id "
                 << session.credential_id << ", aborting GetAssertion.";
      response.set_status(GetAssertionResponse::UNKNOWN_CREDENTIAL_ID);
      session.response->Return(response);
      return;
    }

    // Maybe signing u2fhid credentials. Use legacy secret instead.
    std::optional<brillo::SecureBlob> legacy_secret =
        user_state_->GetUserSecret();
    if (!legacy_secret) {
      LOG(ERROR) << "GetAssertion: Cannot find user secret when trying to sign "
                    "u2fhid credentials";
      response.set_status(GetAssertionResponse::INTERNAL_ERROR);
      session.response->Return(response);
      return;
    }
    credential_secret = std::move(*legacy_secret);
    is_u2f_authenticator_credential = true;
  }

  const std::vector<uint8_t> rp_id_hash = util::Sha256(session.request.rp_id());
  const std::optional<std::vector<uint8_t>> authenticator_data =
      MakeAuthenticatorData(
          rp_id_hash, std::vector<uint8_t>(), std::vector<uint8_t>(),
          // If presence requirement is "power button" then the user was not
          // verified. Otherwise the user was verified through UI.
          /* user_verified = */ presence_requirement !=
              PresenceRequirement::kPowerButton,
          /* include_attested_credential_data = */ false,
          is_u2f_authenticator_credential);
  if (!authenticator_data) {
    LOG(ERROR) << "GetAssertion: MakeAuthenticatorData failed";
    response.set_status(GetAssertionResponse::INTERNAL_ERROR);
    session.response->Return(response);
    return;
  }

  std::vector<uint8_t> data_to_sign(*authenticator_data);
  util::AppendToVector(session.request.client_data_hash(), &data_to_sign);
  std::vector<uint8_t> hash_to_sign = util::Sha256(data_to_sign);

  std::vector<uint8_t> signature;
  GetAssertionResponse::GetAssertionStatus sign_status =
      u2f_command_processor_->U2fSign(rp_id_hash, hash_to_sign,
                                      util::ToVector(session.credential_id),
                                      credential_secret, &credential_key_blob,
                                      presence_requirement, &signature);
  response.set_status(sign_status);

  if (sign_status != GetAssertionResponse::SUCCESS) {
    LOG(ERROR) << "GetAssertion: U2fSign failed with status "
               << static_cast<int>(sign_status) << ".";
    session.response->Return(response);
    return;
  }

  VLOG(1) << "Finished processing GetAssertion request.";
  auto* assertion = response.add_assertion();
  assertion->set_credential_id(session.credential_id);
  AppendToString(*authenticator_data, assertion->mutable_authenticator_data());
  AppendToString(signature, assertion->mutable_signature());

  session.response->Return(response);
}

MatchedCredentials WebAuthnHandler::FindMatchedCredentials(
    const RepeatedPtrField<std::string>& all_credentials,
    const std::string& rp_id,
    const std::string& app_id) {
  std::vector<uint8_t> rp_id_hash = util::Sha256(rp_id);
  std::vector<uint8_t> app_id_hash = util::Sha256(app_id);
  MatchedCredentials result;

  // Platform authenticator credentials.
  for (const auto& credential_id : all_credentials) {
    brillo::SecureBlob credential_secret;
    std::vector<uint8_t> credential_key_blob;

    if (!webauthn_storage_->GetSecretAndKeyBlobByCredentialId(
            credential_id, &credential_secret, &credential_key_blob))
      continue;

    auto ret = u2f_command_processor_->U2fSignCheckOnly(
        rp_id_hash, util::ToVector(credential_id), credential_secret,
        &credential_key_blob);
    if (ret == HasCredentialsResponse::INTERNAL_ERROR) {
      LOG(ERROR) << "U2fSignCheckOnly failed with an internal error.";
      result.has_internal_error = true;
      return result;
    } else if (ret == HasCredentialsResponse::SUCCESS) {
      result.platform_credentials.emplace_back(credential_id);
    }
  }

  const std::optional<brillo::SecureBlob> user_secret =
      user_state_->GetUserSecret();
  if (!user_secret) {
    LOG(ERROR) << "Failed to get user secret.";
    result.has_internal_error = true;
    return result;
  }

  // Legacy credentials. If a legacy credential matches both rp_id and app_id,
  // it will only appear in result.legacy_credentials_for_rp_id.
  for (const auto& credential_id : all_credentials) {
    // First try matching rp_id.
    HasCredentialsResponse::HasCredentialsStatus ret =
        u2f_command_processor_->U2fSignCheckOnly(
            rp_id_hash, util::ToVector(credential_id), *user_secret, nullptr);
    DCHECK(HasCredentialsResponse::HasCredentialsStatus_IsValid(ret));
    switch (ret) {
      case HasCredentialsResponse::SUCCESS:
        // rp_id matched, it's a credential registered with u2fhid on WebAuthn
        // API.
        result.legacy_credentials_for_rp_id.emplace_back(credential_id);
        continue;
      case HasCredentialsResponse::UNKNOWN_CREDENTIAL_ID:
        break;
      case HasCredentialsResponse::UNKNOWN:
      case HasCredentialsResponse::INVALID_REQUEST:
      case HasCredentialsResponse::INTERNAL_ERROR:
        LOG(ERROR) << "U2fSignCheckOnly failed with an internal error.";
        result.has_internal_error = true;
        return result;
      case google::protobuf::kint32min:
      case google::protobuf::kint32max:
        NOTREACHED();
    }

    // Try matching app_id.
    ret = u2f_command_processor_->U2fSignCheckOnly(
        app_id_hash, util::ToVector(credential_id), *user_secret, nullptr);
    DCHECK(HasCredentialsResponse::HasCredentialsStatus_IsValid(ret));
    switch (ret) {
      case HasCredentialsResponse::SUCCESS:
        // App id extension matched. It's a legacy credential registered with
        // the U2F interface.
        result.legacy_credentials_for_app_id.emplace_back(credential_id);
        continue;
      case HasCredentialsResponse::UNKNOWN_CREDENTIAL_ID:
        break;
      case HasCredentialsResponse::UNKNOWN:
      case HasCredentialsResponse::INVALID_REQUEST:
      case HasCredentialsResponse::INTERNAL_ERROR:
        LOG(ERROR) << "U2fSignCheckOnly failed with an internal error.";
        result.has_internal_error = true;
        return result;
      case google::protobuf::kint32min:
      case google::protobuf::kint32max:
        NOTREACHED();
    }
  }

  return result;
}

HasCredentialsResponse WebAuthnHandler::HasCredentials(
    const HasCredentialsRequest& request) {
  HasCredentialsResponse response;

  if (!Initialized()) {
    LOG(WARNING) << "HasCredentials: WebAuthnHandler not initialized.";
    response.set_status(HasCredentialsResponse::INTERNAL_ERROR);
    return response;
  }

  if (request.rp_id().empty() || request.credential_id().empty()) {
    LOG(ERROR) << "HasCredentials: empty rp_id or credential_id.";
    response.set_status(HasCredentialsResponse::INVALID_REQUEST);
    return response;
  }

  MatchedCredentials matched = FindMatchedCredentials(
      request.credential_id(), request.rp_id(), request.app_id());
  if (matched.has_internal_error) {
    LOG(ERROR) << "HasCredentials: FindMatchedCredentials failed with an "
                  "internal error.";
    response.set_status(HasCredentialsResponse::INTERNAL_ERROR);
    return response;
  }

  for (const auto& credential_id : matched.platform_credentials) {
    *response.add_credential_id() = credential_id;
  }
  for (const auto& credential_id : matched.legacy_credentials_for_rp_id) {
    *response.add_credential_id() = credential_id;
  }
  for (const auto& credential_id : matched.legacy_credentials_for_app_id) {
    *response.add_credential_id() = credential_id;
  }

  response.set_status((response.credential_id_size() > 0)
                          ? HasCredentialsResponse::SUCCESS
                          : HasCredentialsResponse::UNKNOWN_CREDENTIAL_ID);
  return response;
}

HasCredentialsResponse WebAuthnHandler::HasLegacyCredentials(
    const HasCredentialsRequest& request) {
  HasCredentialsResponse response;

  if (!Initialized()) {
    LOG(WARNING) << "HasCredentHasLegacyCredentialsials: WebAuthnHandler not "
                    "initialized.";
    response.set_status(HasCredentialsResponse::INTERNAL_ERROR);
    return response;
  }

  if (request.credential_id().empty()) {
    LOG(ERROR) << "HasLegacyCredentials: credential_id is empty.";
    response.set_status(HasCredentialsResponse::INVALID_REQUEST);
    return response;
  }

  MatchedCredentials matched = FindMatchedCredentials(
      request.credential_id(), request.rp_id(), request.app_id());
  if (matched.has_internal_error) {
    LOG(ERROR) << "HasLegacyCredentials: FindMatchedCredentials failed with an "
                  "internal error.";
    response.set_status(HasCredentialsResponse::INTERNAL_ERROR);
    return response;
  }

  // Do not include platform credentials.
  for (const auto& credential_id : matched.legacy_credentials_for_rp_id) {
    *response.add_credential_id() = credential_id;
  }
  for (const auto& credential_id : matched.legacy_credentials_for_app_id) {
    *response.add_credential_id() = credential_id;
  }

  response.set_status((response.credential_id_size() > 0)
                          ? HasCredentialsResponse::SUCCESS
                          : HasCredentialsResponse::UNKNOWN_CREDENTIAL_ID);
  return response;
}

IsPlatformAuthenticatorInitializedResponse
WebAuthnHandler::IsPlatformAuthenticatorInitialized(
    const IsPlatformAuthenticatorInitializedRequest& request) {
  IsPlatformAuthenticatorInitializedResponse response;
  response.set_initialized(Initialized());
  return response;
}

IsU2fEnabledResponse WebAuthnHandler::IsU2fEnabled(
    const IsU2fEnabledRequest& request) {
  IsU2fEnabledResponse response;
  response.set_enabled(AllowPresenceMode());
  return response;
}

void WebAuthnHandler::IsUvpaa(
    std::unique_ptr<IsUvpaaMethodResponse> method_response,
    const IsUvpaaRequest& request) {
  // Checking with the authentication dialog (in Ash) will not work, because
  // currently in Chrome the IsUvpaa is a blocking call, and Ash can't respond
  // to us since it runs in the same process as Chrome. After the Chrome side
  // is refactored to take a callback or Ash is split into a separate binary,
  // we can change the implementation here to query with Ash.

  IsUvpaaResponse response;

  if (!Initialized()) {
    LOG(WARNING) << "IsUvpaa: WebAuthnHandler not initialized.";
    response.set_not_available(true);
    method_response->Return(response);
    return;
  }

  std::optional<std::string> account_id = user_state_->GetUser();
  if (!account_id) {
    LOG(WARNING) << "IsUvpaa: No user.";
    response.set_not_available(true);
    method_response->Return(response);
    return;
  }

  if (!auth_time_secret_hash_) {
    LOG(WARNING) << "IsUvpaa: No auth-time secret hash.";
    response.set_not_available(true);
    method_response->Return(response);
    return;
  }

  response.set_not_available(false);
  method_response->Return(response);
}

CountCredentialsInTimeRangeResponse
WebAuthnHandler::CountCredentialsInTimeRange(
    const CountCredentialsInTimeRangeRequest& request) {
  CountCredentialsInTimeRangeResponse response;

  if (!Initialized()) {
    response.set_status(CountCredentialsInTimeRangeResponse::INTERNAL_ERROR);
    return response;
  }

  int64_t created_not_before = request.created_not_before_seconds();
  int64_t created_not_after = request.created_not_after_seconds();
  if (created_not_before > created_not_after) {
    response.set_status(CountCredentialsInTimeRangeResponse::INVALID_REQUEST);
    return response;
  }
  response.set_num_credentials(webauthn_storage_->CountRecordsInTimeRange(
      created_not_before, created_not_after));
  response.set_status(CountCredentialsInTimeRangeResponse::SUCCESS);
  return response;
}

DeleteCredentialsInTimeRangeResponse
WebAuthnHandler::DeleteCredentialsInTimeRange(
    const DeleteCredentialsInTimeRangeRequest& request) {
  DeleteCredentialsInTimeRangeResponse response;

  if (!Initialized()) {
    response.set_status(DeleteCredentialsInTimeRangeResponse::INTERNAL_ERROR);
    return response;
  }

  int64_t created_not_before = request.created_not_before_seconds();
  int64_t created_not_after = request.created_not_after_seconds();
  if (created_not_before > created_not_after) {
    response.set_status(DeleteCredentialsInTimeRangeResponse::INVALID_REQUEST);
    return response;
  }
  response.set_num_credentials_deleted(
      webauthn_storage_->DeleteRecordsInTimeRange(created_not_before,
                                                  created_not_after));
  response.set_status(DeleteCredentialsInTimeRangeResponse::SUCCESS);
  return response;
}

GetAlgorithmsResponse WebAuthnHandler::GetAlgorithms(
    const GetAlgorithmsRequest&) {
  GetAlgorithmsResponse response;
  if (!Initialized()) {
    response.set_status(GetAlgorithmsResponse::INTERNAL_ERROR);
    return response;
  }
  response.set_status(GetAlgorithmsResponse::SUCCESS);
  response.add_algorithm(
      static_cast<int32_t>(u2f_command_processor_->GetAlgorithm()));
  return response;
}

GetSupportedFeaturesResponse WebAuthnHandler::GetSupportedFeatures(
    const GetSupportedFeaturesRequest& request) {
  GetSupportedFeaturesResponse response;
  response.set_support_lacros(true);
  return response;
}

bool WebAuthnHandler::HasPin(const std::string& account_id) {
  user_data_auth::ListAuthFactorsRequest request;
  request.mutable_account_id()->set_account_id(account_id);

  user_data_auth::ListAuthFactorsReply reply;
  brillo::ErrorPtr error;

  if (!cryptohome_proxy_->ListAuthFactors(
          request, &reply, &error, kCryptohomeTimeout.InMilliseconds())) {
    LOG(ERROR) << "Cannot query PIN availability from cryptohome, error: "
               << error->GetMessage();
    return false;
  }

  if (reply.error() !=
      user_data_auth::CryptohomeErrorCode::CRYPTOHOME_ERROR_NOT_SET) {
    LOG(ERROR) << "ListAuthFactors response has error " << reply.error();
    return false;
  }

  for (const auto& factor : reply.configured_auth_factors()) {
    if (factor.type() == user_data_auth::AUTH_FACTOR_TYPE_PIN) {
      return true;
    }
  }
  return false;
}

bool WebAuthnHandler::HasFingerprint(const std::string& sanitized_user) {
  dbus::ObjectProxy* biod_proxy = bus_->GetObjectProxy(
      biod::kBiodServiceName,
      dbus::ObjectPath(std::string(biod::kBiodServicePath)
                           .append(kCrosFpBiometricsManagerRelativePath)));

  dbus::MethodCall method_call(biod::kBiometricsManagerInterface,
                               biod::kBiometricsManagerGetRecordsForUserMethod);
  dbus::MessageWriter method_writer(&method_call);
  method_writer.AppendString(sanitized_user);

  std::unique_ptr<dbus::Response> response = biod_proxy->CallMethodAndBlock(
      &method_call, dbus::ObjectProxy::TIMEOUT_USE_DEFAULT);
  if (!response) {
    LOG(ERROR)
        << "Cannot check fingerprint availability: no response from biod.";
    return false;
  }

  dbus::MessageReader response_reader(response.get());
  dbus::MessageReader records_reader(nullptr);
  if (!response_reader.PopArray(&records_reader)) {
    LOG(ERROR) << "Cannot parse GetRecordsForUser response from biod.";
    return false;
  }

  int records_count = 0;
  while (records_reader.HasMoreData()) {
    dbus::ObjectPath record_path;
    if (!records_reader.PopObjectPath(&record_path)) {
      LOG(WARNING) << "Cannot parse fingerprint record path";
      continue;
    }
    records_count++;
  }
  return records_count > 0;
}

void WebAuthnHandler::SetWebAuthnStorageForTesting(
    std::unique_ptr<WebAuthnStorage> storage) {
  webauthn_storage_ = std::move(storage);
}

void WebAuthnHandler::SetCryptohomeInterfaceProxyForTesting(
    std::unique_ptr<org::chromium::UserDataAuthInterfaceProxyInterface>
        cryptohome_proxy) {
  cryptohome_proxy_ = std::move(cryptohome_proxy);
}

}  // namespace u2f
