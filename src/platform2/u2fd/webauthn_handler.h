// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef U2FD_WEBAUTHN_HANDLER_H_
#define U2FD_WEBAUTHN_HANDLER_H_

#include <functional>
#include <memory>
#include <optional>
#include <queue>
#include <string>
#include <vector>

#include <brillo/dbus/dbus_method_response.h>
#include <cryptohome/proto_bindings/UserDataAuth.pb.h>
#include <cryptohome/proto_bindings/rpc.pb.h>
#include <metrics/metrics_library.h>
#include <u2f/proto_bindings/u2f_interface.pb.h>
#include <user_data_auth-client/user_data_auth/dbus-proxies.h>

#include "u2fd/allowlisting_util.h"
#include "u2fd/client/user_state.h"
#include "u2fd/u2f_mode.h"
#include "u2fd/webauthn_storage.h"

namespace u2f {

class U2fCommandProcessor;

using MakeCredentialMethodResponse =
    brillo::dbus_utils::DBusMethodResponse<MakeCredentialResponse>;
using GetAssertionMethodResponse =
    brillo::dbus_utils::DBusMethodResponse<GetAssertionResponse>;
using IsUvpaaMethodResponse =
    brillo::dbus_utils::DBusMethodResponse<IsUvpaaResponse>;
using ::google::protobuf::RepeatedPtrField;

struct MakeCredentialSession {
  bool empty() { return !response; }
  uint64_t session_id;
  MakeCredentialRequest request;
  std::unique_ptr<MakeCredentialMethodResponse> response;
  bool canceled = false;
};

struct GetAssertionSession {
  bool empty() { return !response; }
  uint64_t session_id;
  GetAssertionRequest request;
  // The credential_id to send to the TPM. May be a resident credential.
  std::string credential_id;
  std::unique_ptr<GetAssertionMethodResponse> response;
  bool canceled = false;
};

struct MatchedCredentials {
  std::vector<std::string> platform_credentials;
  std::vector<std::string> legacy_credentials_for_rp_id;
  std::vector<std::string> legacy_credentials_for_app_id;
  bool has_internal_error = false;
};

enum class PresenceRequirement {
  kNone,  // Does not require presence. Used only after user-verification in
          // MakeCredential.
  kPowerButton,  // Requires a power button press as indication of presence.
  kFingerprint,  // Requires the GPIO line from fingerprint MCU to be active.
  kAuthorizationSecret,  // Requires the correct authorization secret.
};

// COSE algorithm ID
// https://www.iana.org/assignments/cose/cose.xhtml#algorithms
enum class CoseAlgorithmIdentifier : int32_t {
  kEs256 = -7,
  kRs256 = -257,
};

// Implementation of the WebAuthn DBus API.
// More detailed documentation is available in u2f_interface.proto
class WebAuthnHandler {
 public:
  WebAuthnHandler();
  ~WebAuthnHandler();

  // Initializes WebAuthnHandler.
  // |bus| - DBus pointer.
  // |user_state| - pointer to a UserState instance, for requesting user secret.
  // Owned by U2fDaemon and should outlive WebAuthnHandler.
  // |u2f_mode| - whether u2f or g2f is enabled.
  // |u2f_command_processor| - processor for executing u2f commands.
  // |allowlisting_util| - utility to append allowlisting data to g2f certs.
  // |metrics| pointer to metrics library object.
  void Initialize(dbus::Bus* bus,
                  UserState* user_state,
                  U2fMode u2f_mode,
                  std::unique_ptr<U2fCommandProcessor> u2f_command_processor,
                  std::unique_ptr<AllowlistingUtil> allowlisting_util,
                  MetricsLibraryInterface* metrics);

  // Called when session state changed. Loads/clears state for primary user.
  void OnSessionStarted(const std::string& account_id);
  void OnSessionStopped();

  // Generates a new credential.
  void MakeCredential(
      std::unique_ptr<MakeCredentialMethodResponse> method_response,
      const MakeCredentialRequest& request);

  // Signs a challenge from the relaying party.
  void GetAssertion(std::unique_ptr<GetAssertionMethodResponse> method_response,
                    const GetAssertionRequest& request);

  // Tests validity and/or presence of specified credentials, including u2fhid
  // credentials.
  HasCredentialsResponse HasCredentials(const HasCredentialsRequest& request);

  // Tests whether any credential were registered using the u2fhid (on either
  // WebAuthn API or U2F API).
  HasCredentialsResponse HasLegacyCredentials(
      const HasCredentialsRequest& request);

  // Dismisses user verification UI and abort the operation. This is expected to
  // be called by the browser only in UV operations, because UP operations
  // themselves will timeout after ~5 seconds.
  CancelWebAuthnFlowResponse Cancel(const CancelWebAuthnFlowRequest& request);

  // Checks whether the platform authenticator is initialized. Before
  // initialized, most operations will directly return an error.
  IsPlatformAuthenticatorInitializedResponse IsPlatformAuthenticatorInitialized(
      const IsPlatformAuthenticatorInitializedRequest& request);

  // Checks whether user-verifying platform authenticator is available.
  void IsUvpaa(std::unique_ptr<IsUvpaaMethodResponse> method_response,
               const IsUvpaaRequest& request);

  // Checks whether u2f is enabled (therefore power button mode is supported).
  IsU2fEnabledResponse IsU2fEnabled(const IsU2fEnabledRequest& request);

  // Count how many WebAuthn platform credentials are created within the
  // specified time range.
  CountCredentialsInTimeRangeResponse CountCredentialsInTimeRange(
      const CountCredentialsInTimeRangeRequest& request);

  // Delete all WebAuthn platform credentials created within the specified time
  // range.
  DeleteCredentialsInTimeRangeResponse DeleteCredentialsInTimeRange(
      const DeleteCredentialsInTimeRangeRequest& request);

  // Get the supported algorithms of the platform authenticator. Currently we
  // have no plan to support multiple algorithms on one platform so the response
  // will only contain one entry.
  GetAlgorithmsResponse GetAlgorithms(const GetAlgorithmsRequest& request);

  // Get the supported features of u2fd. currently it only contains whether
  // WebAuthn is enabled on Lacros. This is equivalent to whether the request_id
  // field in WebAuthn requests has changed to str type currently, which is
  // always true.
  GetSupportedFeaturesResponse GetSupportedFeatures(
      const GetSupportedFeaturesRequest& request);

  void SetWebAuthnStorageForTesting(std::unique_ptr<WebAuthnStorage> storage);

  void SetCryptohomeInterfaceProxyForTesting(
      std::unique_ptr<org::chromium::UserDataAuthInterfaceProxyInterface>
          cryptohome_proxy);

 private:
  friend class WebAuthnHandlerTestBase;
  friend class WebAuthnHandlerTestAllowUP;

  bool Initialized();

  // Fetches auth-time WebAuthn secret and keep the hash of it.
  void GetWebAuthnSecretHashAsync(const std::string& account_id);
  void OnGetWebAuthnSecretHashResp(
      const user_data_auth::GetWebAuthnSecretHashReply& reply);
  void OnGetWebAuthnSecretHashCallFailed(brillo::Error* error);

  // Callbacks invoked when UI completes user verification flow.
  void HandleUVFlowResultMakeCredential(dbus::Response* flow_response);
  void HandleUVFlowResultGetAssertion(dbus::Response* flow_response);

  // Proceeds for the current MakeCredential request, and responds to the
  // request with authenticator data. Called directly if the request is
  // user-presence only. Called on user verification success if the request is
  // user-verification.
  void DoMakeCredential(struct MakeCredentialSession session,
                        PresenceRequirement presence_requirement);

  // Find all matching credentials and return them in 3 categories (see struct
  // MatchedCredentials definition). If a legacy credential matches both rp_id
  // and app_id, it will only appear in "legacy_credentials_for_rp_id".
  MatchedCredentials FindMatchedCredentials(
      const RepeatedPtrField<std::string>& all_credentials,
      const std::string& rp_id,
      const std::string& app_id);

  // Called on user verification success if the request is user-verification.
  void DoGetAssertion(struct GetAssertionSession session,
                      PresenceRequirement presence_requirement);

  // Creates and returns authenticator data. |include_attested_credential_data|
  // should be set to true for MakeCredential, false for GetAssertion.
  std::optional<std::vector<uint8_t>> MakeAuthenticatorData(
      const std::vector<uint8_t>& rp_id_hash,
      const std::vector<uint8_t>& credential_id,
      const std::vector<uint8_t>& credential_public_key,
      bool user_verified,
      bool include_attested_credential_data,
      bool is_u2f_authenticator_credential);

  // Appends a none attestation to |response|. Only used in MakeCredential.
  void AppendNoneAttestation(MakeCredentialResponse* response);

  // Creates and returns an U2F attestation statement, or nullopt if attestation
  // fails.
  std::optional<std::vector<uint8_t>> MakeFidoU2fAttestationStatement(
      const std::vector<uint8_t>& app_id,
      const std::vector<uint8_t>& challenge,
      const std::vector<uint8_t>& pub_key,
      const std::vector<uint8_t>& key_handle,
      const MakeCredentialRequest::AttestationConveyancePreference
          attestation_conveyance_preference);

  // Runs U2F_SIGN command with "check only" flag on each excluded credential
  // id. Returns true if one of them belongs to this device.
  HasCredentialsResponse::HasCredentialsStatus HasExcludedCredentials(
      const MakeCredentialRequest& request);

  // Checks whether the user with |account_id| has PIN set up.
  bool HasPin(const std::string& account_id);

  // Checks whether the user with |account_id| has fingerprint set up.
  bool HasFingerprint(const std::string& account_id);

  // Returns whether presence-only mode (power button mode) is allowed.
  bool AllowPresenceMode();

  UserState* user_state_ = nullptr;
  dbus::Bus* bus_ = nullptr;
  // Proxy to user authentication dialog in Ash. Used only in UV requests.
  dbus::ObjectProxy* auth_dialog_dbus_proxy_ = nullptr;

  std::unique_ptr<org::chromium::UserDataAuthInterfaceProxyInterface>
      cryptohome_proxy_;

  // Presence-only mode (power button mode) should only be allowed if u2f or
  // g2f is enabled for the device (it's a per-device policy). The mode also
  // determines the attestation to add to MakeCredential.
  U2fMode u2f_mode_;

  // Util to append allowlisting data to g2f certificates.
  std::unique_ptr<AllowlistingUtil> allowlisting_util_;

  // The MakeCredential session that's waiting on UI. There can only be one
  // such session. UP sessions should not use this since there can be multiple.
  std::optional<MakeCredentialSession> pending_uv_make_credential_session_;

  // The GetAssertion session that's waiting on UI. There can only be one
  // such session. UP sessions should not use this since there can be multiple.
  std::optional<GetAssertionSession> pending_uv_get_assertion_session_;

  // Hash of the per-user auth-time secret for WebAuthn.
  std::unique_ptr<brillo::Blob> auth_time_secret_hash_;

  // Storage for WebAuthn credential records.
  std::unique_ptr<WebAuthnStorage> webauthn_storage_;

  // Processor for u2f commands.
  std::unique_ptr<U2fCommandProcessor> u2f_command_processor_;

  MetricsLibraryInterface* metrics_;
};

}  // namespace u2f

#endif  // U2FD_WEBAUTHN_HANDLER_H_
