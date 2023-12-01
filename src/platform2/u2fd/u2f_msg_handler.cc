// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "u2fd/u2f_msg_handler.h"

#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <base/logging.h>
#include <brillo/secure_blob.h>
#include <libhwsec-foundation/status/status_chain_macros.h>
#include <session_manager/dbus-proxies.h>
#include <trunks/cr50_headers/u2f.h>

#include "u2fd/client/util.h"
#include "u2fd/u2f_corp_processor_interface.h"

using hwsec::TPMError;
using hwsec::TPMRetryAction;
using GenerateResult = hwsec::u2f::GenerateResult;
using Signature = hwsec::u2f::Signature;
using ConsumeMode = hwsec::u2f::ConsumeMode;
using UserPresenceMode = hwsec::u2f::UserPresenceMode;

namespace u2f {

namespace {

// Response to the APDU requesting the U2F protocol version
constexpr char kSupportedU2fVersion[] = "U2F_V2";

// U2F_REGISTER response prefix, indicating U2F_VER_2.
// See FIDO "U2F Raw Message Formats" spec.
constexpr uint8_t kU2fVer2Prefix = 5;

// UMA Metric names.
constexpr char kU2fCommand[] = "Platform.U2F.Command";

std::optional<std::vector<uint8_t>> GetG2fCert(
    const hwsec::U2fVendorFrontend* u2f_frontend) {
  ASSIGN_OR_RETURN(std::vector<uint8_t> cert, u2f_frontend->GetG2fCert(),
                   _.WithStatus<TPMError>("Failed to get G2F cert")
                       .LogError()
                       .As(std::nullopt));

  if (!util::RemoveCertificatePadding(&cert)) {
    LOG(ERROR) << "Failed to remove padding from G2F certificate ";
    return std::nullopt;
  }

  return cert;
}

}  // namespace

U2fMessageHandler::U2fMessageHandler(
    std::unique_ptr<AllowlistingUtil> allowlisting_util,
    std::function<void()> request_user_presence,
    UserState* user_state,
    const hwsec::U2fVendorFrontend* u2f_frontend,
    org::chromium::SessionManagerInterfaceProxy* sm_proxy,
    MetricsLibraryInterface* metrics,
    bool allow_g2f_attestation,
    U2fCorpProcessorInterface* u2f_corp_processor)
    : allowlisting_util_(std::move(allowlisting_util)),
      request_user_presence_(request_user_presence),
      user_state_(user_state),
      u2f_frontend_(u2f_frontend),
      metrics_(metrics),
      allow_g2f_attestation_(allow_g2f_attestation),
      u2f_corp_processor_(u2f_corp_processor) {
  CHECK(u2f_frontend_);
}

U2fResponseApdu U2fMessageHandler::ProcessMsg(const std::string& req) {
  uint16_t u2f_status = 0;

  std::optional<U2fCommandApdu> apdu =
      U2fCommandApdu::ParseFromString(req, &u2f_status);

  if (!apdu.has_value()) {
    return BuildEmptyResponse(u2f_status ?: U2F_SW_WTF);
  }

  U2fIns ins = apdu->Ins();

  if (static_cast<int>(ins) <= static_cast<int>(U2fIns::kU2fVersion)) {
    // TODO(crbug.com/1218246) Change UMA enum name kU2fCommand if new enums for
    // U2fIns are added to avoid data discontinuity, then use <largest-enum>+1
    // rather than <largest-enum>.
    metrics_->SendEnumToUMA(kU2fCommand, static_cast<int>(ins),
                            static_cast<int>(U2fIns::kU2fVersion));
  }

  // TODO(louiscollard): Check expected response length is large enough.

  switch (ins) {
    case U2fIns::kU2fRegister: {
      std::optional<U2fRegisterRequestApdu> reg_apdu =
          U2fRegisterRequestApdu::FromCommandApdu(*apdu, &u2f_status);
      // Chrome may send a dummy register request, which is designed to
      // cause a USB device to flash it's LED. We should simply ignore
      // these.
      if (reg_apdu.has_value()) {
        if (reg_apdu->IsChromeDummyWinkRequest()) {
          return BuildEmptyResponse(U2F_SW_CONDITIONS_NOT_SATISFIED);
        } else {
          return ProcessU2fRegister(*reg_apdu);
        }
      }
      break;  // Handle error.
    }
    case U2fIns::kU2fAuthenticate: {
      std::optional<U2fAuthenticateRequestApdu> auth_apdu =
          U2fAuthenticateRequestApdu::FromCommandApdu(*apdu, &u2f_status);
      if (auth_apdu.has_value()) {
        return ProcessU2fAuthenticate(*auth_apdu);
      }
      break;  // Handle error.
    }
    case U2fIns::kU2fVersion: {
      if (!apdu->Body().empty()) {
        u2f_status = U2F_SW_WRONG_LENGTH;
        break;
      }

      U2fResponseApdu response;
      response.AppendString(kSupportedU2fVersion);
      response.SetStatus(U2F_SW_NO_ERROR);
      return response;
    }
    default:
      if (u2f_corp_processor_) {
        return u2f_corp_processor_->ProcessApdu(*apdu);
      }
      u2f_status = U2F_SW_INS_NOT_SUPPORTED;
      break;
  }

  return BuildEmptyResponse(u2f_status ?: U2F_SW_WTF);
}

U2fResponseApdu U2fMessageHandler::ProcessU2fRegister(
    const U2fRegisterRequestApdu& request) {
  VLOG(1) << "U2F registration requested.";

  std::optional<brillo::SecureBlob> user_secret = user_state_->GetUserSecret();
  if (!user_secret.has_value()) {
    return BuildEmptyResponse(U2F_SW_WTF);
  }

  hwsec::StatusOr<GenerateResult> generate_result =
      u2f_frontend_->GenerateUserPresenceOnly(request.GetAppId(), *user_secret,
                                              ConsumeMode::kConsume,
                                              UserPresenceMode::kRequired);
  if (!generate_result.ok()) {
    if (generate_result.err_status()->ToTPMRetryAction() ==
        TPMRetryAction::kUserPresence) {
      LOG(WARNING) << "U2fGenerate requests user presence.";
      request_user_presence_();
      return BuildEmptyResponse(U2F_SW_CONDITIONS_NOT_SATISFIED);
    }
    LOG(ERROR) << "U2fGenerate failed:" << generate_result.status() << ".";
    return BuildEmptyResponse(U2F_SW_WTF);
  }
  if (!generate_result->public_key) {
    LOG(ERROR) << "No public key in generate result.";
    return BuildEmptyResponse(U2F_SW_WTF);
  }
  std::vector<uint8_t> public_key = generate_result->public_key->raw();
  std::vector<uint8_t> key_handle = std::move(generate_result->key_handle);

  std::vector<uint8_t> data_to_sign = util::BuildU2fRegisterResponseSignedData(
      request.GetAppId(), request.GetChallenge(), public_key, key_handle);

  std::vector<uint8_t> attestation_cert;
  std::vector<uint8_t> signature;

  if (allow_g2f_attestation_ && request.UseG2fAttestation()) {
    std::optional<std::vector<uint8_t>> g2f_cert = GetG2fCert(u2f_frontend_);

    if (!g2f_cert.has_value()) {
      LOG(ERROR) << "Failed to get g2f cert.";
      return BuildEmptyResponse(U2F_SW_WTF);
    }
    attestation_cert = *g2f_cert;

    ASSIGN_OR_RETURN(const Signature& sig,
                     u2f_frontend_->G2fAttest(request.GetAppId(), *user_secret,
                                              request.GetChallenge(),
                                              key_handle, public_key),
                     _.WithStatus<TPMError>("Failed to attest U2F credential")
                         .LogError()
                         .As(BuildEmptyResponse(U2F_SW_WTF)));

    std::optional<std::vector<uint8_t>> sig_der =
        util::SignatureToDerBytes(sig.r, sig.s);
    if (!sig_der.has_value()) {
      LOG(ERROR) << "DER encoding of U2F_ATTEST signature failed.";
      return BuildEmptyResponse(U2F_SW_WTF);
    }
    signature = std::move(*sig_der);

    if (allowlisting_util_ != nullptr &&
        !allowlisting_util_->AppendDataToCert(&attestation_cert)) {
      LOG(ERROR) << "Failed to get allowlisting data for G2F Enroll Request.";
      return BuildEmptyResponse(U2F_SW_WTF);
    }
  } else {
    ASSIGN_OR_RETURN(
        const std::vector<uint8_t>& data,
        u2f_frontend_->GetG2fAttestData(
            request.GetAppId(), request.GetChallenge(), key_handle, public_key),
        _.WithStatus<TPMError>("Failed to get G2F attest data")
            .LogError()
            .As(BuildEmptyResponse(U2F_SW_WTF)));
    if (!util::DoSoftwareAttest(data, &attestation_cert, &signature)) {
      LOG(ERROR) << "Failed to do software attest.";
      return BuildEmptyResponse(U2F_SW_WTF);
    }
  }

  // Prepare response, as specified by "U2F Raw Message Formats".
  U2fResponseApdu register_resp;
  register_resp.AppendByte(kU2fVer2Prefix);
  register_resp.AppendBytes(public_key);
  register_resp.AppendByte(key_handle.size());
  register_resp.AppendBytes(key_handle);
  register_resp.AppendBytes(attestation_cert);
  register_resp.AppendBytes(signature);
  register_resp.SetStatus(U2F_SW_NO_ERROR);

  VLOG(1) << "Finished processing U2F registration request.";
  return register_resp;
}

namespace {

// A success response to a U2F_AUTHENTICATE request includes a signature over
// the following data, in this format.
std::vector<uint8_t> BuildU2fAuthenticateResponseSignedData(
    const std::vector<uint8_t>& app_id,
    const std::vector<uint8_t>& challenge,
    const std::vector<uint8_t>& counter) {
  std::vector<uint8_t> to_sign;
  util::AppendToVector(app_id, &to_sign);
  to_sign.push_back(U2F_AUTH_FLAG_TUP);
  util::AppendToVector(counter, &to_sign);
  util::AppendToVector(challenge, &to_sign);
  return to_sign;
}

}  // namespace

U2fResponseApdu U2fMessageHandler::ProcessU2fAuthenticate(
    const U2fAuthenticateRequestApdu& request) {
  VLOG(1) << "U2F authentication requested.";

  std::optional<brillo::SecureBlob> user_secret = user_state_->GetUserSecret();
  if (!user_secret.has_value()) {
    return BuildEmptyResponse(U2F_SW_WTF);
  }

  if (request.IsAuthenticateCheckOnly()) {
    // The authenticate only version of this command always returns an error (on
    // success, returns an error requesting presence).
    hwsec::Status status = u2f_frontend_->CheckUserPresenceOnly(
        request.GetAppId(), *user_secret, request.GetKeyHandle());
    if (!status.ok()) {
      LOG(ERROR) << "U2fSignCheckOnly failed: " << status << ".";
      return BuildEmptyResponse(status.err_status()->ToTPMRetryAction() ==
                                        TPMRetryAction::kUserAuth
                                    ? U2F_SW_WRONG_DATA
                                    : U2F_SW_WTF);
    }

    VLOG(1) << "Finished processing U2F authentication (check-only) request.";
    return BuildEmptyResponse(U2F_SW_CONDITIONS_NOT_SATISFIED);
  }

  std::optional<std::vector<uint8_t>> counter = user_state_->GetCounter();
  if (!counter.has_value()) {
    LOG(ERROR) << "Failed to retrieve counter value.";
    return BuildEmptyResponse(U2F_SW_WTF);
  }

  std::vector<uint8_t> hash_to_sign =
      util::Sha256(BuildU2fAuthenticateResponseSignedData(
          request.GetAppId(), request.GetChallenge(), *counter));

  hwsec::StatusOr<Signature> sig = u2f_frontend_->SignUserPresenceOnly(
      request.GetAppId(), *user_secret, hash_to_sign, ConsumeMode::kConsume,
      UserPresenceMode::kRequired, request.GetKeyHandle());
  if (!sig.ok()) {
    auto action = sig.err_status()->ToTPMRetryAction();
    if (action == TPMRetryAction::kUserPresence) {
      LOG(WARNING) << "U2fSign requests user presence.";
      request_user_presence_();
      return BuildEmptyResponse(U2F_SW_CONDITIONS_NOT_SATISFIED);
    }
    LOG(ERROR) << "U2fSign failed:" << sig.status() << ".";
    return BuildEmptyResponse(
        action == TPMRetryAction::kUserAuth ? U2F_SW_WRONG_DATA : U2F_SW_WTF);
  }
  std::optional<std::vector<uint8_t>> sig_der =
      util::SignatureToDerBytes(sig->r, sig->s);
  if (!sig_der.has_value()) {
    return BuildEmptyResponse(U2F_SW_WTF);
  }

  if (!user_state_->IncrementCounter()) {
    LOG(ERROR) << "Failed to increment counter value.";
    // If we can't increment the counter we must not return the signed
    // response, as the next authenticate response would end up having
    // the same counter value.
    return BuildEmptyResponse(U2F_SW_WTF);
  }

  // Everything succeeded; build response.

  // Prepare response, as specified by "U2F Raw Message Formats".
  U2fResponseApdu auth_resp;
  auth_resp.AppendByte(U2F_AUTH_FLAG_TUP);
  auth_resp.AppendBytes(*counter);
  auth_resp.AppendBytes(*sig_der);
  auth_resp.SetStatus(U2F_SW_NO_ERROR);

  VLOG(1) << "Finished processing U2F authentication request.";
  return auth_resp;
}

U2fResponseApdu U2fMessageHandler::BuildEmptyResponse(uint16_t sw) {
  U2fResponseApdu resp_apdu;
  resp_apdu.SetStatus(sw);
  return resp_apdu;
}

}  // namespace u2f
