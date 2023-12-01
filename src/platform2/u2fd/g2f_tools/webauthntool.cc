// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <sysexits.h>

#include <base/check.h>
#include <base/command_line.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_split.h>
#include <brillo/dbus/dbus_method_invoker.h>
#include <brillo/dbus/dbus_object.h>
#include <brillo/flag_helper.h>
#include <brillo/syslog_logging.h>
#include <dbus/u2f/dbus-constants.h>
#include <u2f/proto_bindings/u2f_interface.pb.h>

constexpr int kRpIdHashBytes = 32;
constexpr int kFlagsBytes = 1;
constexpr int kCounterBytes = 4;
constexpr int kAaguidBytes = 16;
constexpr int kCredentialIdLengthBytes = 2;

template <typename Req, typename Resp>
Resp SendRequest(dbus::ObjectProxy* proxy,
                 const std::string& method_name,
                 const Req& req) {
  brillo::ErrorPtr error;

  std::unique_ptr<dbus::Response> dbus_response =
      brillo::dbus_utils::CallMethodAndBlock(proxy, u2f::kU2FInterface,
                                             method_name, &error, req);

  if (!dbus_response) {
    LOG(FATAL) << "Call to " << method_name << " failed";
  }

  Resp resp;

  dbus::MessageReader reader(dbus_response.get());
  if (!reader.PopArrayOfBytesAsProto(&resp)) {
    LOG(FATAL) << "Failed to parse reply for call to " << method_name;
  }

  return resp;
}

std::string ResponseStatusToString(
    u2f::MakeCredentialResponse::MakeCredentialStatus status) {
  switch (status) {
    case 1:
      return "SUCCESS";
    case 2:
      return "VERIFICATION_FAILED";
    case 3:
      return "VERIFICATION_TIMEOUT";
    case 4:
      return "INVALID_REQUEST";
    case 5:
      return "INTERNAL_ERROR";
    case 6:
      return "EXCLUDED_CREDENTIAL_ID";
    case 7:
      return "REQUEST_PENDING";
    case 8:
      return "CANCELED";
    default:
      return "UNKNOWN";
  }
}

std::string ResponseStatusToString(
    u2f::GetAssertionResponse::GetAssertionStatus status) {
  switch (status) {
    case 1:
      return "SUCCESS";
    case 2:
      return "VERIFICATION_FAILED";
    case 3:
      return "VERIFICATION_TIMEOUT";
    case 4:
      return "INVALID_REQUEST";
    case 5:
      return "INTERNAL_ERROR";
    case 6:
      return "UNKNOWN_CREDENTIAL_ID";
    case 7:
      return "REQUEST_PENDING";
    case 8:
      return "CANCELED";
    default:
      return "UNKNOWN";
  }
}

std::string ResponseStatusToString(
    u2f::HasCredentialsResponse::HasCredentialsStatus status) {
  switch (status) {
    case 1:
      return "SUCCESS";
    case 2:
      return "INVALID_REQUEST";
    case 3:
      return "INTERNAL_ERROR";
    case 4:
      return "UNKNOWN_CREDENTIAL_ID";
    default:
      return "UNKNOWN";
  }
}

std::string HexEncodeStr(const std::string& str) {
  return base::HexEncode(str.data(), str.size());
}

void AppendToString(const std::vector<uint8_t>& vect, std::string* str) {
  str->append(reinterpret_cast<const char*>(vect.data()), vect.size());
}

const std::vector<std::string> ParseCommaDelimitedString(
    const std::string& str) {
  return base::SplitString(str, ",", base::TRIM_WHITESPACE,
                           base::SPLIT_WANT_NONEMPTY);
}

std::string ExtractCredentialId(const std::string& authenticator_data) {
  size_t credential_id_length_offset =
      kRpIdHashBytes + kFlagsBytes + kCounterBytes + kAaguidBytes;
  if (authenticator_data.size() <
      credential_id_length_offset + kCredentialIdLengthBytes)
    return std::string();
  std::string length_str = authenticator_data.substr(
      credential_id_length_offset, kCredentialIdLengthBytes);
  uint16_t length = ((static_cast<uint16_t>(length_str.at(0))) << 8) +
                    static_cast<uint16_t>(length_str.at(1));
  size_t credential_id_offset =
      credential_id_length_offset + kCredentialIdLengthBytes;
  if (authenticator_data.size() < credential_id_offset + length)
    return std::string();
  return authenticator_data.substr(credential_id_offset, length);
}

void MakeCredential(dbus::ObjectProxy* proxy,
                    int verification_type,
                    const std::string& rp_id,
                    const std::string& request_id,
                    const std::vector<std::string>& excluded_credential_ids) {
  u2f::MakeCredentialRequest req;
  req.set_verification_type(
      static_cast<u2f::VerificationType>(verification_type));
  req.set_rp_id(rp_id);
  req.set_request_id_str(request_id);

  for (const std::string& excluded_credential_id : excluded_credential_ids) {
    if (!excluded_credential_id.empty()) {
      std::vector<uint8_t> excluded_credential_id_bytes;
      if (!base::HexStringToBytes(excluded_credential_id,
                                  &excluded_credential_id_bytes)) {
        LOG(FATAL) << "Could not parse excluded_credential_id bytes";
      }
      AppendToString(excluded_credential_id_bytes,
                     req.add_excluded_credential_id());
    }
  }

  if (verification_type == u2f::VERIFICATION_USER_VERIFICATION) {
    LOG(INFO) << "Please touch the fingerprint sensor.";
  } else if (verification_type == u2f::VERIFICATION_USER_PRESENCE) {
    LOG(INFO) << "Please press the power button.";
  }

  u2f::MakeCredentialResponse resp =
      SendRequest<u2f::MakeCredentialRequest, u2f::MakeCredentialResponse>(
          proxy, u2f::kU2FMakeCredential, req);

  LOG(INFO) << "status: " << ResponseStatusToString(resp.status());
  LOG(INFO) << "authenticator_data: "
            << HexEncodeStr(resp.authenticator_data());
  LOG(INFO) << "credential_id: "
            << HexEncodeStr(ExtractCredentialId(resp.authenticator_data()));
  LOG(INFO) << "attestation_format: " << resp.attestation_format();
  LOG(INFO) << "attestation_statement: "
            << HexEncodeStr(resp.attestation_statement());
}

void GetAssertion(dbus::ObjectProxy* proxy,
                  int verification_type,
                  const std::string& rp_id,
                  const std::string& request_id,
                  const std::string& client_data_hash,
                  const std::vector<std::string>& allowed_credential_ids) {
  u2f::GetAssertionRequest req;
  req.set_verification_type(
      static_cast<u2f::VerificationType>(verification_type));
  req.set_rp_id(rp_id);
  req.set_request_id_str(request_id);
  req.set_client_data_hash(client_data_hash);

  for (const std::string& allowed_credential_id : allowed_credential_ids) {
    std::vector<uint8_t> credential_id_bytes;
    if (!base::HexStringToBytes(allowed_credential_id, &credential_id_bytes)) {
      LOG(FATAL) << "Could not parse credential_id bytes";
    }

    AppendToString(credential_id_bytes, req.add_allowed_credential_id());
  }

  u2f::GetAssertionResponse resp =
      SendRequest<u2f::GetAssertionRequest, u2f::GetAssertionResponse>(
          proxy, u2f::kU2FGetAssertion, req);

  LOG(INFO) << "status: " << ResponseStatusToString(resp.status());
  for (const auto& assertion : resp.assertion()) {
    LOG(INFO) << "credential_id: " << HexEncodeStr(assertion.credential_id());
    LOG(INFO) << "authenticator_data: "
              << HexEncodeStr(assertion.authenticator_data());
    LOG(INFO) << "signature: " << HexEncodeStr(assertion.signature());
  }
}

void HasCredentials(dbus::ObjectProxy* proxy,
                    const std::string& rp_id,
                    const std::vector<std::string>& credential_ids) {
  u2f::HasCredentialsRequest req;
  req.set_rp_id(rp_id);

  for (const std::string& credential_id : credential_ids) {
    std::vector<uint8_t> credential_id_bytes;
    if (!base::HexStringToBytes(credential_id, &credential_id_bytes)) {
      LOG(FATAL) << "Could not parse credential_id bytes";
    }

    AppendToString(credential_id_bytes, req.add_credential_id());
  }

  u2f::HasCredentialsResponse resp =
      SendRequest<u2f::HasCredentialsRequest, u2f::HasCredentialsResponse>(
          proxy, u2f::kU2FHasCredentials, req);

  LOG(INFO) << "status: " << ResponseStatusToString(resp.status());
  LOG(INFO) << "number matched: " << resp.credential_id().size();
  for (const auto& cred : resp.credential_id()) {
    LOG(INFO) << "credential_id: " << HexEncodeStr(cred);
  }
}

void Cancel(dbus::ObjectProxy* proxy, const std::string& request_id) {
  u2f::CancelWebAuthnFlowRequest req;
  req.set_request_id_str(request_id);

  u2f::CancelWebAuthnFlowResponse resp =
      SendRequest<u2f::CancelWebAuthnFlowRequest,
                  u2f::CancelWebAuthnFlowResponse>(
          proxy, u2f::kU2FCancelWebAuthnFlow, req);

  LOG(INFO) << (resp.canceled() ? "Canceled" : "Not canceled");
}

void IsUvpaa(dbus::ObjectProxy* proxy) {
  u2f::IsUvpaaResponse resp =
      SendRequest<u2f::IsUvpaaRequest, u2f::IsUvpaaResponse>(
          proxy, u2f::kU2FIsUvpaa, u2f::IsUvpaaRequest());

  if (!resp.not_available()) {
    LOG(INFO) << "User verifying platform authenticator is available.";
  } else {
    LOG(INFO) << "User verifying platform authenticator is NOT available.";
  }
}

void IsU2fEnabled(dbus::ObjectProxy* proxy) {
  u2f::IsU2fEnabledResponse resp =
      SendRequest<u2f::IsU2fEnabledRequest, u2f::IsU2fEnabledResponse>(
          proxy, u2f::kU2FIsU2fEnabled, u2f::IsU2fEnabledRequest());
  LOG(INFO) << "U2f enabled ? " << resp.enabled();
}

int main(int argc, char* argv[]) {
  DEFINE_bool(make_credential, false, "make a credential");
  DEFINE_bool(get_assertion, false, "get an assertion");
  DEFINE_bool(has_credentials, false,
              "check validity/existence of credentials");
  DEFINE_bool(cancel, false, "cancel ongoing WebAuthn operations");
  DEFINE_bool(is_uvpaa, false, "check whether user-verification is available");
  DEFINE_bool(is_u2f_enabled, false, "check whether u2f is enabled");

  DEFINE_int32(verification_type, 1,
               "type of verification to request: presence=1, verification=2");
  DEFINE_string(rp_id, "", "relaying party ID (domain name)");
  DEFINE_string(request_id, "1",
                "identifier of a request, can be used for cancellation");
  DEFINE_string(client_data_hash, "", "client data hash, as a hex string");
  DEFINE_string(credential_id, "",
                "comma-separated list of credential IDs, as hex strings");
  DEFINE_string(excluded_credential_id, "",
                "comma-separated list of credential IDs to be exluded in "
                "MakeCredential, as hex strings");

  brillo::FlagHelper::Init(argc, argv,
                           "webauthntool - WebAuthn DBus API testing tool");
  brillo::InitLog(brillo::kLogToStderrIfTty);

  dbus::Bus::Options options;
  options.bus_type = dbus::Bus::SYSTEM;

  scoped_refptr<dbus::Bus> bus = new dbus::Bus(options);

  if (!bus->Connect()) {
    LOG(ERROR) << "Cannot connect to D-Bus.";
    return EX_IOERR;
  }

  dbus::ObjectProxy* u2f_proxy = bus->GetObjectProxy(
      u2f::kU2FServiceName, dbus::ObjectPath(u2f::kU2FServicePath));

  CHECK(u2f_proxy) << "Couldn't get u2f proxy";

  if (FLAGS_make_credential) {
    MakeCredential(u2f_proxy, FLAGS_verification_type, FLAGS_rp_id,
                   FLAGS_request_id,
                   ParseCommaDelimitedString(FLAGS_excluded_credential_id));
    return EX_OK;
  }

  if (FLAGS_get_assertion) {
    GetAssertion(u2f_proxy, FLAGS_verification_type, FLAGS_rp_id,
                 FLAGS_request_id, FLAGS_client_data_hash,
                 ParseCommaDelimitedString(FLAGS_credential_id));
    return EX_OK;
  }

  if (FLAGS_has_credentials) {
    HasCredentials(u2f_proxy, FLAGS_rp_id,
                   ParseCommaDelimitedString(FLAGS_credential_id));
    return EX_OK;
  }

  if (FLAGS_cancel) {
    Cancel(u2f_proxy, FLAGS_request_id);
    return EX_OK;
  }

  if (FLAGS_is_uvpaa) {
    IsUvpaa(u2f_proxy);
    return EX_OK;
  }

  if (FLAGS_is_u2f_enabled) {
    IsU2fEnabled(u2f_proxy);
    return EX_OK;
  }

  LOG(INFO) << "Please specify a command.";

  return EX_USAGE;
}
