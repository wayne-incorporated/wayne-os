// Copyright 2014 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stdio.h>
#include <sysexits.h>

#include <memory>
#include <optional>
#include <string>
#include <variant>

#include <attestation/proto_bindings/attestation_ca.pb.h>
#include <attestation/proto_bindings/interface.pb.h>
#include <attestation-client/attestation/dbus-proxies.h>
#include <base/check.h>
#include <base/command_line.h>
#include <base/files/file_util.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <base/task/single_thread_task_runner.h>
#include <brillo/daemons/daemon.h>
#include <brillo/dbus/dbus_connection.h>
#include <brillo/syslog_logging.h>
#include <libhwsec/factory/factory_impl.h>
#include <libhwsec/frontend/attestation/frontend.h>
#include <libhwsec-foundation/tpm/tpm_version.h>

#include "attestation/common/crypto_utility_impl.h"
#include "attestation/common/print_interface_proto.h"

namespace attestation {

namespace {

// The Daemon class works well as a client loop as well.
using ClientLoopBase = brillo::Daemon;

// Certificate profile specific request data. Loosely corresponds to `oneof`
// the proto fields at `GetCertificateRequest::metadata` in
// `dbus/attestation/interface.proto`. `CertProfileSpecificData` itself is
// equivalent to a type-safe tagged union type that can represent any of the
// types inside the `std::variant`.
using CertProfileSpecificData =
    std::variant<DeviceSetupCertificateRequestMetadata>;

constexpr base::TimeDelta kDefaultTimeout = base::Minutes(2);

const char kGetFeaturesCommand[] = "features";
const char kCreateCommand[] = "create";
const char kInfoCommand[] = "info";
const char kSetKeyPayloadCommand[] = "set_key_payload";
const char kDeleteKeysCommand[] = "delete_keys";
const char kEndorsementCommand[] = "endorsement";
const char kAttestationKeyCommand[] = "attestation_key";
const char kVerifyAttestationCommand[] = "verify_attestation";
const char kActivateCommand[] = "activate";
const char kEncryptForActivateCommand[] = "encrypt_for_activate";
const char kEncryptCommand[] = "encrypt";
const char kDecryptCommand[] = "decrypt";
const char kSignCommand[] = "sign";
const char kVerifyCommand[] = "verify";
const char kRegisterCommand[] = "register";
const char kStatusCommand[] = "status";
const char kCreateEnrollRequestCommand[] = "create_enroll_request";
const char kFinishEnrollCommand[] = "finish_enroll";
const char kEnrollCommand[] = "enroll";
const char kCreateCertRequestCommand[] = "create_cert_request";
const char kFinishCertRequestCommand[] = "finish_cert_request";
const char kGetCertCommand[] = "get_cert";
const char kSignChallengeCommand[] = "sign_challenge";
const char kGetEnrollmentId[] = "get_enrollment_id";
const char kGetCertifiedNvIndex[] = "get_certified_nv_index";
const char kDeviceSetupCertId[] = "device_setup_cert_id";
const char kDeviceSetupCertContentBinding[] =
    "device_setup_cert_content_binding";
const char kUsage[] = R"(
Usage: attestation_client <command> [<args>]
Commands:
  features
      Prints the features returned by attestation service.
  create [--user=<email>] [--label=<keylabel>] [--usage=sign|decrypt]
      Creates a certifiable key.
  set_key_payload [--user=<email>] --label=<keylabel> --input=<input_file>
      Reads payload from |input_file| and sets it for the specified key.
  delete_keys [--user=<email>]  --prefix=<prefix>
      Deletes all keys with the specified |prefix|.

  status [--extended]
      Requests and prints status or extended status: prepared_for_enrollment,
      enrolled, verified_boot [extended].
  info [--user=<email>] [--label=<keylabel>]
      Prints info about a key.
  endorsement
      Prints info about the TPM endorsement.
  attestation_key
      Prints info about the TPM attestation key.
  verify_attestation [--ek-only] [--cros-core]
      Verifies attestation information. If |ek-only| flag is provided,
      verifies only the endorsement key. If |cros-core| flag is provided,
      verifies using CrosCore CA public key.

  activate [--attestation-server=default|test] --input=<input_file> [--save]
      Activates an attestation key using the encrypted credential in
      |input_file| and optionally saves it for future certifications.
  encrypt_for_activate --input=<input_file> --output=<output_file>
      Encrypts the content of |input_file| as required by the TPM for
      activating an attestation key. The result is written to |output_file|.

  encrypt [--user=<email>] [--label=<keylabel>] --input=<input_file>
          --output=<output_file>
      Encrypts the contents of |input_file| as required by the TPM for a
      decrypt operation. The result is written to |output_file|.
  decrypt [--user=<email>] [--label=<keylabel>] --input=<input_file>
      Decrypts the contents of |input_file|.

  sign [--user=<email>] [--label=<keylabel>] --input=<input_file>
          [--output=<output_file>]
      Signs the contents of |input_file|.
  verify [--user=<email>] [--label=<keylabel] --input=<signed_data_file>
          --signature=<signature_file>
      Verifies the signature in |signature_file| against the contents of
      |input_file|.

  create_enroll_request [--attestation-server=default|test]
          [--output=<output_file>]
      Creates enroll request to CA and stores it to |output_file|.
  finish_enroll [--attestation-server=default|test] --input=<input_file>
      Finishes enrollment using the CA response from |input_file|.
  enroll [--attestation-server=default|test] [--forced]
      Enrolls the device to the specified CA.
  create_cert_request [--attestation-server=default|test]
        [--profile=<profile>] [--user=<user>] [--origin=<origin>]
        [--key-type={rsa|ecc}] [--output=<output_file>]
        [--device_setup_cert_id=<An id for the cert; usually device id>]
        [--device_setup_cert_content_binding=<A unique string, e.g. timestamp>]
      Creates certificate request to CA for |user|, using provided certificate
      |profile| and |origin|, and stores it to |output_file|.
      Possible |profile| values: user, machine, enrollment, content, cpsi, cast,
      gfsc, device_setup. Default is user.
      |device_setup_cert_id| and |device_setup_cert_content_binding| are
      required if |profile| is "device_setup".
  finish_cert_request [--attestation-server=default|test] [--user=<user>]
          [--label=<label>] --input=<input_file>
      Finishes certificate request for |user| using the CA response from
      |input_file|, and stores it in the key with the specified |label|.
  get_cert [--attestation-server=default|test] [--profile=<profile>]
        [--label=<label>] [--user=<user>] [--origin=<origin>]
        [--output=<output_file>] [--key-type={rsa|ecc}] [--forced]
        [--device_setup_cert_id=<An id for the cert; usually device id>]
        [--device_setup_cert_content_binding=<A unique string, e.g. timestamp>]
      Creates certificate request to CA for |user|, using provided certificate
      |profile| and |origin|, and sends to the specified CA, then stores it
      with the specified |label|.
      Possible |profile| values: user, machine, enrollment, content, cpsi,
      cast, gfsc, device_setup. Default is user.
      |device_setup_cert_id| and |device_setup_cert_content_binding| are
      required if |profile| is "device_setup".
  sign_challenge [--enterprise [--va_server=default|test]] [--user=<user>]
          [--label=<label>] [--domain=<domain>] [--device_id=<device_id>]
          [--spkac] --input=<input_file> [--output=<output_file>]
      Signs a challenge (EnterpriseChallenge, if |enterprise| flag is given,
        otherwise a SimpleChallenge) provided in the |input_file|. Stores
        the response in the |output_file|, if specified.

  register [--user=<email>] [--label=<keylabel]
      Registers a key with a PKCS #11 token.

  get_enrollment_id [--ignore_cache]
      Returns the enrollment ID. If ignore_cache option is provided, the ID is
        computed and the cache is not used to read, nor to update the value.
        Otherwise the value from cache is returned if present.

  get_certified_nv_index [--index=<nv_index>] [--size=<bytes>]
          [--key=<key_label>] [--output=<output_file>]
      Returns a copy of the specified NV index, certified by the specified
      key, eg "attest-ent-machine".
)";

// Reads parameters and `command_line` and optionally returns
// `CertProfileSpecificData` for `DEVICE_SETUP_CERTIFICATE`. Returns an empty
// optional if `command_line` does not contain the flags required for
// constructing `CertProfileSpecificData`.
std::optional<CertProfileSpecificData> CreateDeviceSetupProfileSpecificData(
    const base::CommandLine* command_line) {
  if (!command_line->HasSwitch(kDeviceSetupCertId)) {
    return std::nullopt;
  }

  if (!command_line->HasSwitch(kDeviceSetupCertContentBinding)) {
    return std::nullopt;
  }

  DeviceSetupCertificateRequestMetadata metadata;
  metadata.set_id(command_line->GetSwitchValueASCII(kDeviceSetupCertId));
  metadata.set_content_binding(
      command_line->GetSwitchValueASCII(kDeviceSetupCertContentBinding));
  return std::make_optional(CertProfileSpecificData(metadata));
}

std::optional<CertificateProfile> ToCertificateProfile(
    const std::string& profile) {
  if (profile.empty() || profile == "enterprise_user" || profile == "user" ||
      profile == "u") {
    return ENTERPRISE_USER_CERTIFICATE;
  }
  if (profile == "enterprise_machine" || profile == "machine" ||
      profile == "m") {
    return ENTERPRISE_MACHINE_CERTIFICATE;
  }
  if (profile == "enterprise_enrollment" || profile == "enrollment" ||
      profile == "e") {
    return ENTERPRISE_ENROLLMENT_CERTIFICATE;
  }
  if (profile == "content_protection" || profile == "content" ||
      profile == "c") {
    return CONTENT_PROTECTION_CERTIFICATE;
  }
  if (profile == "content_protection_with_stable_id" || profile == "cpsi") {
    return CONTENT_PROTECTION_CERTIFICATE_WITH_STABLE_ID;
  }
  if (profile == "cast") {
    return CAST_CERTIFICATE;
  }
  if (profile == "gfsc") {
    return GFSC_CERTIFICATE;
  }
  if (profile == "vtpm_ek" || profile == "vtpm") {
    return ENTERPRISE_VTPM_EK_CERTIFICATE;
  }
  if (profile == "device_setup") {
    return DEVICE_SETUP_CERTIFICATE;
  }
  return std::nullopt;
}

}  // namespace

class ClientLoop : public ClientLoopBase {
 public:
  ClientLoop() = default;
  ClientLoop(const ClientLoop&) = delete;
  ClientLoop& operator=(const ClientLoop&) = delete;

  ~ClientLoop() override = default;

 protected:
  int OnInit() override {
    int exit_code = ClientLoopBase::OnInit();
    if (exit_code != EX_OK) {
      return exit_code;
    }

    scoped_refptr<dbus::Bus> bus = connection_.Connect();
    CHECK(bus) << "Failed to connect to system D-Bus";
    attestation_ = std::make_unique<org::chromium::AttestationProxy>(bus);

    exit_code = ScheduleCommand();
    if (exit_code == EX_USAGE) {
      printf("%s", kUsage);
    }
    return exit_code;
  }

  void OnShutdown(int* exit_code) override {
    attestation_.reset();
    ClientLoopBase::OnShutdown(exit_code);
  }

 private:
  // Posts tasks according to the command line options.
  int ScheduleCommand() {
    base::OnceClosure task;
    base::CommandLine* command_line = base::CommandLine::ForCurrentProcess();
    const auto& args = command_line->GetArgs();
    if (command_line->HasSwitch("help") || command_line->HasSwitch("h") ||
        args.empty() || (!args.empty() && args.front() == "help")) {
      return EX_USAGE;
    } else if (args.front() == kGetFeaturesCommand) {
      task = base::BindOnce(&ClientLoop::CallGetFeatures,
                            weak_factory_.GetWeakPtr());
    } else if (args.front() == kCreateCommand) {
      std::string usage_str = command_line->GetSwitchValueASCII("usage");
      KeyUsage usage;
      if (usage_str.empty() || usage_str == "sign") {
        usage = KEY_USAGE_SIGN;
      } else if (usage_str == "decrypt") {
        usage = KEY_USAGE_DECRYPT;
      } else {
        return EX_USAGE;
      }
      task = base::BindOnce(&ClientLoop::CallCreateCertifiableKey,
                            weak_factory_.GetWeakPtr(),
                            command_line->GetSwitchValueASCII("label"),
                            command_line->GetSwitchValueASCII("user"), usage);
    } else if (args.front() == kStatusCommand) {
      task =
          base::BindOnce(&ClientLoop::CallGetStatus, weak_factory_.GetWeakPtr(),
                         command_line->HasSwitch("extended"));
    } else if (args.front() == kInfoCommand) {
      task = base::BindOnce(&ClientLoop::CallGetKeyInfo,
                            weak_factory_.GetWeakPtr(),
                            command_line->GetSwitchValueASCII("label"),
                            command_line->GetSwitchValueASCII("user"));
    } else if (args.front() == kSetKeyPayloadCommand) {
      if (!command_line->HasSwitch("input")) {
        return EX_USAGE;
      }
      std::string input;
      base::FilePath filename(command_line->GetSwitchValueASCII("input"));
      if (!base::ReadFileToString(filename, &input)) {
        LOG(ERROR) << "Failed to read file: " << filename.value();
        return EX_NOINPUT;
      }
      task = base::BindOnce(&ClientLoop::CallSetKeyPayload,
                            weak_factory_.GetWeakPtr(), input,
                            command_line->GetSwitchValueASCII("label"),
                            command_line->GetSwitchValueASCII("user"));
    } else if (args.front() == kDeleteKeysCommand) {
      if (command_line->HasSwitch("label") &&
          command_line->HasSwitch("prefix")) {
        return EX_USAGE;
      }
      task = base::BindOnce(&ClientLoop::CallDeleteKeys,
                            weak_factory_.GetWeakPtr(),
                            command_line->GetSwitchValueASCII("prefix"),
                            command_line->GetSwitchValueASCII("label"),
                            command_line->GetSwitchValueASCII("user"));
    } else if (args.front() == kEndorsementCommand) {
      task = base::BindOnce(&ClientLoop::CallGetEndorsementInfo,
                            weak_factory_.GetWeakPtr());
    } else if (args.front() == kAttestationKeyCommand) {
      ACAType aca_type;
      int status = GetCertificateAuthorityServerType(command_line, &aca_type);
      if (status != EX_OK) {
        return status;
      }
      task = base::BindOnce(&ClientLoop::CallGetAttestationKeyInfo,
                            weak_factory_.GetWeakPtr(), aca_type);
    } else if (args.front() == kVerifyAttestationCommand) {
      task = base::BindOnce(&ClientLoop::CallVerifyAttestation,
                            weak_factory_.GetWeakPtr(),
                            command_line->HasSwitch("cros-core"),
                            command_line->HasSwitch("ek-only"));
    } else if (args.front() == kActivateCommand) {
      ACAType aca_type;
      int status = GetCertificateAuthorityServerType(command_line, &aca_type);
      if (status != EX_OK) {
        return status;
      }
      if (!command_line->HasSwitch("input")) {
        return EX_USAGE;
      }
      std::string input;
      base::FilePath filename(command_line->GetSwitchValueASCII("input"));
      if (!base::ReadFileToString(filename, &input)) {
        LOG(ERROR) << "Failed to read file: " << filename.value();
        return EX_NOINPUT;
      }
      task = base::BindOnce(&ClientLoop::CallActivateAttestationKey,
                            weak_factory_.GetWeakPtr(), aca_type, input,
                            command_line->HasSwitch("save"));
    } else if (args.front() == kEncryptForActivateCommand) {
      if (!command_line->HasSwitch("input") ||
          !command_line->HasSwitch("output")) {
        return EX_USAGE;
      }
      std::string input;
      base::FilePath filename(command_line->GetSwitchValueASCII("input"));
      if (!base::ReadFileToString(filename, &input)) {
        LOG(ERROR) << "Failed to read file: " << filename.value();
        return EX_NOINPUT;
      }
      task = base::BindOnce(&ClientLoop::EncryptForActivate,
                            weak_factory_.GetWeakPtr(), input);
    } else if (args.front() == kEncryptCommand) {
      if (!command_line->HasSwitch("input") ||
          !command_line->HasSwitch("output")) {
        return EX_USAGE;
      }
      std::string input;
      base::FilePath filename(command_line->GetSwitchValueASCII("input"));
      if (!base::ReadFileToString(filename, &input)) {
        LOG(ERROR) << "Failed to read file: " << filename.value();
        return EX_NOINPUT;
      }
      task = base::BindOnce(&ClientLoop::Encrypt, weak_factory_.GetWeakPtr(),
                            command_line->GetSwitchValueASCII("label"),
                            command_line->GetSwitchValueASCII("user"), input);
    } else if (args.front() == kDecryptCommand) {
      if (!command_line->HasSwitch("input")) {
        return EX_USAGE;
      }
      std::string input;
      base::FilePath filename(command_line->GetSwitchValueASCII("input"));
      if (!base::ReadFileToString(filename, &input)) {
        LOG(ERROR) << "Failed to read file: " << filename.value();
        return EX_NOINPUT;
      }
      task =
          base::BindOnce(&ClientLoop::CallDecrypt, weak_factory_.GetWeakPtr(),
                         command_line->GetSwitchValueASCII("label"),
                         command_line->GetSwitchValueASCII("user"), input);
    } else if (args.front() == kSignCommand) {
      if (!command_line->HasSwitch("input")) {
        return EX_USAGE;
      }
      std::string input;
      base::FilePath filename(command_line->GetSwitchValueASCII("input"));
      if (!base::ReadFileToString(filename, &input)) {
        LOG(ERROR) << "Failed to read file: " << filename.value();
        return EX_NOINPUT;
      }
      task = base::BindOnce(&ClientLoop::CallSign, weak_factory_.GetWeakPtr(),
                            command_line->GetSwitchValueASCII("label"),
                            command_line->GetSwitchValueASCII("user"), input);
    } else if (args.front() == kVerifyCommand) {
      if (!command_line->HasSwitch("input") ||
          !command_line->HasSwitch("signature")) {
        return EX_USAGE;
      }
      std::string input;
      base::FilePath filename(command_line->GetSwitchValueASCII("input"));
      if (!base::ReadFileToString(filename, &input)) {
        LOG(ERROR) << "Failed to read file: " << filename.value();
        return EX_NOINPUT;
      }
      std::string signature;
      base::FilePath filename2(command_line->GetSwitchValueASCII("signature"));
      if (!base::ReadFileToString(filename2, &signature)) {
        LOG(ERROR) << "Failed to read file: " << filename2.value();
        return EX_NOINPUT;
      }
      task = base::BindOnce(
          &ClientLoop::VerifySignature, weak_factory_.GetWeakPtr(),
          command_line->GetSwitchValueASCII("label"),
          command_line->GetSwitchValueASCII("user"), input, signature);
    } else if (args.front() == kRegisterCommand) {
      task =
          base::BindOnce(&ClientLoop::CallRegister, weak_factory_.GetWeakPtr(),
                         command_line->GetSwitchValueASCII("label"),
                         command_line->GetSwitchValueASCII("user"));
    } else if (args.front() == kCreateEnrollRequestCommand) {
      ACAType aca_type;
      int status = GetCertificateAuthorityServerType(command_line, &aca_type);
      if (status != EX_OK) {
        return status;
      }
      task = base::BindOnce(&ClientLoop::CallCreateEnrollRequest,
                            weak_factory_.GetWeakPtr(), aca_type);
    } else if (args.front() == kFinishEnrollCommand) {
      ACAType aca_type;
      int status = GetCertificateAuthorityServerType(command_line, &aca_type);
      if (status != EX_OK) {
        return status;
      }
      if (!command_line->HasSwitch("input")) {
        return EX_USAGE;
      }
      std::string input;
      base::FilePath filename(command_line->GetSwitchValueASCII("input"));
      if (!base::ReadFileToString(filename, &input)) {
        LOG(ERROR) << "Failed to read file: " << filename.value();
        return EX_NOINPUT;
      }
      task = base::BindOnce(&ClientLoop::CallFinishEnroll,
                            weak_factory_.GetWeakPtr(), aca_type, input);
    } else if (args.front() == kEnrollCommand) {
      ACAType aca_type;
      int status = GetCertificateAuthorityServerType(command_line, &aca_type);
      if (status != EX_OK) {
        return status;
      }
      bool forced = command_line->HasSwitch("forced");
      task = base::BindOnce(&ClientLoop::CallEnroll, weak_factory_.GetWeakPtr(),
                            aca_type, forced);
    } else if (args.front() == kCreateCertRequestCommand) {
      ACAType aca_type;
      int status = GetCertificateAuthorityServerType(command_line, &aca_type);
      if (status != EX_OK) {
        return status;
      }
      KeyType key_type;
      status = GetKeyType(command_line, &key_type);
      if (status != EX_OK) {
        return status;
      }
      std::optional<CertificateProfile> profile =
          ToCertificateProfile(command_line->GetSwitchValueASCII("profile"));
      if (!profile.has_value()) {
        return EX_USAGE;
      }

      std::optional<CertProfileSpecificData> profile_specific_data;
      if (profile == DEVICE_SETUP_CERTIFICATE) {
        profile_specific_data =
            CreateDeviceSetupProfileSpecificData(command_line);
        if (!profile_specific_data) {
          return EX_USAGE;
        }
      }
      task = base::BindOnce(&ClientLoop::CallCreateCertRequest,
                            weak_factory_.GetWeakPtr(), aca_type, *profile,
                            command_line->GetSwitchValueASCII("user"),
                            command_line->GetSwitchValueASCII("origin"),
                            key_type, profile_specific_data);
    } else if (args.front() == kFinishCertRequestCommand) {
      if (!command_line->HasSwitch("input")) {
        return EX_USAGE;
      }
      std::string input;
      base::FilePath filename(command_line->GetSwitchValueASCII("input"));
      if (!base::ReadFileToString(filename, &input)) {
        LOG(ERROR) << "Failed to read file: " << filename.value();
        return EX_NOINPUT;
      }
      task = base::BindOnce(&ClientLoop::CallFinishCertRequest,
                            weak_factory_.GetWeakPtr(), input,
                            command_line->GetSwitchValueASCII("label"),
                            command_line->GetSwitchValueASCII("user"));
    } else if (args.front() == kGetCertCommand) {
      ACAType aca_type;
      int status = GetCertificateAuthorityServerType(command_line, &aca_type);
      if (status != EX_OK) {
        return status;
      }
      KeyType key_type;
      status = GetKeyType(command_line, &key_type);
      if (status != EX_OK) {
        return status;
      }
      std::optional<CertificateProfile> profile =
          ToCertificateProfile(command_line->GetSwitchValueASCII("profile"));
      if (!profile.has_value()) {
        return EX_USAGE;
      }
      bool forced = command_line->HasSwitch("forced");
      bool shall_trigger_enrollment = command_line->HasSwitch("enroll");

      std::optional<CertProfileSpecificData> profile_specific_data;
      if (profile == DEVICE_SETUP_CERTIFICATE) {
        profile_specific_data =
            CreateDeviceSetupProfileSpecificData(command_line);
        if (!profile_specific_data) {
          return EX_USAGE;
        }
      }

      task = base::BindOnce(
          &ClientLoop::CallGetCert, weak_factory_.GetWeakPtr(), aca_type,
          *profile, command_line->GetSwitchValueASCII("label"),
          command_line->GetSwitchValueASCII("user"),
          command_line->GetSwitchValueASCII("origin"), key_type, forced,
          shall_trigger_enrollment, profile_specific_data);
    } else if (args.front() == kSignChallengeCommand) {
      if (!command_line->HasSwitch("input")) {
        return EX_USAGE;
      }
      std::string input;
      base::FilePath filename(command_line->GetSwitchValueASCII("input"));
      if (!base::ReadFileToString(filename, &input)) {
        LOG(ERROR) << "Failed to read file: " << filename.value();
        return EX_NOINPUT;
      }
      if (command_line->HasSwitch("enterprise")) {
        VAType va_type;
        int status = GetVerifiedAccessServerType(command_line, &va_type);
        if (status != EX_OK) {
          return status;
        }
        task = base::BindOnce(&ClientLoop::CallSignEnterpriseChallenge,
                              weak_factory_.GetWeakPtr(), va_type, input,
                              command_line->GetSwitchValueASCII("label"),
                              command_line->GetSwitchValueASCII("user"),
                              command_line->GetSwitchValueASCII("domain"),
                              command_line->GetSwitchValueASCII("device_id"),
                              command_line->HasSwitch("spkac"));
      } else {
        task = base::BindOnce(&ClientLoop::CallSignSimpleChallenge,
                              weak_factory_.GetWeakPtr(), input,
                              command_line->GetSwitchValueASCII("label"),
                              command_line->GetSwitchValueASCII("user"));
      }
    } else if (args.front() == kGetEnrollmentId) {
      task = base::BindOnce(&ClientLoop::GetEnrollmentId,
                            weak_factory_.GetWeakPtr(),
                            command_line->HasSwitch("ignore_cache"));
    } else if (args.front() == kGetCertifiedNvIndex) {
      task = base::BindOnce(&ClientLoop::GetCertifiedNvIndex,
                            weak_factory_.GetWeakPtr(),
                            command_line->GetSwitchValueASCII("index"),
                            command_line->GetSwitchValueASCII("size"),
                            command_line->GetSwitchValueASCII("key_label"));
    } else {
      return EX_USAGE;
    }
    base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
        FROM_HERE, std::move(task));
    return EX_OK;
  }

  int GetVerifiedAccessServerType(base::CommandLine* command_line,
                                  VAType* va_type) {
    *va_type = DEFAULT_VA;
    if (command_line->HasSwitch("va-server")) {
      std::string va_server(command_line->GetSwitchValueASCII("va-server"));
      if (va_server == "test") {
        *va_type = TEST_VA;
      } else if (va_server != "" && va_server != "default") {
        LOG(ERROR) << "Invalid va-server value: " << va_server;
        return EX_USAGE;
      }
    } else {
      // Convert the CA type to a VA server type.
      ACAType aca_type;
      int status = GetCertificateAuthorityServerType(command_line, &aca_type);
      if (status != EX_OK) {
        return status;
      }
      switch (aca_type) {
        case TEST_ACA:
          *va_type = TEST_VA;
          break;

        case DEFAULT_ACA:
        default:
          *va_type = DEFAULT_VA;
          break;
      }
    }
    return EX_OK;
  }

  int GetCertificateAuthorityServerType(base::CommandLine* command_line,
                                        ACAType* aca_type) {
    *aca_type = DEFAULT_ACA;
    std::string aca_server(
        command_line->GetSwitchValueASCII("attestation-server"));
    if (aca_server == "test") {
      *aca_type = TEST_ACA;
    } else if (aca_server != "" && aca_server != "default") {
      LOG(ERROR) << "Invalid attestation-server value: " << aca_server;
      return EX_USAGE;
    }
    return EX_OK;
  }

  int GetKeyType(base::CommandLine* command_line, KeyType* key_type) {
    *key_type = KEY_TYPE_RSA;
    std::string key_type_str = command_line->GetSwitchValueASCII("key-type");
    if (key_type_str == "ecc") {
      *key_type = KEY_TYPE_ECC;
    } else if (key_type_str != "" && key_type_str != "rsa") {
      LOG(ERROR) << "Invalid key-type value: " << key_type_str;
      return EX_USAGE;
    }
    return EX_OK;
  }

  template <typename ProtobufType>
  void PrintReplyAndQuit(const ProtobufType& reply) {
    printf("%s\n", GetProtoDebugString(reply).c_str());
    Quit();
  }

  void WriteOutput(const std::string& output) {
    base::FilePath filename(
        base::CommandLine::ForCurrentProcess()->GetSwitchValueASCII("output"));
    if (base::WriteFile(filename, output.data(), output.size()) !=
        static_cast<int>(output.size())) {
      LOG(ERROR) << "Failed to write file: " << filename.value();
      QuitWithExitCode(EX_IOERR);
    }
  }

  void PrintErrorAndQuit(brillo::Error* error) {
    printf("Error: %s\n", error->GetMessage().c_str());
    Quit();
  }

  void CallGetStatus(bool extended_status) {
    GetStatusRequest request;
    request.set_extended_status(extended_status);
    attestation_->GetStatusAsync(
        request,
        base::BindOnce(&ClientLoop::PrintReplyAndQuit<GetStatusReply>,
                       weak_factory_.GetWeakPtr()),
        base::BindOnce(&ClientLoop::PrintErrorAndQuit,
                       weak_factory_.GetWeakPtr()),
        kDefaultTimeout.InMilliseconds());
  }

  void CallGetKeyInfo(const std::string& label, const std::string& username) {
    GetKeyInfoRequest request;
    request.set_key_label(label);
    request.set_username(username);
    attestation_->GetKeyInfoAsync(
        request,
        base::BindOnce(&ClientLoop::PrintReplyAndQuit<GetKeyInfoReply>,
                       weak_factory_.GetWeakPtr()),
        base::BindOnce(&ClientLoop::PrintErrorAndQuit,
                       weak_factory_.GetWeakPtr()),
        kDefaultTimeout.InMilliseconds());
  }

  void CallSetKeyPayload(const std::string& payload,
                         const std::string& label,
                         const std::string& username) {
    SetKeyPayloadRequest request;
    request.set_key_label(label);
    request.set_username(username);
    request.set_payload(payload);
    attestation_->SetKeyPayloadAsync(
        request,
        base::BindOnce(&ClientLoop::PrintReplyAndQuit<SetKeyPayloadReply>,
                       weak_factory_.GetWeakPtr()),
        base::BindOnce(&ClientLoop::PrintErrorAndQuit,
                       weak_factory_.GetWeakPtr()),
        kDefaultTimeout.InMilliseconds());
  }

  void CallDeleteKeys(const std::string& prefix,
                      const std::string& label,
                      const std::string& username) {
    DeleteKeysRequest request;
    if (!label.empty()) {
      request.set_key_label_match(label);
      request.set_match_behavior(DeleteKeysRequest::MATCH_BEHAVIOR_EXACT);
    }
    if (!prefix.empty()) {
      request.set_key_label_match(prefix);
      request.set_match_behavior(DeleteKeysRequest::MATCH_BEHAVIOR_PREFIX);
    }
    request.set_username(username);
    attestation_->DeleteKeysAsync(
        request,
        base::BindOnce(&ClientLoop::PrintReplyAndQuit<DeleteKeysReply>,
                       weak_factory_.GetWeakPtr()),
        base::BindOnce(&ClientLoop::PrintErrorAndQuit,
                       weak_factory_.GetWeakPtr()),
        kDefaultTimeout.InMilliseconds());
  }

  void CallGetEndorsementInfo() {
    GetEndorsementInfoRequest request;
    attestation_->GetEndorsementInfoAsync(
        request,
        base::BindOnce(&ClientLoop::PrintReplyAndQuit<GetEndorsementInfoReply>,
                       weak_factory_.GetWeakPtr()),
        base::BindOnce(&ClientLoop::PrintErrorAndQuit,
                       weak_factory_.GetWeakPtr()),
        kDefaultTimeout.InMilliseconds());
  }

  void CallGetAttestationKeyInfo(ACAType aca_type) {
    GetAttestationKeyInfoRequest request;
    request.set_aca_type(aca_type);
    attestation_->GetAttestationKeyInfoAsync(
        request,
        base::BindOnce(
            &ClientLoop::PrintReplyAndQuit<GetAttestationKeyInfoReply>,
            weak_factory_.GetWeakPtr()),
        base::BindOnce(&ClientLoop::PrintErrorAndQuit,
                       weak_factory_.GetWeakPtr()),
        kDefaultTimeout.InMilliseconds());
  }

  void CallVerifyAttestation(bool cros_core, bool ek_only) {
    VerifyRequest request;
    request.set_cros_core(cros_core);
    request.set_ek_only(ek_only);
    attestation_->VerifyAsync(
        request,
        base::BindOnce(&ClientLoop::PrintReplyAndQuit<VerifyReply>,
                       weak_factory_.GetWeakPtr()),
        base::BindOnce(&ClientLoop::PrintErrorAndQuit,
                       weak_factory_.GetWeakPtr()),
        kDefaultTimeout.InMilliseconds());
  }

  void CallActivateAttestationKey(ACAType aca_type,
                                  const std::string& input,
                                  bool save_certificate) {
    ActivateAttestationKeyRequest request;
    request.set_aca_type(aca_type);
    request.mutable_encrypted_certificate()->ParseFromString(input);
    request.set_save_certificate(save_certificate);
    attestation_->ActivateAttestationKeyAsync(
        request,
        base::BindOnce(
            &ClientLoop::PrintReplyAndQuit<ActivateAttestationKeyReply>,
            weak_factory_.GetWeakPtr()),
        base::BindOnce(&ClientLoop::PrintErrorAndQuit,
                       weak_factory_.GetWeakPtr()),
        kDefaultTimeout.InMilliseconds());
  }

  void EncryptForActivate(const std::string& input) {
    GetEndorsementInfoRequest request;
    attestation_->GetEndorsementInfoAsync(
        request,
        base::BindOnce(&ClientLoop::EncryptForActivate2,
                       weak_factory_.GetWeakPtr(), input),
        base::BindOnce(&ClientLoop::PrintErrorAndQuit,
                       weak_factory_.GetWeakPtr()),
        kDefaultTimeout.InMilliseconds());
  }

  void EncryptForActivate2(const std::string& input,
                           const GetEndorsementInfoReply& endorsement_info) {
    if (endorsement_info.status() != STATUS_SUCCESS) {
      PrintReplyAndQuit(endorsement_info);
    }
    GetAttestationKeyInfoRequest request;
    attestation_->GetAttestationKeyInfoAsync(
        request,
        base::BindOnce(&ClientLoop::EncryptForActivate3,
                       weak_factory_.GetWeakPtr(), input, endorsement_info),
        base::BindOnce(&ClientLoop::PrintErrorAndQuit,
                       weak_factory_.GetWeakPtr()),
        kDefaultTimeout.InMilliseconds());
  }

  void EncryptForActivate3(
      const std::string& input,
      const GetEndorsementInfoReply& endorsement_info,
      const GetAttestationKeyInfoReply& attestation_key_info) {
    if (attestation_key_info.status() != STATUS_SUCCESS) {
      PrintReplyAndQuit(attestation_key_info);
    }
    hwsec::FactoryImpl factory(hwsec::ThreadingMode::kCurrentThread);
    auto hwsec = factory.GetAttestationFrontend();
    CryptoUtilityImpl crypto(nullptr, hwsec.get());
    EncryptedIdentityCredential encrypted;

    TpmVersion tpm_version;
    TPM_SELECT_BEGIN;
    TPM1_SECTION({ tpm_version = TPM_1_2; });
    TPM2_SECTION({ tpm_version = TPM_2_0; });
    OTHER_TPM_SECTION({
      LOG(ERROR) << "Calling on none supported TPM platform.";
      tpm_version = TPM_2_0;
    });
    TPM_SELECT_END;

    if (!crypto.EncryptIdentityCredential(
            tpm_version, input, endorsement_info.ek_public_key(),
            attestation_key_info.public_key_tpm_format(), &encrypted)) {
      QuitWithExitCode(EX_SOFTWARE);
    }
    std::string output;
    encrypted.SerializeToString(&output);
    WriteOutput(output);
    Quit();
  }

  void CallGetFeatures() {
    GetFeaturesRequest request;
    attestation_->GetFeaturesAsync(
        request,
        base::BindOnce(&ClientLoop::PrintReplyAndQuit<GetFeaturesReply>,
                       weak_factory_.GetWeakPtr()),
        base::BindOnce(&ClientLoop::PrintErrorAndQuit,
                       weak_factory_.GetWeakPtr()),
        kDefaultTimeout.InMilliseconds());
  }

  void CallCreateCertifiableKey(const std::string& label,
                                const std::string& username,
                                KeyUsage usage) {
    CreateCertifiableKeyRequest request;
    request.set_key_label(label);
    request.set_username(username);
    request.set_key_type(KEY_TYPE_RSA);
    request.set_key_usage(usage);
    attestation_->CreateCertifiableKeyAsync(
        request,
        base::BindOnce(
            &ClientLoop::PrintReplyAndQuit<CreateCertifiableKeyReply>,
            weak_factory_.GetWeakPtr()),
        base::BindOnce(&ClientLoop::PrintErrorAndQuit,
                       weak_factory_.GetWeakPtr()),
        kDefaultTimeout.InMilliseconds());
  }

  void Encrypt(const std::string& label,
               const std::string& username,
               const std::string& input) {
    GetKeyInfoRequest request;
    request.set_key_label(label);
    request.set_username(username);
    attestation_->GetKeyInfoAsync(
        request,
        base::BindOnce(&ClientLoop::Encrypt2, weak_factory_.GetWeakPtr(),
                       input),
        base::BindOnce(&ClientLoop::PrintErrorAndQuit,
                       weak_factory_.GetWeakPtr()),
        kDefaultTimeout.InMilliseconds());
  }

  void Encrypt2(const std::string& input, const GetKeyInfoReply& key_info) {
    hwsec::FactoryImpl factory(hwsec::ThreadingMode::kCurrentThread);
    auto hwsec = factory.GetAttestationFrontend();
    CryptoUtilityImpl crypto(nullptr, hwsec.get());
    std::string output;
    if (!crypto.EncryptForUnbind(key_info.public_key(), input, &output)) {
      QuitWithExitCode(EX_SOFTWARE);
    }
    WriteOutput(output);
    Quit();
  }

  void CallDecrypt(const std::string& label,
                   const std::string& username,
                   const std::string& input) {
    DecryptRequest request;
    request.set_key_label(label);
    request.set_username(username);
    request.set_encrypted_data(input);
    attestation_->DecryptAsync(
        request,
        base::BindOnce(&ClientLoop::PrintReplyAndQuit<DecryptReply>,
                       weak_factory_.GetWeakPtr()),
        base::BindOnce(&ClientLoop::PrintErrorAndQuit,
                       weak_factory_.GetWeakPtr()),
        kDefaultTimeout.InMilliseconds());
  }

  void CallSign(const std::string& label,
                const std::string& username,
                const std::string& input) {
    SignRequest request;
    request.set_key_label(label);
    request.set_username(username);
    request.set_data_to_sign(input);
    attestation_->SignAsync(
        request,
        base::BindOnce(&ClientLoop::OnSignComplete, weak_factory_.GetWeakPtr()),
        base::BindOnce(&ClientLoop::PrintErrorAndQuit,
                       weak_factory_.GetWeakPtr()),
        kDefaultTimeout.InMilliseconds());
  }

  void OnSignComplete(const SignReply& reply) {
    if (reply.status() == STATUS_SUCCESS &&
        base::CommandLine::ForCurrentProcess()->HasSwitch("output")) {
      WriteOutput(reply.signature());
    }
    PrintReplyAndQuit<SignReply>(reply);
  }

  void VerifySignature(const std::string& label,
                       const std::string& username,
                       const std::string& input,
                       const std::string& signature) {
    GetKeyInfoRequest request;
    request.set_key_label(label);
    request.set_username(username);
    attestation_->GetKeyInfoAsync(
        request,
        base::BindOnce(&ClientLoop::VerifySignature2,
                       weak_factory_.GetWeakPtr(), input, signature),
        base::BindOnce(&ClientLoop::PrintErrorAndQuit,
                       weak_factory_.GetWeakPtr()),
        kDefaultTimeout.InMilliseconds());
  }

  void VerifySignature2(const std::string& input,
                        const std::string& signature,
                        const GetKeyInfoReply& key_info) {
    hwsec::FactoryImpl factory(hwsec::ThreadingMode::kCurrentThread);
    auto hwsec = factory.GetAttestationFrontend();
    CryptoUtilityImpl crypto(nullptr, hwsec.get());
    if (crypto.VerifySignature(crypto.DefaultDigestAlgoForSignature(),
                               key_info.public_key(), input, signature)) {
      printf("Signature is OK!\n");
    } else {
      printf("Signature is BAD!\n");
    }
    Quit();
  }

  void CallRegister(const std::string& label, const std::string& username) {
    RegisterKeyWithChapsTokenRequest request;
    request.set_key_label(label);
    request.set_username(username);
    attestation_->RegisterKeyWithChapsTokenAsync(
        request,
        base::BindOnce(
            &ClientLoop::PrintReplyAndQuit<RegisterKeyWithChapsTokenReply>,
            weak_factory_.GetWeakPtr()),
        base::BindOnce(&ClientLoop::PrintErrorAndQuit,
                       weak_factory_.GetWeakPtr()),
        kDefaultTimeout.InMilliseconds());
  }

  void CallCreateEnrollRequest(ACAType aca_type) {
    CreateEnrollRequestRequest request;
    request.set_aca_type(aca_type);
    attestation_->CreateEnrollRequestAsync(
        request,
        base::BindOnce(&ClientLoop::OnCreateEnrollRequestComplete,
                       weak_factory_.GetWeakPtr()),
        base::BindOnce(&ClientLoop::PrintErrorAndQuit,
                       weak_factory_.GetWeakPtr()),
        kDefaultTimeout.InMilliseconds());
  }

  void OnCreateEnrollRequestComplete(const CreateEnrollRequestReply& reply) {
    if (reply.status() == STATUS_SUCCESS &&
        base::CommandLine::ForCurrentProcess()->HasSwitch("output")) {
      WriteOutput(reply.pca_request());
    }
    PrintReplyAndQuit<CreateEnrollRequestReply>(reply);
  }

  void CallFinishEnroll(ACAType aca_type, const std::string& pca_response) {
    FinishEnrollRequest request;
    request.set_aca_type(aca_type);
    request.set_pca_response(pca_response);
    attestation_->FinishEnrollAsync(
        request,
        base::BindOnce(&ClientLoop::PrintReplyAndQuit<FinishEnrollReply>,
                       weak_factory_.GetWeakPtr()),
        base::BindOnce(&ClientLoop::PrintErrorAndQuit,
                       weak_factory_.GetWeakPtr()),
        kDefaultTimeout.InMilliseconds());
  }

  void CallEnroll(ACAType aca_type, bool forced) {
    EnrollRequest request;
    request.set_aca_type(aca_type);
    request.set_forced(forced);
    attestation_->EnrollAsync(
        request,
        base::BindOnce(&ClientLoop::PrintReplyAndQuit<EnrollReply>,
                       weak_factory_.GetWeakPtr()),
        base::BindOnce(&ClientLoop::PrintErrorAndQuit,
                       weak_factory_.GetWeakPtr()),
        kDefaultTimeout.InMilliseconds());
  }

  void CallCreateCertRequest(
      ACAType aca_type,
      CertificateProfile profile,
      const std::string& username,
      const std::string& origin,
      KeyType key_type,
      const std::optional<CertProfileSpecificData>& profile_specific_data) {
    CreateCertificateRequestRequest request;
    request.set_aca_type(aca_type);
    request.set_certificate_profile(profile);
    request.set_username(username);
    request.set_request_origin(origin);
    request.set_key_type(key_type);

    if (profile == DEVICE_SETUP_CERTIFICATE) {
      if (profile_specific_data &&
          std::holds_alternative<DeviceSetupCertificateRequestMetadata>(
              profile_specific_data.value())) {
        const DeviceSetupCertificateRequestMetadata& metadata =
            std::get<DeviceSetupCertificateRequestMetadata>(
                profile_specific_data.value());
        request.mutable_device_setup_certificate_request_metadata()->set_id(
            metadata.id());
        request.mutable_device_setup_certificate_request_metadata()
            ->set_content_binding(metadata.content_binding());
      }
    }

    attestation_->CreateCertificateRequestAsync(
        request,
        base::BindOnce(&ClientLoop::OnCreateCertRequestComplete,
                       weak_factory_.GetWeakPtr()),
        base::BindOnce(&ClientLoop::PrintErrorAndQuit,
                       weak_factory_.GetWeakPtr()),
        kDefaultTimeout.InMilliseconds());
  }

  void OnCreateCertRequestComplete(const CreateCertificateRequestReply& reply) {
    if (reply.status() == STATUS_SUCCESS &&
        base::CommandLine::ForCurrentProcess()->HasSwitch("output")) {
      WriteOutput(reply.pca_request());
    }
    PrintReplyAndQuit<CreateCertificateRequestReply>(reply);
  }

  void CallFinishCertRequest(const std::string& pca_response,
                             const std::string& label,
                             const std::string& username) {
    FinishCertificateRequestRequest request;
    request.set_pca_response(pca_response);
    request.set_key_label(label);
    request.set_username(username);
    attestation_->FinishCertificateRequestAsync(
        request,
        base::BindOnce(
            &ClientLoop::PrintReplyAndQuit<FinishCertificateRequestReply>,
            weak_factory_.GetWeakPtr()),
        base::BindOnce(&ClientLoop::PrintErrorAndQuit,
                       weak_factory_.GetWeakPtr()),
        kDefaultTimeout.InMilliseconds());
  }

  void CallGetCert(
      ACAType aca_type,
      CertificateProfile profile,
      const std::string& label,
      const std::string& username,
      const std::string& origin,
      KeyType key_type,
      bool forced,
      bool shall_trigger_enrollment,
      const std::optional<CertProfileSpecificData>& profile_specific_data) {
    GetCertificateRequest request;
    request.set_aca_type(aca_type);
    request.set_certificate_profile(profile);
    request.set_key_label(label);
    request.set_username(username);
    request.set_request_origin(origin);
    request.set_key_type(key_type);
    request.set_forced(forced);
    request.set_shall_trigger_enrollment(shall_trigger_enrollment);

    if (profile == DEVICE_SETUP_CERTIFICATE) {
      if (profile_specific_data &&
          std::holds_alternative<DeviceSetupCertificateRequestMetadata>(
              profile_specific_data.value())) {
        const DeviceSetupCertificateRequestMetadata& metadata =
            std::get<DeviceSetupCertificateRequestMetadata>(
                profile_specific_data.value());
        request.mutable_device_setup_certificate_request_metadata()->set_id(
            metadata.id());
        request.mutable_device_setup_certificate_request_metadata()
            ->set_content_binding(metadata.content_binding());
      }
    }

    attestation_->GetCertificateAsync(
        request,
        base::BindOnce(&ClientLoop::PrintReplyAndQuit<GetCertificateReply>,
                       weak_factory_.GetWeakPtr()),
        base::BindOnce(&ClientLoop::PrintErrorAndQuit,
                       weak_factory_.GetWeakPtr()),
        kDefaultTimeout.InMilliseconds());
  }

  void CallSignEnterpriseChallenge(VAType va_type,
                                   const std::string& input,
                                   const std::string& label,
                                   const std::string& username,
                                   const std::string& domain,
                                   const std::string& device_id,
                                   bool include_spkac) {
    SignEnterpriseChallengeRequest request;
    request.set_va_type(va_type);
    request.set_key_label(label);
    request.set_username(username);
    request.set_domain(domain);
    request.set_device_id(device_id);
    request.set_include_signed_public_key(include_spkac);
    request.set_challenge(input);
    attestation_->SignEnterpriseChallengeAsync(
        request,
        base::BindOnce(&ClientLoop::OnSignEnterpriseChallengeComplete,
                       weak_factory_.GetWeakPtr()),
        base::BindOnce(&ClientLoop::PrintErrorAndQuit,
                       weak_factory_.GetWeakPtr()),
        kDefaultTimeout.InMilliseconds());
  }

  void OnSignEnterpriseChallengeComplete(
      const SignEnterpriseChallengeReply& reply) {
    if (reply.status() == STATUS_SUCCESS &&
        base::CommandLine::ForCurrentProcess()->HasSwitch("output")) {
      WriteOutput(reply.challenge_response());
    }
    PrintReplyAndQuit<SignEnterpriseChallengeReply>(reply);
  }

  void CallSignSimpleChallenge(const std::string& input,
                               const std::string& label,
                               const std::string& username) {
    SignSimpleChallengeRequest request;
    request.set_key_label(label);
    request.set_username(username);
    request.set_challenge(input);
    attestation_->SignSimpleChallengeAsync(
        request,
        base::BindOnce(&ClientLoop::OnSignSimpleChallengeComplete,
                       weak_factory_.GetWeakPtr()),
        base::BindOnce(&ClientLoop::PrintErrorAndQuit,
                       weak_factory_.GetWeakPtr()),
        kDefaultTimeout.InMilliseconds());
  }

  void OnSignSimpleChallengeComplete(const SignSimpleChallengeReply& reply) {
    if (reply.status() == STATUS_SUCCESS &&
        base::CommandLine::ForCurrentProcess()->HasSwitch("output")) {
      WriteOutput(reply.challenge_response());
    }
    PrintReplyAndQuit<SignSimpleChallengeReply>(reply);
  }

  void GetEnrollmentId(bool ignore_cache) {
    GetEnrollmentIdRequest request;
    request.set_ignore_cache(ignore_cache);
    attestation_->GetEnrollmentIdAsync(
        request,
        base::BindOnce(&ClientLoop::OnGetEnrollmentIdComplete,
                       weak_factory_.GetWeakPtr()),
        base::BindOnce(&ClientLoop::PrintErrorAndQuit,
                       weak_factory_.GetWeakPtr()),
        kDefaultTimeout.InMilliseconds());
  }

  void OnGetEnrollmentIdComplete(const GetEnrollmentIdReply& reply) {
    PrintReplyAndQuit<GetEnrollmentIdReply>(reply);
  }

  void GetCertifiedNvIndex(const std::string& index,
                           const std::string& size_bytes,
                           const std::string& key_label) {
    GetCertifiedNvIndexRequest request;
    uint32_t parsed_index;
    uint32_t parsed_size;

    if (!base::HexStringToUInt(index, &parsed_index))
      LOG(ERROR) << "Failed to parse index.";
    if (!base::StringToUint(size_bytes, &parsed_size))
      LOG(ERROR) << "Failed to parse size.";

    request.set_nv_index(parsed_index);
    request.set_nv_size(parsed_size);
    request.set_key_label(key_label);

    attestation_->GetCertifiedNvIndexAsync(
        request,
        base::BindOnce(&ClientLoop::OnGetCertifiedNvIndexComplete,
                       weak_factory_.GetWeakPtr()),
        base::BindOnce(&ClientLoop::PrintErrorAndQuit,
                       weak_factory_.GetWeakPtr()),
        kDefaultTimeout.InMilliseconds());
  }

  void OnGetCertifiedNvIndexComplete(const GetCertifiedNvIndexReply& reply) {
    if (reply.status() == STATUS_SUCCESS &&
        base::CommandLine::ForCurrentProcess()->HasSwitch("output")) {
      WriteOutput(reply.SerializeAsString());
    }
    PrintReplyAndQuit<GetCertifiedNvIndexReply>(reply);
  }

  brillo::DBusConnection connection_;

  std::unique_ptr<org::chromium::AttestationProxy> attestation_;

  // Declare this last so weak pointers will be destroyed first.
  base::WeakPtrFactory<ClientLoop> weak_factory_{this};
};

}  // namespace attestation

int main(int argc, char* argv[]) {
  base::CommandLine::Init(argc, argv);
  brillo::InitLog(brillo::kLogToStderr);
  attestation::ClientLoop loop;
  return loop.Run();
}
