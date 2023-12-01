// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// Cryptohome client that uses the dbus client interface

#include <inttypes.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

#include <cstdarg>
#include <iostream>
#include <iterator>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <base/check.h>
#include <base/command_line.h>
#include <base/compiler_specific.h>
#include <base/files/file_descriptor_watcher_posix.h>
#include <base/files/file_path.h>
#include <base/logging.h>
#include <base/run_loop.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_split.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>
#include <base/task/single_thread_task_executor.h>
#include <base/time/time.h>
#include <brillo/cryptohome.h>
#include <brillo/dbus/dbus_connection.h>
#include <brillo/dbus/dbus_object.h>
#include <brillo/secure_blob.h>
#include <brillo/syslog_logging.h>
#include <chromeos/constants/cryptohome.h>
#include <chromeos/dbus/service_constants.h>
#include <cryptohome/proto_bindings/auth_factor.pb.h>
#include <cryptohome/proto_bindings/key.pb.h>
#include <cryptohome/proto_bindings/rpc.pb.h>
#include <cryptohome/proto_bindings/UserDataAuth.pb.h>
#include <dbus/cryptohome/dbus-constants.h>
#include <google/protobuf/message_lite.h>
#include <libhwsec-foundation/crypto/secure_blob_util.h>

#include "cryptohome/common/print_UserDataAuth_proto.h"
#include "cryptohome/crypto.h"
#include "cryptohome/filesystem_layout.h"
#include "cryptohome/pkcs11_init.h"
#include "cryptohome/platform.h"
#include "cryptohome/storage/homedirs.h"
#include "cryptohome/storage/mount_utils.h"
#include "cryptohome/timestamp.pb.h"
#include "cryptohome/username.h"
#include "cryptohome/vault_keyset.pb.h"
#include "user_data_auth/dbus-proxies.h"
// The dbus_adaptor and proxy include must happen after the protobuf include

using base::FilePath;
using brillo::SecureBlob;
using brillo::cryptohome::home::SanitizeUserNameWithSalt;
using hwsec_foundation::BlobToHex;
using hwsec_foundation::SecureBlobToHex;
using user_data_auth::GetProtoDebugString;

namespace {
// Duration that the set_current_user_old action uses when updating the home
// directory timestamp.  ~3 months should be old enough for test purposes.
constexpr base::TimeDelta kSetCurrentUserOldOffset = base::Days(92);

// Five minutes is enough to wait for any TPM operations, sync() calls, etc.
const int kDefaultTimeoutMs = 300000;

// Converts a brillo::Error* to string for printing.
std::string BrilloErrorToString(brillo::Error* err) {
  std::string result;
  if (err) {
    result = "(" + err->GetDomain() + ", " + err->GetCode() + ", " +
             err->GetMessage() + ")";
  } else {
    result = "(null)";
  }
  return result;
}

// Defines the output format to use for display.
enum class OutputFormat {
  // The default format used, geared towards human readability. This will use
  // the proto_print generated libraries for formatting any protobuf output, and
  // will also include informational text. It is not reliably machine-parsable.
  kDefault,
  // Binary protobuf format. The result of the underlying dbus request will be
  // written to standard output, in serialized binary format. Any other
  // informational output will be written to standard error.
  kBinaryProtobuf,
};

class Printer {
 public:
  explicit Printer(OutputFormat output_format)
      : output_format_(output_format) {}
  ~Printer() = default;

  // No copying. Share the printer by pointer or reference.
  Printer(Printer&) = delete;
  Printer& operator=(Printer&) = delete;
  Printer(Printer&&) = delete;
  Printer& operator=(Printer&&) = delete;

  // Print the reply protobuf from a command request.
  template <typename T>
  void PrintReplyProtobuf(const T& protobuf) {
    switch (output_format_) {
      case OutputFormat::kDefault:
        std::cout << GetProtoDebugString(protobuf);
        return;
      case OutputFormat::kBinaryProtobuf:
        protobuf.SerializeToOstream(&std::cout);
        return;
    }
  }
  // Print a human-oriented text string to output.
  void PrintHumanOutput(const std::string& str) {
    switch (output_format_) {
      case OutputFormat::kDefault:
        std::cout << str;
        return;
      case OutputFormat::kBinaryProtobuf:
        std::cerr << str;
        return;
    }
  }
  // A version of PrintHumanOutput that uses printf-style formatting.
  void PrintFormattedHumanOutput(const char* format, ...) PRINTF_FORMAT(2, 3) {
    va_list ap;
    va_start(ap, format);
    std::string output;
    base::StringAppendV(&output, format, ap);
    va_end(ap);
    PrintHumanOutput(output);
  }

  // Force a write of any of the buffers in the underlying streams.
  void Flush() {
    switch (output_format_) {
      case OutputFormat::kDefault:
        std::cout.flush();
        return;
      case OutputFormat::kBinaryProtobuf:
        std::cout.flush();
        std::cerr.flush();
        return;
    }
  }

 private:
  const OutputFormat output_format_;
};

}  // namespace

namespace switches {
namespace {
constexpr char kSyslogSwitch[] = "syslog";
constexpr struct {
  const char* name;
  const OutputFormat format;
} kOutputFormats[] = {{"default", OutputFormat::kDefault},
                      {"binary-protobuf", OutputFormat::kBinaryProtobuf}};
constexpr char kOutputFormatSwitch[] = "output-format";
constexpr char kActionSwitch[] = "action";
constexpr const char* kActions[] = {"unmount",
                                    "is_mounted",
                                    "list_keys_ex",
                                    "update_key_ex",
                                    "remove",
                                    "obfuscate_user",
                                    "get_system_salt",
                                    "dump_keyset",
                                    "dump_last_activity",
                                    "set_current_user_old",
                                    "install_attributes_set",
                                    "install_attributes_get",
                                    "install_attributes_finalize",
                                    "install_attributes_count",
                                    "install_attributes_get_status",
                                    "install_attributes_is_ready",
                                    "install_attributes_is_secure",
                                    "install_attributes_is_invalid",
                                    "install_attributes_is_first_install",
                                    "pkcs11_get_user_token_info",
                                    "pkcs11_get_system_token_info",
                                    "pkcs11_is_user_token_ok",
                                    "pkcs11_terminate",
                                    "pkcs11_restore_tpm_tokens",
                                    "get_login_status",
                                    "get_firmware_management_parameters",
                                    "set_firmware_management_parameters",
                                    "remove_firmware_management_parameters",
                                    "migrate_to_dircrypto",
                                    "needs_dircrypto_migration",
                                    "get_supported_key_policies",
                                    "get_account_disk_usage",
                                    "lock_to_single_user_mount_until_reboot",
                                    "get_rsu_device_id",
                                    "start_auth_session",
                                    "invalidate_auth_session",
                                    "extend_auth_session",
                                    "create_persistent_user",
                                    "prepare_guest_vault",
                                    "prepare_ephemeral_vault",
                                    "prepare_persistent_vault",
                                    "prepare_vault_for_migration",
                                    "add_auth_factor",
                                    "authenticate_auth_factor",
                                    "authenticate_with_status_update",
                                    "fetch_status_update",
                                    "update_auth_factor",
                                    "remove_auth_factor",
                                    "list_auth_factors",
                                    "get_auth_session_status",
                                    "get_recovery_request",
                                    "reset_application_container",
                                    "prepare_auth_factor",
                                    "terminate_auth_factor",
                                    "prepare_and_add_auth_factor",
                                    "prepare_and_authenticate_auth_factor",
                                    nullptr};
enum ActionEnum {
  ACTION_UNMOUNT,
  ACTION_MOUNTED,
  ACTION_LIST_KEYS_EX,
  ACTION_UPDATE_KEY_EX,
  ACTION_REMOVE,
  ACTION_OBFUSCATE_USER,
  ACTION_GET_SYSTEM_SALT,
  ACTION_DUMP_KEYSET,
  ACTION_DUMP_LAST_ACTIVITY,
  ACTION_SET_CURRENT_USER_OLD,
  ACTION_INSTALL_ATTRIBUTES_SET,
  ACTION_INSTALL_ATTRIBUTES_GET,
  ACTION_INSTALL_ATTRIBUTES_FINALIZE,
  ACTION_INSTALL_ATTRIBUTES_COUNT,
  ACTION_INSTALL_ATTRIBUTES_GET_STATUS,
  ACTION_INSTALL_ATTRIBUTES_IS_READY,
  ACTION_INSTALL_ATTRIBUTES_IS_SECURE,
  ACTION_INSTALL_ATTRIBUTES_IS_INVALID,
  ACTION_INSTALL_ATTRIBUTES_IS_FIRST_INSTALL,
  ACTION_PKCS11_GET_USER_TOKEN_INFO,
  ACTION_PKCS11_GET_SYSTEM_TOKEN_INFO,
  ACTION_PKCS11_IS_USER_TOKEN_OK,
  ACTION_PKCS11_TERMINATE,
  ACTION_PKCS11_RESTORE_TPM_TOKENS,
  ACTION_GET_LOGIN_STATUS,
  ACTION_GET_FIRMWARE_MANAGEMENT_PARAMETERS,
  ACTION_SET_FIRMWARE_MANAGEMENT_PARAMETERS,
  ACTION_REMOVE_FIRMWARE_MANAGEMENT_PARAMETERS,
  ACTION_MIGRATE_TO_DIRCRYPTO,
  ACTION_NEEDS_DIRCRYPTO_MIGRATION,
  ACTION_GET_SUPPORTED_KEY_POLICIES,
  ACTION_GET_ACCOUNT_DISK_USAGE,
  ACTION_LOCK_TO_SINGLE_USER_MOUNT_UNTIL_REBOOT,
  ACTION_GET_RSU_DEVICE_ID,
  ACTION_START_AUTH_SESSION,
  ACTION_INVALIDATE_AUTH_SESSION,
  ACTION_EXTEND_AUTH_SESSION,
  ACTION_CREATE_PERSISTENT_USER,
  ACTION_PREPARE_GUEST_VAULT,
  ACTION_PREPARE_EPHEMERAL_VAULT,
  ACTION_PREPARE_PERSISTENT_VAULT,
  ACTION_PREPARE_VAULT_FOR_MIGRATION,
  ACTION_ADD_AUTH_FACTOR,
  ACTION_AUTHENTICATE_AUTH_FACTOR,
  ACTION_AUTHENTICATE_WITH_STATUS_UPDATE,
  ACTION_FETCH_STATUS_UPDATE,
  ACTION_UPDATE_AUTH_FACTOR,
  ACTION_REMOVE_AUTH_FACTOR,
  ACTION_LIST_AUTH_FACTORS,
  ACTION_GET_AUTH_SESSION_STATUS,
  ACTION_GET_RECOVERY_REQUEST,
  ACTION_RESET_APPLICATION_CONTAINER,
  ACTION_PREPARE_AUTH_FACTOR,
  ACTION_TERMINATE_AUTH_FACTOR,
  ACTION_PREPARE_AND_ADD_AUTH_FACTOR,
  ACTION_PREPARE_AND_AUTHENTICATE_AUTH_FACTOR,
};
constexpr char kUserSwitch[] = "user";
constexpr char kPasswordSwitch[] = "password";
constexpr char kKeyLabelSwitch[] = "key_label";
constexpr char kKeyLabelsSwitch[] = "key_labels";
constexpr char kNewKeyLabelSwitch[] = "new_key_label";
constexpr char kForceSwitch[] = "force";
constexpr char kAttrNameSwitch[] = "name";
constexpr char kAttrValueSwitch[] = "value";
constexpr char kFileSwitch[] = "file";
constexpr char kInputFileSwitch[] = "input";
constexpr char kOutputFileSwitch[] = "output";
constexpr char kEnsureEphemeralSwitch[] = "ensure_ephemeral";
constexpr char kFlagsSwitch[] = "flags";
constexpr char kDevKeyHashSwitch[] = "developer_key_hash";
constexpr char kEcryptfsSwitch[] = "ecryptfs";
constexpr char kMinimalMigration[] = "minimal_migration";
constexpr char kPublicMount[] = "public_mount";
constexpr char kUseDBus[] = "use_dbus";
constexpr char kAuthSessionId[] = "auth_session_id";
constexpr char kChallengeAlgorithm[] = "challenge_alg";
constexpr char kChallengeSPKI[] = "challenge_spki";
constexpr char kKeyDelegateName[] = "key_delegate_name";
constexpr char kExtensionDuration[] = "extension_duration";
constexpr char kPinSwitch[] = "pin";
constexpr char kRecoveryMediatorPubKeySwitch[] = "recovery_mediator_pub_key";
constexpr char kRecoveryUserIdSwitch[] = "recovery_user_gaia_id";
constexpr char kRecoveryDeviceIdSwitch[] = "recovery_device_user_id";
constexpr char kRecoveryEpochResponseSwitch[] = "recovery_epoch_response";
constexpr char kRecoveryResponseSwitch[] = "recovery_response";
constexpr char kRecoveryLedgerNameSwitch[] = "recovery_ledger_name";
constexpr char kRecoveryLedgerPublicKeyHashSwitch[] =
    "recovery_ledger_pub_key_hash";
constexpr char kRecoveryLedgerPublicKeySwitch[] = "recovery_ledger_pub_key";
constexpr char kAuthIntentSwitch[] = "auth_intent";
constexpr char kApplicationName[] = "application_name";
constexpr char kFingerprintSwitch[] = "fingerprint";
constexpr char kPreparePurposeAddSwitch[] = "add";
constexpr char kPreparePurposeAuthSwitch[] = "auth";
constexpr char kUseTimeLockout[] = "timed_lockout";
}  // namespace
}  // namespace switches

namespace {
brillo::SecureBlob GetSystemSalt(
    org::chromium::CryptohomeMiscInterfaceProxy* proxy) {
  user_data_auth::GetSystemSaltRequest req;
  user_data_auth::GetSystemSaltReply reply;
  brillo::ErrorPtr error;
  if (!proxy->GetSystemSalt(req, &reply, &error, kDefaultTimeoutMs) || error) {
    LOG(ERROR) << "GetSystemSalt failed: " << BrilloErrorToString(error.get());
    return brillo::SecureBlob();
  }
  brillo::SecureBlob system_salt(reply.salt());
  return system_salt;
}

bool GetAttrName(Printer& printer,
                 const base::CommandLine* cl,
                 std::string* name_out) {
  *name_out = cl->GetSwitchValueASCII(switches::kAttrNameSwitch);

  if (name_out->length() == 0) {
    printer.PrintHumanOutput(
        "No install attribute name specified (--name=<name>)\n");
    return false;
  }
  return true;
}

bool GetAttrValue(Printer& printer,
                  const base::CommandLine* cl,
                  std::string* value_out) {
  *value_out = cl->GetSwitchValueASCII(switches::kAttrValueSwitch);

  if (value_out->length() == 0) {
    printer.PrintHumanOutput(
        "No install attribute value specified (--value=<value>)\n");
    return false;
  }
  return true;
}

bool GetAccountId(Printer& printer,
                  const base::CommandLine* cl,
                  cryptohome::Username& user_out) {
  user_out =
      cryptohome::Username(cl->GetSwitchValueASCII(switches::kUserSwitch));

  if (user_out->length() == 0) {
    printer.PrintHumanOutput("No user specified (--user=<account_id>)\n");
    return false;
  }
  return true;
}

bool GetAuthSessionId(Printer& printer,
                      const base::CommandLine* cl,
                      std::string* session_id_out) {
  *session_id_out = cl->GetSwitchValueASCII(switches::kAuthSessionId);

  if (session_id_out->length() == 0) {
    printer.PrintHumanOutput(
        "No auth_session_id specified (--auth_session_id=<auth_session_id>)\n");
    return false;
  }
  return true;
}

bool GetSecret(Printer& printer,
               org::chromium::CryptohomeMiscInterfaceProxy* proxy,
               const base::CommandLine* cl,
               const std::string& cl_switch,
               const std::string& prompt,
               std::string* secret_out) {
  std::string secret = cl->GetSwitchValueASCII(cl_switch);

  if (secret.length() == 0) {
    char buffer[256];
    struct termios original_attr;
    struct termios new_attr;
    tcgetattr(0, &original_attr);
    memcpy(&new_attr, &original_attr, sizeof(new_attr));
    new_attr.c_lflag &= ~(ECHO);
    tcsetattr(0, TCSANOW, &new_attr);
    printer.PrintFormattedHumanOutput("%s: ", prompt.c_str());
    printer.Flush();
    if (fgets(buffer, std::size(buffer), stdin))
      secret = buffer;
    printer.PrintHumanOutput("\n");
    tcsetattr(0, TCSANOW, &original_attr);
  }

  std::string trimmed_secret;
  base::TrimString(secret, "\r\n", &trimmed_secret);
  SecureBlob passkey;
  cryptohome::Crypto::PasswordToPasskey(trimmed_secret.c_str(),
                                        GetSystemSalt(proxy), &passkey);
  *secret_out = passkey.to_string();

  return true;
}

bool IsMixingOldAndNewFileSwitches(const base::CommandLine* cl) {
  return cl->HasSwitch(switches::kFileSwitch) &&
         (cl->HasSwitch(switches::kInputFileSwitch) ||
          cl->HasSwitch(switches::kOutputFileSwitch));
}

bool ConfirmRemove(Printer& printer, const cryptohome::Username& user) {
  printer.PrintHumanOutput(
      "!!! Are you sure you want to remove the user's cryptohome?\n");
  printer.PrintHumanOutput("!!!\n");
  printer.PrintHumanOutput(
      "!!! Re-enter the username at the prompt to remove the\n");
  printer.PrintHumanOutput("!!! cryptohome for the user.\n");
  printer.PrintFormattedHumanOutput("Enter the username <%s>: ", user->c_str());
  printer.Flush();

  char buffer[256];
  if (!fgets(buffer, std::size(buffer), stdin)) {
    printer.PrintHumanOutput("Error while reading username.\n");
    return false;
  }
  std::string verification = buffer;
  // fgets will append the newline character, remove it.
  base::TrimWhitespaceASCII(verification, base::TRIM_ALL, &verification);
  if (*user != verification) {
    printer.PrintHumanOutput("Usernames do not match.\n");
    return false;
  }
  return true;
}

bool BuildAccountId(Printer& printer,
                    const base::CommandLine* cl,
                    cryptohome::AccountIdentifier* id) {
  cryptohome::Username account_id;
  if (!GetAccountId(printer, cl, account_id)) {
    printer.PrintHumanOutput("No account_id specified.\n");
    return false;
  }
  id->set_account_id(*account_id);
  return true;
}

bool BuildStartAuthSessionRequest(
    Printer& printer,
    const base::CommandLine& cl,
    user_data_auth::StartAuthSessionRequest& req) {
  if (!BuildAccountId(printer, &cl, req.mutable_account_id())) {
    return false;
  }
  unsigned int flags = 0;
  flags |= cl.HasSwitch(switches::kEnsureEphemeralSwitch)
               ? user_data_auth::AUTH_SESSION_FLAGS_EPHEMERAL_USER
               : 0;
  req.set_flags(flags);
  if (cl.HasSwitch(switches::kAuthIntentSwitch)) {
    std::string intent_string =
        cl.GetSwitchValueASCII(switches::kAuthIntentSwitch);
    user_data_auth::AuthIntent intent;
    if (!AuthIntent_Parse(intent_string, &intent)) {
      printer.PrintFormattedHumanOutput("Invalid auth intent \"%s\".\n",
                                        intent_string.c_str());
      return false;
    }
    req.set_intent(intent);
  }
  return true;
}

bool BuildAuthFactor(Printer& printer,
                     base::CommandLine* cl,
                     user_data_auth::AuthFactor* auth_factor) {
  std::string label = cl->GetSwitchValueASCII(switches::kKeyLabelSwitch);
  if (label.empty()) {
    printer.PrintHumanOutput("No auth factor label specified\n");
    return false;
  }
  auth_factor->set_label(label);
  if (cl->HasSwitch(switches::kPasswordSwitch)) {
    auth_factor->set_type(user_data_auth::AUTH_FACTOR_TYPE_PASSWORD);
    // Password metadata has no fields currently.
    auth_factor->mutable_password_metadata();
    return true;
  } else if (cl->HasSwitch(switches::kPinSwitch)) {
    auth_factor->set_type(user_data_auth::AUTH_FACTOR_TYPE_PIN);
    // Pin metadata has no fields currently.
    auth_factor->mutable_pin_metadata();
    auth_factor->mutable_common_metadata()->set_lockout_policy(
        cl->HasSwitch(switches::kUseTimeLockout)
            ? user_data_auth::LOCKOUT_POLICY_TIME_LIMITED
            : user_data_auth::LOCKOUT_POLICY_ATTEMPT_LIMITED);
    return true;
  } else if (cl->HasSwitch(switches::kRecoveryMediatorPubKeySwitch)) {
    auth_factor->set_type(user_data_auth::AUTH_FACTOR_TYPE_CRYPTOHOME_RECOVERY);
    // Recovery metadata has no fields currently.
    auth_factor->mutable_cryptohome_recovery_metadata();
    return true;
  } else if (cl->HasSwitch(switches::kPublicMount)) {
    auth_factor->set_type(user_data_auth::AUTH_FACTOR_TYPE_KIOSK);
    auth_factor->mutable_kiosk_metadata();
    return true;
  } else if (cl->HasSwitch(switches::kChallengeSPKI)) {
    // Parameters for smart card metadata:
    // --challenge_spki=<DER Encoded SPKI Public Key in hex>
    auth_factor->set_type(user_data_auth::AUTH_FACTOR_TYPE_SMART_CARD);

    std::string challenge_spki;
    if (!base::HexStringToString(
            cl->GetSwitchValueASCII(switches::kChallengeSPKI),
            &challenge_spki)) {
      printf("Challenge SPKI Public Key DER is not hex encoded.\n");
      return false;
    }
    auth_factor->mutable_smart_card_metadata()->set_public_key_spki_der(
        challenge_spki);
    return true;
  } else if (cl->HasSwitch(switches::kFingerprintSwitch)) {
    auth_factor->set_type(user_data_auth::AUTH_FACTOR_TYPE_FINGERPRINT);
    auth_factor->mutable_fingerprint_metadata();
    return true;
  }
  printer.PrintHumanOutput("No auth factor specified\n");
  return false;
}

bool BuildAuthInput(Printer& printer,
                    base::CommandLine* cl,
                    org::chromium::CryptohomeMiscInterfaceProxy* proxy,
                    user_data_auth::AuthInput* auth_input) {
  // TODO(b/208357699): Support other auth factor types.
  std::string password;
  if (cl->HasSwitch(switches::kPasswordSwitch)) {
    std::string password;
    if (GetSecret(printer, proxy, cl, switches::kPasswordSwitch,
                  "Enter the password", &password)) {
      auth_input->mutable_password_input()->set_secret(password);
      return true;
    }
  } else if (cl->HasSwitch(switches::kPinSwitch)) {
    std::string pin;
    if (GetSecret(printer, proxy, cl, switches::kPinSwitch, "Enter the pin",
                  &pin)) {
      auth_input->mutable_pin_input()->set_secret(pin);
      return true;
    }
  } else if (cl->HasSwitch(switches::kRecoveryMediatorPubKeySwitch)) {
    std::string mediator_pub_key_hex =
        cl->GetSwitchValueASCII(switches::kRecoveryMediatorPubKeySwitch);
    std::string mediator_pub_key;
    if (!base::HexStringToString(mediator_pub_key_hex.c_str(),
                                 &mediator_pub_key)) {
      printer.PrintHumanOutput(
          "Couldn't convert mediator_pub_key_hex to string\n");
      return false;
    }
    auth_input->mutable_cryptohome_recovery_input()->set_mediator_pub_key(
        mediator_pub_key);
    if (cl->HasSwitch(switches::kRecoveryUserIdSwitch)) {
      std::string user_gaia_id =
          cl->GetSwitchValueASCII(switches::kRecoveryUserIdSwitch);
      auth_input->mutable_cryptohome_recovery_input()->set_user_gaia_id(
          user_gaia_id);
    }
    if (cl->HasSwitch(switches::kRecoveryDeviceIdSwitch)) {
      std::string device_user_id =
          cl->GetSwitchValueASCII(switches::kRecoveryDeviceIdSwitch);
      auth_input->mutable_cryptohome_recovery_input()->set_device_user_id(
          device_user_id);
    }
    return true;
  } else if (cl->HasSwitch(switches::kRecoveryResponseSwitch)) {
    std::string recovery_response_hex =
        cl->GetSwitchValueASCII(switches::kRecoveryResponseSwitch);
    std::string recovery_response;
    if (!base::HexStringToString(recovery_response_hex.c_str(),
                                 &recovery_response)) {
      printer.PrintHumanOutput(
          "Couldn't convert recovery_response_hex to string\n");
      return false;
    }
    auth_input->mutable_cryptohome_recovery_input()->set_recovery_response(
        recovery_response);

    if (!cl->HasSwitch(switches::kRecoveryEpochResponseSwitch)) {
      printer.PrintFormattedHumanOutput("No %s switch specified\n",
                                        switches::kRecoveryEpochResponseSwitch);
      return false;
    }
    std::string epoch_response_hex =
        cl->GetSwitchValueASCII(switches::kRecoveryEpochResponseSwitch);
    std::string epoch_response;
    if (!base::HexStringToString(epoch_response_hex.c_str(), &epoch_response)) {
      printer.PrintHumanOutput(
          "Couldn't convert epoch_response_hex to string\n");
      return false;
    }
    auth_input->mutable_cryptohome_recovery_input()->set_epoch_response(
        epoch_response);

    if (!cl->HasSwitch(switches::kRecoveryLedgerNameSwitch)) {
      printer.PrintFormattedHumanOutput("No %s switch specified\n",
                                        switches::kRecoveryLedgerNameSwitch);
      return false;
    }
    if (!cl->HasSwitch(switches::kRecoveryLedgerPublicKeyHashSwitch)) {
      printer.PrintFormattedHumanOutput(
          "No %s switch specified\n",
          switches::kRecoveryLedgerPublicKeyHashSwitch);
      return false;
    }
    if (!cl->HasSwitch(switches::kRecoveryLedgerPublicKeySwitch)) {
      printer.PrintFormattedHumanOutput(
          "No %s switch specified\n", switches::kRecoveryLedgerPublicKeySwitch);
      return false;
    }
    std::string ledger_name =
        cl->GetSwitchValueASCII(switches::kRecoveryLedgerNameSwitch);
    auth_input->mutable_cryptohome_recovery_input()
        ->mutable_ledger_info()
        ->set_name(ledger_name);
    uint32_t pub_key_hash;
    if (!base::StringToUint(cl->GetSwitchValueASCII(
                                switches::kRecoveryLedgerPublicKeyHashSwitch),
                            &pub_key_hash)) {
      printer.PrintFormattedHumanOutput(
          "ledger_pub_key_hash value cannot be converted to int.\n");
      return false;
    }
    auth_input->mutable_cryptohome_recovery_input()
        ->mutable_ledger_info()
        ->set_key_hash(pub_key_hash);
    std::string pub_key =
        cl->GetSwitchValueASCII(switches::kRecoveryLedgerPublicKeySwitch);
    auth_input->mutable_cryptohome_recovery_input()
        ->mutable_ledger_info()
        ->set_public_key(pub_key);
    return true;
  } else if (cl->HasSwitch(switches::kPublicMount)) {
    auth_input->mutable_kiosk_input();
    return true;
  } else if (cl->HasSwitch(switches::kChallengeAlgorithm) ||
             cl->HasSwitch(switches::kKeyDelegateName)) {
    // We're doing challenge response auth.
    // Parameters for SmartCardAuthInput:
    // --challenge_alg=<Algorithm>(,<Algorithm>)*: See
    //   SmartCardSignatureAlgorithm in auth_factor.proto for valid values.
    //   Example: "CHALLENGE_RSASSA_PKCS1_V1_5_SHA1".
    // --key_delegate_name=<Key Delegate DBus Service Name>

    // Check that all parameters are supplied.
    if (!(cl->HasSwitch(switches::kChallengeAlgorithm) &&
          cl->HasSwitch(switches::kKeyDelegateName))) {
      printer.PrintFormattedHumanOutput(
          "One or more of the switches for challenge response auth is "
          "missing.\n");
      return false;
    }

    const std::vector<std::string> algo_strings =
        SplitString(cl->GetSwitchValueASCII(switches::kChallengeAlgorithm), ",",
                    base::TRIM_WHITESPACE, base::SPLIT_WANT_NONEMPTY);
    for (const auto& algo_string : algo_strings) {
      user_data_auth::SmartCardSignatureAlgorithm challenge_alg;
      if (!SmartCardSignatureAlgorithm_Parse(algo_string, &challenge_alg)) {
        printer.PrintFormattedHumanOutput(
            "Invalid challenge response algorithm \"%s\".\n",
            algo_string.c_str());
        return false;
      }
      auth_input->mutable_smart_card_input()->add_signature_algorithms(
          challenge_alg);
    }
    auth_input->mutable_smart_card_input()->set_key_delegate_dbus_service_name(
        cl->GetSwitchValueASCII(switches::kKeyDelegateName));
    return true;
  } else if (cl->HasSwitch(switches::kFingerprintSwitch)) {
    auth_input->mutable_fingerprint_input();
    return true;
  }
  printer.PrintHumanOutput("No auth input specified\n");
  return false;
}

bool GetAuthFactorType(Printer& printer,
                       base::CommandLine* cl,
                       user_data_auth::AuthFactorType* auth_factor_type) {
  if (cl->HasSwitch(switches::kPasswordSwitch)) {
    *auth_factor_type = user_data_auth::AUTH_FACTOR_TYPE_PASSWORD;
    return true;
  } else if (cl->HasSwitch(switches::kPinSwitch)) {
    *auth_factor_type = user_data_auth::AUTH_FACTOR_TYPE_PIN;
    return true;
  } else if (cl->HasSwitch(switches::kRecoveryMediatorPubKeySwitch)) {
    *auth_factor_type = user_data_auth::AUTH_FACTOR_TYPE_CRYPTOHOME_RECOVERY;
    return true;
  } else if (cl->HasSwitch(switches::kPublicMount)) {
    *auth_factor_type = user_data_auth::AUTH_FACTOR_TYPE_KIOSK;
    return true;
  } else if (cl->HasSwitch(switches::kChallengeSPKI)) {
    *auth_factor_type = user_data_auth::AUTH_FACTOR_TYPE_SMART_CARD;
    return true;
  } else if (cl->HasSwitch(switches::kFingerprintSwitch)) {
    *auth_factor_type = user_data_auth::AUTH_FACTOR_TYPE_FINGERPRINT;
    return true;
  }
  printer.PrintHumanOutput("No auth factor type specified\n");
  return false;
}

bool GetPreparePurpose(Printer& printer,
                       base::CommandLine* cl,
                       user_data_auth::AuthFactorPreparePurpose* purpose) {
  if (cl->HasSwitch(switches::kPreparePurposeAddSwitch)) {
    *purpose = user_data_auth::PURPOSE_ADD_AUTH_FACTOR;
    return true;
  } else if (cl->HasSwitch(switches::kPreparePurposeAuthSwitch)) {
    *purpose = user_data_auth::PURPOSE_AUTHENTICATE_AUTH_FACTOR;
    return true;
  }
  printer.PrintHumanOutput("No auth factor prepare purpose specified\n");
  return false;
}

// This is used as the signal callback for the PrepareAuthFactorProgress signal
// emitted from userdataauth service. |auth_factor_type| and |prepare_purpose|
// are the parameters specified by the user, which are passed to the callback so
// we only parse relevant signals. The CLI will indefinitely block on upcoming
// signals, so when we know that the preparation is finished (either because the
// operation has completed or a failure has occurred), we need to quit
// |run_loop| and write to |ret_code| for the CLI process to end with that
// return code.
void OnPrepareSignal(
    base::RunLoop* run_loop,
    int* ret_code,
    Printer* printer,
    user_data_auth::AuthFactorType auth_factor_type,
    user_data_auth::AuthFactorPreparePurpose prepare_purpose,
    base::RepeatingCallback<void(base::RunLoop*, int*)> on_success,
    const user_data_auth::PrepareAuthFactorProgress& progress) {
  auto QuitWithFailure = [&](const std::string& msg) {
    printer->PrintHumanOutput(msg);
    run_loop->Quit();
    *ret_code = 1;
  };
  if (progress.purpose() != prepare_purpose) {
    QuitWithFailure("Mismatched purpose.\n");
    return;
  }
  if (prepare_purpose == user_data_auth::PURPOSE_ADD_AUTH_FACTOR) {
    user_data_auth::PrepareAuthFactorForAddProgress add_progress =
        progress.add_progress();
    if (add_progress.auth_factor_type() != auth_factor_type) {
      QuitWithFailure("Mismatched auth factor type.\n");
      return;
    }
    switch (auth_factor_type) {
      case user_data_auth::AUTH_FACTOR_TYPE_FINGERPRINT: {
        user_data_auth::AuthEnrollmentProgress fp_progress =
            add_progress.biometrics_progress();
        printer->PrintReplyProtobuf(fp_progress);
        // We use the fatal error to signal a session failure.
        if (fp_progress.scan_result().fingerprint_result() ==
            user_data_auth::FINGERPRINT_SCAN_RESULT_FATAL_ERROR) {
          QuitWithFailure("Session failed.\n");
          return;
        } else if (fp_progress.done()) {
          // Preparation is finished.
          on_success.Run(run_loop, ret_code);
          return;
        }
        return;
      }
      default:
        QuitWithFailure(
            "Invalid auth factor type for PrepareAuthFactorForAdd.\n");
        return;
    }
  } else if (prepare_purpose ==
             user_data_auth::PURPOSE_AUTHENTICATE_AUTH_FACTOR) {
    user_data_auth::PrepareAuthFactorForAuthProgress auth_progress =
        progress.auth_progress();
    if (auth_progress.auth_factor_type() != auth_factor_type) {
      QuitWithFailure("Mismatched auth factor type.\n");
      return;
    }
    switch (auth_factor_type) {
      case user_data_auth::AUTH_FACTOR_TYPE_FINGERPRINT: {
        user_data_auth::AuthScanDone fp_progress =
            auth_progress.biometrics_progress();
        printer->PrintReplyProtobuf(fp_progress);
        // Anything other than SUCCESS signals a session failure.
        if (fp_progress.scan_result().fingerprint_result() !=
            user_data_auth::FINGERPRINT_SCAN_RESULT_SUCCESS) {
          QuitWithFailure("Session failed.\n");
          return;
        }
        // Preparation is finished, next action expected in the session is
        // AuthenticateAuthFactor.
        on_success.Run(run_loop, ret_code);
        return;
      }
      default:
        QuitWithFailure(
            "Invalid auth factor type for PrepareAuthFactorForAuth.\n");
        return;
    }
  } else {
    QuitWithFailure("Unrecognized prepare purpose.\n");
    return;
  }
}

// This is used as the signal connected callback for userdataauth's
// PrepareAuthFactorProgress signal. If the signal connection is successful,
// send the PrepareAuthFactor request and parse its response. If any errors
// occur, we need to quit the |run_loop| with |ret_code|. If PrepareAuthFactor
// completes successfully, the signal callback OnPrepareSignal will continue
// take care of the signals emitted.
void OnPrepareSignalConnected(base::RunLoop* run_loop,
                              int* ret_code,
                              Printer* printer,
                              org::chromium::UserDataAuthInterfaceProxy* proxy,
                              user_data_auth::PrepareAuthFactorRequest request,
                              const std::string&,
                              const std::string&,
                              bool success) {
  if (!success) {
    printer->PrintHumanOutput(
        "Failed to connect to signal PrepareAuthFactorProgress.\n");
    run_loop->Quit();
    *ret_code = 1;
    return;
  }

  user_data_auth::PrepareAuthFactorReply reply;
  brillo::ErrorPtr error;
  VLOG(1) << "Attempting to PrepareAuthFactor";
  if (!proxy->PrepareAuthFactor(request, &reply, &error, kDefaultTimeoutMs) ||
      error) {
    printer->PrintFormattedHumanOutput(
        "PrepareAuthFactor call failed: %s.\n",
        BrilloErrorToString(error.get()).c_str());
    run_loop->Quit();
    *ret_code = 1;
    return;
  }

  printer->PrintReplyProtobuf(reply);
  if (reply.error() !=
      user_data_auth::CryptohomeErrorCode::CRYPTOHOME_ERROR_NOT_SET) {
    printer->PrintHumanOutput("Failed to prepare auth factor.\n");
    run_loop->Quit();
    *ret_code = static_cast<int>(reply.error());
    return;
  }
}

int DoAddAuthFactor(
    Printer& printer,
    base::CommandLine* cl,
    org::chromium::UserDataAuthInterfaceProxy& userdataauth_proxy,
    org::chromium::CryptohomeMiscInterfaceProxy& misc_proxy) {
  user_data_auth::AddAuthFactorRequest req;
  user_data_auth::AddAuthFactorReply reply;

  std::string auth_session_id_hex, auth_session_id;

  if (!GetAuthSessionId(printer, cl, &auth_session_id_hex))
    return 1;
  base::HexStringToString(auth_session_id_hex.c_str(), &auth_session_id);
  req.set_auth_session_id(auth_session_id);
  if (!BuildAuthFactor(printer, cl, req.mutable_auth_factor()) ||
      !BuildAuthInput(printer, cl, &misc_proxy, req.mutable_auth_input())) {
    return 1;
  }

  brillo::ErrorPtr error;
  VLOG(1) << "Attempting to add AuthFactor";
  if (!userdataauth_proxy.AddAuthFactor(req, &reply, &error,
                                        kDefaultTimeoutMs) ||
      error) {
    printer.PrintFormattedHumanOutput("AddAuthFactor call failed: %s.\n",
                                      BrilloErrorToString(error.get()).c_str());
    return 1;
  }
  printer.PrintReplyProtobuf(reply);
  if (reply.error() !=
      user_data_auth::CryptohomeErrorCode::CRYPTOHOME_ERROR_NOT_SET) {
    printer.PrintHumanOutput("Failed to AddAuthFactor.\n");
    return static_cast<int>(reply.error());
  }

  printer.PrintHumanOutput("AuthFactor added.\n");
  return 0;
}

int DoAuthenticateAuthFactor(
    Printer* printer,
    base::CommandLine* cl,
    org::chromium::UserDataAuthInterfaceProxy* userdataauth_proxy,
    org::chromium::CryptohomeMiscInterfaceProxy* misc_proxy) {
  user_data_auth::AuthenticateAuthFactorRequest req;
  user_data_auth::AuthenticateAuthFactorReply reply;

  std::string auth_session_id_hex, auth_session_id;

  if (!GetAuthSessionId(*printer, cl, &auth_session_id_hex))
    return 1;
  base::HexStringToString(auth_session_id_hex.c_str(), &auth_session_id);
  req.set_auth_session_id(auth_session_id);

  bool has_key_label_switch = cl->HasSwitch(switches::kKeyLabelSwitch);
  bool has_key_labels_switch = cl->HasSwitch(switches::kKeyLabelsSwitch);
  if (!(has_key_label_switch ^ has_key_labels_switch)) {
    printer->PrintHumanOutput(
        "Exactly one of `key_label` and `key_labels` should be specified.\n");
    return 1;
  }
  req.set_auth_factor_label(cl->GetSwitchValueASCII(switches::kKeyLabelSwitch));
  std::vector<std::string> labels =
      base::SplitString(cl->GetSwitchValueASCII(switches::kKeyLabelsSwitch),
                        ",", base::WhitespaceHandling::KEEP_WHITESPACE,
                        base::SplitResult::SPLIT_WANT_ALL);
  for (std::string& label : labels) {
    req.add_auth_factor_labels(std::move(label));
  }
  if (!BuildAuthInput(*printer, cl, misc_proxy, req.mutable_auth_input())) {
    return 1;
  }

  brillo::ErrorPtr error;
  VLOG(1) << "Attempting to authenticate AuthFactor";
  if (!userdataauth_proxy->AuthenticateAuthFactor(req, &reply, &error,
                                                  kDefaultTimeoutMs) ||
      error) {
    printer->PrintFormattedHumanOutput(
        "AuthenticateAuthFactor call failed: %s.\n",
        BrilloErrorToString(error.get()).c_str());
    return 1;
  }
  printer->PrintReplyProtobuf(reply);
  if (reply.error() !=
      user_data_auth::CryptohomeErrorCode::CRYPTOHOME_ERROR_NOT_SET) {
    printer->PrintHumanOutput("Failed to authenticate AuthFactor.\n");
    return static_cast<int>(reply.error());
  }

  printer->PrintHumanOutput("AuthFactor authenticated.\n");
  return 0;
}

void OnAuthFactorStatusUpdateSignal(
    Printer* printer,
    base::RunLoop* run_loop,
    const user_data_auth::AuthFactorStatusUpdate& auth_factor_status_update) {
  printer->PrintReplyProtobuf(auth_factor_status_update);
  run_loop->Quit();
}

void OnAuthFactorStatusUpdateSignalConnected(
    base::RunLoop* run_loop,
    int* ret_code,
    Printer* printer,
    base::RepeatingCallback<int()> signal_connected_callback,
    const std::string&,
    const std::string&,
    bool success) {
  if (!success) {
    printer->PrintHumanOutput(
        "Failed to connect to AuthFactorStatusUpdate Signal.\n");
    run_loop->Quit();
    *ret_code = 1;
    return;
  }
  *ret_code = signal_connected_callback.Run();
}

int DoAuthenticateWithStatusUpdate(
    Printer& printer,
    base::CommandLine* cl,
    org::chromium::UserDataAuthInterfaceProxy& proxy,
    org::chromium::CryptohomeMiscInterfaceProxy& misc_proxy) {
  // Because signals might be emitted as soon as AuthenticateAuthFactor is
  // called, we need to ensure the signal is connected first. Therefore, the
  // actual request will be sent in |OnAuthFactorStatusUpdateSignalConnected|.
  // We will indefinitely block on the AuthFactorStatusUpdate signals in the CLI
  // until either the operation either fails or succeeds. So we'll start the run
  // loop here, pass its pointer to the callbacks, and let the callbacks end the
  // run loop when the conditions are met.
  int ret_code = 1;
  base::RunLoop run_loop;
  proxy.RegisterAuthFactorStatusUpdateSignalHandler(
      base::BindRepeating(&OnAuthFactorStatusUpdateSignal, &printer, &run_loop),
      base::BindOnce(&OnAuthFactorStatusUpdateSignalConnected, &run_loop,
                     &ret_code, &printer,
                     base::BindRepeating(DoAuthenticateAuthFactor, &printer, cl,
                                         &proxy, &misc_proxy)));
  run_loop.Run();
  return ret_code;
}

int FetchStatusUpdateSignal(Printer& printer,
                            org::chromium::UserDataAuthInterfaceProxy& proxy) {
  // A run loop is created to wait for the next signal.
  int ret_code = 1;
  base::RunLoop run_loop;
  proxy.RegisterAuthFactorStatusUpdateSignalHandler(
      base::BindRepeating(&OnAuthFactorStatusUpdateSignal, &printer, &run_loop),
      base::BindOnce(&OnAuthFactorStatusUpdateSignalConnected, &run_loop,
                     &ret_code, &printer,
                     base::BindRepeating([] { return 0; })));

  run_loop.Run();
  return ret_code;
}

// The |on_success| callback is triggered whenever the prepare signal that
// represents a "complete state", i.e., it's the caller's turn to perform the
// next action now.
int DoPrepareAuthFactor(
    Printer& printer,
    base::CommandLine* cl,
    org::chromium::UserDataAuthInterfaceProxy& proxy,
    user_data_auth::AuthFactorPreparePurpose prepare_purpose,
    base::RepeatingCallback<void(base::RunLoop*, int*)> on_success) {
  user_data_auth::PrepareAuthFactorRequest request;

  std::string auth_session_id_hex, auth_session_id;
  if (!GetAuthSessionId(printer, cl, &auth_session_id_hex))
    return 1;
  base::HexStringToString(auth_session_id_hex.c_str(), &auth_session_id);
  request.set_auth_session_id(auth_session_id);

  user_data_auth::AuthFactorType auth_factor_type;
  if (!GetAuthFactorType(printer, cl, &auth_factor_type))
    return 1;
  request.set_auth_factor_type(auth_factor_type);
  request.set_purpose(prepare_purpose);

  // Because signals might be emitted as soon as PrepareAuthFactor operation
  // returns successfully, we need to ensure the signal is connected first.
  // Therefore, the actual request will be sent in OnPrepareSignalConnected.
  // We will indefinitely block on the prepare signals in the CLI until either
  // the operation failed or completed. So we'll start the run loop here, pass
  // its pointer to the callbacks, and let the callbacks end the run loop when
  // the conditions are met.
  int ret_code = 1;
  base::RunLoop run_loop;
  proxy.RegisterPrepareAuthFactorProgressSignalHandler(
      base::BindRepeating(&OnPrepareSignal, &run_loop, &ret_code, &printer,
                          auth_factor_type, prepare_purpose, on_success),
      base::BindOnce(&OnPrepareSignalConnected, &run_loop, &ret_code, &printer,
                     &proxy, std::move(request)));

  run_loop.Run();
  return ret_code;
}

int DoTerminateAuthFactor(Printer& printer,
                          base::CommandLine* cl,
                          org::chromium::UserDataAuthInterfaceProxy& proxy) {
  user_data_auth::TerminateAuthFactorRequest request;
  user_data_auth::TerminateAuthFactorReply reply;

  std::string auth_session_id_hex, auth_session_id;
  if (!GetAuthSessionId(printer, cl, &auth_session_id_hex))
    return 1;
  base::HexStringToString(auth_session_id_hex.c_str(), &auth_session_id);
  request.set_auth_session_id(auth_session_id);

  user_data_auth::AuthFactorType auth_factor_type;
  if (!GetAuthFactorType(printer, cl, &auth_factor_type))
    return 1;
  request.set_auth_factor_type(auth_factor_type);

  brillo::ErrorPtr error;
  VLOG(1) << "Attempting to TerminateAuthFactor";
  if (!proxy.TerminateAuthFactor(request, &reply, &error, kDefaultTimeoutMs) ||
      error) {
    printer.PrintFormattedHumanOutput("TerminateAuthFactor call failed: %s.\n",
                                      BrilloErrorToString(error.get()).c_str());
    return 1;
  }

  printer.PrintReplyProtobuf(reply);
  if (reply.error() !=
      user_data_auth::CryptohomeErrorCode::CRYPTOHOME_ERROR_NOT_SET) {
    printer.PrintHumanOutput("Failed to prepare auth factor.\n");
    return static_cast<int>(reply.error());
  }
  return 0;
}

// This is used as the |on_success| callback for the PrepareAuthFactor signal
// handler. Attempts to add the auth factor and quit the run loop that listens
// to the signals.
void AddAfterPrepareDone(
    Printer* printer,
    base::CommandLine* cl,
    org::chromium::UserDataAuthInterfaceProxy* userdataauth_proxy,
    org::chromium::CryptohomeMiscInterfaceProxy* misc_proxy,
    base::RunLoop* run_loop,
    int* ret_code) {
  *ret_code = DoAddAuthFactor(*printer, cl, *userdataauth_proxy, *misc_proxy);
  run_loop->Quit();
}

// Perform PrepareAuthFactor. Upon the complete signal, add the auth factor.
// Terminate the auth factor afterwards in all situations.
int DoPrepareAddTerminate(
    Printer& printer,
    base::CommandLine* cl,
    org::chromium::UserDataAuthInterfaceProxy& userdataauth_proxy,
    org::chromium::CryptohomeMiscInterfaceProxy& misc_proxy) {
  auto prepare_add_result = DoPrepareAuthFactor(
      printer, cl, userdataauth_proxy, user_data_auth::PURPOSE_ADD_AUTH_FACTOR,
      base::BindRepeating(&AddAfterPrepareDone, &printer, cl,
                          &userdataauth_proxy, &misc_proxy));
  int terminate_result = DoTerminateAuthFactor(printer, cl, userdataauth_proxy);
  // Prioritize returning the prepare_add_result as it's usually more useful.
  if (prepare_add_result != 0) {
    return prepare_add_result;
  }
  return terminate_result;
}

// This is used as the |on_success| callback for the PrepareAuthFactor signal
// handler. Attempts to authenticate the auth factor, and, if either the result
// is success or a non-retryable error, quit the run loop that listens to the
// signals.
void AuthenticateAfterPrepareDone(
    Printer* printer,
    base::CommandLine* cl,
    org::chromium::UserDataAuthInterfaceProxy* userdataauth_proxy,
    org::chromium::CryptohomeMiscInterfaceProxy* misc_proxy,
    base::RunLoop* run_loop,
    int* ret_code) {
  *ret_code =
      DoAuthenticateAuthFactor(printer, cl, userdataauth_proxy, misc_proxy);
  // Currently the only auth factor type that utilizes this helper function is
  // fingerprint, and this is the easiest way to determine whether it needs to
  // keep the session open for retries. Switch to a more generic method in the
  // future.
  if (*ret_code !=
      user_data_auth::CRYPTOHOME_ERROR_FINGERPRINT_RETRY_REQUIRED) {
    run_loop->Quit();
  }
}

// Perform PrepareAuthFactor. Upon the complete signal, authenticate the auth
// factor. Terminate the auth factor afterwards in all situations.
int DoPrepareAuthenticateTerminate(
    Printer& printer,
    base::CommandLine* cl,
    org::chromium::UserDataAuthInterfaceProxy& userdataauth_proxy,
    org::chromium::CryptohomeMiscInterfaceProxy& misc_proxy) {
  auto prepare_auth_result = DoPrepareAuthFactor(
      printer, cl, userdataauth_proxy,
      user_data_auth::PURPOSE_AUTHENTICATE_AUTH_FACTOR,
      base::BindRepeating(&AuthenticateAfterPrepareDone, &printer, cl,
                          &userdataauth_proxy, &misc_proxy));
  int terminate_result = DoTerminateAuthFactor(printer, cl, userdataauth_proxy);
  // Prioritize returning the prepare_auth_result as it's usually more useful.
  if (prepare_auth_result != 0) {
    return prepare_auth_result;
  }
  return terminate_result;
}

}  // namespace

int main(int argc, char** argv) {
  base::CommandLine::Init(argc, argv);
  base::CommandLine* cl = base::CommandLine::ForCurrentProcess();
  if (cl->HasSwitch(switches::kSyslogSwitch))
    brillo::InitLog(brillo::kLogToSyslog | brillo::kLogToStderr);
  else
    brillo::InitLog(brillo::kLogToStderr);

  // Use output format to construct a printer. We process this argument first so
  // that we can use the resulting printer for outputting errors when processing
  // any of the other arguments.
  OutputFormat output_format = OutputFormat::kDefault;
  if (cl->HasSwitch(switches::kOutputFormatSwitch)) {
    std::string output_format_str =
        cl->GetSwitchValueASCII(switches::kOutputFormatSwitch);
    std::optional<OutputFormat> found_output_format;
    for (const auto& value : switches::kOutputFormats) {
      if (output_format_str == value.name) {
        found_output_format = value.format;
        break;
      }
    }
    if (found_output_format) {
      output_format = *found_output_format;
    } else {
      // Do manual output here because we don't have a working printer.
      std::cerr << "Invalid output format: " << output_format_str << std::endl;
      return 1;
    }
  }
  Printer printer(output_format);

  if (IsMixingOldAndNewFileSwitches(cl)) {
    printer.PrintFormattedHumanOutput(
        "Use either --%s and --%s together, or --%s only.\n",
        switches::kInputFileSwitch, switches::kOutputFileSwitch,
        switches::kFileSwitch);
    return 1;
  }

  std::string action = cl->GetSwitchValueASCII(switches::kActionSwitch);
  const int timeout_ms = kDefaultTimeoutMs;

  base::SingleThreadTaskExecutor task_executor(base::MessagePumpType::IO);
  base::FileDescriptorWatcher watcher(task_executor.task_runner());

  // Setup libbrillo dbus.
  brillo::DBusConnection connection;
  scoped_refptr<dbus::Bus> bus = connection.Connect();
  DCHECK(bus) << "Failed to connect to system bus through libbrillo";

  org::chromium::UserDataAuthInterfaceProxy userdataauth_proxy(bus);
  org::chromium::CryptohomePkcs11InterfaceProxy pkcs11_proxy(bus);
  org::chromium::InstallAttributesInterfaceProxy install_attributes_proxy(bus);
  org::chromium::CryptohomeMiscInterfaceProxy misc_proxy(bus);

  cryptohome::Platform platform;

  if (!strcmp(switches::kActions[switches::ACTION_LIST_KEYS_EX],
              action.c_str())) {
    user_data_auth::ListKeysRequest req;
    if (!BuildAccountId(printer, cl, req.mutable_account_id()))
      return 1;

    user_data_auth::ListKeysReply reply;
    brillo::ErrorPtr error;
    if (!userdataauth_proxy.ListKeys(req, &reply, &error, timeout_ms) ||
        error) {
      printer.PrintFormattedHumanOutput(
          "ListKeysEx call failed: %s",
          BrilloErrorToString(error.get()).c_str());
      return 1;
    }
    printer.PrintReplyProtobuf(reply);
    if (reply.error() !=
        user_data_auth::CryptohomeErrorCode::CRYPTOHOME_ERROR_NOT_SET) {
      printer.PrintHumanOutput("Failed to list keys.\n");
      return reply.error();
    }
    for (int i = 0; i < reply.labels_size(); ++i) {
      printer.PrintFormattedHumanOutput("Label: %s\n", reply.labels(i).c_str());
    }
  } else if (!strcmp(switches::kActions[switches::ACTION_REMOVE],
                     action.c_str())) {
    user_data_auth::RemoveRequest req;
    cryptohome::Username account_id;

    if (!GetAccountId(printer, cl, account_id)) {
      return 1;
    }

    if (cl->HasSwitch(switches::kAuthSessionId)) {
      std::string auth_session_id_hex, auth_session_id;
      if (!GetAuthSessionId(printer, cl, &auth_session_id_hex))
        return 1;
      base::HexStringToString(auth_session_id_hex.c_str(), &auth_session_id);
      req.set_auth_session_id(auth_session_id);
    }

    if (!cl->HasSwitch(switches::kForceSwitch) &&
        !ConfirmRemove(printer, account_id)) {
      return 1;
    }

    req.mutable_identifier()->set_account_id(*account_id);

    user_data_auth::RemoveReply reply;
    brillo::ErrorPtr error;
    if (!userdataauth_proxy.Remove(req, &reply, &error, timeout_ms) || error) {
      printer.PrintFormattedHumanOutput(
          "Remove call failed: %s.\n",
          BrilloErrorToString(error.get()).c_str());
      return 1;
    }
    printer.PrintReplyProtobuf(reply);
    if (reply.error() !=
        user_data_auth::CryptohomeErrorCode::CRYPTOHOME_ERROR_NOT_SET) {
      printer.PrintHumanOutput("Remove failed.\n");
      return 1;
    }
    printer.PrintHumanOutput("Remove succeeded.\n");
  } else if (!strcmp(switches::kActions[switches::ACTION_UNMOUNT],
                     action.c_str())) {
    user_data_auth::UnmountRequest req;

    user_data_auth::UnmountReply reply;
    brillo::ErrorPtr error;
    if (!userdataauth_proxy.Unmount(req, &reply, &error, timeout_ms) || error) {
      printer.PrintFormattedHumanOutput(
          "Unmount call failed: %s.\n",
          BrilloErrorToString(error.get()).c_str());
      return 1;
    }
    printer.PrintReplyProtobuf(reply);
    if (reply.error() !=
        user_data_auth::CryptohomeErrorCode::CRYPTOHOME_ERROR_NOT_SET) {
      printer.PrintHumanOutput("Unmount failed.\n");
      return 1;
    }
    printer.PrintHumanOutput("Unmount succeeded.\n");
  } else if (!strcmp(switches::kActions[switches::ACTION_MOUNTED],
                     action.c_str())) {
    user_data_auth::IsMountedRequest req;
    std::string account_id = cl->GetSwitchValueASCII(switches::kUserSwitch);
    if (!account_id.empty()) {
      req.set_username(account_id);
    }

    user_data_auth::IsMountedReply reply;
    brillo::ErrorPtr error;
    bool is_mounted = false;
    if (!userdataauth_proxy.IsMounted(req, &reply, &error, timeout_ms) ||
        error) {
      printer.PrintFormattedHumanOutput(
          "IsMounted call failed: %s.\n",
          BrilloErrorToString(error.get()).c_str());
    } else {
      is_mounted = reply.is_mounted();
    }
    if (is_mounted) {
      printer.PrintHumanOutput("true\n");
    } else {
      printer.PrintHumanOutput("false\n");
    }
  } else if (!strcmp(switches::kActions[switches::ACTION_OBFUSCATE_USER],
                     action.c_str())) {
    cryptohome::Username account_id;

    if (!GetAccountId(printer, cl, account_id)) {
      return 1;
    }

    if (cl->HasSwitch(switches::kUseDBus)) {
      user_data_auth::GetSanitizedUsernameRequest req;
      req.set_username(*account_id);

      user_data_auth::GetSanitizedUsernameReply reply;
      brillo::ErrorPtr error;
      if (!misc_proxy.GetSanitizedUsername(req, &reply, &error, timeout_ms) ||
          error) {
        printer.PrintFormattedHumanOutput(
            "GetSanitizedUserName call failed: %s.\n",
            BrilloErrorToString(error.get()).c_str());
        return 1;
      }
      printer.PrintFormattedHumanOutput("%s\n",
                                        reply.sanitized_username().c_str());
    } else {
      // Use libbrillo directly instead of going through dbus/cryptohome.
      if (!brillo::cryptohome::home::EnsureSystemSaltIsLoaded()) {
        printer.PrintHumanOutput("Failed to load system salt\n");
        return 1;
      }

      std::string* salt_ptr = brillo::cryptohome::home::GetSystemSalt();
      brillo::SecureBlob system_salt = SecureBlob(*salt_ptr);
      printer.PrintFormattedHumanOutput(
          "%s\n", SanitizeUserNameWithSalt(account_id, system_salt)->c_str());
    }
  } else if (!strcmp(switches::kActions[switches::ACTION_GET_SYSTEM_SALT],
                     action.c_str())) {
    brillo::SecureBlob system_salt;
    if (cl->HasSwitch(switches::kUseDBus)) {
      system_salt = GetSystemSalt(&misc_proxy);
      if (system_salt.empty()) {
        printer.PrintHumanOutput("Failed to retrieve system salt\n");
      }
    } else {
      // Use libbrillo directly instead of going through dbus/cryptohome.
      if (!brillo::cryptohome::home::EnsureSystemSaltIsLoaded()) {
        printer.PrintHumanOutput("Failed to load system salt\n");
        return 1;
      }

      std::string* salt_ptr = brillo::cryptohome::home::GetSystemSalt();
      system_salt = SecureBlob(*salt_ptr);
    }
    std::string hex_salt =
        base::HexEncode(system_salt.data(), system_salt.size());
    // We want to follow the convention of having low case hex for output as in
    // GetSanitizedUsername().
    std::transform(hex_salt.begin(), hex_salt.end(), hex_salt.begin(),
                   ::tolower);
    printer.PrintFormattedHumanOutput("%s\n", hex_salt.c_str());
  } else if (!strcmp(switches::kActions[switches::ACTION_DUMP_KEYSET],
                     action.c_str())) {
    cryptohome::Username account_id;

    if (!GetAccountId(printer, cl, account_id)) {
      return 1;
    }

    FilePath vault_path =
        FilePath("/home/.shadow")
            .Append(*SanitizeUserNameWithSalt(account_id,
                                              GetSystemSalt(&misc_proxy)))
            .Append(std::string(cryptohome::kKeyFile).append(".0"));
    brillo::Blob contents;
    if (!platform.ReadFile(vault_path, &contents)) {
      printer.PrintFormattedHumanOutput("Couldn't load keyset contents: %s.\n",
                                        vault_path.value().c_str());
      return 1;
    }
    cryptohome::SerializedVaultKeyset serialized;
    if (!serialized.ParseFromArray(contents.data(), contents.size())) {
      printer.PrintFormattedHumanOutput("Couldn't parse keyset contents: %s.\n",
                                        vault_path.value().c_str());
      return 1;
    }
    printer.PrintFormattedHumanOutput("For keyset: %s\n",
                                      vault_path.value().c_str());
    printer.PrintHumanOutput("  Flags:\n");
    if ((serialized.flags() & cryptohome::SerializedVaultKeyset::TPM_WRAPPED) &&
        serialized.has_tpm_key()) {
      printer.PrintHumanOutput("    TPM_WRAPPED\n");
    }
    if ((serialized.flags() & cryptohome::SerializedVaultKeyset::PCR_BOUND) &&
        serialized.has_tpm_key() && serialized.has_extended_tpm_key()) {
      printer.PrintHumanOutput("    PCR_BOUND\n");
    }
    if (serialized.flags() &
        cryptohome::SerializedVaultKeyset::SCRYPT_WRAPPED) {
      printer.PrintHumanOutput("    SCRYPT_WRAPPED\n");
    }
    SecureBlob blob(serialized.salt().length());
    serialized.salt().copy(blob.char_data(), serialized.salt().length(), 0);
    printer.PrintHumanOutput("  Salt:\n");
    printer.PrintFormattedHumanOutput("    %s\n",
                                      SecureBlobToHex(blob).c_str());
    blob.resize(serialized.wrapped_keyset().length());
    serialized.wrapped_keyset().copy(blob.char_data(),
                                     serialized.wrapped_keyset().length(), 0);
    printer.PrintHumanOutput("  Wrapped (Encrypted) Keyset:\n");
    printer.PrintFormattedHumanOutput("    %s\n",
                                      SecureBlobToHex(blob).c_str());
    if (serialized.has_tpm_key()) {
      blob.resize(serialized.tpm_key().length());
      serialized.tpm_key().copy(blob.char_data(), serialized.tpm_key().length(),
                                0);
      printer.PrintHumanOutput(
          "  TPM-Bound (Encrypted) Vault Encryption Key:\n");
      printer.PrintFormattedHumanOutput("    %s\n",
                                        SecureBlobToHex(blob).c_str());
    }
    if (serialized.has_extended_tpm_key()) {
      blob.resize(serialized.extended_tpm_key().length());
      serialized.extended_tpm_key().copy(
          blob.char_data(), serialized.extended_tpm_key().length(), 0);
      printer.PrintHumanOutput(
          "  TPM-Bound (Encrypted) Vault Encryption Key, PCR extended:\n");
      printer.PrintFormattedHumanOutput("    %s\n",
                                        SecureBlobToHex(blob).c_str());
    }
    if (serialized.has_tpm_public_key_hash()) {
      blob.resize(serialized.tpm_public_key_hash().length());
      serialized.tpm_public_key_hash().copy(blob.char_data(),
                                            serialized.tpm_key().length(), 0);
      printer.PrintHumanOutput("  TPM Public Key Hash:\n");
      printer.PrintFormattedHumanOutput("    %s\n",
                                        SecureBlobToHex(blob).c_str());
    }
    if (serialized.has_password_rounds()) {
      printer.PrintHumanOutput("  Password rounds:\n");
      printer.PrintFormattedHumanOutput("    %d\n",
                                        serialized.password_rounds());
    }
  } else if (!strcmp(switches::kActions[switches::ACTION_DUMP_LAST_ACTIVITY],
                     action.c_str())) {
    std::vector<FilePath> user_dirs;
    if (!platform.EnumerateDirectoryEntries(FilePath("/home/.shadow/"), false,
                                            &user_dirs)) {
      LOG(ERROR) << "Can not list shadow root.";
      return 1;
    }
    for (std::vector<FilePath>::iterator it = user_dirs.begin();
         it != user_dirs.end(); ++it) {
      const std::string dir_name = it->BaseName().value();
      if (!brillo::cryptohome::home::IsSanitizedUserName(dir_name))
        continue;
      base::Time last_activity = base::Time::UnixEpoch();

      FilePath timestamp_path = it->Append("timestamp");
      brillo::Blob tcontents;
      if (platform.ReadFile(timestamp_path, &tcontents)) {
        cryptohome::Timestamp timestamp;
        if (!timestamp.ParseFromArray(tcontents.data(), tcontents.size())) {
          printer.PrintFormattedHumanOutput(
              "Couldn't parse timestamp contents: %s.\n",
              timestamp_path.value().c_str());
        }
        last_activity = base::Time::FromDeltaSinceWindowsEpoch(
            base::Seconds(timestamp.timestamp()));
      } else {
        printer.PrintFormattedHumanOutput(
            "Couldn't load timestamp contents: %s.\n",
            timestamp_path.value().c_str());
      }
      if (last_activity > base::Time::UnixEpoch()) {
        printer.PrintFormattedHumanOutput(
            "%s %3d\n", dir_name.c_str(),
            (base::Time::Now() - last_activity).InDays());
      }
    }
  } else if (!strcmp(switches::kActions[switches::ACTION_SET_CURRENT_USER_OLD],
                     action.c_str())) {
    user_data_auth::UpdateCurrentUserActivityTimestampRequest req;
    user_data_auth::UpdateCurrentUserActivityTimestampReply reply;
    req.set_time_shift_sec(kSetCurrentUserOldOffset.InSeconds());
    brillo::ErrorPtr error;
    if (!misc_proxy.UpdateCurrentUserActivityTimestamp(req, &reply, &error,
                                                       timeout_ms) ||
        error) {
      printer.PrintFormattedHumanOutput(
          "UpdateCurrentUserActivityTimestamp call failed: %s.\n",
          BrilloErrorToString(error.get()).c_str());
    } else {
      printer.PrintHumanOutput(
          "Timestamp successfully updated. You may verify it with "
          "--action=dump_keyset --user=...\n");
    }
  } else if (!strcmp(
                 switches::kActions[switches::ACTION_INSTALL_ATTRIBUTES_GET],
                 action.c_str())) {
    std::string name;
    if (!GetAttrName(printer, cl, &name)) {
      printer.PrintHumanOutput("No attribute name specified.\n");
      return 1;
    }

    // Make sure install attributes are ready.
    user_data_auth::InstallAttributesGetStatusRequest status_req;
    user_data_auth::InstallAttributesGetStatusReply status_reply;
    brillo::ErrorPtr error;
    if (!install_attributes_proxy.InstallAttributesGetStatus(
            status_req, &status_reply, &error, timeout_ms) ||
        error) {
      printer.PrintFormattedHumanOutput(
          "InstallAttributesGetStatus call failed: %s.\n",
          BrilloErrorToString(error.get()).c_str());
      return 1;
    }
    if (status_reply.state() ==
            user_data_auth::InstallAttributesState::UNKNOWN ||
        status_reply.state() ==
            user_data_auth::InstallAttributesState::TPM_NOT_OWNED) {
      printer.PrintHumanOutput("InstallAttributes() is not ready.\n");
      return 1;
    }

    user_data_auth::InstallAttributesGetRequest req;
    user_data_auth::InstallAttributesGetReply reply;
    req.set_name(name);
    error.reset();
    if (!install_attributes_proxy.InstallAttributesGet(req, &reply, &error,
                                                       timeout_ms) ||
        error) {
      printer.PrintFormattedHumanOutput(
          "InstallAttributesGet call failed: %s.\n",
          BrilloErrorToString(error.get()).c_str());
      return 1;
    }
    if (reply.error() ==
        user_data_auth::CryptohomeErrorCode::CRYPTOHOME_ERROR_NOT_SET) {
      printer.PrintFormattedHumanOutput("%s\n", reply.value().c_str());
    } else {
      return 1;
    }
  } else if (!strcmp(
                 switches::kActions[switches::ACTION_INSTALL_ATTRIBUTES_SET],
                 action.c_str())) {
    std::string name;
    if (!GetAttrName(printer, cl, &name)) {
      printer.PrintHumanOutput("No attribute name specified.\n");
      return 1;
    }
    std::string value;
    if (!GetAttrValue(printer, cl, &value)) {
      printer.PrintHumanOutput("No attribute value specified.\n");
      return 1;
    }

    // Make sure install attributes are ready.
    user_data_auth::InstallAttributesGetStatusRequest status_req;
    user_data_auth::InstallAttributesGetStatusReply status_reply;
    brillo::ErrorPtr error;
    if (!install_attributes_proxy.InstallAttributesGetStatus(
            status_req, &status_reply, &error, timeout_ms) ||
        error) {
      printer.PrintFormattedHumanOutput(
          "InstallAttributesGetStatus call failed: %s.\n",
          BrilloErrorToString(error.get()).c_str());
      return 1;
    }
    if (status_reply.state() ==
            user_data_auth::InstallAttributesState::UNKNOWN ||
        status_reply.state() ==
            user_data_auth::InstallAttributesState::TPM_NOT_OWNED) {
      printer.PrintHumanOutput("InstallAttributes() is not ready.\n");
      return 1;
    }

    user_data_auth::InstallAttributesSetRequest req;
    user_data_auth::InstallAttributesSetReply reply;
    req.set_name(name);
    // It is expected that a null terminator is part of the value.
    value.push_back('\0');
    req.set_value(value);
    error.reset();
    if (!install_attributes_proxy.InstallAttributesSet(req, &reply, &error,
                                                       timeout_ms) ||
        error) {
      printer.PrintFormattedHumanOutput(
          "InstallAttributesSet call failed: %s.\n",
          BrilloErrorToString(error.get()).c_str());
      return 1;
    }
    if (reply.error() !=
        user_data_auth::CryptohomeErrorCode::CRYPTOHOME_ERROR_NOT_SET) {
      printer.PrintHumanOutput("Call to InstallAttributesSet() failed.\n");
      return 1;
    }
  } else if (!strcmp(switches::kActions
                         [switches::ACTION_INSTALL_ATTRIBUTES_FINALIZE],
                     action.c_str())) {
    // Make sure install attributes are ready.
    user_data_auth::InstallAttributesGetStatusRequest status_req;
    user_data_auth::InstallAttributesGetStatusReply status_reply;
    brillo::ErrorPtr error;
    if (!install_attributes_proxy.InstallAttributesGetStatus(
            status_req, &status_reply, &error, timeout_ms) ||
        error) {
      printer.PrintFormattedHumanOutput(
          "InstallAttributesGetStatus call failed: %s.\n",
          BrilloErrorToString(error.get()).c_str());
      return 1;
    }
    if (status_reply.state() ==
            user_data_auth::InstallAttributesState::UNKNOWN ||
        status_reply.state() ==
            user_data_auth::InstallAttributesState::TPM_NOT_OWNED) {
      printer.PrintHumanOutput("InstallAttributes() is not ready.\n");
      return 1;
    }

    user_data_auth::InstallAttributesFinalizeRequest req;
    user_data_auth::InstallAttributesFinalizeReply reply;
    error.reset();
    if (!install_attributes_proxy.InstallAttributesFinalize(req, &reply, &error,
                                                            timeout_ms) ||
        error) {
      printer.PrintFormattedHumanOutput(
          "InstallAttributesFinalize() failed: %s.\n",
          BrilloErrorToString(error.get()).c_str());
      return 1;
    }
    bool result = reply.error() ==
                  user_data_auth::CryptohomeErrorCode::CRYPTOHOME_ERROR_NOT_SET;
    printer.PrintFormattedHumanOutput("InstallAttributesFinalize(): %d\n",
                                      static_cast<int>(result));
  } else if (!strcmp(
                 switches::kActions[switches::ACTION_INSTALL_ATTRIBUTES_COUNT],
                 action.c_str())) {
    user_data_auth::InstallAttributesGetStatusRequest req;
    user_data_auth::InstallAttributesGetStatusReply reply;
    brillo::ErrorPtr error;
    if (!install_attributes_proxy.InstallAttributesGetStatus(
            req, &reply, &error, timeout_ms) ||
        error) {
      printer.PrintFormattedHumanOutput(
          "InstallAttributesGetStatus() call failed: %s.\n",
          BrilloErrorToString(error.get()).c_str());
      return 1;
    }
    if (reply.error() !=
        user_data_auth::CryptohomeErrorCode::CRYPTOHOME_ERROR_NOT_SET) {
      printer.PrintHumanOutput(
          "Call to InstallAttributesGetStatus() failed.\n");
      return 1;
    }
    printer.PrintFormattedHumanOutput("InstallAttributesCount(): %d\n",
                                      reply.count());
  } else if (!strcmp(switches::kActions
                         [switches::ACTION_INSTALL_ATTRIBUTES_GET_STATUS],
                     action.c_str())) {
    user_data_auth::InstallAttributesGetStatusRequest req;
    user_data_auth::InstallAttributesGetStatusReply reply;
    brillo::ErrorPtr error;
    if (!install_attributes_proxy.InstallAttributesGetStatus(
            req, &reply, &error, timeout_ms) ||
        error) {
      printer.PrintFormattedHumanOutput(
          "InstallAttributesGetStatus() call failed: %s.\n",
          BrilloErrorToString(error.get()).c_str());
      return 1;
    }
    if (reply.error() !=
        user_data_auth::CryptohomeErrorCode::CRYPTOHOME_ERROR_NOT_SET) {
      printer.PrintHumanOutput(
          "Call to InstallAttributesGetStatus() failed.\n");
      return 1;
    }
    printer.PrintFormattedHumanOutput(
        "%s\n", InstallAttributesState_Name(reply.state()).c_str());
  } else if (!strcmp(switches::kActions
                         [switches::ACTION_INSTALL_ATTRIBUTES_IS_READY],
                     action.c_str())) {
    user_data_auth::InstallAttributesGetStatusRequest req;
    user_data_auth::InstallAttributesGetStatusReply reply;
    brillo::ErrorPtr error;
    if (!install_attributes_proxy.InstallAttributesGetStatus(
            req, &reply, &error, timeout_ms) ||
        error) {
      printer.PrintFormattedHumanOutput(
          "InstallAttributesGetStatus() call failed: %s.\n",
          BrilloErrorToString(error.get()).c_str());
      return 1;
    }
    if (reply.error() !=
        user_data_auth::CryptohomeErrorCode::CRYPTOHOME_ERROR_NOT_SET) {
      printer.PrintHumanOutput(
          "Call to InstallAttributesGetStatus() failed.\n");
      return 1;
    }

    bool result =
        (reply.state() != user_data_auth::InstallAttributesState::UNKNOWN &&
         reply.state() !=
             user_data_auth::InstallAttributesState::TPM_NOT_OWNED);
    printer.PrintFormattedHumanOutput("InstallAttributesIsReady(): %d\n",
                                      static_cast<int>(result));
  } else if (!strcmp(switches::kActions
                         [switches::ACTION_INSTALL_ATTRIBUTES_IS_SECURE],
                     action.c_str())) {
    user_data_auth::InstallAttributesGetStatusRequest req;
    user_data_auth::InstallAttributesGetStatusReply reply;
    brillo::ErrorPtr error;
    if (!install_attributes_proxy.InstallAttributesGetStatus(
            req, &reply, &error, timeout_ms) ||
        error) {
      printer.PrintFormattedHumanOutput(
          "InstallAttributesGetStatus() call failed: %s.\n",
          BrilloErrorToString(error.get()).c_str());
      return 1;
    }
    if (reply.error() !=
        user_data_auth::CryptohomeErrorCode::CRYPTOHOME_ERROR_NOT_SET) {
      printer.PrintHumanOutput(
          "Call to InstallAttributesGetStatus() failed.\n");
      return 1;
    }

    bool result = reply.is_secure();
    printer.PrintFormattedHumanOutput("InstallAttributesIsSecure(): %d\n",
                                      static_cast<int>(result));
  } else if (!strcmp(switches::kActions
                         [switches::ACTION_INSTALL_ATTRIBUTES_IS_INVALID],
                     action.c_str())) {
    user_data_auth::InstallAttributesGetStatusRequest req;
    user_data_auth::InstallAttributesGetStatusReply reply;
    brillo::ErrorPtr error;
    if (!install_attributes_proxy.InstallAttributesGetStatus(
            req, &reply, &error, timeout_ms) ||
        error) {
      printer.PrintFormattedHumanOutput(
          "InstallAttributesGetStatus() call failed: %s.\n",
          BrilloErrorToString(error.get()).c_str());
      return 1;
    }
    if (reply.error() !=
        user_data_auth::CryptohomeErrorCode::CRYPTOHOME_ERROR_NOT_SET) {
      printer.PrintHumanOutput(
          "Call to InstallAttributesGetStatus() failed.\n");
      return 1;
    }

    bool result =
        (reply.state() == user_data_auth::InstallAttributesState::INVALID);
    printer.PrintFormattedHumanOutput("InstallAttributesIsInvalid(): %d\n",
                                      static_cast<int>(result));
  } else if (!strcmp(switches::kActions
                         [switches::ACTION_INSTALL_ATTRIBUTES_IS_FIRST_INSTALL],
                     action.c_str())) {
    user_data_auth::InstallAttributesGetStatusRequest req;
    user_data_auth::InstallAttributesGetStatusReply reply;
    brillo::ErrorPtr error;
    if (!install_attributes_proxy.InstallAttributesGetStatus(
            req, &reply, &error, timeout_ms) ||
        error) {
      printer.PrintFormattedHumanOutput(
          "InstallAttributesGetStatus() call failed: %s.\n",
          BrilloErrorToString(error.get()).c_str());
      return 1;
    }
    if (reply.error() !=
        user_data_auth::CryptohomeErrorCode::CRYPTOHOME_ERROR_NOT_SET) {
      printer.PrintHumanOutput(
          "Call to InstallAttributesGetStatus() failed.\n");
      return 1;
    }
    bool result = (reply.state() ==
                   user_data_auth::InstallAttributesState::FIRST_INSTALL);

    printer.PrintFormattedHumanOutput("InstallAttributesIsFirstInstall(): %d\n",
                                      static_cast<int>(result));
  } else if (!strcmp(switches::kActions
                         [switches::ACTION_PKCS11_GET_USER_TOKEN_INFO],
                     action.c_str())) {
    // If no account_id is specified, proceed with the empty string.
    std::string account_id = cl->GetSwitchValueASCII(switches::kUserSwitch);
    if (!account_id.empty()) {
      user_data_auth::Pkcs11GetTpmTokenInfoRequest req;
      user_data_auth::Pkcs11GetTpmTokenInfoReply reply;
      req.set_username(account_id);
      brillo::ErrorPtr error;
      if (!pkcs11_proxy.Pkcs11GetTpmTokenInfo(req, &reply, &error,
                                              timeout_ms) ||
          error) {
        printer.PrintFormattedHumanOutput(
            "PKCS #11 info call failed: %s.\n",
            BrilloErrorToString(error.get()).c_str());
      } else {
        printer.PrintFormattedHumanOutput("Token properties for %s:\n",
                                          account_id.c_str());
        printer.PrintFormattedHumanOutput("Label = %s\n",
                                          reply.token_info().label().c_str());
        printer.PrintFormattedHumanOutput(
            "Pin = %s\n", reply.token_info().user_pin().c_str());
        printer.PrintFormattedHumanOutput("Slot = %d\n",
                                          reply.token_info().slot());
      }
    } else {
      printer.PrintHumanOutput("Account ID/Username not specified.\n");
      return 1;
    }
  } else if (!strcmp(switches::kActions
                         [switches::ACTION_PKCS11_GET_SYSTEM_TOKEN_INFO],
                     action.c_str())) {
    user_data_auth::Pkcs11GetTpmTokenInfoRequest req;
    user_data_auth::Pkcs11GetTpmTokenInfoReply reply;
    brillo::ErrorPtr error;
    if (!pkcs11_proxy.Pkcs11GetTpmTokenInfo(req, &reply, &error, timeout_ms) ||
        error) {
      printer.PrintFormattedHumanOutput(
          "PKCS #11 info call failed: %s.\n",
          BrilloErrorToString(error.get()).c_str());
    } else {
      printer.PrintHumanOutput("System token properties:\n");
      printer.PrintFormattedHumanOutput("Label = %s\n",
                                        reply.token_info().label().c_str());
      printer.PrintFormattedHumanOutput("Pin = %s\n",
                                        reply.token_info().user_pin().c_str());
      printer.PrintFormattedHumanOutput("Slot = %d\n",
                                        reply.token_info().slot());
    }
  } else if (!strcmp(
                 switches::kActions[switches::ACTION_PKCS11_IS_USER_TOKEN_OK],
                 action.c_str())) {
    cryptohome::Pkcs11Init init;
    if (!init.IsUserTokenOK()) {
      printer.PrintHumanOutput("User token looks broken!\n");
      return 1;
    }
    printer.PrintHumanOutput("User token looks OK!\n");
  } else if (!strcmp(switches::kActions[switches::ACTION_PKCS11_TERMINATE],
                     action.c_str())) {
    user_data_auth::Pkcs11TerminateRequest req;
    user_data_auth::Pkcs11TerminateReply reply;

    if (cl->HasSwitch(switches::kUserSwitch)) {
      cryptohome::Username account_id;
      if (!GetAccountId(printer, cl, account_id)) {
        return 1;
      }
      req.set_username(*account_id);
    }

    brillo::ErrorPtr error;
    if (!pkcs11_proxy.Pkcs11Terminate(req, &reply, &error, timeout_ms) ||
        error) {
      printer.PrintFormattedHumanOutput(
          "PKCS #11 terminate call failed: %s.\n",
          BrilloErrorToString(error.get()).c_str());
    }
  } else if (!strcmp(
                 switches::kActions[switches::ACTION_PKCS11_RESTORE_TPM_TOKENS],
                 action.c_str())) {
    user_data_auth::Pkcs11RestoreTpmTokensRequest req;
    user_data_auth::Pkcs11RestoreTpmTokensReply reply;
    brillo::ErrorPtr error;
    if (!pkcs11_proxy.Pkcs11RestoreTpmTokens(req, &reply, &error, timeout_ms) ||
        error) {
      printer.PrintFormattedHumanOutput(
          "PKCS #11 restore TPM tokens call failed: %s.\n",
          BrilloErrorToString(error.get()).c_str());
    }
  } else if (!strcmp(switches::kActions[switches::ACTION_GET_LOGIN_STATUS],
                     action.c_str())) {
    user_data_auth::GetLoginStatusRequest req;
    user_data_auth::GetLoginStatusReply reply;

    brillo::ErrorPtr error;
    if (!misc_proxy.GetLoginStatus(req, &reply, &error, timeout_ms) || error) {
      printer.PrintFormattedHumanOutput(
          "Failed to call GetLoginStatus: %s\n",
          BrilloErrorToString(error.get()).c_str());
      return 1;
    }

    printer.PrintReplyProtobuf(reply);
    if (reply.error() !=
        user_data_auth::CryptohomeErrorCode::CRYPTOHOME_ERROR_NOT_SET) {
      printer.PrintFormattedHumanOutput(
          "Failed to call GetLoginStatus: status %d\n",
          static_cast<int>(reply.error()));
      return 1;
    }
    // TODO(b/189388158): because PrintDebugString won't print a field if it's
    // default value in proto3. We use a workaround to print it manually here.
    if (!reply.owner_user_exists()) {
      printer.PrintHumanOutput("owner_user_exists: false\n");
    }
    if (!reply.is_locked_to_single_user()) {
      printer.PrintHumanOutput("is_locked_to_single_user: false\n");
    }

    printer.PrintHumanOutput("GetLoginStatus success.\n");
  } else if (!strcmp(switches::kActions
                         [switches::ACTION_GET_FIRMWARE_MANAGEMENT_PARAMETERS],
                     action.c_str())) {
    user_data_auth::GetFirmwareManagementParametersRequest req;
    user_data_auth::GetFirmwareManagementParametersReply reply;

    brillo::ErrorPtr error;
    if (!install_attributes_proxy.GetFirmwareManagementParameters(
            req, &reply, &error, timeout_ms) ||
        error) {
      printer.PrintFormattedHumanOutput(
          "Failed to call GetFirmwareManagementParameters: %s\n",
          BrilloErrorToString(error.get()).c_str());
      return 1;
    } else {
      printer.PrintReplyProtobuf(reply);
      if (reply.error() !=
          user_data_auth::CryptohomeErrorCode::CRYPTOHOME_ERROR_NOT_SET) {
        printer.PrintFormattedHumanOutput(
            "Failed to call GetFirmwareManagementParameters: status %d\n",
            static_cast<int>(reply.error()));
        return 1;
      }
    }

    printer.PrintFormattedHumanOutput("flags=0x%08x\n", reply.fwmp().flags());
    brillo::Blob hash =
        brillo::BlobFromString(reply.fwmp().developer_key_hash());
    printer.PrintFormattedHumanOutput("hash=%s\n", BlobToHex(hash).c_str());
    printer.PrintHumanOutput("GetFirmwareManagementParameters success.\n");
  } else if (!strcmp(switches::kActions
                         [switches::ACTION_SET_FIRMWARE_MANAGEMENT_PARAMETERS],
                     action.c_str())) {
    user_data_auth::SetFirmwareManagementParametersRequest req;
    user_data_auth::SetFirmwareManagementParametersReply reply;

    if (cl->HasSwitch(switches::kFlagsSwitch)) {
      std::string flags_str = cl->GetSwitchValueASCII(switches::kFlagsSwitch);
      char* end = NULL;
      int32_t flags = strtol(flags_str.c_str(), &end, 0);
      if (end && *end != '\0') {
        printer.PrintHumanOutput("Bad flags value.\n");
        return 1;
      }
      req.mutable_fwmp()->set_flags(flags);
    } else {
      printer.PrintHumanOutput(
          "Use --flags (and optionally --developer_key_hash).\n");
      return 1;
    }

    if (cl->HasSwitch(switches::kDevKeyHashSwitch)) {
      std::string hash_str =
          cl->GetSwitchValueASCII(switches::kDevKeyHashSwitch);
      brillo::Blob hash;
      if (!base::HexStringToBytes(hash_str, &hash)) {
        printer.PrintHumanOutput("Bad hash value.\n");
        return 1;
      }
      if (hash.size() != SHA256_DIGEST_LENGTH) {
        printer.PrintHumanOutput("Bad hash size.\n");
        return 1;
      }

      req.mutable_fwmp()->set_developer_key_hash(brillo::BlobToString(hash));
    }

    brillo::ErrorPtr error;
    if (!install_attributes_proxy.SetFirmwareManagementParameters(
            req, &reply, &error, timeout_ms) ||
        error) {
      printer.PrintFormattedHumanOutput(
          "Failed to call SetFirmwareManagementParameters: %s\n",
          BrilloErrorToString(error.get()).c_str());
      return 1;
    } else {
      printer.PrintReplyProtobuf(reply);
      if (reply.error() !=
          user_data_auth::CryptohomeErrorCode::CRYPTOHOME_ERROR_NOT_SET) {
        printer.PrintFormattedHumanOutput(
            "Failed to call SetFirmwareManagementParameters: status %d\n",
            static_cast<int>(reply.error()));
        return 1;
      }
    }

    printer.PrintHumanOutput("SetFirmwareManagementParameters success.\n");
  } else if (!strcmp(
                 switches::kActions
                     [switches::ACTION_REMOVE_FIRMWARE_MANAGEMENT_PARAMETERS],
                 action.c_str())) {
    user_data_auth::RemoveFirmwareManagementParametersRequest req;
    user_data_auth::RemoveFirmwareManagementParametersReply reply;

    brillo::ErrorPtr error;
    if (!install_attributes_proxy.RemoveFirmwareManagementParameters(
            req, &reply, &error, timeout_ms) ||
        error) {
      printer.PrintFormattedHumanOutput(
          "Failed to call RemoveFirmwareManagementParameters: %s\n",
          BrilloErrorToString(error.get()).c_str());
      return 1;
    } else {
      printer.PrintReplyProtobuf(reply);
      if (reply.error() !=
          user_data_auth::CryptohomeErrorCode::CRYPTOHOME_ERROR_NOT_SET) {
        printer.PrintFormattedHumanOutput(
            "Failed to call RemoveFirmwareManagementParameters: status %d\n",
            static_cast<int>(reply.error()));
        return 1;
      }
    }

    printer.PrintHumanOutput("RemoveFirmwareManagementParameters success.\n");
  } else if (!strcmp(switches::kActions[switches::ACTION_MIGRATE_TO_DIRCRYPTO],
                     action.c_str())) {
    cryptohome::AccountIdentifier id;
    if (!BuildAccountId(printer, cl, &id))
      return 1;

    user_data_auth::StartMigrateToDircryptoRequest req;
    user_data_auth::StartMigrateToDircryptoReply reply;
    *req.mutable_account_id() = id;
    req.set_minimal_migration(cl->HasSwitch(switches::kMinimalMigration));

    brillo::ErrorPtr error;
    if (!userdataauth_proxy.StartMigrateToDircrypto(req, &reply, &error,
                                                    timeout_ms) ||
        error) {
      printer.PrintFormattedHumanOutput(
          "MigrateToDircrypto call failed: %s\n",
          BrilloErrorToString(error.get()).c_str());
      return 1;
    } else if (reply.error() !=
               user_data_auth::CryptohomeErrorCode::CRYPTOHOME_ERROR_NOT_SET) {
      printer.PrintFormattedHumanOutput(
          "MigrateToDircrypto call failed: status %d\n",
          static_cast<int>(reply.error()));
      return 1;
    }

    printer.PrintHumanOutput("MigrateToDircrypto call succeeded.\n");
  } else if (!strcmp(
                 switches::kActions[switches::ACTION_NEEDS_DIRCRYPTO_MIGRATION],
                 action.c_str())) {
    cryptohome::AccountIdentifier id;
    if (!BuildAccountId(printer, cl, &id)) {
      printer.PrintHumanOutput("No account_id specified.\n");
      return 1;
    }

    user_data_auth::NeedsDircryptoMigrationRequest req;
    user_data_auth::NeedsDircryptoMigrationReply reply;
    *req.mutable_account_id() = id;

    brillo::ErrorPtr error;
    if (!userdataauth_proxy.NeedsDircryptoMigration(req, &reply, &error,
                                                    timeout_ms) ||
        error) {
      printer.PrintFormattedHumanOutput(
          "NeedsDirCryptoMigration call failed: %s.\n",
          BrilloErrorToString(error.get()).c_str());
      return 1;
    } else if (reply.error() !=
               user_data_auth::CryptohomeErrorCode::CRYPTOHOME_ERROR_NOT_SET) {
      printer.PrintFormattedHumanOutput(
          "NeedsDirCryptoMigration call failed: status %d\n",
          static_cast<int>(reply.error()));
      return 1;
    }

    if (reply.needs_dircrypto_migration())
      printer.PrintHumanOutput("Yes\n");
    else
      printer.PrintHumanOutput("No\n");
  } else if (!strcmp(switches::kActions
                         [switches::ACTION_GET_SUPPORTED_KEY_POLICIES],
                     action.c_str())) {
    user_data_auth::GetSupportedKeyPoliciesRequest req;
    user_data_auth::GetSupportedKeyPoliciesReply reply;

    brillo::ErrorPtr error;
    if (!userdataauth_proxy.GetSupportedKeyPolicies(req, &reply, &error,
                                                    timeout_ms) ||
        error) {
      printer.PrintFormattedHumanOutput(
          "GetSupportedKeyPolicies call failed: %s.\n",
          BrilloErrorToString(error.get()).c_str());
      return 1;
    }
    printer.PrintReplyProtobuf(reply);

    printer.PrintHumanOutput("GetSupportedKeyPolicies success.\n");
  } else if (!strcmp(
                 switches::kActions[switches::ACTION_GET_ACCOUNT_DISK_USAGE],
                 action.c_str())) {
    user_data_auth::GetAccountDiskUsageRequest req;
    user_data_auth::GetAccountDiskUsageReply reply;

    cryptohome::AccountIdentifier id;
    if (!BuildAccountId(printer, cl, &id))
      return 1;

    *req.mutable_identifier() = id;

    brillo::ErrorPtr error;
    if (!userdataauth_proxy.GetAccountDiskUsage(req, &reply, &error,
                                                timeout_ms) ||
        error) {
      printer.PrintFormattedHumanOutput(
          "GetAccountDiskUsage call failed: %s.\n",
          BrilloErrorToString(error.get()).c_str());
      return 1;
    }

    printer.PrintReplyProtobuf(reply);
    if (reply.error() !=
        user_data_auth::CryptohomeErrorCode::CRYPTOHOME_ERROR_NOT_SET) {
      printer.PrintFormattedHumanOutput(
          "GetAccountDiskUsage call failed: status %d\n",
          static_cast<int>(reply.error()));
      return 1;
    }

    printer.PrintFormattedHumanOutput(
        "Account Disk Usage in bytes: %" PRId64 "\n", reply.size());
    return 0;
  } else if (!strcmp(
                 switches::kActions
                     [switches::ACTION_LOCK_TO_SINGLE_USER_MOUNT_UNTIL_REBOOT],
                 action.c_str())) {
    user_data_auth::LockToSingleUserMountUntilRebootRequest req;
    user_data_auth::LockToSingleUserMountUntilRebootReply reply;

    cryptohome::AccountIdentifier id;
    if (!BuildAccountId(printer, cl, &id))
      return 1;
    *req.mutable_account_id() = id;

    brillo::ErrorPtr error;
    if (!misc_proxy.LockToSingleUserMountUntilReboot(req, &reply, &error,
                                                     timeout_ms) ||
        error) {
      printer.PrintFormattedHumanOutput(
          "LockToSingleUserMountUntilReboot call failed: %s.\n",
          BrilloErrorToString(error.get()).c_str());
      return 1;
    }

    printer.PrintReplyProtobuf(reply);
    if (reply.error() !=
        user_data_auth::CryptohomeErrorCode::CRYPTOHOME_ERROR_NOT_SET) {
      printer.PrintFormattedHumanOutput(
          "LockToSingleUserMountUntilReboot call failed: status %d\n",
          static_cast<int>(reply.error()));
      return 1;
    }

    printer.PrintHumanOutput("Login disabled.\n");
  } else if (!strcmp(switches::kActions[switches::ACTION_GET_RSU_DEVICE_ID],
                     action.c_str())) {
    user_data_auth::GetRsuDeviceIdRequest req;
    user_data_auth::GetRsuDeviceIdReply reply;

    brillo::ErrorPtr error;
    if (!misc_proxy.GetRsuDeviceId(req, &reply, &error, timeout_ms) || error) {
      printer.PrintFormattedHumanOutput(
          "GetRsuDeviceId call failed: %s.\n",
          BrilloErrorToString(error.get()).c_str());
      return 1;
    }

    printer.PrintReplyProtobuf(reply);
    if (reply.error() !=
        user_data_auth::CryptohomeErrorCode::CRYPTOHOME_ERROR_NOT_SET) {
      printer.PrintFormattedHumanOutput(
          "GetRsuDeviceId call failed: status %d\n",
          static_cast<int>(reply.error()));
      return 1;
    }
  } else if (!strcmp(switches::kActions[switches::ACTION_START_AUTH_SESSION],
                     action.c_str())) {
    user_data_auth::StartAuthSessionRequest req;
    if (!BuildStartAuthSessionRequest(printer, *cl, req)) {
      return 1;
    }

    user_data_auth::StartAuthSessionReply reply;
    brillo::ErrorPtr error;
    if (!userdataauth_proxy.StartAuthSession(req, &reply, &error, timeout_ms) ||
        error) {
      printer.PrintFormattedHumanOutput(
          "StartAuthSession call failed: %s.\n",
          BrilloErrorToString(error.get()).c_str());
      return 1;
    }
    if (reply.error() !=
        user_data_auth::CryptohomeErrorCode::CRYPTOHOME_ERROR_NOT_SET) {
      printer.PrintHumanOutput("Auth session failed to start.\n");
      return static_cast<int>(reply.error());
    }

    printer.PrintReplyProtobuf(reply);
    printer.PrintHumanOutput("Auth session start succeeded.\n");
  } else if (!strcmp(
                 switches::kActions[switches::ACTION_INVALIDATE_AUTH_SESSION],
                 action.c_str())) {
    user_data_auth::InvalidateAuthSessionRequest req;
    user_data_auth::InvalidateAuthSessionReply reply;

    std::string auth_session_id_hex, auth_session_id;

    if (!GetAuthSessionId(printer, cl, &auth_session_id_hex))
      return 1;
    base::HexStringToString(auth_session_id_hex.c_str(), &auth_session_id);
    req.set_auth_session_id(auth_session_id);

    brillo::ErrorPtr error;
    VLOG(1) << "Attempting to invalidate auth session";
    if (!userdataauth_proxy.InvalidateAuthSession(req, &reply, &error,
                                                  timeout_ms) ||
        error) {
      printer.PrintFormattedHumanOutput(
          "InvalidateAuthSession call failed: %s.\n",
          BrilloErrorToString(error.get()).c_str());
      return 1;
    }
    printer.PrintReplyProtobuf(reply);
    if (reply.error() !=
        user_data_auth::CryptohomeErrorCode::CRYPTOHOME_ERROR_NOT_SET) {
      printer.PrintHumanOutput("Auth session failed to invalidate.\n");
      return static_cast<int>(reply.error());
    }

    printer.PrintHumanOutput("Auth session invalidated.\n");
  } else if (!strcmp(switches::kActions[switches::ACTION_EXTEND_AUTH_SESSION],
                     action.c_str())) {
    user_data_auth::ExtendAuthSessionRequest req;
    user_data_auth::ExtendAuthSessionReply reply;

    std::string auth_session_id_hex, auth_session_id;

    if (!GetAuthSessionId(printer, cl, &auth_session_id_hex))
      return 1;
    base::HexStringToString(auth_session_id_hex.c_str(), &auth_session_id);
    req.set_auth_session_id(auth_session_id);

    // Parse extension duration from string to integer.
    std::string extension_duration_str =
        cl->GetSwitchValueASCII(switches::kExtensionDuration);
    // Default value to extend is 60 seconds, if not specified.
    int extension_duration = 60;
    if (extension_duration_str.empty()) {
      printer.PrintHumanOutput(
          "Extension duration not specified, using default of 60 seconds\n");
    } else if (!base::StringToInt(extension_duration_str,
                                  &extension_duration)) {
      printer.PrintFormattedHumanOutput(
          "Extension duration specified is not a valid duration"
          "(--%s=<extension_duration>)\n",
          switches::kExtensionDuration);
      return 1;
    } else if (extension_duration < 0) {
      printer.PrintFormattedHumanOutput(
          "Extension duration specified is a negative value"
          "(--%s=<extension_duration>)\n",
          switches::kExtensionDuration);
      return 1;
    }
    req.set_extension_duration(extension_duration);

    brillo::ErrorPtr error;
    VLOG(1) << "Attempting to extend auth session";
    if (!userdataauth_proxy.ExtendAuthSession(req, &reply, &error,
                                              timeout_ms) ||
        error) {
      printer.PrintFormattedHumanOutput(
          "ExtendAuthSession call failed: %s.\n",
          BrilloErrorToString(error.get()).c_str());
      return 1;
    }
    printer.PrintReplyProtobuf(reply);
    if (reply.error() !=
        user_data_auth::CryptohomeErrorCode::CRYPTOHOME_ERROR_NOT_SET) {
      printer.PrintHumanOutput("Auth session failed to extend.\n");
      return static_cast<int>(reply.error());
    }

    printer.PrintHumanOutput("Auth session extended.\n");
  } else if (!strcmp(
                 switches::kActions[switches::ACTION_CREATE_PERSISTENT_USER],
                 action.c_str())) {
    user_data_auth::CreatePersistentUserRequest req;
    user_data_auth::CreatePersistentUserReply reply;

    std::string auth_session_id_hex, auth_session_id;
    if (!GetAuthSessionId(printer, cl, &auth_session_id_hex))
      return 1;
    base::HexStringToString(auth_session_id_hex.c_str(), &auth_session_id);

    req.set_auth_session_id(auth_session_id);

    brillo::ErrorPtr error;
    if (!userdataauth_proxy.CreatePersistentUser(req, &reply, &error,
                                                 timeout_ms) ||
        error) {
      printer.PrintFormattedHumanOutput(
          "CreatePersistentUser call failed: %s.\n",
          BrilloErrorToString(error.get()).c_str());
      return 1;
    }
    printer.PrintReplyProtobuf(reply);
    if (reply.error() !=
        user_data_auth::CryptohomeErrorCode::CRYPTOHOME_ERROR_NOT_SET) {
      printer.PrintHumanOutput("Failed to create persistent user.\n");
      return static_cast<int>(reply.error());
    }

    printer.PrintHumanOutput("Created persistent user.\n");
  } else if (!strcmp(switches::kActions[switches::ACTION_PREPARE_GUEST_VAULT],
                     action.c_str())) {
    user_data_auth::PrepareGuestVaultRequest req;
    user_data_auth::PrepareGuestVaultReply reply;

    brillo::ErrorPtr error;
    if (!userdataauth_proxy.PrepareGuestVault(req, &reply, &error,
                                              timeout_ms) ||
        error) {
      printer.PrintFormattedHumanOutput(
          "PrepareGuestVault call failed: %s.\n",
          BrilloErrorToString(error.get()).c_str());
      return 1;
    }
    printer.PrintReplyProtobuf(reply);
    if (reply.error() !=
        user_data_auth::CryptohomeErrorCode::CRYPTOHOME_ERROR_NOT_SET) {
      printer.PrintHumanOutput("Failed to prepare guest vault.\n");
      return static_cast<int>(reply.error());
    }

    printer.PrintHumanOutput("Prepared guest vault.\n");
  } else if (!strcmp(
                 switches::kActions[switches::ACTION_PREPARE_EPHEMERAL_VAULT],
                 action.c_str())) {
    user_data_auth::PrepareEphemeralVaultRequest req;
    user_data_auth::PrepareEphemeralVaultReply reply;

    std::string auth_session_id_hex, auth_session_id;
    if (!GetAuthSessionId(printer, cl, &auth_session_id_hex))
      return 1;
    base::HexStringToString(auth_session_id_hex.c_str(), &auth_session_id);

    req.set_auth_session_id(auth_session_id);

    brillo::ErrorPtr error;
    if (!userdataauth_proxy.PrepareEphemeralVault(req, &reply, &error,
                                                  timeout_ms) ||
        error) {
      printer.PrintFormattedHumanOutput(
          "PrepareEphemeralVault call failed: %s.\n",
          BrilloErrorToString(error.get()).c_str());
      return 1;
    }
    printer.PrintReplyProtobuf(reply);
    if (reply.error() !=
        user_data_auth::CryptohomeErrorCode::CRYPTOHOME_ERROR_NOT_SET) {
      printer.PrintHumanOutput("Failed to prepare ephemeral vault.\n");
      return static_cast<int>(reply.error());
    }

    printer.PrintHumanOutput("Prepared ephemeral vault.\n");
  } else if (!strcmp(
                 switches::kActions[switches::ACTION_PREPARE_PERSISTENT_VAULT],
                 action.c_str())) {
    user_data_auth::PreparePersistentVaultRequest req;
    user_data_auth::PreparePersistentVaultReply reply;

    std::string auth_session_id_hex, auth_session_id;
    if (!GetAuthSessionId(printer, cl, &auth_session_id_hex))
      return 1;
    base::HexStringToString(auth_session_id_hex.c_str(), &auth_session_id);

    req.set_auth_session_id(auth_session_id);
    if (cl->HasSwitch(switches::kEcryptfsSwitch)) {
      req.set_encryption_type(
          user_data_auth::CRYPTOHOME_VAULT_ENCRYPTION_ECRYPTFS);
    }

    brillo::ErrorPtr error;
    if (!userdataauth_proxy.PreparePersistentVault(req, &reply, &error,
                                                   timeout_ms) ||
        error) {
      printer.PrintFormattedHumanOutput(
          "PreparePersistentVault call failed: %s.\n",
          BrilloErrorToString(error.get()).c_str());
      return 1;
    }
    printer.PrintReplyProtobuf(reply);
    if (reply.error() !=
        user_data_auth::CryptohomeErrorCode::CRYPTOHOME_ERROR_NOT_SET) {
      printer.PrintHumanOutput("Failed to prepare persistent vault.\n");
      return static_cast<int>(reply.error());
    }

    printer.PrintHumanOutput("Prepared persistent vault.\n");
  } else if (!strcmp(switches::kActions
                         [switches::ACTION_PREPARE_VAULT_FOR_MIGRATION],
                     action.c_str())) {
    user_data_auth::PrepareVaultForMigrationRequest req;
    user_data_auth::PrepareVaultForMigrationReply reply;

    std::string auth_session_id_hex, auth_session_id;
    if (!GetAuthSessionId(printer, cl, &auth_session_id_hex))
      return 1;
    base::HexStringToString(auth_session_id_hex.c_str(), &auth_session_id);

    req.set_auth_session_id(auth_session_id);

    brillo::ErrorPtr error;
    if (!userdataauth_proxy.PrepareVaultForMigration(req, &reply, &error,
                                                     timeout_ms) ||
        error) {
      printer.PrintFormattedHumanOutput(
          "PrepareVaultForMigration call failed: %s.\n",
          BrilloErrorToString(error.get()).c_str());
      return 1;
    }
    printer.PrintReplyProtobuf(reply);
    if (reply.error() !=
        user_data_auth::CryptohomeErrorCode::CRYPTOHOME_ERROR_NOT_SET) {
      printer.PrintHumanOutput("Failed to prepare vault for migration.\n");
      return static_cast<int>(reply.error());
    }

    printer.PrintHumanOutput("Prepared vault for migration.\n");
  } else if (!strcmp(switches::kActions[switches::ACTION_ADD_AUTH_FACTOR],
                     action.c_str())) {
    return DoAddAuthFactor(printer, cl, userdataauth_proxy, misc_proxy);
  } else if (!strcmp(
                 switches::kActions[switches::ACTION_AUTHENTICATE_AUTH_FACTOR],
                 action.c_str())) {
    return DoAuthenticateAuthFactor(&printer, cl, &userdataauth_proxy,
                                    &misc_proxy);
  } else if (!strcmp(switches::kActions
                         [switches::ACTION_AUTHENTICATE_WITH_STATUS_UPDATE],
                     action.c_str())) {
    return DoAuthenticateWithStatusUpdate(printer, cl, userdataauth_proxy,
                                          misc_proxy);
  } else if (!strcmp(switches::kActions[switches::ACTION_FETCH_STATUS_UPDATE],
                     action.c_str())) {
    return FetchStatusUpdateSignal(printer, userdataauth_proxy);
  } else if (!strcmp(switches::kActions[switches::ACTION_UPDATE_AUTH_FACTOR],
                     action.c_str())) {
    user_data_auth::UpdateAuthFactorRequest req;
    user_data_auth::UpdateAuthFactorReply reply;

    std::string auth_session_id_hex, auth_session_id;

    if (!GetAuthSessionId(printer, cl, &auth_session_id_hex))
      return 1;
    base::HexStringToString(auth_session_id_hex.c_str(), &auth_session_id);
    req.set_auth_session_id(auth_session_id);
    if (!BuildAuthFactor(printer, cl, req.mutable_auth_factor()) ||
        !BuildAuthInput(printer, cl, &misc_proxy, req.mutable_auth_input())) {
      return 1;
    }
    // By default, old and new labels are equal; if requested, the new label can
    // be overridden.
    req.set_auth_factor_label(req.auth_factor().label());
    if (!cl->GetSwitchValueASCII(switches::kNewKeyLabelSwitch).empty()) {
      req.mutable_auth_factor()->set_label(
          cl->GetSwitchValueASCII(switches::kNewKeyLabelSwitch));
    }

    brillo::ErrorPtr error;
    VLOG(1) << "Attempting to Update AuthFactor";
    if (!userdataauth_proxy.UpdateAuthFactor(req, &reply, &error, timeout_ms) ||
        error) {
      printer.PrintFormattedHumanOutput(
          "UpdateAuthFactor call failed: %s.\n",
          BrilloErrorToString(error.get()).c_str());
      return 1;
    }
    printer.PrintReplyProtobuf(reply);
    if (reply.error() !=
        user_data_auth::CryptohomeErrorCode::CRYPTOHOME_ERROR_NOT_SET) {
      printer.PrintHumanOutput("Failed to update AuthFactor.\n");
      return static_cast<int>(reply.error());
    }

    printer.PrintHumanOutput("AuthFactor updated.\n");
  } else if (!strcmp(switches::kActions[switches::ACTION_REMOVE_AUTH_FACTOR],
                     action.c_str())) {
    user_data_auth::RemoveAuthFactorRequest req;
    user_data_auth::RemoveAuthFactorReply reply;

    std::string auth_session_id_hex, auth_session_id;

    if (!GetAuthSessionId(printer, cl, &auth_session_id_hex))
      return 1;
    base::HexStringToString(auth_session_id_hex.c_str(), &auth_session_id);
    req.set_auth_session_id(auth_session_id);
    if (cl->GetSwitchValueASCII(switches::kKeyLabelSwitch).empty()) {
      printer.PrintHumanOutput("No auth factor label specified.\n");
      return 1;
    }
    req.set_auth_factor_label(
        cl->GetSwitchValueASCII(switches::kKeyLabelSwitch));

    brillo::ErrorPtr error;
    VLOG(1) << "Attempting to Remove AuthFactor";
    if (!userdataauth_proxy.RemoveAuthFactor(req, &reply, &error, timeout_ms) ||
        error) {
      printer.PrintFormattedHumanOutput(
          "RemoveAuthFactor call failed: %s.\n",
          BrilloErrorToString(error.get()).c_str());
      return 1;
    }
    printer.PrintReplyProtobuf(reply);
    if (reply.error() !=
        user_data_auth::CryptohomeErrorCode::CRYPTOHOME_ERROR_NOT_SET) {
      printer.PrintHumanOutput("Failed to remove AuthFactor.\n");
      return static_cast<int>(reply.error());
    }

    printer.PrintHumanOutput("AuthFactor removed.\n");
  } else if (!strcmp(switches::kActions[switches::ACTION_LIST_AUTH_FACTORS],
                     action.c_str())) {
    user_data_auth::ListAuthFactorsRequest req;
    user_data_auth::ListAuthFactorsReply reply;

    if (!BuildAccountId(printer, cl, req.mutable_account_id())) {
      return 1;
    }

    brillo::ErrorPtr error;
    VLOG(1) << "Attempting to list AuthFactors";
    if (!userdataauth_proxy.ListAuthFactors(req, &reply, &error, timeout_ms) ||
        error) {
      printer.PrintFormattedHumanOutput(
          "ListAuthFactors call failed: %s.\n",
          BrilloErrorToString(error.get()).c_str());
      return 1;
    }
    printer.PrintReplyProtobuf(reply);
    if (reply.error() !=
        user_data_auth::CryptohomeErrorCode::CRYPTOHOME_ERROR_NOT_SET) {
      printer.PrintHumanOutput("Failed to list auth factors.\n");
      return static_cast<int>(reply.error());
    }
  } else if (!strcmp(
                 switches::kActions[switches::ACTION_GET_AUTH_SESSION_STATUS],
                 action.c_str())) {
    user_data_auth::GetAuthSessionStatusRequest req;
    user_data_auth::GetAuthSessionStatusReply reply;
    std::string auth_session_id_hex, auth_session_id;

    if (!GetAuthSessionId(printer, cl, &auth_session_id_hex)) {
      return 1;
    }
    base::HexStringToString(auth_session_id_hex.c_str(), &auth_session_id);
    req.set_auth_session_id(auth_session_id);

    brillo::ErrorPtr error;
    VLOG(1) << "Attempting to GetAuthSessionStatus";
    if (!userdataauth_proxy.GetAuthSessionStatus(req, &reply, &error,
                                                 timeout_ms) ||
        error) {
      printer.PrintFormattedHumanOutput(
          "GetAuthSessionStatus call failed: %s.\n",
          BrilloErrorToString(error.get()).c_str());
      return 1;
    }
    printer.PrintReplyProtobuf(reply);
    if (reply.error() !=
        user_data_auth::CryptohomeErrorCode::CRYPTOHOME_ERROR_NOT_SET) {
      printer.PrintHumanOutput("Failed to get auth session status.\n");
      return static_cast<int>(reply.error());
    }
  } else if (!strcmp(switches::kActions[switches::ACTION_GET_RECOVERY_REQUEST],
                     action.c_str())) {
    user_data_auth::GetRecoveryRequestRequest req;
    user_data_auth::GetRecoveryRequestReply reply;
    std::string auth_session_id_hex, auth_session_id;

    if (!GetAuthSessionId(printer, cl, &auth_session_id_hex)) {
      return 1;
    }
    base::HexStringToString(auth_session_id_hex.c_str(), &auth_session_id);
    req.set_auth_session_id(auth_session_id);
    if (cl->GetSwitchValueASCII(switches::kKeyLabelSwitch).empty()) {
      printer.PrintHumanOutput("No auth factor label specified.\n");
      return 1;
    }
    req.set_auth_factor_label(
        cl->GetSwitchValueASCII(switches::kKeyLabelSwitch));
    if (cl->GetSwitchValueASCII(switches::kRecoveryEpochResponseSwitch)
            .empty()) {
      printer.PrintHumanOutput("No epoch response specified.\n");
      return 1;
    }
    std::string epoch_response_hex, epoch_response;
    epoch_response_hex =
        cl->GetSwitchValueASCII(switches::kRecoveryEpochResponseSwitch);
    base::HexStringToString(epoch_response_hex.c_str(), &epoch_response);
    req.set_epoch_response(epoch_response);

    brillo::ErrorPtr error;
    VLOG(1) << "Attempting to GetRecoveryRequest";
    if (!userdataauth_proxy.GetRecoveryRequest(req, &reply, &error,
                                               timeout_ms) ||
        error) {
      printer.PrintFormattedHumanOutput(
          "GetRecoveryRequest call failed: %s.\n",
          BrilloErrorToString(error.get()).c_str());
      return 1;
    }
    printer.PrintReplyProtobuf(reply);
    if (reply.error() !=
        user_data_auth::CryptohomeErrorCode::CRYPTOHOME_ERROR_NOT_SET) {
      printer.PrintHumanOutput("Failed to get recovery request.\n");
      return static_cast<int>(reply.error());
    }
  } else if (!strcmp(switches::kActions
                         [switches::ACTION_RESET_APPLICATION_CONTAINER],
                     action.c_str())) {
    user_data_auth::ResetApplicationContainerRequest request;
    user_data_auth::ResetApplicationContainerReply reply;

    if (!BuildAccountId(printer, cl, request.mutable_account_id())) {
      return 1;
    }
    request.set_application_name(
        cl->GetSwitchValueASCII(switches::kApplicationName));

    brillo::ErrorPtr error;
    VLOG(1) << "Attempting to ResetApplicationContainer";
    if (!userdataauth_proxy.ResetApplicationContainer(request, &reply, &error,
                                                      timeout_ms) ||
        error) {
      printer.PrintFormattedHumanOutput(
          "ResetApplicationContainer call failed: %s.\n",
          BrilloErrorToString(error.get()).c_str());
      return 1;
    }

    printer.PrintReplyProtobuf(reply);
    if (reply.error() !=
        user_data_auth::CryptohomeErrorCode::CRYPTOHOME_ERROR_NOT_SET) {
      printer.PrintHumanOutput(
          "Failed to reset application container"
          ".\n");
      return static_cast<int>(reply.error());
    }
  } else if (!strcmp(switches::kActions[switches::ACTION_PREPARE_AUTH_FACTOR],
                     action.c_str())) {
    user_data_auth::AuthFactorPreparePurpose prepare_purpose;
    if (!GetPreparePurpose(printer, cl, &prepare_purpose))
      return 1;

    auto normal_exit = [](base::RunLoop* run_loop, int* ret_code) {
      *ret_code = 0;
      run_loop->Quit();
    };
    return DoPrepareAuthFactor(printer, cl, userdataauth_proxy, prepare_purpose,
                               base::BindRepeating(normal_exit));
  } else if (!strcmp(switches::kActions[switches::ACTION_TERMINATE_AUTH_FACTOR],
                     action.c_str())) {
    return DoTerminateAuthFactor(printer, cl, userdataauth_proxy);
  } else if (!strcmp(switches::kActions
                         [switches::ACTION_PREPARE_AND_ADD_AUTH_FACTOR],
                     action.c_str())) {
    return DoPrepareAddTerminate(printer, cl, userdataauth_proxy, misc_proxy);
  } else if (!strcmp(
                 switches::kActions
                     [switches::ACTION_PREPARE_AND_AUTHENTICATE_AUTH_FACTOR],
                 action.c_str())) {
    return DoPrepareAuthenticateTerminate(printer, cl, userdataauth_proxy,
                                          misc_proxy);
  } else {
    printer.PrintHumanOutput(
        "Unknown action or no action given.  Available actions:\n");
    for (int i = 0; switches::kActions[i]; i++)
      printer.PrintFormattedHumanOutput("  --action=%s\n",
                                        switches::kActions[i]);
  }
  return 0;
}  // NOLINT(readability/fn_size)
