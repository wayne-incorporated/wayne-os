// Copyright 2014 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// trunks_client is a command line tool that supports various TPM operations. It
// does not provide direct access to the trunksd D-Bus interface.

#include <inttypes.h>
#include <stdio.h>

#include <memory>
#include <set>
#include <string>

#include <base/check.h>
#include <base/command_line.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <base/timer/elapsed_timer.h>
#include <brillo/file_utils.h>
#include <brillo/syslog_logging.h>
#include <crypto/libcrypto-compat.h>
#include <crypto/scoped_openssl_types.h>
#include <openssl/sha.h>

#include "trunks/error_codes.h"
#include "trunks/hmac_session.h"
#include "trunks/password_authorization_delegate.h"
#include "trunks/policy_session.h"
#include "trunks/scoped_key_handle.h"
#include "trunks/session_manager.h"
#include "trunks/tpm_state.h"
#include "trunks/tpm_utility.h"
#include "trunks/trunks_client_test.h"
#include "trunks/trunks_factory_impl.h"
#include "trunks/vtpm_client_support/create_dbus_proxy.h"

namespace {

using trunks::AuthorizationDelegate;
using trunks::CommandTransceiver;
using trunks::CreateTrunksDBusProxyToTrunks;
using trunks::CreateTrunksDBusProxyToVtpm;
using trunks::TrunksDBusProxy;
using trunks::TrunksFactory;
using trunks::TrunksFactoryImpl;

// Initial PCR0 value at boot (all zeroes).
constexpr unsigned char kPcr0ValueZero[SHA256_DIGEST_SIZE] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

// PCR0 value for Recovery mode.
// Equals to SHA256(initial_value | extended_value), where
//   - initial_value = 0..0 (32 bytes),
//   - extended_value = SHA1(0x00|0x01|0x00) + 00s to 32 bytes.
constexpr unsigned char kPcr0ValueRec[SHA256_DIGEST_SIZE] = {
    0x9F, 0x9E, 0xA8, 0x66, 0xD3, 0xF3, 0x4F, 0xE3, 0xA3, 0x11, 0x2A,
    0xE9, 0xCB, 0x1F, 0xBA, 0xBC, 0x6F, 0xFE, 0x8C, 0xD2, 0x61, 0xD4,
    0x24, 0x93, 0xBC, 0x68, 0x42, 0xA9, 0xE4, 0xF9, 0x3B, 0x3D,
};

// PCR0 value for Recovery+Developer mode.
// Equals to SHA256(initial_value | extended_value), where
//   - initial_value = 0..0 (32 bytes),
//   - extended_value = SHA1(0x01|0x01|0x00) + 00s to 32 bytes.
constexpr unsigned char kPcr0ValueRecDev[SHA256_DIGEST_SIZE] = {
    0x2A, 0x75, 0x80, 0xE5, 0xDA, 0x28, 0x95, 0x46, 0xF4, 0xD2, 0xE0,
    0x50, 0x9C, 0xC6, 0xDE, 0x15, 0x5E, 0xA1, 0x31, 0x81, 0x89, 0x54,
    0xD3, 0x6D, 0x49, 0xE0, 0x27, 0xFD, 0x42, 0xB8, 0xC8, 0xF8,
};

void PrintUsage() {
  puts("TPM command options:");
  puts("  --allocate_pcr - Configures PCR 0-15 under the SHA256 bank.");
  puts("  --clear - Clears the TPM. Use before initializing the TPM.");
  puts("  --csme_test_pcr --index=<INDEX>.");
  puts("  --csme_read_pcr --index=<INDEX>.");
  puts("  --help - Prints this message.");
  puts("  --init_tpm - Initializes a TPM as CrOS firmware does.");
  puts("  --own - Takes ownership of the TPM with the provided password.");
  puts("  --owner_password - used to provide an owner password");
  puts("  --endorsement_password - used to provide an endorsement password");
  puts("  --regression_test - Runs some basic regression tests. If");
  puts("                      *_password is supplied, it runs tests that");
  puts("                      require the permissions.");
  puts("  --startup - Performs startup and self-tests.");
  puts("  --status - Prints TPM status information.");
  puts("  --stress_test - Runs some basic stress tests.");
  puts("  --read_pcr --index=<N> - Reads a PCR and prints the value.");
  puts("  --extend_pcr --index=<N> --value=<value> - Extends a PCR.");
  puts("  --tpm_version - Prints TPM versions and IDs similar to tpm_version.");
  puts("  --endorsement_public_key - Prints the public endorsement key.");
  puts("  --key_create (--rsa=<bits>|--ecc) --usage=sign|decrypt|all");
  puts("               --key_blob=<file> [--print_time] [--sess_*]");
  puts("                    - Creates a key and saves the blob to file.");
  puts("  --key_load --key_blob=<file> [--print_time] [--sess_*]");
  puts("                    - Loads key from blob, returns handle.");
  puts("  --key_unload --handle=<H>");
  puts("                    - Unloads a loaded key.");
  puts("  --key_sign --handle=<H> --data=<in_file> --signature=<out_file>");
  puts("             [--ecc] [--print_time] [--sess_*]");
  puts("                    - Signs the hash of data using the loaded key.");
  puts("  --key_info --handle=<H> - Prints information about the loaded key.");
  puts("  --persistent_keys - Prints all persistent key handles (Up to 128).");
  puts("  --transient_keys - Prints all transient key handles (Up to 128).");
  puts("  --key_test_short_ecc --handle=<H>.");
  puts("  --sess_* - group of options providing parameters for auth session:");
  puts("      --sess_salted");
  puts("      --sess_encrypted");
  puts("      --sess_empty_auth (supports --key_create  and --key_load)");
  puts("  --index_name --index=<N> - print the name of NV index N in hex");
  puts("                             format.");
  puts("  --index_data --index=<N> - print the data of NV index N in hex");
  puts("                             format.");
  puts("  --ext_command_test - Runs regression tests on extended commands.");
  puts("  --uds_calc [(--zero|--rec|--recdev)]");
  puts("      - Calculate UnDefineSpecial(UDS) digest for the PCR0 value");
  puts("        (use current value, if none of the perdefined is specified)");
  puts("  --policy_or=<val1>,<val2>,<val3>");
  puts("      - Calculate PolicyOR digest for the specified digests");
  puts("  --uds_create --index=<index> --size=<size> --digest=<digest>");
  puts("      - Create test nvmem space with UDS digest.");
  puts("  --uds_delete --index=<index> [(--zero|--rec|--recdev)]");
  puts("               [--or=<val1>,<val2>,<val3>]");
  puts("      - Delete test nvmem space with UDS digest and");
  puts("        optional PolicyOR using current PCR0 value.");
  puts("  --ecc_ek_handle --password=<endorsement passwword");
  puts("      - Get the ECC EK handle.");
  puts("  --test_credential_command --password=<hex endorsement password>");
  puts("                             -handle=<endorsement key handle>");
  puts("      - Perform a closed-loop testing: Create AIK-> Make credential");
  puts("        -> Activate credential with EK.");
  puts("  --test_sign_verify - Perform a closed-loop sign and verify test");
  puts("  --test_certify_simple");
  puts("     - Perform certifying key and partially verify the output-");
  puts("D-Bus options:");
  puts("  --vtpm");
  puts("      - Send the TPM command to vtpm instead of trunks.");
}

std::string HexEncode(const std::string& bytes) {
  return base::HexEncode(bytes.data(), bytes.size());
}

std::string HexEncode(const trunks::TPM2B_DIGEST& tpm2b) {
  return base::HexEncode(tpm2b.buffer, tpm2b.size);
}
std::string HexEncode(const trunks::TPM2B_ECC_PARAMETER& tpm2b) {
  return base::HexEncode(tpm2b.buffer, tpm2b.size);
}
std::string HexEncode(const trunks::TPM2B_PUBLIC_KEY_RSA& tpm2b) {
  return base::HexEncode(tpm2b.buffer, tpm2b.size);
}

int OutputToFile(const std::string& file_name, const std::string& data) {
  if (!brillo::WriteStringToFile(base::FilePath(file_name), data)) {
    LOG(ERROR) << "Failed to write to " << file_name;
    return -1;
  }
  return 0;
}

int InputFromFile(const std::string& file_name, std::string* data) {
  if (!base::ReadFileToString(base::FilePath(file_name), data)) {
    LOG(ERROR) << "Failed to write to " << file_name;
    return -1;
  }
  return 0;
}

template <typename OP, typename... ARGS>
trunks::TPM_RC CallTimed(bool print_time,
                         const char* op_name,
                         OP op_func,
                         ARGS&&... args) {
  base::ElapsedTimer timer;
  trunks::TPM_RC rc = op_func(args...);
  if (print_time) {
    printf("%s took %" PRId64 " ms\n", op_name,
           timer.Elapsed().InMilliseconds());
  }
  return rc;
}

template <typename OP, typename... ARGS>
trunks::TPM_RC CallTpmUtility(bool print_time,
                              const TrunksFactory& factory,
                              const char* op_name,
                              OP op_func,
                              ARGS&&... args) {
  std::unique_ptr<trunks::TpmUtility> tpm_utility = factory.GetTpmUtility();
  trunks::TPM_RC rc = CallTimed(print_time, op_name, std::mem_fn(op_func),
                                tpm_utility.get(), args...);
  LOG_IF(ERROR, rc) << "Error during " << op_name << ": "
                    << trunks::GetErrorString(rc);
  return rc;
}

// An authorization delegate to manage multiple authorization sessions for a
// single command.
// Copied from attestaion/common/tpm_utility_v2.cc
class MultipleAuthorizations : public trunks::AuthorizationDelegate {
 public:
  MultipleAuthorizations() = default;
  ~MultipleAuthorizations() override = default;

  void AddAuthorizationDelegate(trunks::AuthorizationDelegate* delegate) {
    delegates_.push_back(delegate);
  }

  bool GetCommandAuthorization(const std::string& command_hash,
                               bool is_command_parameter_encryption_possible,
                               bool is_response_parameter_encryption_possible,
                               std::string* authorization) override {
    std::string combined_authorization;
    for (auto delegate : delegates_) {
      std::string authorization;
      if (!delegate->GetCommandAuthorization(
              command_hash, is_command_parameter_encryption_possible,
              is_response_parameter_encryption_possible, &authorization)) {
        return false;
      }
      combined_authorization += authorization;
    }
    *authorization = combined_authorization;
    return true;
  }

  bool CheckResponseAuthorization(const std::string& response_hash,
                                  const std::string& authorization) override {
    std::string mutable_authorization = authorization;
    for (auto delegate : delegates_) {
      if (!delegate->CheckResponseAuthorization(
              response_hash,
              ExtractSingleAuthorizationResponse(&mutable_authorization))) {
        return false;
      }
    }
    return true;
  }

  bool EncryptCommandParameter(std::string* parameter) override {
    for (auto delegate : delegates_) {
      if (!delegate->EncryptCommandParameter(parameter)) {
        return false;
      }
    }
    return true;
  }

  bool DecryptResponseParameter(std::string* parameter) override {
    for (auto delegate : delegates_) {
      if (!delegate->DecryptResponseParameter(parameter)) {
        return false;
      }
    }
    return true;
  }

  bool GetTpmNonce(std::string* nonce) override { return false; }

 private:
  std::string ExtractSingleAuthorizationResponse(std::string* all_responses) {
    std::string response;
    trunks::TPMS_AUTH_RESPONSE not_used;
    if (trunks::TPM_RC_SUCCESS !=
        trunks::Parse_TPMS_AUTH_RESPONSE(all_responses, &not_used, &response)) {
      return std::string();
    }
    return response;
  }

  std::vector<trunks::AuthorizationDelegate*> delegates_;
};

int Startup(const TrunksFactory& factory) {
  factory.GetTpmUtility()->Shutdown();
  return factory.GetTpmUtility()->Startup();
}

int Clear(const TrunksFactory& factory) {
  return factory.GetTpmUtility()->Clear();
}

int InitializeTpm(const TrunksFactory& factory) {
  return factory.GetTpmUtility()->InitializeTpm();
}

int AllocatePCR(const TrunksFactory& factory) {
  trunks::TPM_RC result;
  result = factory.GetTpmUtility()->AllocatePCR("");
  if (result != trunks::TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error allocating PCR:" << trunks::GetErrorString(result);
    return result;
  }
  factory.GetTpmUtility()->Shutdown();
  return factory.GetTpmUtility()->Startup();
}

int TakeOwnership(const std::string& owner_password,
                  const TrunksFactory& factory) {
  trunks::TPM_RC rc;
  rc = factory.GetTpmUtility()->TakeOwnership(owner_password, owner_password,
                                              owner_password);
  if (rc) {
    LOG(ERROR) << "Error taking ownership: " << trunks::GetErrorString(rc);
    return rc;
  }
  return 0;
}

int DumpStatus(const TrunksFactory& factory) {
  std::unique_ptr<trunks::TpmState> state = factory.GetTpmState();
  trunks::TPM_RC result = state->Initialize();
  if (result != trunks::TPM_RC_SUCCESS) {
    LOG(ERROR) << "Failed to read TPM state: "
               << trunks::GetErrorString(result);
    return result;
  }
  printf("Owner password set: %s\n",
         state->IsOwnerPasswordSet() ? "true" : "false");
  printf("Endorsement password set: %s\n",
         state->IsEndorsementPasswordSet() ? "true" : "false");
  printf("Lockout password set: %s\n",
         state->IsLockoutPasswordSet() ? "true" : "false");
  printf("Ownership status: %s\n", state->IsOwned() ? "true" : "false");
  printf("In lockout: %s\n", state->IsInLockout() ? "true" : "false");
  printf("Platform hierarchy enabled: %s\n",
         state->IsPlatformHierarchyEnabled() ? "true" : "false");
  printf("Storage hierarchy enabled: %s\n",
         state->IsStorageHierarchyEnabled() ? "true" : "false");
  printf("Endorsement hierarchy enabled: %s\n",
         state->IsEndorsementHierarchyEnabled() ? "true" : "false");
  printf("Is Tpm enabled: %s\n", state->IsEnabled() ? "true" : "false");
  printf("Was shutdown orderly: %s\n",
         state->WasShutdownOrderly() ? "true" : "false");
  printf("Is RSA supported: %s\n", state->IsRSASupported() ? "true" : "false");
  printf("Is ECC supported: %s\n", state->IsECCSupported() ? "true" : "false");
  printf("Lockout Counter: %u\n", state->GetLockoutCounter());
  printf("Lockout Threshold: %u\n", state->GetLockoutThreshold());
  printf("Lockout Interval: %u\n", state->GetLockoutInterval());
  printf("Lockout Recovery: %u\n", state->GetLockoutRecovery());
  return 0;
}

int ReadPCR(const TrunksFactory& factory, int index) {
  std::unique_ptr<trunks::TpmUtility> tpm_utility = factory.GetTpmUtility();
  std::string value;
  trunks::TPM_RC result = tpm_utility->ReadPCR(index, &value);
  if (result) {
    LOG(ERROR) << "ReadPCR: " << trunks::GetErrorString(result);
    return result;
  }
  printf("PCR Value: %s\n", HexEncode(value).c_str());
  return 0;
}

int ExtendPCR(const TrunksFactory& factory,
              int index,
              const std::string& value) {
  std::unique_ptr<trunks::TpmUtility> tpm_utility = factory.GetTpmUtility();
  trunks::TPM_RC result = tpm_utility->ExtendPCR(index, value, nullptr);
  if (result) {
    LOG(ERROR) << "ExtendPCR: " << trunks::GetErrorString(result);
    return result;
  }
  return 0;
}

char* TpmPropertyToStr(uint32_t value) {
  static char str[5];
  char c;
  int i = 0;
  int shift = 24;
  for (; i < 4; i++, shift -= 8) {
    c = static_cast<char>((value >> shift) & 0xFF);
    if (c == 0)
      break;
    str[i] = (c >= 32 && c < 127) ? c : ' ';
  }
  str[i] = 0;
  return str;
}

int TpmVersion(const TrunksFactory& factory) {
  std::unique_ptr<trunks::TpmState> state = factory.GetTpmState();
  trunks::TPM_RC result = state->Initialize();
  if (result != trunks::TPM_RC_SUCCESS) {
    LOG(ERROR) << "Failed to read TPM state: "
               << trunks::GetErrorString(result);
    return result;
  }
  printf("  TPM 2.0 Version Info:\n");
  // Print Chip Version for compatibility with tpm_version, hardcoded as
  // there's no 2.0 equivalent (TPM_PT_FAMILY_INDICATOR is const).
  printf("  Chip Version:        2.0.0.0\n");
  uint32_t family = state->GetTpmFamily();
  printf("  Spec Family:         %08" PRIx32 "\n", family);
  printf("  Spec Family String:  %s\n", TpmPropertyToStr(family));
  printf("  Spec Level:          %" PRIu32 "\n",
         state->GetSpecificationLevel());
  printf("  Spec Revision:       %" PRIu32 "\n",
         state->GetSpecificationRevision());
  uint32_t manufacturer = state->GetManufacturer();
  printf("  Manufacturer Info:   %08" PRIx32 "\n", manufacturer);
  printf("  Manufacturer String: %s\n", TpmPropertyToStr(manufacturer));
  printf("  Vendor ID:           %s\n", state->GetVendorIDString().c_str());
  printf("  TPM Model:           %08" PRIx32 "\n", state->GetTpmModel());
  printf("  Firmware Version:    %016" PRIx64 "\n",
         state->GetFirmwareVersion());

  return 0;
}

int EndorsementPublicKey(const TrunksFactory& factory) {
  std::string ekm;
  factory.GetTpmUtility()->GetPublicRSAEndorsementKeyModulus(&ekm);
  std::string ekm_hex = HexEncode(ekm);
  printf("  Public Endorsement Key Modulus: %s\n", ekm_hex.c_str());
  return 0;
}

int KeyStartSession(trunks::SessionManager* session_manager,
                    base::CommandLine* cl,
                    trunks::HmacAuthorizationDelegate* delegate) {
  bool salted = cl->HasSwitch("sess_salted");
  bool encrypted = cl->HasSwitch("sess_encrypted");
  bool print_time = cl->HasSwitch("print_time");

  trunks::TPM_RC rc =
      CallTimed(print_time, "StartSession",
                std::mem_fn(&trunks::SessionManager::StartSession),
                session_manager, trunks::TPM_SE_HMAC, trunks::TPM_RH_NULL, "",
                salted, encrypted, delegate);
  LOG_IF(ERROR, rc) << "Failed to start session: "
                    << trunks::GetErrorString(rc);
  return rc;
}

int GetKeyUsage(const std::string& option_value,
                trunks::TpmUtility::AsymmetricKeyUsage* key_usage) {
  const std::map<std::string, trunks::TpmUtility::AsymmetricKeyUsage> mapping =
      // NOLINTNEXTLINE(whitespace/braces)
      {
          {"decrypt", trunks::TpmUtility::kDecryptKey},
          {"sign", trunks::TpmUtility::kSignKey},
          {"all", trunks::TpmUtility::kDecryptAndSignKey},
      };
  auto entry = mapping.find(option_value);
  if (entry == mapping.end()) {
    LOG(ERROR) << "Unrecognized key usage: " << option_value;
    return -1;
  }
  *key_usage = entry->second;
  return 0;
}

int KeyInfo(bool print_time, const TrunksFactory& factory, uint32_t handle) {
  trunks::TPMT_PUBLIC public_area;
  if (CallTpmUtility(print_time, factory, "GetKeyPublicArea",
                     &trunks::TpmUtility::GetKeyPublicArea, handle,
                     &public_area)) {
    return -1;
  }
  puts("Key public area:");
  printf("  type: %#x\n", public_area.type);
  printf("  name_alg: %#x\n", public_area.name_alg);
  printf("  attributes: %#x\n", public_area.object_attributes);
  printf("  auth_policy: %s\n", HexEncode(public_area.auth_policy).c_str());
  if (public_area.type == trunks::TPM_ALG_RSA) {
    printf("  RSA modulus: %s\n", HexEncode(public_area.unique.rsa).c_str());
  } else if (public_area.type == trunks::TPM_ALG_ECC) {
    printf("  ECC X: %s\n", HexEncode(public_area.unique.ecc.x).c_str());
    printf("  ECC Y: %s\n", HexEncode(public_area.unique.ecc.y).c_str());
  }

  std::string key_name;
  if (CallTpmUtility(print_time, factory, "GetKeyName",
                     &trunks::TpmUtility::GetKeyName, handle, &key_name)) {
    return -1;
  }
  printf("Key name: %s\n", HexEncode(key_name).c_str());

  return 0;
}

int PersistentKeys(const TrunksFactory& factory) {
  trunks::TPMI_YES_NO more_data = YES;
  trunks::TPMS_CAPABILITY_DATA capability_data;
  trunks::TPM_RC rc = factory.GetTpm()->GetCapabilitySync(
      trunks::TPM_CAP_HANDLES, trunks::PERSISTENT_FIRST, 128 /*property_count*/,
      &more_data, &capability_data, nullptr /*authorization_delegate*/);
  if (rc != trunks::TPM_RC_SUCCESS) {
    LOG(ERROR) << ": Error querying handles: " << trunks::GetErrorString(rc);
    return -1;
  }
  const trunks::TPML_HANDLE& handles = capability_data.data.handles;
  if (handles.count == 0) {
    puts("No persistent key found.");
    return 0;
  }
  puts("Persistent keys:");
  for (int i = 0; i < handles.count; ++i) {
    printf("  %#x\n", handles.handle[i]);
  }
  return 0;
}

int TransientKeys(const TrunksFactory& factory) {
  trunks::TPMI_YES_NO more_data = YES;
  trunks::TPMS_CAPABILITY_DATA capability_data;
  trunks::TPM_RC rc = factory.GetTpm()->GetCapabilitySync(
      trunks::TPM_CAP_HANDLES, trunks::TRANSIENT_FIRST, 128 /*property_count*/,
      &more_data, &capability_data, nullptr /*authorization_delegate*/);
  if (rc != trunks::TPM_RC_SUCCESS) {
    LOG(ERROR) << ": Error querying handles: " << trunks::GetErrorString(rc);
    return -1;
  }
  const trunks::TPML_HANDLE& handles = capability_data.data.handles;
  if (handles.count == 0) {
    puts("No transient key found.");
    return 0;
  }
  puts("Transient keys:");
  for (int i = 0; i < handles.count; ++i) {
    printf("  %#x\n", handles.handle[i]);
  }
  return 0;
}

void PrintEccPoint(const char* name, const trunks::TPM2B_ECC_POINT& point) {
  printf("%s point: [%u]", name, point.size);
  printf("  X=[%u] %s, ", point.point.x.size, HexEncode(point.point.x).c_str());
  printf("  Y=[%u] %s\n", point.point.y.size, HexEncode(point.point.y).c_str());
}

int KeyTestShortEcc(const TrunksFactory& factory, uint32_t handle) {
  std::unique_ptr<trunks::TpmUtility> tpm_utility = factory.GetTpmUtility();
  std::string name;
  trunks::TPM_RC rc = tpm_utility->GetKeyName(handle, &name);
  if (rc != trunks::TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error during GetKeyName: " << trunks::GetErrorString(rc);
    return -1;
  }

  trunks::HmacAuthorizationDelegate delegate;
  std::unique_ptr<trunks::SessionManager> session_manager =
      factory.GetSessionManager();
  rc = session_manager->StartSession(trunks::TPM_SE_HMAC, trunks::TPM_RH_NULL,
                                     "", false, false, &delegate);
  if (rc != trunks::TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error during StartSession: " << trunks::GetErrorString(rc);
    return -1;
  }

  trunks::TPM2B_ECC_POINT z_point;
  trunks::TPM2B_ECC_POINT pub_point;

  do {
    rc = factory.GetTpm()->ECDH_KeyGenSync(handle, name, &z_point, &pub_point,
                                           nullptr);
    if (rc != trunks::TPM_RC_SUCCESS) {
      LOG(ERROR) << "Error during ECDH_KeyGen: " << trunks::GetErrorString(rc);
      return -1;
    }
  } while (pub_point.point.x.buffer[0] && pub_point.point.y.buffer[0]);
  PrintEccPoint("z", z_point);
  PrintEccPoint("pub", pub_point);

  trunks::TPM2B_ECC_POINT out1_point;
  rc = factory.GetTpm()->ECDH_ZGenSync(handle, name, pub_point, &out1_point,
                                       &delegate);
  if (rc != trunks::TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error during ECDH_ZGen (pass 1): "
               << trunks::GetErrorString(rc);
    return -1;
  }
  PrintEccPoint("out1", out1_point);

  if (pub_point.point.x.buffer[0] == 0) {
    pub_point.point.x.size--;
    memmove(pub_point.point.x.buffer, pub_point.point.x.buffer + 1,
            pub_point.point.x.size);
  }
  if (pub_point.point.y.buffer[0] == 0) {
    pub_point.point.y.size--;
    memmove(pub_point.point.y.buffer, pub_point.point.y.buffer + 1,
            pub_point.point.y.size);
  }
  PrintEccPoint("shortened pub", pub_point);

  trunks::TPM2B_ECC_POINT out2_point;
  rc = factory.GetTpm()->ECDH_ZGenSync(handle, name, pub_point, &out2_point,
                                       &delegate);
  if (rc != trunks::TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error during ECDH_ZGen (pass 2): "
               << trunks::GetErrorString(rc);
    return -1;
  }
  PrintEccPoint("out2", out2_point);

  if (out1_point.point.x.size != out2_point.point.x.size ||
      out1_point.point.y.size != out2_point.point.y.size ||
      memcmp(out1_point.point.x.buffer, out2_point.point.x.buffer,
             out1_point.point.x.size) ||
      memcmp(out1_point.point.y.buffer, out2_point.point.y.buffer,
             out1_point.point.y.size)) {
    LOG(ERROR) << "Different out points produced by pass 1 and pass 2";
    return -1;
  }

  printf("SUCCESS\n");
  return 0;
}

int CsmeTestPcr(const TrunksFactory& factory, int index) {
  const std::set kPcrsInUse = {0, 1, 2, 3, 4};
  if (kPcrsInUse.count(index) > 0) {
    LOG(ERROR) << "PCR Index " << index
               << " is in use for Chrome OS, disallowed for testing.";
    return -1;
  }
  std::unique_ptr<trunks::TpmUtility> tpm_utility = factory.GetTpmUtility();
  std::string tpm_pcr_value, csme_pcr_value;
  trunks::TPM_RC rc = tpm_utility->ReadPCR(index, &tpm_pcr_value);
  if (rc != trunks::TPM_RC_SUCCESS) {
    LOG(ERROR) << "Failed to read TPM PRC value before extension.";
    return -1;
  }
  rc = tpm_utility->ReadPCRFromCSME(index, &csme_pcr_value);
  if (rc != trunks::TPM_RC_SUCCESS) {
    LOG(ERROR) << "Failed to read CSME PRC value before extension.";
    return -1;
  }
  printf("TPM  PCR value: %s\n", HexEncode(tpm_pcr_value).c_str());
  printf("CSME PCR value: %s\n", HexEncode(csme_pcr_value).c_str());
  if (tpm_pcr_value != csme_pcr_value) {
    LOG(ERROR) << "PCR value mismatch before extension.";
    return -1;
  }

  constexpr static char kTestExtension[] = "test extension";
  rc = tpm_utility->ExtendPCR(index, kTestExtension, nullptr);
  if (rc != trunks::TPM_RC_SUCCESS) {
    LOG(ERROR) << "Failed to extend PCR for TPM.";
    return -1;
  }
  rc = tpm_utility->ExtendPCRForCSME(index, kTestExtension);
  if (rc != trunks::TPM_RC_SUCCESS) {
    LOG(ERROR) << "Failed to extend PCR for CSME.";
    return -1;
  }

  rc = tpm_utility->ReadPCR(index, &tpm_pcr_value);
  if (rc != trunks::TPM_RC_SUCCESS) {
    LOG(ERROR) << "Failed to read TPM PRC value after extension.";
    return -1;
  }
  rc = tpm_utility->ReadPCRFromCSME(index, &csme_pcr_value);
  if (rc != trunks::TPM_RC_SUCCESS) {
    LOG(ERROR) << "Failed to read CSME PRC value after extension.";
    return -1;
  }
  printf("TPM  PCR value: %s\n", HexEncode(tpm_pcr_value).c_str());
  printf("CSME PCR value: %s\n", HexEncode(csme_pcr_value).c_str());
  if (tpm_pcr_value != csme_pcr_value) {
    LOG(ERROR) << "PCR value mismatch after extension.";
    return -1;
  }

  printf("SUCCESS\n");
  return 0;
}

int CsmeReadPcr(const TrunksFactory& factory, int index) {
  std::unique_ptr<trunks::TpmUtility> tpm_utility = factory.GetTpmUtility();
  std::string csme_pcr_value;
  trunks::TPM_RC rc = tpm_utility->ReadPCRFromCSME(index, &csme_pcr_value);
  if (rc != trunks::TPM_RC_SUCCESS) {
    LOG(ERROR) << "Failed to read CSME PCR: " << trunks::GetErrorString(rc);
    return -1;
  }
  printf("CSME PCR value: %s\n", HexEncode(csme_pcr_value).c_str());
  return 0;
}

int PrintIndexNameInHex(const TrunksFactory& factory, int index) {
  // Mask out the nv index handle so the user can either add or not add it
  // themselves.
  index &= trunks::HR_HANDLE_MASK;
  std::unique_ptr<trunks::TpmUtility> tpm_utility = factory.GetTpmUtility();
  std::string name;
  trunks::TPM_RC rc = tpm_utility->GetNVSpaceName(index, &name);
  if (rc != trunks::TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error getting NV index name: " << trunks::GetErrorString(rc);
    return -1;
  }
  // Also, print the name returned by TPM directly..
  trunks::TPM2B_NAME nvram_name;
  trunks::TPM2B_NV_PUBLIC public_area;
  public_area.nv_public.nv_index = 0;
  const trunks::UINT32 nv_index = trunks::NV_INDEX_FIRST + index;
  rc = factory.GetTpm()->NV_ReadPublicSync(nv_index, "", &public_area,
                                           &nvram_name, nullptr);
  std::string name_from_tpm(nvram_name.name, nvram_name.name + nvram_name.size);
  printf("NV Index name:          %s\n", HexEncode(name).c_str());
  printf("NV Index name from tpm: %s\n", HexEncode(name_from_tpm).c_str());
  return 0;
}

int PrintIndexDataInHex(const TrunksFactory& factory, int index) {
  // Mask out the nv index handle so the user can either add or not add it
  // themselves.
  index &= trunks::HR_HANDLE_MASK;
  std::unique_ptr<trunks::TpmUtility> tpm_utility = factory.GetTpmUtility();
  trunks::TPMS_NV_PUBLIC nvram_public;
  trunks::TPM_RC rc = tpm_utility->GetNVSpacePublicArea(index, &nvram_public);
  if (rc != trunks::TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error reading NV space public area: "
               << trunks::GetErrorString(rc);
    return -1;
  }
  std::unique_ptr<AuthorizationDelegate> empty_password_authorization =
      factory.GetPasswordAuthorization("");
  std::string nvram_data;
  rc =
      tpm_utility->ReadNVSpace(index, /*offset=*/0, nvram_public.data_size,
                               /*using_owner_authorization=*/false, &nvram_data,
                               empty_password_authorization.get());
  if (rc != trunks::TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error reading NV space: " << trunks::GetErrorString(rc);
    return -1;
  }
  printf("NV Index data: %s\n", HexEncode(nvram_data).c_str());
  return 0;
}

std::string DigestString(const unsigned char* digest_value) {
  auto ptr = reinterpret_cast<const char*>(digest_value);
  return std::string(ptr, SHA256_DIGEST_SIZE);
}

std::string GetPcr0Digest(const TrunksFactory& factory, base::CommandLine* cl) {
  if (cl->HasSwitch("zero")) {
    return DigestString(kPcr0ValueZero);
  } else if (cl->HasSwitch("rec")) {
    return DigestString(kPcr0ValueRec);
  } else if (cl->HasSwitch("recdev")) {
    return DigestString(kPcr0ValueRecDev);
  }
  std::string pcr_digest;
  if (CallTpmUtility(false, factory, "ReadPCR", &trunks::TpmUtility::ReadPCR, 0,
                     &pcr_digest)) {
    return std::string();
  }
  return pcr_digest;
}

std::unique_ptr<trunks::PolicySession> GetUDSSession(
    const TrunksFactory& factory, base::CommandLine* cl, bool trial) {
  auto session = trial ? factory.GetTrialSession() : factory.GetPolicySession();
  if (!session) {
    LOG(ERROR) << "Error during Get" << (trial ? "Trial" : "Policy")
               << "Session";
    return nullptr;
  }

  trunks::TPM_RC rc = session->StartUnboundSession(false, false);
  if (rc) {
    LOG(ERROR) << "Error during StartUnboundSession: "
               << trunks::GetErrorString(rc);
    return nullptr;
  }

  rc = session->PolicyCommandCode(trunks::TPM_CC_NV_UndefineSpaceSpecial);
  if (rc) {
    LOG(ERROR) << "Error during PolicyCommandCode: "
               << trunks::GetErrorString(rc);
    return nullptr;
  }

  const std::string pcr_digest = GetPcr0Digest(factory, cl);
  if (pcr_digest.empty()) {
    return nullptr;
  }

  const std::map<uint32_t, std::string> pcrs{{0, pcr_digest}};
  rc = session->PolicyPCR(pcrs);
  if (rc) {
    LOG(ERROR) << "Error during PolicyPCR: " << trunks::GetErrorString(rc);
    return nullptr;
  }

  return session;
}

int PrintEccEndorsementKeyHandle(const trunks::TrunksFactory& factory,
                                 const std::string& endorsement_password) {
  std::unique_ptr<AuthorizationDelegate> endorsement_password_authorization =
      factory.GetPasswordAuthorization(endorsement_password);
  // Won't be used because we don't persist ECC EK.
  std::unique_ptr<AuthorizationDelegate> owner_password_authorization =
      factory.GetPasswordAuthorization("");
  trunks::TPM_HANDLE endorsement_key_handle = 0;
  trunks::TPM_RC rc = factory.GetTpmUtility()->GetEndorsementKey(
      trunks::TPM_ALG_ECC, endorsement_password_authorization.get(),
      owner_password_authorization.get(), &endorsement_key_handle);
  if (rc) {
    LOG(ERROR) << "Error getting ECC EK handle: " << trunks::GetErrorString(rc);
    return -1;
  }
  printf("Loaded key handle: %#x\n", endorsement_key_handle);
  return 0;
}

bool TestCredentialCommand(const trunks::TrunksFactory& factory,
                           const std::string& endorsement_password,
                           trunks::TPM_HANDLE endorsement_key_handle) {
  std::unique_ptr<AuthorizationDelegate> empty_password_authorization =
      factory.GetPasswordAuthorization("");
  std::string aik_blob;
  trunks::TPM_RC rc = factory.GetTpmUtility()->CreateIdentityKey(
      trunks::TPM_ALG_ECC, empty_password_authorization.get(), &aik_blob);
  if (rc) {
    LOG(ERROR) << "Failed to call `TpmUtility::CreateIdentityKey()`: "
               << trunks::GetErrorString(rc);
    return false;
  }
  // load aik.
  trunks::TPM_HANDLE aik_handle = 0;
  rc = factory.GetTpmUtility()->LoadKey(
      aik_blob, empty_password_authorization.get(), &aik_handle);
  if (rc) {
    LOG(ERROR) << "Failed to call `TpmUtility::LoadKey()`: "
               << trunks::GetErrorString(rc);
    return false;
  }

  // Make sure the object is flushed.
  trunks::ScopedKeyHandle scoped_aik(factory, aik_handle);
  scoped_aik.set_synchronized(true);

  const std::string fake_credential = "fake credential";
  std::string endorsement_key_name;
  rc = factory.GetTpmUtility()->GetKeyName(endorsement_key_handle,
                                           &endorsement_key_name);
  if (rc) {
    LOG(ERROR) << "Failed to call `TpmUtility::GetKeyName()` for ek: "
               << trunks::GetErrorString(rc);
    return false;
  }
  std::string aik_name;
  rc = factory.GetTpmUtility()->GetKeyName(aik_handle, &aik_name);
  if (rc) {
    LOG(ERROR) << "Failed to call `TpmUtility::GetKeyName()` for aik: "
               << trunks::GetErrorString(rc);
    return false;
  }
  trunks::TPM2B_ID_OBJECT credential_blob = {};
  trunks::TPM2B_ENCRYPTED_SECRET secret = {};
  rc = factory.GetTpm()->MakeCredentialSync(
      endorsement_key_handle, endorsement_key_name,
      trunks::Make_TPM2B_DIGEST(fake_credential),
      trunks::Make_TPM2B_NAME(aik_name), &credential_blob, &secret, nullptr);
  if (rc) {
    LOG(ERROR) << "Failed to call `Tpm::MakeCredentialSync()`: "
               << trunks::GetErrorString(rc);
    return false;
  }

  // Prepare the auth session.
  std::unique_ptr<AuthorizationDelegate> endorsement_password_authorization =
      factory.GetPasswordAuthorization(endorsement_password);

  std::unique_ptr<trunks::PolicySession> session = factory.GetPolicySession();
  rc = session->StartUnboundSession(false /* salted */,
                                    false /* enable_encryption */);
  if (rc) {
    LOG(ERROR) << "Failed to start policy session: "
               << trunks::GetErrorString(rc);
    return false;
  }

  trunks::TPMI_DH_ENTITY auth_entity = trunks::TPM_RH_ENDORSEMENT;
  std::string auth_entity_name;
  trunks::Serialize_TPM_HANDLE(auth_entity, &auth_entity_name);

  rc = session->PolicySecret(auth_entity, auth_entity_name, std::string(),
                             std::string(), std::string(), 0,
                             endorsement_password_authorization.get());
  if (rc) {
    LOG(ERROR) << __func__
               << ": Failed to set the secret: " << trunks::GetErrorString(rc);
    return false;
  }

  // Activate the credential.
  MultipleAuthorizations authorization;
  authorization.AddAuthorizationDelegate(empty_password_authorization.get());
  authorization.AddAuthorizationDelegate(session->GetDelegate());

  trunks::TPM2B_DIGEST blob_out;
  LOG(WARNING) << secret.size;

  rc = factory.GetTpm()->ActivateCredentialSync(
      aik_handle, aik_name, endorsement_key_handle, endorsement_key_name,
      credential_blob, secret, &blob_out, &authorization);
  if (rc) {
    LOG(ERROR) << "Failed to call `Tpm::ActivateCredentialSync()`: "
               << trunks::GetErrorString(rc);
    return false;
  }
  std::string activated_credential = trunks::StringFrom_TPM2B_DIGEST(blob_out);
  printf("fake credential in:  %s\n", fake_credential.c_str());
  printf("fake credential out: %s\n", activated_credential.c_str());
  return fake_credential == activated_credential;
}

bool TestSignVerify(const trunks::TrunksFactory& factory) {
  std::unique_ptr<AuthorizationDelegate> empty_password_authorization =
      factory.GetPasswordAuthorization("");
  std::string blob, creation_blob;
  trunks::TPM_RC rc = factory.GetTpmUtility()->CreateECCKeyPair(
      trunks::TpmUtility::AsymmetricKeyUsage::kSignKey,
      trunks::TPM_ECC_NIST_P256,
      /*password=*/"",
      /*policy_digest=*/"",
      /*use_only_policy_authorization=*/false,
      /*creation_pcr_indexes=*/{}, empty_password_authorization.get(), &blob,
      &creation_blob);
  if (rc) {
    LOG(ERROR) << "Failed to create key: " << trunks::GetErrorString(rc);
    return false;
  }

  trunks::TPM_HANDLE handle;
  rc = factory.GetTpmUtility()->LoadKey(
      blob, empty_password_authorization.get(), &handle);
  if (rc) {
    LOG(ERROR) << "Failed to load key: " << trunks::GetErrorString(rc);
    return false;
  }
  trunks::ScopedKeyHandle scoped_key(factory, handle);
  scoped_key.set_synchronized(true);

  const std::string data = "At the end it doesn't even matter.";
  trunks::TPM2B_DIGEST digest = {};
  trunks::TPMT_TK_HASHCHECK validation = {};
  rc = factory.GetTpm()->HashSync(trunks::Make_TPM2B_MAX_BUFFER(data),
                                  trunks::TPM_ALG_SHA256, trunks::TPM_RH_OWNER,
                                  &digest, &validation,
                                  /*authorization_delegate=*/nullptr);
  if (rc) {
    LOG(ERROR) << "Failed to hash: " << trunks::GetErrorString(rc);
    return false;
  }

  trunks::TPMT_SIG_SCHEME scheme = {
      .scheme = trunks::TPM_ALG_ECDSA,
      .details.any.hash_alg = trunks::TPM_ALG_SHA256,
  };
  trunks::TPMT_SIGNATURE signature = {};
  rc = factory.GetTpm()->SignSync(
      handle, /*key_handle_name=*/"not used w/o auth session", digest, scheme,
      validation, &signature, empty_password_authorization.get());
  if (rc) {
    LOG(ERROR) << "Failed to sign: " << trunks::GetErrorString(rc);
    return false;
  }
  trunks::TPMT_TK_VERIFIED verified = {};
  rc = factory.GetTpm()->VerifySignatureSync(
      handle, /*key_handle_name=*/"not used w/o auth session", digest,
      signature, &verified, /*authorization_delegate=*/nullptr);
  if (rc) {
    LOG(ERROR) << "Failed to verify signature: " << trunks::GetErrorString(rc);
    return false;
  }
  return true;
}

bool TestCertify(const trunks::TrunksFactory& factory) {
  std::unique_ptr<AuthorizationDelegate> empty_password_authorization =
      factory.GetPasswordAuthorization("");
  std::string aik_blob;
  trunks::TPM_RC rc = factory.GetTpmUtility()->CreateIdentityKey(
      trunks::TPM_ALG_ECC, empty_password_authorization.get(), &aik_blob);
  if (rc) {
    LOG(ERROR) << "Failed to call `TpmUtility::CreateIdentityKey()`: "
               << trunks::GetErrorString(rc);
    return false;
  }

  std::string blob, creation_blob;
  rc = factory.GetTpmUtility()->CreateECCKeyPair(
      trunks::TpmUtility::AsymmetricKeyUsage::kSignKey,
      trunks::TPM_ECC_NIST_P256,
      /*password=*/"",
      /*policy_digest=*/"",
      /*use_only_policy_authorization=*/false,
      /*creation_pcr_indexes=*/{}, empty_password_authorization.get(), &blob,
      &creation_blob);
  if (rc) {
    LOG(ERROR) << "Failed to create key: " << trunks::GetErrorString(rc);
    return false;
  }

  // Load aik.
  trunks::TPM_HANDLE aik_handle = 0;
  rc = factory.GetTpmUtility()->LoadKey(
      aik_blob, empty_password_authorization.get(), &aik_handle);
  if (rc) {
    LOG(ERROR) << "Failed to call `TpmUtility::LoadKey()`: "
               << trunks::GetErrorString(rc);
    return false;
  }

  // Load key to be certified.
  trunks::TPM_HANDLE handle = 0;
  rc = factory.GetTpmUtility()->LoadKey(
      blob, empty_password_authorization.get(), &handle);
  if (rc) {
    LOG(ERROR) << "Failed to call `TpmUtility::LoadKey()`: "
               << trunks::GetErrorString(rc);
    return false;
  }

  // Make sure the object is flushed.
  trunks::ScopedKeyHandle scoped_aik(factory, aik_handle);
  scoped_aik.set_synchronized(true);
  trunks::ScopedKeyHandle scoped_key(factory, handle);
  scoped_key.set_synchronized(true);

  // Certify.
  MultipleAuthorizations authorization;
  authorization.AddAuthorizationDelegate(empty_password_authorization.get());
  authorization.AddAuthorizationDelegate(empty_password_authorization.get());

  trunks::TPMT_SIG_SCHEME scheme = {
      .scheme = trunks::TPM_ALG_ECDSA,
      .details.any.hash_alg = trunks::TPM_ALG_SHA256,
  };

  trunks::TPM2B_ATTEST certify_info = {};
  trunks::TPMT_SIGNATURE signature = {};

  rc = factory.GetTpm()->CertifySync(
      handle,
      /*object_handle_name=*/"not used w/o auth session", aik_handle,
      /*sign_handle_name=*/"not used w/o auth session",
      trunks::Make_TPM2B_DATA("qualifying data"), scheme, &certify_info,
      &signature, &authorization);

  if (rc) {
    LOG(ERROR) << "Failed to certify: " << trunks::GetErrorString(rc);
    return false;
  }

  // Only perform a simple verification against the output `TPMS_ATTEST`.
  trunks::TPMS_ATTEST attest = {};
  std::string buffer = StringFrom_TPM2B_ATTEST(certify_info);
  rc = trunks::Parse_TPMS_ATTEST(&buffer, &attest, nullptr);
  if (rc) {
    LOG(ERROR) << "Failed to call `Parse_TPMS_ATTEST()`: "
               << trunks::GetErrorString(rc);
    return false;
  }
  if (!buffer.empty()) {
    LOG(ERROR) << "wrong size of `TPMS_ATTEST` buffer.";
    return false;
  }
  if (attest.magic != trunks::TPM_GENERATED_VALUE) {
    LOG(ERROR) << "Unexpected magic number: " << attest.magic;
    return false;
  }
  if (attest.type != trunks::TPM_ST_ATTEST_CERTIFY) {
    LOG(ERROR) << "Unexpected attest type: " << attest.type;
    return false;
  }

  return true;
}

std::vector<std::string> BreakByDelim(const std::string& value,
                                      const std::string& delim) {
  std::vector<std::string> result;
  size_t beg = 0;
  size_t end = value.find(delim);
  while (end != std::string::npos) {
    result.emplace_back(value, beg, end - beg);
    beg = end + delim.size();
    end = value.find(delim, beg);
  }
  result.emplace_back(value, beg);
  return result;
}

}  // namespace

int main(int argc, char** argv) {
  base::CommandLine::Init(argc, argv);
  brillo::InitLog(brillo::kLogToStderr);
  base::CommandLine* cl = base::CommandLine::ForCurrentProcess();
  if (cl->HasSwitch("help")) {
    puts("Trunks Client: A command line tool to access the TPM.");
    PrintUsage();
    return 0;
  }

  std::unique_ptr<TrunksDBusProxy> dbus_proxy =
      cl->HasSwitch("vtpm") ? CreateTrunksDBusProxyToVtpm()
                            : CreateTrunksDBusProxyToTrunks();

  CHECK(dbus_proxy->Init()) << "Failed to initialize D-Bus proxy.";

  TrunksFactoryImpl factory(dbus_proxy.get());
  CHECK(factory.Initialize()) << "Failed to initialize trunks factory.";

  std::unique_ptr<AuthorizationDelegate> empty_password_authorization =
      factory.GetPasswordAuthorization("");

  bool print_time = cl->HasSwitch("print_time");
  if (cl->HasSwitch("status")) {
    return DumpStatus(factory);
  }
  if (cl->HasSwitch("startup")) {
    return Startup(factory);
  }
  if (cl->HasSwitch("clear")) {
    return Clear(factory);
  }
  if (cl->HasSwitch("init_tpm")) {
    return InitializeTpm(factory);
  }
  if (cl->HasSwitch("allocate_pcr")) {
    return AllocatePCR(factory);
  }

  if (cl->HasSwitch("own")) {
    return TakeOwnership(cl->GetSwitchValueASCII("owner_password"), factory);
  }
  if (cl->HasSwitch("regression_test")) {
    trunks::TrunksClientTest test(factory);
    LOG(INFO) << "Running RNG test.";
    if (!test.RNGTest()) {
      LOG(ERROR) << "Error running RNGtest.";
      return -1;
    }
    LOG(INFO) << "Running RSA key tests.";
    if (!test.SignTest()) {
      LOG(ERROR) << "Error running SignTest.";
      return -1;
    }
    if (!test.DecryptTest()) {
      LOG(ERROR) << "Error running DecryptTest.";
      return -1;
    }
    if (!test.ImportTest()) {
      LOG(ERROR) << "Error running ImportTest.";
      return -1;
    }
    if (!test.AuthChangeTest()) {
      LOG(ERROR) << "Error running AuthChangeTest.";
      return -1;
    }
    if (!test.VerifyKeyCreationTest()) {
      LOG(ERROR) << "Error running VerifyKeyCreationTest.";
      return -1;
    }
    LOG(INFO) << "Running Sealed Data test.";
    if (!test.SealedDataTest()) {
      LOG(ERROR) << "Error running SealedDataTest.";
      return -1;
    }
    LOG(INFO) << "Running Sealed to Multiple PCR Data test.";
    if (!test.SealedToMultiplePCRDataTest()) {
      LOG(ERROR) << "Error running SealedToMultiplePCRDataTest.";
      return -1;
    }
    LOG(INFO) << "Running PCR test.";
    if (!test.PCRTest()) {
      LOG(ERROR) << "Error running PCRTest.";
      return -1;
    }
    LOG(INFO) << "Running policy tests.";
    if (!test.PolicyAuthValueTest()) {
      LOG(ERROR) << "Error running PolicyAuthValueTest.";
      return -1;
    }
    if (!test.PolicyAndTest()) {
      LOG(ERROR) << "Error running PolicyAndTest.";
      return -1;
    }
    if (!test.PolicyOrTest()) {
      LOG(ERROR) << "Error running PolicyOrTest.";
      return -1;
    }
    LOG(INFO) << "Running identity key test.";
    if (!test.IdentityKeyTest()) {
      LOG(ERROR) << "Error running IdentityKeyTest.";
      return -1;
    }
    if (cl->HasSwitch("owner_password")) {
      std::string owner_password = cl->GetSwitchValueASCII("owner_password");
      LOG(INFO) << "Running NVRAM test.";
      if (!test.NvramTest(owner_password)) {
        LOG(ERROR) << "Error running NvramTest.";
        return -1;
      }
      if (cl->HasSwitch("endorsement_password")) {
        std::string endorsement_password =
            cl->GetSwitchValueASCII("endorsement_password");
        LOG(INFO) << "Running endorsement test.";
        if (!test.EndorsementTest(endorsement_password, owner_password)) {
          LOG(ERROR) << "Error running EndorsementTest.";
          return -1;
        }
      }
    }
    LOG(INFO) << "All tests were run successfully.";
    return 0;
  }
  if (cl->HasSwitch("ext_command_test")) {
    trunks::TrunksClientTest test(factory);
    LOG(INFO) << "Running PolicyFidoSigned test.";
    if (!test.PolicyFidoSignedTest(trunks::TPM_ALG_RSASSA)) {
      LOG(ERROR) << "Error running PolicyFidoSigned with RSASSA scheme.";
      return -1;
    }
    if (!test.PolicyFidoSignedTest(trunks::TPM_ALG_ECDSA)) {
      LOG(ERROR) << "Error running PolicyFidoSigned with ECDSA scheme.";
      return -1;
    }
    LOG(INFO) << "All tests were run successfully.";
    return 0;
  }
  if (cl->HasSwitch("stress_test")) {
    LOG(INFO) << "Running stress tests.";
    trunks::TrunksClientTest test(factory);
    if (!test.ManyKeysTest()) {
      LOG(ERROR) << "Error running ManyKeysTest.";
      return -1;
    }
    if (!test.ManySessionsTest()) {
      LOG(ERROR) << "Error running ManySessionsTest.";
      return -1;
    }
    return 0;
  }
  if (cl->HasSwitch("read_pcr") && cl->HasSwitch("index")) {
    return ReadPCR(factory, atoi(cl->GetSwitchValueASCII("index").c_str()));
  }
  if (cl->HasSwitch("extend_pcr") && cl->HasSwitch("index") &&
      cl->HasSwitch("value")) {
    return ExtendPCR(factory, atoi(cl->GetSwitchValueASCII("index").c_str()),
                     cl->GetSwitchValueASCII("value"));
  }
  if (cl->HasSwitch("tpm_version")) {
    return TpmVersion(factory);
  }
  if (cl->HasSwitch("endorsement_public_key")) {
    return EndorsementPublicKey(factory);
  }

  if (cl->HasSwitch("key_create") &&
      (cl->HasSwitch("rsa") || cl->HasSwitch("ecc")) &&
      cl->HasSwitch("usage") && cl->HasSwitch("key_blob")) {
    trunks::TpmUtility::AsymmetricKeyUsage key_usage;
    if (GetKeyUsage(cl->GetSwitchValueASCII("usage"), &key_usage)) {
      return -1;
    }
    trunks::HmacAuthorizationDelegate hmac_delegate;
    trunks::AuthorizationDelegate* delegate = nullptr;
    std::unique_ptr<trunks::SessionManager> session_manager =
        factory.GetSessionManager();
    if (cl->HasSwitch("sess_empty_auth")) {
      delegate = empty_password_authorization.get();
    } else if (KeyStartSession(session_manager.get(), cl, &hmac_delegate)) {
      return -1;
    } else {
      delegate = &hmac_delegate;
    }

    std::string key_blob;

    if (cl->HasSwitch("rsa")) {
      int modulus_bits = std::stoi(cl->GetSwitchValueASCII("rsa"), nullptr, 0);
      if (CallTpmUtility(print_time, factory, "CreateRSAKeyPair",
                         &trunks::TpmUtility::CreateRSAKeyPair, key_usage,
                         modulus_bits, 0x10001 /* exponent */,
                         "" /* password */, "" /* policy_digest */,
                         false /* use_only_policy_digest */,
                         std::vector<uint32_t>() /* pcrs */, delegate,
                         &key_blob, nullptr /* creation_blob */)) {
        return -1;
      }
    } else {
      if (CallTpmUtility(print_time, factory, "CreateECCKeyPair",
                         &trunks::TpmUtility::CreateECCKeyPair, key_usage,
                         trunks::TPM_ECC_NIST_P256 /* curve_id */,
                         "" /* password */, "" /* policy_digest */,
                         false /* use_only_policy_digest */,
                         std::vector<uint32_t>() /* pcrs */, delegate,
                         &key_blob, nullptr /* creation_blob */)) {
        return -1;
      }
    }
    return OutputToFile(cl->GetSwitchValueASCII("key_blob"), key_blob);
  }
  if (cl->HasSwitch("key_load") && cl->HasSwitch("key_blob")) {
    std::string key_blob;
    if (InputFromFile(cl->GetSwitchValueASCII("key_blob"), &key_blob)) {
      return -1;
    }
    trunks::HmacAuthorizationDelegate hmac_delegate;
    trunks::AuthorizationDelegate* delegate = nullptr;
    std::unique_ptr<trunks::SessionManager> session_manager =
        factory.GetSessionManager();
    if (cl->HasSwitch("sess_empty_auth")) {
      delegate = empty_password_authorization.get();
    } else if (KeyStartSession(session_manager.get(), cl, &hmac_delegate)) {
      return -1;
    } else {
      delegate = &hmac_delegate;
    }

    trunks::TPM_HANDLE handle;
    if (CallTpmUtility(print_time, factory, "Load",
                       &trunks::TpmUtility::LoadKey, key_blob, delegate,
                       &handle)) {
      return -1;
    }
    printf("Loaded key handle: %#x\n", handle);
    return 0;
  }
  if (cl->HasSwitch("key_unload") && cl->HasSwitch("handle")) {
    const trunks::TPM_HANDLE handle = static_cast<trunks::TPM_HANDLE>(
        std::stoul(cl->GetSwitchValueASCII("handle"), nullptr, 0));

    trunks::TPM_RC result = factory.GetTpm()->FlushContextSync(handle, nullptr);
    if (result) {
      LOG(ERROR) << "Error closing handle: " << handle << " : "
                 << trunks::GetErrorString(result);
      return -1;
    }
    return 0;
  }
  if (cl->HasSwitch("key_sign") && cl->HasSwitch("handle") &&
      cl->HasSwitch("data") && cl->HasSwitch("signature")) {
    uint32_t handle = std::stoul(cl->GetSwitchValueASCII("handle"), nullptr, 0);
    std::string data;
    if (InputFromFile(cl->GetSwitchValueASCII("data"), &data)) {
      return -1;
    }
    trunks::HmacAuthorizationDelegate delegate;
    std::unique_ptr<trunks::SessionManager> session_manager =
        factory.GetSessionManager();
    if (KeyStartSession(session_manager.get(), cl, &delegate)) {
      return -1;
    }
    trunks::TPM_ALG_ID signature_algorithm =
        cl->HasSwitch("ecc") ? trunks::TPM_ALG_ECDSA : trunks::TPM_ALG_RSASSA;
    std::string signature;
    if (CallTpmUtility(print_time, factory, "Sign", &trunks::TpmUtility::Sign,
                       handle, signature_algorithm, trunks::TPM_ALG_SHA256,
                       data, true /* generate_hash */, &delegate, &signature)) {
      return -1;
    }

    if (signature_algorithm == trunks::TPM_ALG_ECDSA) {
      trunks::TPMT_SIGNATURE tpm_signature;
      trunks::TPM_RC result =
          trunks::Parse_TPMT_SIGNATURE(&signature, &tpm_signature, nullptr);
      if (result != trunks::TPM_RC_SUCCESS) {
        LOG(ERROR) << "Error when parsing TPM signing result.";
        return -1;
      }

      // Pack TPM structure to OpenSSL ECDSA_SIG structure.
      crypto::ScopedECDSA_SIG openssl_ecdsa(ECDSA_SIG_new());
      crypto::ScopedBIGNUM r(BN_new()), s(BN_new());
      if (!openssl_ecdsa || !r || !s) {
        LOG(ERROR) << "Failed to allocate ECDSA_SIG or its BIGNUMs.";
        return -1;
      }
      if (!BN_bin2bn(tpm_signature.signature.ecdsa.signature_r.buffer,
                     tpm_signature.signature.ecdsa.signature_r.size, r.get()) ||
          !BN_bin2bn(tpm_signature.signature.ecdsa.signature_s.buffer,
                     tpm_signature.signature.ecdsa.signature_s.size, s.get()) ||
          !ECDSA_SIG_set0(openssl_ecdsa.get(), r.release(), s.release())) {
        LOG(ERROR) << "Error when parse TPM signing result.";
        return -1;
      }

      // Dump ECDSA_SIG to DER format
      unsigned char* openssl_buffer = nullptr;
      int length = i2d_ECDSA_SIG(openssl_ecdsa.get(), &openssl_buffer);
      crypto::ScopedOpenSSLBytes scoped_buffer(openssl_buffer);

      signature = std::string(reinterpret_cast<char*>(openssl_buffer), length);
    }

    return OutputToFile(cl->GetSwitchValueASCII("signature"), signature);
  }
  if (cl->HasSwitch("key_info") && cl->HasSwitch("handle")) {
    uint32_t handle = std::stoul(cl->GetSwitchValueASCII("handle"), nullptr, 0);
    return KeyInfo(print_time, factory, handle);
  }
  if (cl->HasSwitch("persistent_keys")) {
    return PersistentKeys(factory);
  }
  if (cl->HasSwitch("transient_keys")) {
    return TransientKeys(factory);
  }
  if (cl->HasSwitch("key_test_short_ecc") && cl->HasSwitch("handle")) {
    uint32_t handle = std::stoul(cl->GetSwitchValueASCII("handle"), nullptr, 0);
    return KeyTestShortEcc(factory, handle);
  }
  if (cl->HasSwitch("csme_test_pcr") && cl->HasSwitch("index")) {
    uint32_t index = std::stoul(cl->GetSwitchValueASCII("index"), nullptr, 0);
    return CsmeTestPcr(factory, index);
  }
  if (cl->HasSwitch("csme_read_pcr") && cl->HasSwitch("index")) {
    uint32_t index = std::stoul(cl->GetSwitchValueASCII("index"), nullptr, 0);
    return CsmeReadPcr(factory, index);
  }
  if (cl->HasSwitch("index_name") && cl->HasSwitch("index")) {
    uint32_t nv_index =
        std::stoul(cl->GetSwitchValueASCII("index"), nullptr, 16);
    return PrintIndexNameInHex(factory, nv_index);
  }
  if (cl->HasSwitch("index_data") && cl->HasSwitch("index")) {
    uint32_t nv_index =
        std::stoul(cl->GetSwitchValueASCII("index"), nullptr, 16);
    return PrintIndexDataInHex(factory, nv_index);
  }

  if (cl->HasSwitch("uds_calc")) {
    auto session = GetUDSSession(factory, cl, true);

    std::string digest;
    trunks::TPM_RC rc = session->GetDigest(&digest);
    if (rc) {
      LOG(ERROR) << "Error during GetDigest: " << trunks::GetErrorString(rc);
      return -1;
    }
    printf("Digest: %s\n", HexEncode(digest).c_str());
    return 0;
  }

  if (cl->HasSwitch("policy_or")) {
    auto hexdigests = BreakByDelim(cl->GetSwitchValueASCII("policy_or"), ",");

    std::vector<std::string> digests;
    for (const auto& hexdigest : hexdigests) {
      std::string digest;
      if (!base::HexStringToString(hexdigest, &digest) ||
          digest.size() != SHA256_DIGEST_SIZE) {
        LOG(ERROR) << "Syntax error: policy_or takes "
                   << "a list of comma-separated SHA256 digests";
        return -1;
      }
      digests.push_back(digest);
    }
    if (digests.size() > 8) {
      LOG(ERROR) << "Syntax error: policy_or supports "
                 << "up to 8 digests";
      return -1;
    }
    for (const auto& digest : digests) {
      printf("Input Digest: %s\n", HexEncode(digest).c_str());
    }
    printf("\n");

    auto session = factory.GetTrialSession();
    if (!session) {
      LOG(ERROR) << "Error during GetTrialSession";
      return -1;
    }

    trunks::TPM_RC rc = session->StartUnboundSession(false, false);
    if (rc) {
      LOG(ERROR) << "Error during StartUnboundSession: "
                 << trunks::GetErrorString(rc);
      return -1;
    }

    rc = session->PolicyOR(digests);
    if (rc) {
      LOG(ERROR) << "Error during PolicyOR: " << trunks::GetErrorString(rc);
      return -1;
    }

    std::string digest;
    rc = session->GetDigest(&digest);
    if (rc) {
      LOG(ERROR) << "Error during GetDigest: " << trunks::GetErrorString(rc);
      return -1;
    }
    printf("Digest: %s\n", HexEncode(digest).c_str());
    return 0;
  }

  if (cl->HasSwitch("uds_create") && cl->HasSwitch("index") &&
      cl->HasSwitch("size") && cl->HasSwitch("digest")) {
    uint32_t index = std::stoul(cl->GetSwitchValueASCII("index"), nullptr, 0);
    uint32_t size = std::stoul(cl->GetSwitchValueASCII("size"), nullptr, 0);
    if (size > MAX_NV_BUFFER_SIZE) {
      LOG(ERROR) << "Size too big";
      return -1;
    }
    auto hexdigest = cl->GetSwitchValueASCII("digest");
    std::string digest;
    if (!base::HexStringToString(hexdigest, &digest) ||
        digest.size() != SHA256_DIGEST_SIZE) {
      PrintUsage();
      return -1;
    }

    const uint32_t nv_index = trunks::NV_INDEX_FIRST + index;
    trunks::TPMS_NV_PUBLIC public_data;
    public_data.nv_index = nv_index;
    public_data.name_alg = trunks::TPM_ALG_SHA256;
    public_data.attributes =
        trunks::TPMA_NV_PPWRITE + trunks::TPMA_NV_AUTHREAD +
        trunks::TPMA_NV_PPREAD + trunks::TPMA_NV_PLATFORMCREATE +
        trunks::TPMA_NV_WRITE_STCLEAR + trunks::TPMA_NV_POLICY_DELETE;
    public_data.auth_policy = trunks::Make_TPM2B_DIGEST(digest);
    public_data.data_size = size;

    const trunks::TPM2B_AUTH authorization = trunks::Make_TPM2B_DIGEST("");
    const trunks::TPM2B_NV_PUBLIC public_area =
        trunks::Make_TPM2B_NV_PUBLIC(public_data);
    std::string rh_name;
    trunks::Serialize_TPM_HANDLE(trunks::TPM_RH_PLATFORM, &rh_name);
    trunks::PasswordAuthorizationDelegate delegate("");

    trunks::TPM_RC rc = factory.GetTpm()->NV_DefineSpaceSync(
        trunks::TPM_RH_PLATFORM, rh_name, authorization, public_area,
        &delegate);
    if (rc) {
      LOG(ERROR) << "Error during NV_DefineSpace: "
                 << trunks::GetErrorString(rc);
      return -1;
    }

    std::string nv_name;
    rc = factory.GetTpmUtility()->GetNVSpaceName(index, &nv_name);
    if (rc) {
      LOG(ERROR) << "Error during GetNVSpaceName: "
                 << trunks::GetErrorString(rc);
      return -1;
    }

    trunks::TPM2B_MAX_NV_BUFFER data;
    data.size = size;
    memset(data.buffer, 0xA5, size);
    rc = factory.GetTpm()->NV_WriteSync(trunks::TPM_RH_PLATFORM, rh_name,
                                        nv_index, nv_name, data, 0, &delegate);
    if (rc) {
      LOG(ERROR) << "Error during NV_Write: " << trunks::GetErrorString(rc);
      return -1;
    }

    rc = factory.GetTpm()->NV_WriteLockSync(trunks::TPM_RH_PLATFORM, rh_name,
                                            nv_index, nv_name, &delegate);
    if (rc) {
      LOG(ERROR) << "Error during NV_WriteLock: " << trunks::GetErrorString(rc);
      return -1;
    }

    return 0;
  }

  if (cl->HasSwitch("uds_delete") && cl->HasSwitch("index")) {
    uint32_t index = std::stoul(cl->GetSwitchValueASCII("index"), nullptr, 0);
    auto hexdigests = BreakByDelim(cl->GetSwitchValueASCII("or"), ",");
    auto empty_password_authorization =
        factory.GetPasswordAuthorization(std::string());

    std::vector<std::string> digests;
    for (const auto& hexdigest : hexdigests) {
      std::string digest;
      if (!base::HexStringToString(hexdigest, &digest) ||
          digest.size() != SHA256_DIGEST_SIZE) {
        LOG(ERROR) << "Syntax error: or takes "
                   << "a list of comma-separated SHA256 digests";
        return -1;
      }
      digests.push_back(digest);
    }
    if (digests.size() > 8) {
      LOG(ERROR) << "Syntax error: or supports "
                 << "up to 8 digests";
      return -1;
    }
    for (const auto& digest : digests) {
      printf("Or Digest: %s\n", HexEncode(digest).c_str());
    }
    printf("\n");

    auto session = GetUDSSession(factory, cl, false);
    trunks::TPM_RC rc = session->PolicyOR(digests);
    if (rc) {
      LOG(ERROR) << "Error during PolicyOR: " << trunks::GetErrorString(rc);
      return -1;
    }

    const uint32_t nv_index = trunks::NV_INDEX_FIRST + index;
    std::string nv_name;
    rc = factory.GetTpmUtility()->GetNVSpaceName(index, &nv_name);
    if (rc) {
      LOG(ERROR) << "Error during GetNVSpaceName: "
                 << trunks::GetErrorString(rc);
      return -1;
    }
    std::string rh_name;
    trunks::Serialize_TPM_HANDLE(trunks::TPM_RH_PLATFORM, &rh_name);

    MultipleAuthorizations authorization;
    authorization.AddAuthorizationDelegate(session->GetDelegate());
    authorization.AddAuthorizationDelegate(empty_password_authorization.get());
    rc = factory.GetTpm()->NV_UndefineSpaceSpecialSync(
        nv_index, nv_name, trunks::TPM_RH_PLATFORM, rh_name, &authorization);
    if (rc) {
      LOG(ERROR) << "Error during NV_UndefineSpaceSpecial: "
                 << trunks::GetErrorString(rc);
      return -1;
    }
    return 0;
  }
  if (cl->HasSwitch("ecc_ek_handle") && cl->HasSwitch("password")) {
    const std::string hex_password = cl->GetSwitchValueASCII("password");
    std::string endorsement_password;
    if (!hex_password.empty() &&
        !base::HexStringToString(hex_password, &endorsement_password)) {
      puts("Error hex-decoding endorsement password.");
      return -1;
    }
    return PrintEccEndorsementKeyHandle(factory, endorsement_password);
  }
  if (cl->HasSwitch("test_credential_command") && cl->HasSwitch("password") &&
      cl->HasSwitch("handle")) {
    uint32_t endorsement_key_handle =
        std::stoul(cl->GetSwitchValueASCII("handle"), nullptr, 0);
    const std::string hex_password = cl->GetSwitchValueASCII("password");
    std::string endorsement_password;
    if (!hex_password.empty() &&
        !base::HexStringToString(hex_password, &endorsement_password)) {
      puts("Error hex-decoding endorsement password.");
      return -1;
    }
    if (TestCredentialCommand(factory, endorsement_password,
                              endorsement_key_handle)) {
      puts("pass");
      return 0;
    }
    puts("fail");
    return -1;
  }
  if (cl->HasSwitch("test_sign_verify")) {
    if (TestSignVerify(factory)) {
      puts("pass");
      return 0;
    }
    puts("fail");
    return -1;
  }
  if (cl->HasSwitch("test_certify_simple")) {
    if (TestCertify(factory)) {
      puts("pass");
      return 0;
    }
    puts("fail");
    return -1;
  }

  puts("Invalid options!");
  PrintUsage();
  return -1;
}
