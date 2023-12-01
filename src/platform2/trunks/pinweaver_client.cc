// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
// pinweaver_client is a command line tool for executing PinWeaver vendor
// specific commands to GSC.

#include <base/check.h>
#include <base/command_line.h>
#include <base/json/json_writer.h>
#include <base/logging.h>
#include <base/rand_util.h>
#include <base/strings/string_number_conversions.h>
#include <base/threading/platform_thread.h>
#include <base/time/time.h>
#include <base/values.h>
#include <brillo/syslog_logging.h>
#include <libhwsec-foundation/crypto/aes.h>
#include <libhwsec-foundation/crypto/big_num_util.h>
#include <libhwsec-foundation/crypto/ecdh_hkdf.h>
#include <libhwsec-foundation/crypto/sha.h>
#include <openssl/sha.h>

#include <algorithm>
#include <cinttypes>
#include <memory>

#include "trunks/tpm_pinweaver.h"
#include "trunks/tpm_utility.h"
#include "trunks/trunks_client_test.h"
#include "trunks/trunks_factory_impl.h"

using hwsec_foundation::EllipticCurve;

namespace {

enum return_codes {
  EXIT_SUCCESS_RESERVED = EXIT_SUCCESS,
  EXIT_FAILURE_RESERVED = EXIT_FAILURE,
  EXIT_PINWEAVER_NOT_SUPPORTED = 2,
};

const uint8_t DEFAULT_BITS_PER_LEVEL = 2;
const uint8_t DEFAULT_HEIGHT = 6;
const uint8_t DEFAULT_LE_SECRET[PW_SECRET_SIZE] = {
    // clang-format off
    0xba, 0xbc, 0x98, 0x9d, 0x97, 0x20, 0xcf, 0xea,
    0xaa, 0xbd, 0xb2, 0xe3, 0xe0, 0x2c, 0x5c, 0x55,
    0x06, 0x60, 0x93, 0xbd, 0x07, 0xe2, 0xba, 0x92,
    0x10, 0x19, 0x24, 0xb1, 0x29, 0x33, 0x5a, 0xe2
    // clang-format on
};
const uint8_t DEFAULT_HE_SECRET[PW_SECRET_SIZE] = {
    // clang-format off
    0xe3, 0x46, 0xe3, 0x62, 0x01, 0x5d, 0xfe, 0x0a,
    0xd3, 0x67, 0xd7, 0xef, 0xab, 0x01, 0xad, 0x0e,
    0x3a, 0xed, 0xe8, 0x2f, 0x99, 0xd1, 0x2d, 0x13,
    0x4d, 0x4e, 0xe4, 0x02, 0xbe, 0x71, 0x8e, 0x40
    // clang-format on
};
const uint8_t DEFAULT_RESET_SECRET[PW_SECRET_SIZE] = {
    // clang-format off
    0x8c, 0x33, 0x8c, 0xa7, 0x0f, 0x81, 0xa4, 0xee,
    0x24, 0xcd, 0x04, 0x84, 0x9c, 0xa8, 0xfd, 0xdd,
    0x14, 0xb0, 0xad, 0xe6, 0xb7, 0x6a, 0x10, 0xfc,
    0x03, 0x22, 0xcb, 0x71, 0x31, 0xd3, 0x74, 0xd6
    // clang-format on
};

uint8_t protocol_version = PW_PROTOCOL_VERSION;

using trunks::CommandTransceiver;
using trunks::TrunksFactory;
using trunks::TrunksFactoryImpl;

void PrintUsage() {
  puts("Usage:");
  puts("  help - prints this help message.");
  puts("  resettree [<bits_per_level> <height> --protocol=<protocol>]");
  puts("            - sends a reset tree command.");
  puts("      The default parameters are bits_per_level=2 height=6 protocol=");
  puts("      PW_PROTOCOL_VERSION.");
  puts("  insert [...] - sends an insert leaf command.");
  puts("  remove [...] - sends an remove leaf command.");
  puts("  auth [...] - sends an try auth command.");
  puts("  resetleaf [...] - sends an reset auth command.");
  puts("  getlog [...] - sends an get log command.");
  puts("  replay [...] - sends an log replay command.");
  puts(
      "  generate_ba_pk <auth_channel> <public_key.x> <public_key.y> - sends "
      "a generate ba pk command.");
  puts(
      "  block_generate_ba_pk - blocks future generate_ba_pk commands until "
      "GSC reboots.");
  puts("  selftest [--protocol=<version>] - runs a self test with the");
  puts("           following commands:");
  puts("  biometrics_selftest [--full] - runs a self test for the biometrics");
  puts("           pinweaver commands. Full test can only be run on platforms");
  puts("           that support at least two Pk slots.");
}

std::string HexEncode(const std::string& bytes) {
  return base::HexEncode(bytes.data(), bytes.size());
}

std::string HexDecode(const std::string& hex) {
  std::vector<uint8_t> output;
  CHECK(base::HexStringToBytes(hex, &output));
  return std::string(output.begin(), output.end());
}

std::string PwErrorStr(int code) {
  switch (code) {
    case 0:
      return "EC_SUCCESS";
    case 1:
      return "EC_ERROR_UNKNOWN";
    case 2:
      return "EC_ERROR_UNIMPLEMENTED";
    case PW_ERR_VERSION_MISMATCH:
      return "PW_ERR_VERSION_MISMATCH";
    case PW_ERR_LENGTH_INVALID:
      return "PW_ERR_LENGTH_INVALID";
    case PW_ERR_TYPE_INVALID:
      return "PW_ERR_TYPE_INVALID";
    case PW_ERR_BITS_PER_LEVEL_INVALID:
      return "PW_ERR_BITS_PER_LEVEL_INVALID";
    case PW_ERR_HEIGHT_INVALID:
      return "PW_ERR_HEIGHT_INVALID";
    case PW_ERR_LABEL_INVALID:
      return "PW_ERR_LABEL_INVALID";
    case PW_ERR_DELAY_SCHEDULE_INVALID:
      return "PW_ERR_DELAY_SCHEDULE_INVALID";
    case PW_ERR_PATH_AUTH_FAILED:
      return "PW_ERR_PATH_AUTH_FAILED";
    case PW_ERR_LEAF_VERSION_MISMATCH:
      return "PW_ERR_LEAF_VERSION_MISMATCH";
    case PW_ERR_HMAC_AUTH_FAILED:
      return "PW_ERR_HMAC_AUTH_FAILED";
    case PW_ERR_LOWENT_AUTH_FAILED:
      return "PW_ERR_LOWENT_AUTH_FAILED";
    case PW_ERR_RESET_AUTH_FAILED:
      return "PW_ERR_RESET_AUTH_FAILED";
    case PW_ERR_CRYPTO_FAILURE:
      return "PW_ERR_CRYPTO_FAILURE";
    case PW_ERR_RATE_LIMIT_REACHED:
      return "PW_ERR_RATE_LIMIT_REACHED";
    case PW_ERR_ROOT_NOT_FOUND:
      return "PW_ERR_ROOT_NOT_FOUND";
    case PW_ERR_NV_EMPTY:
      return "PW_ERR_NV_EMPTY";
    case PW_ERR_NV_LENGTH_MISMATCH:
      return "PW_ERR_NV_LENGTH_MISMATCH";
    case PW_ERR_NV_VERSION_MISMATCH:
      return "PW_ERR_NV_VERSION_MISMATCH";
    case PW_ERR_PCR_NOT_MATCH:
      return "PW_ERR_PCR_NOT_MATCH";
    case PW_ERR_INTERNAL_FAILURE:
      return "PW_ERR_INTERNAL_FAILURE";
    case PW_ERR_EXPIRED:
      return "PW_ERR_EXPIRED";
    case PW_ERR_BIO_AUTH_CHANNEL_INVALID:
      return "PW_ERR_BIO_AUTH_CHANNEL_INVALID";
    case PW_ERR_BIO_AUTH_PUBLIC_KEY_VERSION_MISMATCH:
      return "PW_ERR_BIO_AUTH_PUBLIC_KEY_VERSION_MISMATCH";
    case PW_ERR_BIO_AUTH_ACCESS_DENIED:
      return "PW_ERR_BIO_AUTH_ACCESS_DENIED";
    case PW_ERR_BIO_AUTH_PK_NOT_ESTABLISHED:
      return "PW_ERR_BIO_AUTH_PK_NOT_ESTABLISHED";
    default:
      return "?";
  }
}

void GetEmptyPath(uint8_t bits_per_level, uint8_t height, std::string* h_aux) {
  static_assert(SHA256_DIGEST_SIZE >= PW_HASH_SIZE, "");
  std::vector<uint8_t> hash(SHA256_DIGEST_SIZE, 0);
  uint8_t num_siblings = (1 << bits_per_level) - 1;
  size_t level_size = num_siblings * PW_HASH_SIZE;

  h_aux->resize(height * level_size);

  for (auto level_ptr = h_aux->begin(); level_ptr < h_aux->end();
       level_ptr += level_size) {
    for (auto index_ptr = level_ptr; index_ptr < level_ptr + level_size;
         index_ptr += PW_HASH_SIZE) {
      std::copy(hash.begin(), hash.begin() + PW_HASH_SIZE, index_ptr);
    }

    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    for (uint8_t x = 0; x <= num_siblings; ++x) {
      SHA256_Update(&ctx, hash.data(), PW_HASH_SIZE);
    }
    SHA256_Final(hash.data(), &ctx);
  }
}

uint64_t GetDefaultLabel() {
  return 0x1b1llu;  // {0, 1, 2, 3, 0, 1}
}

void GetDefaultHAux(std::string* h_aux) {
  GetEmptyPath(DEFAULT_BITS_PER_LEVEL, DEFAULT_HEIGHT, h_aux);
}

void GetDefaultLeSecret(brillo::SecureBlob* secret) {
  secret->assign(DEFAULT_LE_SECRET,
                 DEFAULT_LE_SECRET + sizeof(DEFAULT_LE_SECRET));
}

void GetDefaultHeSecret(brillo::SecureBlob* secret) {
  secret->assign(DEFAULT_HE_SECRET,
                 DEFAULT_HE_SECRET + sizeof(DEFAULT_HE_SECRET));
}

void GetDefaultResetSecret(brillo::SecureBlob* secret) {
  secret->assign(DEFAULT_RESET_SECRET,
                 DEFAULT_RESET_SECRET + sizeof(DEFAULT_RESET_SECRET));
}

void GetDefaultDelaySchedule(std::map<uint32_t, uint32_t>* delay_schedule) {
  delay_schedule->clear();
  delay_schedule->emplace(5, 5);
  delay_schedule->emplace(6, 10);
  delay_schedule->emplace(7, 300);
  delay_schedule->emplace(8, 600);
  delay_schedule->emplace(9, 1800);
  delay_schedule->emplace(10, 3600);
  delay_schedule->emplace(50, PW_BLOCK_ATTEMPTS);
}

void GetDefaultValidPcrCriteria(trunks::ValidPcrCriteria* valid_pcr_criteria) {
  valid_pcr_criteria->Clear();
  if (protocol_version > 0) {
    trunks::ValidPcrValue* default_pcr_value =
        valid_pcr_criteria->add_valid_pcr_values();
    uint8_t bitmask[2]{0, 0};
    default_pcr_value->set_bitmask(&bitmask, sizeof(bitmask));
  }
}

void GetInsertLeafDefaults(uint64_t* label,
                           std::string* h_aux,
                           brillo::SecureBlob* le_secret,
                           brillo::SecureBlob* he_secret,
                           brillo::SecureBlob* reset_secret,
                           std::map<uint32_t, uint32_t>* delay_schedule,
                           trunks::ValidPcrCriteria* valid_pcr_criteria) {
  *label = GetDefaultLabel();
  GetDefaultHAux(h_aux);
  GetDefaultLeSecret(le_secret);
  GetDefaultHeSecret(he_secret);
  GetDefaultResetSecret(reset_secret);
  GetDefaultDelaySchedule(delay_schedule);
  GetDefaultValidPcrCriteria(valid_pcr_criteria);
}

base::Value::Dict SetupBaseOutcome(uint32_t result_code,
                                   const std::string& root) {
  // This is exported as a string because the API handles integers as signed.
  base::Value::Dict outcome;
  outcome.SetByDottedPath("result_code.value", std::to_string(result_code));
  outcome.SetByDottedPath("result_code.name", PwErrorStr(result_code));
  outcome.Set("root_hash", HexEncode(root));
  return outcome;
}

std::string GetOutcomeJson(const base::Value::Dict& outcome) {
  std::string json;
  base::JSONWriter::WriteWithOptions(
      outcome, base::JSONWriter::OPTIONS_PRETTY_PRINT, &json);
  return json;
}

int HandleResetTree(base::CommandLine::StringVector::const_iterator begin,
                    base::CommandLine::StringVector::const_iterator end,
                    TrunksFactoryImpl* factory) {
  uint8_t bits_per_level;
  uint8_t height;
  if (begin == end) {
    bits_per_level = DEFAULT_BITS_PER_LEVEL;
    height = DEFAULT_HEIGHT;
  } else if (end - begin != 2) {
    puts("Invalid options!");
    PrintUsage();
    return EXIT_FAILURE;
  } else {
    bits_per_level = std::stoi(begin[0]);
    height = std::stoi(begin[1]);
  }

  uint32_t result_code = 0;
  std::string root;
  std::unique_ptr<trunks::TpmUtility> tpm_utility = factory->GetTpmUtility();
  trunks::TPM_RC result = tpm_utility->PinWeaverResetTree(
      protocol_version, bits_per_level, height, &result_code, &root);

  if (result) {
    LOG(ERROR) << "PinWeaverResetTree: " << trunks::GetErrorString(result);
  }

  base::Value::Dict outcome = SetupBaseOutcome(result_code, root);
  puts(GetOutcomeJson(outcome).c_str());
  return result;
}

int HandleInsert(base::CommandLine::StringVector::const_iterator begin,
                 base::CommandLine::StringVector::const_iterator end,
                 TrunksFactoryImpl* factory) {
  uint64_t label;
  std::string h_aux;
  brillo::SecureBlob le_secret;
  brillo::SecureBlob he_secret;
  brillo::SecureBlob reset_secret;
  std::map<uint32_t, uint32_t> delay_schedule;
  trunks::ValidPcrCriteria valid_pcr_criteria;
  if (begin == end) {
    GetInsertLeafDefaults(&label, &h_aux, &le_secret, &he_secret, &reset_secret,
                          &delay_schedule, &valid_pcr_criteria);
  } else if (end - begin < 6) {
    puts("Invalid options!");
    PrintUsage();
    return EXIT_FAILURE;
  } else {
    label = std::stoul(begin[0]);

    std::vector<uint8_t> bytes;
    if (!base::HexStringToBytes(begin[1], &bytes))
      return EXIT_FAILURE;
    h_aux.assign(bytes.begin(), bytes.end());

    bytes.clear();
    if (!base::HexStringToBytes(begin[2], &bytes))
      return EXIT_FAILURE;
    le_secret.assign(bytes.begin(), bytes.end());

    bytes.clear();
    if (!base::HexStringToBytes(begin[3], &bytes))
      return EXIT_FAILURE;
    he_secret.assign(bytes.begin(), bytes.end());

    bytes.clear();
    if (!base::HexStringToBytes(begin[4], &bytes))
      return EXIT_FAILURE;
    reset_secret.assign(bytes.begin(), bytes.end());

    begin += 5;
    for (size_t x = 0; x < end - begin; x += 2) {
      delay_schedule.emplace(static_cast<uint32_t>(std::stoul(begin[x])),
                             static_cast<uint32_t>(std::stoul(begin[x + 1])));
    }
  }

  uint32_t result_code = 0;
  std::string root;
  std::string cred_metadata;
  std::string mac;
  std::unique_ptr<trunks::TpmUtility> tpm_utility = factory->GetTpmUtility();
  trunks::TPM_RC result = tpm_utility->PinWeaverInsertLeaf(
      protocol_version, label, h_aux, le_secret, he_secret, reset_secret,
      delay_schedule, valid_pcr_criteria, std::nullopt, &result_code, &root,
      &cred_metadata, &mac);

  if (result) {
    LOG(ERROR) << "PinWeaverInsertLeaf: " << trunks::GetErrorString(result);
  }

  base::Value::Dict outcome = SetupBaseOutcome(result_code, root);
  outcome.Set("cred_metadata", HexEncode(cred_metadata));
  outcome.Set("mac", HexEncode(mac));
  puts(GetOutcomeJson(outcome).c_str());
  return result;
}

int HandleRemove(base::CommandLine::StringVector::const_iterator begin,
                 base::CommandLine::StringVector::const_iterator end,
                 TrunksFactoryImpl* factory) {
  if (end - begin != 3) {
    puts("Invalid options!");
    PrintUsage();
    return EXIT_FAILURE;
  }
  uint64_t label = std::stoul(begin[0]);

  std::vector<uint8_t> bytes;
  if (!base::HexStringToBytes(begin[1], &bytes))
    return EXIT_FAILURE;
  std::string h_aux(bytes.begin(), bytes.end());

  bytes.clear();
  if (!base::HexStringToBytes(begin[2], &bytes))
    return EXIT_FAILURE;
  std::string mac(bytes.begin(), bytes.end());

  uint32_t result_code = 0;
  std::string root;
  std::unique_ptr<trunks::TpmUtility> tpm_utility = factory->GetTpmUtility();
  trunks::TPM_RC result = tpm_utility->PinWeaverRemoveLeaf(
      protocol_version, label, h_aux, mac, &result_code, &root);

  if (result) {
    LOG(ERROR) << "PinWeaverRemoveLeaf: " << trunks::GetErrorString(result);
  }

  base::Value::Dict outcome = SetupBaseOutcome(result_code, root);
  puts(GetOutcomeJson(outcome).c_str());
  return result;
}

int HandleAuth(base::CommandLine::StringVector::const_iterator begin,
               base::CommandLine::StringVector::const_iterator end,
               TrunksFactoryImpl* factory) {
  std::string h_aux;
  brillo::SecureBlob le_secret;
  std::string cred_metadata;
  if (end - begin != 3) {
    puts("Invalid options!");
    PrintUsage();
    return EXIT_FAILURE;
  } else {
    std::vector<uint8_t> bytes;
    if (!base::HexStringToBytes(begin[0], &bytes))
      return EXIT_FAILURE;
    h_aux.assign(bytes.begin(), bytes.end());

    bytes.clear();
    if (!base::HexStringToBytes(begin[1], &bytes))
      return EXIT_FAILURE;
    le_secret.assign(bytes.begin(), bytes.end());

    bytes.clear();
    if (!base::HexStringToBytes(begin[2], &bytes))
      return EXIT_FAILURE;
    cred_metadata.assign(bytes.begin(), bytes.end());
  }

  uint32_t result_code = 0;
  std::string root;
  uint32_t seconds_to_wait;
  brillo::SecureBlob he_secret;
  brillo::SecureBlob reset_secret;
  std::string cred_metadata_out;
  std::string mac_out;
  std::unique_ptr<trunks::TpmUtility> tpm_utility = factory->GetTpmUtility();
  trunks::TPM_RC result = tpm_utility->PinWeaverTryAuth(
      protocol_version, le_secret, h_aux, cred_metadata, &result_code, &root,
      &seconds_to_wait, &he_secret, &reset_secret, &cred_metadata_out,
      &mac_out);

  if (result) {
    LOG(ERROR) << "PinWeaverTryAuth: " << trunks::GetErrorString(result);
  }

  base::Value::Dict outcome = SetupBaseOutcome(result_code, root);
  outcome.Set("seconds_to_wait", std::to_string(seconds_to_wait));
  outcome.Set("he_secret", HexEncode(he_secret.to_string()));
  outcome.Set("cred_metadata", HexEncode(cred_metadata_out));
  outcome.Set("mac", HexEncode(mac_out));
  puts(GetOutcomeJson(outcome).c_str());
  return result;
}

int HandleResetLeaf(base::CommandLine::StringVector::const_iterator begin,
                    base::CommandLine::StringVector::const_iterator end,
                    TrunksFactoryImpl* factory) {
  std::string h_aux;
  brillo::SecureBlob reset_secret;
  std::string cred_metadata;
  if (end - begin != 3) {
    puts("Invalid options!");
    PrintUsage();
    return EXIT_FAILURE;
  } else {
    std::vector<uint8_t> bytes;
    if (!base::HexStringToBytes(begin[0], &bytes))
      return EXIT_FAILURE;
    h_aux.assign(bytes.begin(), bytes.end());

    bytes.clear();
    if (!base::HexStringToBytes(begin[1], &bytes))
      return EXIT_FAILURE;
    reset_secret.assign(bytes.begin(), bytes.end());

    bytes.clear();
    if (!base::HexStringToBytes(begin[2], &bytes))
      return EXIT_FAILURE;
    cred_metadata.assign(bytes.begin(), bytes.end());
  }

  uint32_t result_code = 0;
  std::string root;
  std::string cred_metadata_out;
  std::string mac_out;
  std::unique_ptr<trunks::TpmUtility> tpm_utility = factory->GetTpmUtility();
  trunks::TPM_RC result = tpm_utility->PinWeaverResetAuth(
      protocol_version, reset_secret, false, h_aux, cred_metadata, &result_code,
      &root, &cred_metadata_out, &mac_out);

  if (result) {
    LOG(ERROR) << "PinWeaverResetAuth: " << trunks::GetErrorString(result);
  }

  base::Value::Dict outcome = SetupBaseOutcome(result_code, root);
  outcome.Set("cred_metadata", HexEncode(cred_metadata_out));
  outcome.Set("mac", HexEncode(mac_out));
  puts(GetOutcomeJson(outcome).c_str());
  return result;
}

int HandleGetLog(base::CommandLine::StringVector::const_iterator begin,
                 base::CommandLine::StringVector::const_iterator end,
                 TrunksFactoryImpl* factory) {
  std::string root;
  if (end - begin > 1) {
    puts("Invalid options!");
    PrintUsage();
    return EXIT_FAILURE;
  } else if (end == begin) {
    root.assign(static_cast<size_t>(SHA256_DIGEST_SIZE), '\0');
  } else {
    std::vector<uint8_t> bytes;
    if (!base::HexStringToBytes(begin[0], &bytes))
      return EXIT_FAILURE;
    root.assign(bytes.begin(), bytes.end());
  }

  uint32_t result_code = 0;
  std::string root_hash;
  std::vector<trunks::PinWeaverLogEntry> log;
  std::unique_ptr<trunks::TpmUtility> tpm_utility = factory->GetTpmUtility();
  trunks::TPM_RC result = tpm_utility->PinWeaverGetLog(
      protocol_version, root, &result_code, &root_hash, &log);

  if (result) {
    LOG(ERROR) << "PinWeaverGetLog: " << trunks::GetErrorString(result);
  }

  base::Value::Dict outcome = SetupBaseOutcome(result_code, root);

  base::Value::List out_entries;
  for (const auto& entry : log) {
    base::Value::Dict out_entry;
    out_entry.Set("label", std::to_string(entry.label()));
    out_entry.Set("root", HexEncode(entry.root()));
    switch (entry.type_case()) {
      case trunks::PinWeaverLogEntry::TypeCase::kInsertLeaf:
        out_entry.Set("type", "InsertLeaf");
        out_entry.Set("hmac", HexEncode(entry.insert_leaf().hmac()));
        break;
      case trunks::PinWeaverLogEntry::TypeCase::kRemoveLeaf:
        out_entry.Set("type", "RemoveLeaf");
        break;
      case trunks::PinWeaverLogEntry::TypeCase::kAuth:
        out_entry.Set("type", "Auth");
        break;
      case trunks::PinWeaverLogEntry::TypeCase::kResetTree:
        out_entry.Set("type", "ResetTree");
        break;
      default:
        out_entry.Set("type", std::to_string(entry.type_case()));
    }
    out_entries.Append(std::move(out_entry));
  }
  outcome.Set("entries", std::move(out_entries));
  puts(GetOutcomeJson(outcome).c_str());
  return result;
}

int HandleReplay(base::CommandLine::StringVector::const_iterator begin,
                 base::CommandLine::StringVector::const_iterator end,
                 TrunksFactoryImpl* factory) {
  std::string h_aux;
  std::string log_root;
  std::string cred_metadata;
  if (end - begin != 3) {
    puts("Invalid options!");
    PrintUsage();
    return EXIT_FAILURE;
  } else {
    std::vector<uint8_t> bytes;
    if (!base::HexStringToBytes(begin[0], &bytes))
      return EXIT_FAILURE;
    h_aux.assign(bytes.begin(), bytes.end());

    bytes.clear();
    if (!base::HexStringToBytes(begin[1], &bytes))
      return EXIT_FAILURE;
    log_root.assign(bytes.begin(), bytes.end());

    bytes.clear();
    if (!base::HexStringToBytes(begin[2], &bytes))
      return EXIT_FAILURE;
    cred_metadata.assign(bytes.begin(), bytes.end());
  }

  uint32_t result_code = 0;
  std::string root;
  std::string cred_metadata_out;
  std::string mac_out;
  std::unique_ptr<trunks::TpmUtility> tpm_utility = factory->GetTpmUtility();
  trunks::TPM_RC result = tpm_utility->PinWeaverLogReplay(
      protocol_version, log_root, h_aux, cred_metadata, &result_code, &root,
      &cred_metadata_out, &mac_out);

  if (result) {
    LOG(ERROR) << "PinWeaverResetAuth: " << trunks::GetErrorString(result);
  }

  base::Value::Dict outcome = SetupBaseOutcome(result_code, root);
  outcome.Set("cred_metadata", HexEncode(cred_metadata_out));
  outcome.Set("mac", HexEncode(mac_out));
  puts(GetOutcomeJson(outcome).c_str());
  return result;
}

int HandleGenerateBiometricsAuthPk(
    base::CommandLine::StringVector::const_iterator begin,
    base::CommandLine::StringVector::const_iterator end,
    TrunksFactoryImpl* factory) {
  uint8_t auth_channel;
  trunks::PinWeaverEccPoint client_pt;
  if (end - begin != 3) {
    puts("Invalid options!");
    PrintUsage();
    return EXIT_FAILURE;
  } else {
    auth_channel = std::stoul(begin[0]);

    std::vector<uint8_t> bytes;
    if (!base::HexStringToBytes(begin[1], &bytes) ||
        bytes.size() != trunks::PinWeaverEccPointSize) {
      puts("Invalid point!");
      return EXIT_FAILURE;
    }
    memcpy(client_pt.x, bytes.data(), bytes.size());

    bytes.clear();
    if (!base::HexStringToBytes(begin[2], &bytes) ||
        bytes.size() != trunks::PinWeaverEccPointSize)
      return EXIT_FAILURE;
    memcpy(client_pt.y, bytes.data(), bytes.size());
  }

  uint32_t result_code = 0;
  std::string root;
  trunks::PinWeaverEccPoint server_pt;
  std::unique_ptr<trunks::TpmUtility> tpm_utility = factory->GetTpmUtility();
  trunks::TPM_RC result = tpm_utility->PinWeaverGenerateBiometricsAuthPk(
      protocol_version, auth_channel, client_pt, &result_code, &root,
      &server_pt);

  if (result) {
    LOG(ERROR) << "PinWeaverGenerateBiometricsAuthPk: "
               << trunks::GetErrorString(result);
    return result;
  }

  base::Value::Dict outcome = SetupBaseOutcome(result_code, root);
  if (result_code == 0) {
    base::Value::Dict server_public_key;
    server_public_key.Set(
        "x", base::HexEncode(server_pt.x, trunks::PinWeaverEccPointSize));
    server_public_key.Set(
        "y", base::HexEncode(server_pt.y, trunks::PinWeaverEccPointSize));
    outcome.Set("server_public_key", std::move(server_public_key));
  }
  puts(GetOutcomeJson(outcome).c_str());
  return 0;
}

int HandleBlockGenerateBiometricsAuthPk(
    base::CommandLine::StringVector::const_iterator begin,
    base::CommandLine::StringVector::const_iterator end,
    TrunksFactoryImpl* factory) {
  if (begin != end) {
    puts("Invalid options!");
    PrintUsage();
    return EXIT_FAILURE;
  }

  uint32_t result_code = 0;
  std::string root;
  std::unique_ptr<trunks::TpmUtility> tpm_utility = factory->GetTpmUtility();
  trunks::TPM_RC result = tpm_utility->PinWeaverBlockGenerateBiometricsAuthPk(
      protocol_version, &result_code, &root);

  if (result) {
    LOG(ERROR) << "PinWeaverBlockGenerateBiometricsAuthPk: "
               << trunks::GetErrorString(result);
    return result;
  }

  base::Value::Dict outcome = SetupBaseOutcome(result_code, root);
  puts(GetOutcomeJson(outcome).c_str());
  return 0;
}

int HandleSelfTest(base::CommandLine::StringVector::const_iterator begin,
                   base::CommandLine::StringVector::const_iterator end,
                   TrunksFactoryImpl* factory) {
  if (begin != end) {
    puts("Invalid options!");
    PrintUsage();
    return EXIT_FAILURE;
  }

  LOG(INFO) << "reset_tree";
  uint32_t result_code = 0;
  std::string root;
  std::unique_ptr<trunks::TpmUtility> tpm_utility = factory->GetTpmUtility();
  trunks::TPM_RC result =
      tpm_utility->PinWeaverResetTree(protocol_version, DEFAULT_BITS_PER_LEVEL,
                                      DEFAULT_HEIGHT, &result_code, &root);
  if (result || result_code) {
    LOG(ERROR) << "reset_tree failed! " << result_code << " "
               << PwErrorStr(result_code);
    return EXIT_FAILURE;
  }

  LOG(INFO) << "insert_leaf";
  result_code = 0;
  uint64_t label;
  std::string h_aux;
  brillo::SecureBlob le_secret;
  brillo::SecureBlob he_secret;
  brillo::SecureBlob reset_secret;
  brillo::SecureBlob test_reset_secret;
  std::map<uint32_t, uint32_t> delay_schedule;
  trunks::ValidPcrCriteria valid_pcr_criteria;
  GetInsertLeafDefaults(&label, &h_aux, &le_secret, &he_secret, &reset_secret,
                        &delay_schedule, &valid_pcr_criteria);
  std::string cred_metadata;
  std::string mac;
  result = tpm_utility->PinWeaverInsertLeaf(
      protocol_version, label, h_aux, le_secret, he_secret, reset_secret,
      delay_schedule, valid_pcr_criteria, std::nullopt, &result_code, &root,
      &cred_metadata, &mac);
  if (result || result_code) {
    LOG(ERROR) << "insert_leaf failed! " << result_code << " "
               << PwErrorStr(result_code);
    return EXIT_FAILURE;
  }

  LOG(INFO) << "try_auth auth success";
  result_code = 0;
  uint32_t seconds_to_wait;
  result = tpm_utility->PinWeaverTryAuth(
      protocol_version, le_secret, h_aux, cred_metadata, &result_code, &root,
      &seconds_to_wait, &he_secret, &test_reset_secret, &cred_metadata, &mac);
  if (result || result_code) {
    LOG(ERROR) << "try_auth failed! " << result_code << " "
               << PwErrorStr(result_code);
    return EXIT_FAILURE;
  }

  if (he_secret.size() != PW_SECRET_SIZE ||
      std::mismatch(he_secret.begin(), he_secret.end(), DEFAULT_HE_SECRET)
              .first != he_secret.end()) {
    LOG(ERROR) << "try_auth credential retrieval failed!";
    return EXIT_FAILURE;
  }

  if (protocol_version > 0 &&
      (test_reset_secret.size() != PW_SECRET_SIZE ||
       std::mismatch(test_reset_secret.begin(), test_reset_secret.end(),
                     DEFAULT_RESET_SECRET)
               .first != test_reset_secret.end())) {
    LOG(ERROR) << "try_auth reset_secret retrieval failed!";
    return EXIT_FAILURE;
  }

  LOG(INFO) << "try_auth auth fail";
  result_code = 0;
  std::string pre_fail_root = root;
  std::string old_metadata = cred_metadata;
  brillo::SecureBlob wrong_le_secret = he_secret;
  result = tpm_utility->PinWeaverTryAuth(
      protocol_version, wrong_le_secret, h_aux, cred_metadata, &result_code,
      &root, &seconds_to_wait, &he_secret, &test_reset_secret, &cred_metadata,
      &mac);
  if (result) {
    LOG(ERROR) << "try_auth failed! " << result_code << " "
               << PwErrorStr(result_code);
    return EXIT_FAILURE;
  }
  // Most of the checks covered by the unit tests don't make sense to test here,
  // but since authentication is critical this check is justified.
  if (result_code != PW_ERR_LOWENT_AUTH_FAILED) {
    LOG(ERROR) << "try_auth verification failed!";
    return EXIT_FAILURE;
  }

  LOG(INFO) << "get_log";
  result_code = 0;
  std::vector<trunks::PinWeaverLogEntry> log;
  result = tpm_utility->PinWeaverGetLog(protocol_version, pre_fail_root,
                                        &result_code, &root, &log);
  if (result || result_code) {
    LOG(ERROR) << "get_log failed! " << result_code << " "
               << PwErrorStr(result_code);
    return EXIT_FAILURE;
  }
  bool fail = false;
  if (log.empty()) {
    LOG(ERROR) << "get_log verification failed: empty log!";
    fail = true;
  }
  if (log.front().root() != root) {
    LOG(ERROR) << "get_log verification failed: wrong root!";
    LOG(ERROR) << HexEncode(log.front().root());
    fail = true;
  }
  if (log.front().type_case() != trunks::PinWeaverLogEntry::TypeCase::kAuth) {
    LOG(ERROR) << "get_log verification failed: wrong entry type!";
    LOG(ERROR) << log.front().type_case();
    fail = true;
  }
  if (fail) {
    return EXIT_FAILURE;
  }

  LOG(INFO) << "log_replay";
  result_code = 0;
  std::string replay_metadata, replay_mac;
  result = tpm_utility->PinWeaverLogReplay(protocol_version, root, h_aux,
                                           old_metadata, &result_code, &root,
                                           &replay_metadata, &replay_mac);
  if (result) {
    LOG(ERROR) << "log_replay failed! " << result_code << " "
               << PwErrorStr(result_code);
    return EXIT_FAILURE;
  }
  if (replay_metadata != cred_metadata) {
    LOG(ERROR) << "log_replay verification failed: bad metadata!";
    return EXIT_FAILURE;
  }
  if (replay_mac != mac) {
    LOG(ERROR) << "log_replay verification failed: bad HMAC!";
    return EXIT_FAILURE;
  }

  LOG(INFO) << "reset_auth";
  result_code = 0;
  result = tpm_utility->PinWeaverResetAuth(
      protocol_version, reset_secret, false, h_aux, cred_metadata, &result_code,
      &root, &cred_metadata, &mac);
  if (result || result_code) {
    LOG(ERROR) << "reset_auth failed! " << result_code << " "
               << PwErrorStr(result_code);
    return EXIT_FAILURE;
  }

  LOG(INFO) << "try_auth auth fail for 5 times";
  for (int i = 0; i < 5; ++i) {
    result_code = 0;
    result = tpm_utility->PinWeaverTryAuth(
        protocol_version, wrong_le_secret, h_aux, cred_metadata, &result_code,
        &root, &seconds_to_wait, &he_secret, &test_reset_secret, &cred_metadata,
        &mac);
    if (result) {
      LOG(ERROR) << "try_auth failed! " << result_code << " "
                 << PwErrorStr(result_code);
      return EXIT_FAILURE;
    }
    if (result_code != PW_ERR_LOWENT_AUTH_FAILED) {
      LOG(ERROR) << "try_auth verification failed!";
      return EXIT_FAILURE;
    }
  }
  LOG(INFO) << "Now credential should be locked for 5 seconds.";

  LOG(INFO) << "try_auth should fail (rate-limited)";
  result_code = 0;
  std::string no_cred_metadata, no_mac;
  result = tpm_utility->PinWeaverTryAuth(
      protocol_version, le_secret, h_aux, cred_metadata, &result_code, &root,
      &seconds_to_wait, &he_secret, &test_reset_secret, &no_cred_metadata,
      &no_mac);
  if (result) {
    LOG(ERROR) << "try_auth failed! " << result_code << " "
               << PwErrorStr(result_code);
    return EXIT_FAILURE;
  }
  if (result_code != PW_ERR_RATE_LIMIT_REACHED) {
    LOG(ERROR) << "try_auth verification failed!";
    return EXIT_FAILURE;
  }

  LOG(INFO) << "try_auth fail after waiting 7 seconds";
  base::PlatformThread::Sleep(base::Seconds(7));
  result_code = 0;
  result = tpm_utility->PinWeaverTryAuth(
      protocol_version, wrong_le_secret, h_aux, cred_metadata, &result_code,
      &root, &seconds_to_wait, &he_secret, &test_reset_secret, &cred_metadata,
      &mac);
  if (result) {
    LOG(ERROR) << "try_auth failed! " << result_code << " "
               << PwErrorStr(result_code);
    return EXIT_FAILURE;
  }
  if (result_code != PW_ERR_LOWENT_AUTH_FAILED) {
    LOG(ERROR) << "try_auth verification failed!";
    return EXIT_FAILURE;
  }
  LOG(INFO) << "Now credential should be locked for 10 seconds.";

  LOG(INFO) << "try_auth should fail (rate-limited) after waiting 8 seconds";
  base::PlatformThread::Sleep(base::Seconds(8));
  result_code = 0;
  result = tpm_utility->PinWeaverTryAuth(
      protocol_version, le_secret, h_aux, cred_metadata, &result_code, &root,
      &seconds_to_wait, &he_secret, &test_reset_secret, &no_cred_metadata,
      &no_mac);
  if (result) {
    LOG(ERROR) << "try_auth failed! " << result_code << " "
               << PwErrorStr(result_code);
    return EXIT_FAILURE;
  }
  if (result_code != PW_ERR_RATE_LIMIT_REACHED) {
    LOG(ERROR) << "try_auth verification failed!";
    return EXIT_FAILURE;
  }

  LOG(INFO) << "try_auth success after waiting 4 seconds";
  base::PlatformThread::Sleep(base::Seconds(4));
  result_code = 0;
  result = tpm_utility->PinWeaverTryAuth(
      protocol_version, le_secret, h_aux, cred_metadata, &result_code, &root,
      &seconds_to_wait, &he_secret, &test_reset_secret, &cred_metadata, &mac);
  if (result || result_code) {
    LOG(ERROR) << "try_auth failed! " << result_code << " "
               << PwErrorStr(result_code);
    return EXIT_FAILURE;
  }
  if (he_secret.size() != PW_SECRET_SIZE ||
      std::mismatch(he_secret.begin(), he_secret.end(), DEFAULT_HE_SECRET)
              .first != he_secret.end()) {
    LOG(ERROR) << "try_auth credential retrieval failed!";
    return EXIT_FAILURE;
  }

  LOG(INFO) << "remove_leaf";
  result_code = 0;
  result = tpm_utility->PinWeaverRemoveLeaf(protocol_version, label, h_aux, mac,
                                            &result_code, &root);
  if (result || result_code) {
    LOG(ERROR) << "remove_leaf failed! " << result_code << " "
               << PwErrorStr(result_code);
    return EXIT_FAILURE;
  }

  LOG(INFO) << "insert new leaf with good PCR (PCR4 must be empty)";
  GetInsertLeafDefaults(&label, &h_aux, &le_secret, &he_secret, &reset_secret,
                        &delay_schedule, &valid_pcr_criteria);
  if (protocol_version > 0) {
    std::string digest = HexDecode(
        "66687AADF862BD776C8FC18B8E9F8E20089714856EE233B3902A591D0D5F2925");
    trunks::ValidPcrValue* value =
        valid_pcr_criteria.mutable_valid_pcr_values(0);
    const uint8_t bitmask[2] = {1 << 4 /* PCR 4 */, 0};
    value->set_bitmask(&bitmask, sizeof(bitmask));
    value->set_digest(digest);
  }
  result = tpm_utility->PinWeaverInsertLeaf(
      protocol_version, label, h_aux, le_secret, he_secret, reset_secret,
      delay_schedule, valid_pcr_criteria, std::nullopt, &result_code, &root,
      &cred_metadata, &mac);
  if (result || result_code) {
    LOG(ERROR) << "insert_leaf failed! " << result_code << " "
               << PwErrorStr(result_code);
    return EXIT_FAILURE;
  }

  LOG(INFO) << "try_auth should succeed";
  result_code = 0;
  he_secret.clear();
  result = tpm_utility->PinWeaverTryAuth(
      protocol_version, le_secret, h_aux, cred_metadata, &result_code, &root,
      &seconds_to_wait, &he_secret, &reset_secret, &cred_metadata, &mac);
  if (result || result_code) {
    LOG(ERROR) << "try_auth failed";
    return EXIT_FAILURE;
  }

  if (he_secret.size() != PW_SECRET_SIZE ||
      std::mismatch(he_secret.begin(), he_secret.end(), DEFAULT_HE_SECRET)
              .first != he_secret.end()) {
    LOG(ERROR) << "try_auth credential retrieval failed!";
    return EXIT_FAILURE;
  }

  LOG(INFO) << "remove_leaf";
  result_code = 0;
  result = tpm_utility->PinWeaverRemoveLeaf(protocol_version, label, h_aux, mac,
                                            &result_code, &root);
  if (result || result_code) {
    LOG(ERROR) << "remove_leaf failed! " << result_code << " "
               << PwErrorStr(result_code);
    return EXIT_FAILURE;
  }

  if (protocol_version > 0) {
    LOG(INFO) << "insert new leaf with bad PCR";
    GetInsertLeafDefaults(&label, &h_aux, &le_secret, &he_secret, &reset_secret,
                          &delay_schedule, &valid_pcr_criteria);
    trunks::ValidPcrValue* value =
        valid_pcr_criteria.mutable_valid_pcr_values(0);
    const uint8_t bitmask[2] = {16, 0};
    value->set_bitmask(&bitmask, sizeof(bitmask));
    value->set_digest("bad_digest");
    result = tpm_utility->PinWeaverInsertLeaf(
        protocol_version, label, h_aux, le_secret, he_secret, reset_secret,
        delay_schedule, valid_pcr_criteria, std::nullopt, &result_code, &root,
        &cred_metadata, &mac);
    if (result || result_code) {
      LOG(ERROR) << "insert_leaf failed! " << result_code << " "
                 << PwErrorStr(result_code);
      return EXIT_FAILURE;
    }

    LOG(INFO) << "try_auth should fail";
    result_code = 0;
    he_secret.clear();
    replay_mac = mac;
    result = tpm_utility->PinWeaverTryAuth(
        protocol_version, le_secret, h_aux, cred_metadata, &result_code, &root,
        &seconds_to_wait, &he_secret, &test_reset_secret, &cred_metadata, &mac);
    if (!result && !result_code) {
      LOG(ERROR) << "try_auth with wrong PCR failed to fail";
      return EXIT_FAILURE;
    }

    // Make sure that he_secret was not leaked.
    if (he_secret.size() > 0 || test_reset_secret.size() > 0) {
      LOG(ERROR) << "try_auth populated the he_secret";
      return EXIT_FAILURE;
    }

    LOG(INFO) << "remove_leaf";
    result_code = 0;
    result = tpm_utility->PinWeaverRemoveLeaf(protocol_version, label, h_aux,
                                              replay_mac, &result_code, &root);
    if (result || result_code) {
      LOG(ERROR) << "remove_leaf failed! " << result_code << " "
                 << PwErrorStr(result_code);
      return EXIT_FAILURE;
    }
  }

  if (protocol_version > 1) {
    LOG(INFO) << "sending sys_info to check initial timestamp";
    uint32_t boot_count;
    uint64_t seconds_since_boot;
    result =
        tpm_utility->PinWeaverSysInfo(protocol_version, &result_code, &root,
                                      &boot_count, &seconds_since_boot);
    if (result || result_code) {
      LOG(ERROR) << "sys_info failed! " << result_code << " "
                 << PwErrorStr(result_code);
      return EXIT_FAILURE;
    }
    uint32_t old_boot_count = boot_count;
    uint64_t old_seconds_since_boot = seconds_since_boot;

    GetInsertLeafDefaults(&label, &h_aux, &le_secret, &he_secret, &reset_secret,
                          &delay_schedule, &valid_pcr_criteria);
    // Choose a reasonable value to test for credential expiration.
    uint32_t expiration_delay = 5;
    result = tpm_utility->PinWeaverInsertLeaf(
        protocol_version, label, h_aux, le_secret, he_secret, reset_secret,
        delay_schedule, valid_pcr_criteria, expiration_delay, &result_code,
        &root, &cred_metadata, &mac);
    if (result || result_code) {
      LOG(ERROR) << "insert_leaf failed! " << result_code << " "
                 << PwErrorStr(result_code);
      return EXIT_FAILURE;
    }

    LOG(INFO) << "the leaf has a 5-second expiration window.";
    LOG(INFO) << "try_auth should fail (expired) after waiting 7 seconds";
    base::PlatformThread::Sleep(base::Seconds(7));
    result_code = 0;
    result = tpm_utility->PinWeaverTryAuth(
        protocol_version, le_secret, h_aux, cred_metadata, &result_code, &root,
        &seconds_to_wait, &he_secret, &test_reset_secret, &no_cred_metadata,
        &no_mac);
    if (result) {
      LOG(ERROR) << "try_auth failed! " << result_code << " "
                 << PwErrorStr(result_code);
      return EXIT_FAILURE;
    }
    if (result_code != PW_ERR_EXPIRED) {
      LOG(ERROR) << "try_auth verification failed!";
      return EXIT_FAILURE;
    }

    LOG(INFO) << "reset_auth";
    result_code = 0;
    result = tpm_utility->PinWeaverResetAuth(
        protocol_version, reset_secret, false, h_aux, cred_metadata,
        &result_code, &root, &cred_metadata, &mac);
    if (result || result_code) {
      LOG(ERROR) << "reset_auth failed! " << result_code << " "
                 << PwErrorStr(result_code);
      return EXIT_FAILURE;
    }

    LOG(INFO) << "try_auth should still fail (expired) because normal reset "
                 "doesn't reset expiration";
    result_code = 0;
    result = tpm_utility->PinWeaverTryAuth(
        protocol_version, le_secret, h_aux, cred_metadata, &result_code, &root,
        &seconds_to_wait, &he_secret, &test_reset_secret, &no_cred_metadata,
        &no_mac);
    if (result) {
      LOG(ERROR) << "try_auth failed! " << result_code << " "
                 << PwErrorStr(result_code);
      return EXIT_FAILURE;
    }
    if (result_code != PW_ERR_EXPIRED) {
      LOG(ERROR) << "try_auth verification failed!";
      return EXIT_FAILURE;
    }

    LOG(INFO) << "reset_auth (strong)";
    result_code = 0;
    result = tpm_utility->PinWeaverResetAuth(
        protocol_version, reset_secret, true, h_aux, cred_metadata,
        &result_code, &root, &cred_metadata, &mac);
    if (result || result_code) {
      LOG(ERROR) << "reset_auth failed! " << result_code << " "
                 << PwErrorStr(result_code);
      return EXIT_FAILURE;
    }

    LOG(INFO) << "try_auth success";
    result_code = 0;
    result = tpm_utility->PinWeaverTryAuth(
        protocol_version, le_secret, h_aux, cred_metadata, &result_code, &root,
        &seconds_to_wait, &he_secret, &test_reset_secret, &cred_metadata, &mac);
    if (result || result_code) {
      LOG(ERROR) << "try_auth failed! " << result_code << " "
                 << PwErrorStr(result_code);
      return EXIT_FAILURE;
    }
    if (he_secret.size() != PW_SECRET_SIZE ||
        std::mismatch(he_secret.begin(), he_secret.end(), DEFAULT_HE_SECRET)
                .first != he_secret.end()) {
      LOG(ERROR) << "try_auth credential retrieval failed!";
      return EXIT_FAILURE;
    }

    LOG(INFO) << "remove_leaf";
    result_code = 0;
    result = tpm_utility->PinWeaverRemoveLeaf(protocol_version, label, h_aux,
                                              mac, &result_code, &root);
    if (result || result_code) {
      LOG(ERROR) << "remove_leaf failed! " << result_code << " "
                 << PwErrorStr(result_code);
      return EXIT_FAILURE;
    }

    LOG(INFO) << "sending sys_info to check final timestamp";
    result =
        tpm_utility->PinWeaverSysInfo(protocol_version, &result_code, &root,
                                      &boot_count, &seconds_since_boot);
    if (result || result_code) {
      LOG(ERROR) << "sys_info failed! " << result_code << " "
                 << PwErrorStr(result_code);
      return EXIT_FAILURE;
    }

    LOG(INFO) << "boot_count: before = " << old_boot_count
              << ", after = " << boot_count;
    if (boot_count != old_boot_count) {
      LOG(ERROR) << "boot_count increased!";
    }
    LOG(INFO) << "seconds_since_boot: before = " << old_seconds_since_boot
              << ", after = " << seconds_since_boot;
    if (seconds_since_boot < old_seconds_since_boot) {
      LOG(ERROR) << "seconds_since_boot decreased!";
    }
    uint64_t seconds_passed = seconds_since_boot - old_seconds_since_boot;
    if (seconds_passed < 5 || seconds_passed > 9) {
      LOG(ERROR) << "seconds_passed isn't reasonable!";
    }
  }

  puts("Success!");
  return EXIT_SUCCESS;
}

std::optional<trunks::PinWeaverEccPoint> ToPinWeaverEccPoint(
    const EllipticCurve& ec, BN_CTX* ctx, const EC_POINT* point) {
  crypto::ScopedBIGNUM out_x = hwsec_foundation::CreateBigNum(),
                       out_y = hwsec_foundation::CreateBigNum();
  if (!out_x || !out_y) {
    LOG(ERROR) << "Failed to create bignums.";
    return std::nullopt;
  }
  if (!EC_POINT_get_affine_coordinates(ec.GetGroup(), point, out_x.get(),
                                       out_y.get(), ctx)) {
    LOG(ERROR) << "Failed to get affine coords for point";
    return std::nullopt;
  }
  brillo::SecureBlob out_x_blob, out_y_blob;
  if (!hwsec_foundation::BigNumToSecureBlob(*out_x, PW_BA_ECC_CORD_SIZE,
                                            &out_x_blob) ||
      !hwsec_foundation::BigNumToSecureBlob(*out_y, PW_BA_ECC_CORD_SIZE,
                                            &out_y_blob)) {
    LOG(ERROR) << "Failed to transform bignums to secure blobs.";
    return std::nullopt;
  }

  trunks::PinWeaverEccPoint ret;
  memcpy(ret.x, out_x_blob.data(), PW_BA_ECC_CORD_SIZE);
  memcpy(ret.y, out_y_blob.data(), PW_BA_ECC_CORD_SIZE);

  return ret;
}

crypto::ScopedEC_POINT FromPinWeaverEccPoint(
    const EllipticCurve& ec,
    BN_CTX* ctx,
    const trunks::PinWeaverEccPoint& point_in) {
  crypto::ScopedEC_POINT point = ec.CreatePoint();
  if (!point) {
    LOG(ERROR) << "Failed to create EC point.";
    return nullptr;
  }
  const brillo::SecureBlob in_x_blob(point_in.x,
                                     point_in.x + PW_BA_ECC_CORD_SIZE),
      in_y_blob(point_in.y, point_in.y + PW_BA_ECC_CORD_SIZE);
  const crypto::ScopedBIGNUM in_x =
      hwsec_foundation::SecureBlobToBigNum(in_x_blob);
  const crypto::ScopedBIGNUM in_y =
      hwsec_foundation::SecureBlobToBigNum(in_y_blob);
  if (!in_x || !in_y) {
    LOG(ERROR) << "Failed to transform secure blobs to bignums.";
    return nullptr;
  }
  if (!EC_POINT_set_affine_coordinates(ec.GetGroup(), point.get(), in_x.get(),
                                       in_y.get(), ctx)) {
    LOG(ERROR) << "Failed to set affine coords for point";
    return nullptr;
  }
  return point;
}

std::optional<brillo::SecureBlob> CalculatePkFromKeys(
    const EllipticCurve& ec,
    BN_CTX* ctx,
    const BIGNUM& own_priv,
    const EC_POINT& others_pub) {
  crypto::ScopedEC_POINT shared_point =
      ComputeEcdhSharedSecretPoint(ec, others_pub, own_priv);
  if (!shared_point) {
    LOG(ERROR) << "Failed to compute shared secret point.";
    return std::nullopt;
  }
  brillo::SecureBlob secret;
  if (!ComputeEcdhSharedSecret(ec, *shared_point, &secret)) {
    LOG(ERROR) << "Failed to compute shared secret.";
    return std::nullopt;
  }

  return hwsec_foundation::Sha256(secret);
}

int HandleBiometricsSelfTest(
    base::CommandLine::StringVector::const_iterator begin,
    base::CommandLine::StringVector::const_iterator end,
    TrunksFactoryImpl* factory) {
  const uint8_t kFpAuthChannel = 0, kFaceAuthChannel = 1;

  bool full = false;
  if (end - begin == 1 && begin[0] == "--full") {
    full = true;
  } else if (begin != end) {
    puts("Invalid options!");
    PrintUsage();
    return EXIT_FAILURE;
  }

  if (protocol_version < 2) {
    LOG(ERROR) << "Biometrics feature is only available since v2.";
    return EXIT_FAILURE;
  }

  // 1. Reset tree
  LOG(INFO) << "reset_tree";
  uint32_t result_code = 0;
  std::string root;
  std::unique_ptr<trunks::TpmUtility> tpm_utility = factory->GetTpmUtility();
  trunks::TPM_RC result =
      tpm_utility->PinWeaverResetTree(protocol_version, DEFAULT_BITS_PER_LEVEL,
                                      DEFAULT_HEIGHT, &result_code, &root);
  if (result || result_code) {
    LOG(ERROR) << "reset_tree failed! " << result_code << " "
               << PwErrorStr(result_code);
    return EXIT_FAILURE;
  }

  // Initialize the context and the curve for EC operations.
  hwsec_foundation::ScopedBN_CTX context =
      hwsec_foundation::CreateBigNumContext();
  std::optional<EllipticCurve> ec =
      EllipticCurve::Create(EllipticCurve::CurveType::kPrime256, context.get());
  if (!ec.has_value()) {
    LOG(ERROR) << "Failed to create EllipticCurve.";
    return EXIT_FAILURE;
  }

  // 2. Generate Pk for fingerprint slot
  LOG(INFO) << "generate_ba_pk (fp slot)";
  result_code = 0;
  crypto::ScopedEC_KEY key_pair = ec->GenerateKey(context.get());
  if (!key_pair) {
    LOG(ERROR) << "Failed to generate EC key.";
    return EXIT_FAILURE;
  }
  const EC_POINT* pub_point = EC_KEY_get0_public_key(key_pair.get());
  std::optional<trunks::PinWeaverEccPoint> auth_pk =
      ToPinWeaverEccPoint(*ec, context.get(), pub_point);
  if (!auth_pk.has_value()) {
    LOG(ERROR) << "Failed to generate EC point proto.";
    return EXIT_FAILURE;
  }
  trunks::PinWeaverEccPoint gsc_pk;
  result = tpm_utility->PinWeaverGenerateBiometricsAuthPk(
      protocol_version, kFpAuthChannel, *auth_pk, &result_code, &root, &gsc_pk);
  if (result || result_code) {
    LOG(ERROR) << "generate_ba_pk failed! " << result_code << " "
               << PwErrorStr(result_code);
    return EXIT_FAILURE;
  }
  crypto::ScopedEC_POINT gsc_pub_point =
      FromPinWeaverEccPoint(*ec, context.get(), gsc_pk);
  const std::optional<brillo::SecureBlob> pk_fp = CalculatePkFromKeys(
      *ec, context.get(), *EC_KEY_get0_private_key(key_pair.get()),
      *gsc_pub_point);
  if (!pk_fp.has_value()) {
    LOG(ERROR) << "Failed to calculate Pk.";
    return EXIT_FAILURE;
  }

  if (full) {
    // 3. Generate Pk for face slot
    LOG(INFO) << "generate_ba_pk (face slot)";
    result_code = 0;
    key_pair = ec->GenerateKey(context.get());
    if (!key_pair) {
      LOG(ERROR) << "Failed to generate EC key.";
      return EXIT_FAILURE;
    }
    pub_point = EC_KEY_get0_public_key(key_pair.get());
    auth_pk = ToPinWeaverEccPoint(*ec, context.get(), pub_point);
    if (!auth_pk.has_value()) {
      LOG(ERROR) << "Failed to generate EC point proto.";
      return EXIT_FAILURE;
    }
    result = tpm_utility->PinWeaverGenerateBiometricsAuthPk(
        protocol_version, kFaceAuthChannel, *auth_pk, &result_code, &root,
        &gsc_pk);
    if (result || result_code) {
      LOG(ERROR) << "generate_ba_pk failed! " << result_code << " "
                 << PwErrorStr(result_code);
      return EXIT_FAILURE;
    }
    gsc_pub_point = FromPinWeaverEccPoint(*ec, context.get(), gsc_pk);
    const std::optional<brillo::SecureBlob> pk_face = CalculatePkFromKeys(
        *ec, context.get(), *EC_KEY_get0_private_key(key_pair.get()),
        *gsc_pub_point);
    if (!pk_face.has_value()) {
      LOG(ERROR) << "Failed to calculate Pk.";
      return EXIT_FAILURE;
    }
  }

  // 4. Generate Pk for fingerprint slot again should fail because there's
  // already a Pk for it.
  LOG(INFO) << "generate_ba_pk should fail (fingerprint slot)";
  result_code = 0;
  result = tpm_utility->PinWeaverGenerateBiometricsAuthPk(
      protocol_version, kFpAuthChannel, *auth_pk, &result_code, &root, &gsc_pk);
  if (result) {
    LOG(ERROR) << "generate_ba_pk failed!";
    return EXIT_FAILURE;
  }
  if (result_code != PW_ERR_BIO_AUTH_ACCESS_DENIED) {
    LOG(ERROR) << "unexpected generate_ba_pk result code: " << result_code
               << " " << PwErrorStr(result_code);
    return EXIT_FAILURE;
  }

  // 5. Create a rate-limiter for FP channel.
  LOG(INFO) << "create_rate_limiter";
  result_code = 0;
  uint64_t label = GetDefaultLabel();
  std::string h_aux;
  brillo::SecureBlob reset_secret;
  std::map<uint32_t, uint32_t> delay_schedule({{2, PW_BLOCK_ATTEMPTS}});
  trunks::ValidPcrCriteria valid_pcr_criteria;
  GetDefaultHAux(&h_aux);
  GetDefaultResetSecret(&reset_secret);
  GetDefaultValidPcrCriteria(&valid_pcr_criteria);

  std::string cred_metadata;
  std::string mac;
  result = tpm_utility->PinWeaverCreateBiometricsAuthRateLimiter(
      protocol_version, kFpAuthChannel, label, h_aux, reset_secret,
      delay_schedule, valid_pcr_criteria, std::nullopt, &result_code, &root,
      &cred_metadata, &mac);
  if (result || result_code) {
    LOG(ERROR) << "create_rate_limiter failed! " << result_code << " "
               << PwErrorStr(result_code);
    return EXIT_FAILURE;
  }

  std::string old_root = root;
  std::string old_metadata = cred_metadata;

  // 6. Start an authenticate attempt toward the rate-limiter.
  LOG(INFO) << "start_bio_auth success";
  result_code = 0;
  brillo::Blob auth_nonce(PW_SECRET_SIZE, 0);
  base::RandBytes(auth_nonce.data(), auth_nonce.size());
  brillo::Blob gsc_nonce, encrypted_hec, iv;
  result = tpm_utility->PinWeaverStartBiometricsAuth(
      protocol_version, kFpAuthChannel, auth_nonce, h_aux, cred_metadata,
      &result_code, &root, &gsc_nonce, &encrypted_hec, &iv, &cred_metadata,
      &mac);
  if (result || result_code) {
    LOG(ERROR) << "start_bio_auth failed!\npw error: " << result_code << " "
               << PwErrorStr(result_code)
               << "\ntrunks error: " << trunks::GetErrorString(result);
    return EXIT_FAILURE;
  }
  if (gsc_nonce.size() != PW_SECRET_SIZE ||
      encrypted_hec.size() != PW_SECRET_SIZE ||
      iv.size() != PW_WRAP_BLOCK_SIZE) {
    LOG(ERROR) << "start_bio_auth returned bad credential!";
    return EXIT_FAILURE;
  }
  brillo::SecureBlob session_key =
      hwsec_foundation::Sha256(brillo::SecureBlob::Combine(
          brillo::SecureBlob(brillo::CombineBlobs({auth_nonce, gsc_nonce})),
          *pk_fp));
  brillo::SecureBlob label_seed;
  if (!hwsec_foundation::AesDecryptSpecifyBlockMode(
          brillo::SecureBlob(encrypted_hec), 0, encrypted_hec.size(),
          session_key, brillo::SecureBlob(iv),
          hwsec_foundation::PaddingScheme::kPaddingNone,
          hwsec_foundation::BlockMode::kCtr, &label_seed)) {
    LOG(ERROR) << "decrypting label_seed failed!";
  }
  brillo::SecureBlob old_label_seed(label_seed);

  LOG(INFO) << "get_log";
  result_code = 0;
  std::vector<trunks::PinWeaverLogEntry> log;
  result = tpm_utility->PinWeaverGetLog(protocol_version, old_root,
                                        &result_code, &root, &log);
  if (result || result_code) {
    LOG(ERROR) << "get_log failed! " << result_code << " "
               << PwErrorStr(result_code);
    return EXIT_FAILURE;
  }
  bool fail = false;
  if (log.empty()) {
    LOG(ERROR) << "get_log verification failed: empty log!";
    fail = true;
  }
  if (log.front().root() != root) {
    LOG(ERROR) << "get_log verification failed: wrong root!";
    LOG(ERROR) << HexEncode(log.front().root());
    fail = true;
  }
  if (log.front().type_case() != trunks::PinWeaverLogEntry::TypeCase::kAuth) {
    LOG(ERROR) << "get_log verification failed: wrong entry type!";
    LOG(ERROR) << log.front().type_case();
    fail = true;
  }
  if (fail) {
    return EXIT_FAILURE;
  }

  LOG(INFO) << "log_replay";
  result_code = 0;
  std::string replay_metadata = cred_metadata;
  std::string replay_mac = mac;
  result = tpm_utility->PinWeaverLogReplay(protocol_version, root, h_aux,
                                           old_metadata, &result_code, &root,
                                           &replay_metadata, &replay_mac);
  if (result) {
    LOG(ERROR) << "log_replay failed! " << result_code << " "
               << PwErrorStr(result_code);
    return EXIT_FAILURE;
  }
  if (replay_metadata != cred_metadata) {
    LOG(ERROR) << "log_replay verification failed: bad metadata!";
    return EXIT_FAILURE;
  }
  if (replay_mac != mac) {
    LOG(ERROR) << "log_replay verification failed: bad HMAC!";
    return EXIT_FAILURE;
  }

  // 6. Start an authenticate attempt toward the rate-limiter again, and verify
  // the returned secret is identical.
  LOG(INFO) << "start_bio_auth success (check label_seed is the same)";
  result_code = 0;
  base::RandBytes(auth_nonce.data(), auth_nonce.size());
  result = tpm_utility->PinWeaverStartBiometricsAuth(
      protocol_version, kFpAuthChannel, auth_nonce, h_aux, cred_metadata,
      &result_code, &root, &gsc_nonce, &encrypted_hec, &iv, &cred_metadata,
      &mac);
  if (result || result_code) {
    LOG(ERROR) << "start_bio_auth failed!\npw error: " << result_code << " "
               << PwErrorStr(result_code)
               << "\ntrunks error: " << trunks::GetErrorString(result);
    return EXIT_FAILURE;
  }
  if (gsc_nonce.size() != PW_SECRET_SIZE ||
      encrypted_hec.size() != PW_SECRET_SIZE ||
      iv.size() != PW_WRAP_BLOCK_SIZE) {
    LOG(ERROR) << "start_bio_auth returned bad credential!";
    return EXIT_FAILURE;
  }
  session_key = hwsec_foundation::Sha256(brillo::SecureBlob::Combine(
      brillo::SecureBlob(brillo::CombineBlobs({auth_nonce, gsc_nonce})),
      *pk_fp));
  if (!hwsec_foundation::AesDecryptSpecifyBlockMode(
          brillo::SecureBlob(encrypted_hec), 0, encrypted_hec.size(),
          session_key, brillo::SecureBlob(iv),
          hwsec_foundation::PaddingScheme::kPaddingNone,
          hwsec_foundation::BlockMode::kCtr, &label_seed)) {
    LOG(ERROR) << "decrypting label_seed failed!";
  }
  if (label_seed != old_label_seed) {
    LOG(ERROR) << "Label seeds returned from the two attempts are different!";
    return EXIT_FAILURE;
  }

  // 7. Start an authenticate attempt toward the rate-limiter again, it should
  // fail because the rate-limiter is locked out after 2 attempts.
  LOG(INFO) << "start_bio_auth should fail (rate-limited)";
  result_code = 0;
  base::RandBytes(auth_nonce.data(), auth_nonce.size());
  std::string no_cred_metadata, no_mac;
  result = tpm_utility->PinWeaverStartBiometricsAuth(
      protocol_version, kFpAuthChannel, auth_nonce, h_aux, cred_metadata,
      &result_code, &root, &gsc_nonce, &encrypted_hec, &iv, &no_cred_metadata,
      &no_mac);
  if (result) {
    LOG(ERROR) << "start_bio_auth failed!\npw error: " << result_code << " "
               << PwErrorStr(result_code)
               << "\ntrunks error: " << trunks::GetErrorString(result);
    return EXIT_FAILURE;
  }
  if (result_code != PW_ERR_RATE_LIMIT_REACHED) {
    LOG(ERROR) << "unexpected start_bio_auth result code: " << result_code
               << " " << PwErrorStr(result_code);
    return EXIT_FAILURE;
  }
  // Verify that secrets are not leaked
  if (!gsc_nonce.empty() || !encrypted_hec.empty() || !iv.empty()) {
    LOG(ERROR) << "secrets are leaked!";
    return EXIT_FAILURE;
  }

  // 8. Reset the rate-limiter.
  LOG(INFO) << "reset_auth";
  result_code = 0;
  result = tpm_utility->PinWeaverResetAuth(
      protocol_version, reset_secret, false, h_aux, cred_metadata, &result_code,
      &root, &cred_metadata, &mac);
  if (result || result_code) {
    LOG(ERROR) << "reset_auth failed! " << result_code << " "
               << PwErrorStr(result_code);
    return EXIT_FAILURE;
  }

  if (full) {
    // 9. Verify the authenticate attempt will fail with
    // PW_ERR_LOWENT_AUTH_FAILED if we send the wrong auth channel.
    LOG(INFO) << "start_bio_auth should fail (wrong channel)";
    result_code = 0;
    base::RandBytes(auth_nonce.data(), auth_nonce.size());
    result = tpm_utility->PinWeaverStartBiometricsAuth(
        protocol_version, kFaceAuthChannel, auth_nonce, h_aux, cred_metadata,
        &result_code, &root, &gsc_nonce, &encrypted_hec, &iv, &cred_metadata,
        &mac);
    if (result) {
      LOG(ERROR) << "start_bio_auth failed!\ntrunks error: "
                 << trunks::GetErrorString(result);
      return EXIT_FAILURE;
    }
    if (result_code != PW_ERR_LOWENT_AUTH_FAILED) {
      LOG(ERROR) << "unexpected start_bio_auth result code: " << result_code
                 << " " << PwErrorStr(result_code);
      return EXIT_FAILURE;
    }
    // Verify that secrets are not leaked
    if (!gsc_nonce.empty() || !encrypted_hec.empty() || !iv.empty()) {
      LOG(ERROR) << "secrets are leaked!";
      return EXIT_FAILURE;
    }
  }

  // 10. Start an authenticate attempt toward the rate-limiter again, and verify
  // the returned secret is identical.
  LOG(INFO) << "start_bio_auth success (check label_seed is the same)";
  result_code = 0;
  base::RandBytes(auth_nonce.data(), auth_nonce.size());
  result = tpm_utility->PinWeaverStartBiometricsAuth(
      protocol_version, kFpAuthChannel, auth_nonce, h_aux, cred_metadata,
      &result_code, &root, &gsc_nonce, &encrypted_hec, &iv, &cred_metadata,
      &mac);
  if (result || result_code) {
    LOG(ERROR) << "start_bio_auth failed!\npw error: " << result_code << " "
               << PwErrorStr(result_code)
               << "\ntrunks error: " << trunks::GetErrorString(result);
    return EXIT_FAILURE;
  }
  if (gsc_nonce.size() != PW_SECRET_SIZE ||
      encrypted_hec.size() != PW_SECRET_SIZE ||
      iv.size() != PW_WRAP_BLOCK_SIZE) {
    LOG(ERROR) << "start_bio_auth returned bad credential!";
    return EXIT_FAILURE;
  }
  session_key = hwsec_foundation::Sha256(brillo::SecureBlob::Combine(
      brillo::SecureBlob(brillo::CombineBlobs({auth_nonce, gsc_nonce})),
      *pk_fp));
  if (!hwsec_foundation::AesDecryptSpecifyBlockMode(
          brillo::SecureBlob(encrypted_hec), 0, encrypted_hec.size(),
          session_key, brillo::SecureBlob(iv),
          hwsec_foundation::PaddingScheme::kPaddingNone,
          hwsec_foundation::BlockMode::kCtr, &label_seed)) {
    LOG(ERROR) << "decrypting label_seed failed!";
  }
  if (label_seed != old_label_seed) {
    LOG(ERROR) << "Label seeds returned from the two attempts are different!";
    return EXIT_FAILURE;
  }

  puts("Success!");
  return EXIT_SUCCESS;
}

}  // namespace

int main(int argc, char** argv) {
  base::CommandLine::Init(argc, argv);
  brillo::InitLog(brillo::kLogToStderr);
  base::CommandLine* cl = base::CommandLine::ForCurrentProcess();
  int requested_protocol = PW_PROTOCOL_VERSION;
  if (cl->HasSwitch("protocol")) {
    requested_protocol = std::min(
        PW_PROTOCOL_VERSION, std::stoi(cl->GetSwitchValueASCII("protocol")));
  }
  const auto& args = cl->GetArgs();

  if (args.size() < 1) {
    puts("Invalid options!");
    PrintUsage();
    return EXIT_FAILURE;
  }

  const auto& command = args[0];

  if (command == "help") {
    puts("Pinweaver Client: A command line tool to invoke PinWeaver on GSC.");
    PrintUsage();
    return EXIT_SUCCESS;
  }

  TrunksFactoryImpl factory;
  CHECK(factory.Initialize()) << "Failed to initialize trunks factory.";

  {
    std::unique_ptr<trunks::TpmUtility> tpm_utility = factory.GetTpmUtility();
    trunks::TPM_RC result = tpm_utility->PinWeaverIsSupported(
        requested_protocol, &protocol_version);
    if (result == trunks::SAPI_RC_ABI_MISMATCH) {
      result = tpm_utility->PinWeaverIsSupported(0, &protocol_version);
    }
    if (result) {
      LOG(ERROR) << "PinWeaver is not supported on this device!";
      return EXIT_PINWEAVER_NOT_SUPPORTED;
    }
    protocol_version = std::min(protocol_version, (uint8_t)requested_protocol);
    LOG(INFO) << "Protocol version: " << static_cast<int>(protocol_version);
  }

  auto command_args_start = args.begin() + 1;

  const struct {
    const std::string command;
    int (*handler)(base::CommandLine::StringVector::const_iterator begin,
                   base::CommandLine::StringVector::const_iterator end,
                   TrunksFactoryImpl* factory);
  } command_handlers[] = {
      // clang-format off
      {"resettree", HandleResetTree},
      {"insert", HandleInsert},
      {"remove", HandleRemove},
      {"auth", HandleAuth},
      {"resetleaf", HandleResetLeaf},
      {"getlog", HandleGetLog},
      {"replay", HandleReplay},
      {"generate_ba_pk", HandleGenerateBiometricsAuthPk},
      {"block_generate_ba_pk", HandleBlockGenerateBiometricsAuthPk},
      {"selftest", HandleSelfTest},
      {"biometrics_selftest", HandleBiometricsSelfTest},
      // clang-format on
  };

  for (const auto& command_handler : command_handlers) {
    if (command_handler.command == command) {
      return command_handler.handler(command_args_start, args.end(), &factory);
    }
  }

  puts("Invalid options!");
  PrintUsage();
  return EXIT_FAILURE;
}
