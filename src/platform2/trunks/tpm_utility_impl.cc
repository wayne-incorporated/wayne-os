// Copyright 2014 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "trunks/tpm_utility_impl.h"

#include <algorithm>
#include <cstdint>
#include <iterator>
#include <memory>
#include <optional>

#include <base/check.h>
#include <base/check_op.h>
#include <base/hash/sha1.h>
#include <base/logging.h>
#include <base/notreached.h>
#include <base/strings/string_number_conversions.h>
#include <base/sys_byteorder.h>
#include <crypto/libcrypto-compat.h>
#include <crypto/openssl_util.h>
#include <crypto/scoped_openssl_types.h>
#include <crypto/secure_hash.h>
#include <crypto/sha2.h>
#include <openssl/aes.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/x509.h>

#include "trunks/authorization_delegate.h"
#include "trunks/blob_parser.h"
#include "trunks/command_transceiver.h"
#include "trunks/cr50_headers/ap_ro_status.h"
#include "trunks/error_codes.h"
#include "trunks/hmac_authorization_delegate.h"
#include "trunks/hmac_session.h"
#include "trunks/policy_session.h"
#include "trunks/tpm_constants.h"
#include "trunks/tpm_generated.h"
#include "trunks/tpm_pinweaver.h"
#include "trunks/tpm_state.h"
#include "trunks/tpm_u2f.h"
#include "trunks/trunks_factory.h"

#include "trunks/csme/mei_client_factory.h"
#include "trunks/csme/pinweaver_core_client.h"
#include "trunks/csme/pinweaver_provision_client.h"

namespace {

enum class VendorVariant {
  kUnknown,
  kGsc,
  kSimulator,
  kOther,
};

const char kPlatformPassword[] = "cros-platform";
const size_t kMaxPasswordLength = 32;
// The below maximum is defined in TPM 2.0 Library Spec Part 2 Section 13.1
const uint32_t kMaxNVSpaceIndex = (1 << 24) - 1;
// GSC Vendor ID ("CROS").
const uint32_t kVendorIdGsc = 0x43524f53;
// Simulator Vendor ID ("SIMU").
const uint32_t kVendorIdSimulator = 0x53494d55;
// Command code for GSC vendor-specific commands,
const uint32_t kGscVendorCC = 0x20000000 | 0; /* Vendor Bit Set + 0 */
// Vendor-specific subcommand codes.
const uint16_t kGscSubcmdInvalidateInactiveRW = 20;
const uint16_t kGscGetRmaChallenge = 30;
const uint16_t kGscSubcmdManageCCDPwd = 33;
const uint16_t kGscSubcmdGetAlertsData = 35;
const uint16_t kGscSubcmdPinWeaver = 37;
const uint16_t kGscSubcmdU2fGenerate = 44;
const uint16_t kGscSubcmdU2fSign = 45;
const uint16_t kGscSubcmdU2fAttest = 46;
const uint16_t kGscSubcmdGetRoStatus = 57;
const uint16_t kTi50GetMetrics = 65;

// Salt used exclusively for the Remote Server Unlock process due to the privacy
// reasons.
const char kRsuSalt[] = "Wu8oGt0uu0H8uSGxfo75uSDrGcRk2BXh";

constexpr uint8_t kPwLeafTypeNormal = 0;
constexpr uint8_t kPwLeafTypeBiometrics = 1;
constexpr uint8_t kPwSecretSize = 32;

// Returns a serialized representation of the unmodified handle. This is useful
// for predefined handle values, like TPM_RH_OWNER. For details on what types of
// handles use this name formula see Table 3 in the TPM 2.0 Library Spec Part 1
// (Section 16 - Names).
std::string NameFromHandle(trunks::TPM_HANDLE handle) {
  std::string name;
  trunks::Serialize_TPM_HANDLE(handle, &name);
  return name;
}

std::string HashString(const std::string& plaintext,
                       trunks::TPM_ALG_ID hash_alg) {
  switch (hash_alg) {
    case trunks::TPM_ALG_SHA1:
      return base::SHA1HashString(plaintext);
    case trunks::TPM_ALG_SHA256:
      return crypto::SHA256HashString(plaintext);
  }
  NOTREACHED();
  return std::string();
}

VendorVariant ToVendorVariant(std::optional<uint32_t> vendor_id) {
  if (!vendor_id.has_value()) {
    return VendorVariant::kUnknown;
  }
  switch (*vendor_id) {
    case kVendorIdGsc:
      return VendorVariant::kGsc;
    case kVendorIdSimulator:
      return VendorVariant::kSimulator;
    default:
      return VendorVariant::kOther;
  }
}

}  // namespace

namespace trunks {

TpmUtilityImpl::TpmUtilityImpl(const TrunksFactory& factory)
    : factory_(factory) {
  crypto::EnsureOpenSSLInit();
}

TpmUtilityImpl::~TpmUtilityImpl() {}

template <typename S, typename P>
TPM_RC TpmUtilityImpl::U2fCommand(const std::string& tag,
                                  uint16_t subcommand,
                                  S serialize,
                                  P parse) {
  if (!IsGsc()) {
    LOG(WARNING) << "U2F not supported on non-GSC vendor variants.";
    return TPM_RC_FAILURE;
  }

  std::string in;
  TPM_RC rc = serialize(&in);
  if (rc) {
    LOG(ERROR) << tag << ": Serialize failed: 0x" << std::hex << rc << " "
               << GetErrorString(rc);
    return rc;
  }

  std::string out;
  rc = GscVendorCommand(subcommand, in, &out);

  if (rc == TPM_RC_SUCCESS) {
    rc = parse(out);
  }
  return rc;
}

TPM_RC TpmUtilityImpl::Startup() {
  TPM_RC result = TPM_RC_SUCCESS;
  Tpm* tpm = factory_.GetTpm();
  result = tpm->StartupSync(TPM_SU_CLEAR, nullptr);
  // Ignore TPM_RC_INITIALIZE, that means it was already started.
  if (result && result != TPM_RC_INITIALIZE) {
    LOG(ERROR) << __func__
               << ": Failed to startup sync: " << GetErrorString(result);
    return result;
  }
  result = tpm->SelfTestSync(YES /* Full test. */, nullptr);
  if (result) {
    LOG(ERROR) << __func__
               << ": Failed self test sync: " << GetErrorString(result);
    return result;
  }
  return TPM_RC_SUCCESS;
}

TPM_RC TpmUtilityImpl::Clear() {
  TPM_RC result = TPM_RC_SUCCESS;
  std::unique_ptr<AuthorizationDelegate> password_delegate(
      factory_.GetPasswordAuthorization(""));
  result = factory_.GetTpm()->ClearSync(TPM_RH_PLATFORM,
                                        NameFromHandle(TPM_RH_PLATFORM),
                                        password_delegate.get());
  // If there was an error in the initialization, platform auth is in a bad
  // state.
  if (result == TPM_RC_AUTH_MISSING) {
    std::unique_ptr<AuthorizationDelegate> authorization(
        factory_.GetPasswordAuthorization(kPlatformPassword));
    result = factory_.GetTpm()->ClearSync(
        TPM_RH_PLATFORM, NameFromHandle(TPM_RH_PLATFORM), authorization.get());
  }
  if (GetFormatOneError(result) == TPM_RC_BAD_AUTH) {
    LOG(INFO) << __func__
              << ": Clear failed because of BAD_AUTH. This probably means "
              << "that the TPM was already initialized.";
    return result;
  }
  if (result) {
    LOG(ERROR) << __func__
               << ": Failed to clear the TPM: " << GetErrorString(result);
  }
  return result;
}

void TpmUtilityImpl::Shutdown() {
  TPM_RC return_code = factory_.GetTpm()->ShutdownSync(TPM_SU_CLEAR, nullptr);
  if (return_code && return_code != TPM_RC_INITIALIZE) {
    // This should not happen, but if it does, there is nothing we can do.
    LOG(ERROR) << __func__
               << ": Error shutting down: " << GetErrorString(return_code);
  }
}

TPM_RC TpmUtilityImpl::TpmBasicInit(std::unique_ptr<TpmState>* tpm_state) {
  TPM_RC result = TPM_RC_SUCCESS;

  *tpm_state = factory_.GetTpmState();
  result = (*tpm_state)->Initialize();
  if (result) {
    LOG(ERROR) << __func__ << ": Failed to initialize TPM state: "
               << GetErrorString(result);
    return result;
  }
  // Warn about various unexpected conditions.
  if (!(*tpm_state)->WasShutdownOrderly()) {
    LOG(WARNING) << __func__
                 << ": WARNING: The last TPM shutdown was not orderly.";
  }
  if ((*tpm_state)->IsInLockout()) {
    LOG(WARNING) << __func__ << ": WARNING: The TPM is currently in lockout.";
  }

  return TPM_RC_SUCCESS;
}

TPM_RC TpmUtilityImpl::CheckState() {
  TPM_RC result;
  std::unique_ptr<TpmState> tpm_state;

  result = TpmBasicInit(&tpm_state);

  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << __func__
               << ": Failed TPM basic init: " << GetErrorString(result);
    return result;
  }

  if (tpm_state->IsPlatformHierarchyEnabled())
    LOG(WARNING) << __func__ << ": Platform Hierarchy Enabled!";

  if (!tpm_state->IsStorageHierarchyEnabled())
    LOG(WARNING) << __func__ << ": Storage Hierarchy Disabled!";

  if (!tpm_state->IsEndorsementHierarchyEnabled())
    LOG(WARNING) << __func__ << ": Endorsement Hierarchy Disabled!";

  LOG(INFO) << __func__ << ": TPM State verified.";
  return TPM_RC_SUCCESS;
}

TPM_RC TpmUtilityImpl::InitializeTpm() {
  TPM_RC result;
  std::unique_ptr<TpmState> tpm_state;

  result = TpmBasicInit(&tpm_state);
  if (result) {
    LOG(ERROR) << __func__
               << ": Failed TPM basic init: " << GetErrorString(result);
    return result;
  }

  // We expect the firmware has already locked down the platform hierarchy. If
  // it hasn't, do it now.
  if (tpm_state->IsPlatformHierarchyEnabled()) {
    std::unique_ptr<AuthorizationDelegate> empty_password(
        factory_.GetPasswordAuthorization(""));
    result = SetHierarchyAuthorization(TPM_RH_PLATFORM, kPlatformPassword,
                                       empty_password.get());
    if (GetFormatOneError(result) == TPM_RC_BAD_AUTH) {
      // Most likely the platform password has already been set.
      result = TPM_RC_SUCCESS;
    }
    if (result != TPM_RC_SUCCESS) {
      LOG(ERROR) << __func__ << ": Failed to set hierarchy authorization: "
                 << GetErrorString(result);
      return result;
    }
    result = AllocatePCR(kPlatformPassword);
    if (result != TPM_RC_SUCCESS) {
      LOG(ERROR) << __func__
                 << ": Failed to alocate PCR: " << GetErrorString(result);
      return result;
    }
    std::unique_ptr<AuthorizationDelegate> authorization(
        factory_.GetPasswordAuthorization(kPlatformPassword));
    result = DisablePlatformHierarchy(authorization.get());
    if (result != TPM_RC_SUCCESS) {
      LOG(ERROR) << __func__ << ": Failed to disable platform hierarchy: "
                 << GetErrorString(result);
      return result;
    }
  }
  return TPM_RC_SUCCESS;
}

TPM_RC TpmUtilityImpl::AllocatePCR(const std::string& platform_password) {
  TPM_RC result;
  TPMI_YES_NO more_data = YES;
  TPMS_CAPABILITY_DATA capability_data;
  result = factory_.GetTpm()->GetCapabilitySync(
      TPM_CAP_PCRS, 0 /*property (not used)*/, 1 /*property_count*/, &more_data,
      &capability_data, nullptr /*authorization_delegate*/);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << __func__
               << ": Error querying PCRs: " << GetErrorString(result);
    return result;
  }
  TPML_PCR_SELECTION& existing_pcrs = capability_data.data.assigned_pcr;
  bool sha256_needed = true;
  std::vector<TPMI_ALG_HASH> pcr_banks_to_remove;
  for (uint32_t i = 0; i < existing_pcrs.count; ++i) {
    if (existing_pcrs.pcr_selections[i].hash == TPM_ALG_SHA256) {
      sha256_needed = false;
    } else {
      pcr_banks_to_remove.push_back(existing_pcrs.pcr_selections[i].hash);
    }
  }
  if (!sha256_needed && pcr_banks_to_remove.empty()) {
    return TPM_RC_SUCCESS;
  }
  TPML_PCR_SELECTION pcr_allocation;
  memset(&pcr_allocation, 0, sizeof(pcr_allocation));
  if (sha256_needed) {
    pcr_allocation.pcr_selections[pcr_allocation.count].hash = TPM_ALG_SHA256;
    pcr_allocation.pcr_selections[pcr_allocation.count].sizeof_select =
        PCR_SELECT_MIN;
    for (int i = 0; i < PCR_SELECT_MIN; ++i) {
      pcr_allocation.pcr_selections[pcr_allocation.count].pcr_select[i] = 0xff;
    }
    ++pcr_allocation.count;
  }
  for (auto pcr_type : pcr_banks_to_remove) {
    pcr_allocation.pcr_selections[pcr_allocation.count].hash = pcr_type;
    pcr_allocation.pcr_selections[pcr_allocation.count].sizeof_select =
        PCR_SELECT_MAX;
    ++pcr_allocation.count;
  }
  std::unique_ptr<AuthorizationDelegate> platform_delegate(
      factory_.GetPasswordAuthorization(platform_password));
  TPMI_YES_NO allocation_success;
  uint32_t max_pcr;
  uint32_t size_needed;
  uint32_t size_available;
  result = factory_.GetTpm()->PCR_AllocateSync(
      TPM_RH_PLATFORM, NameFromHandle(TPM_RH_PLATFORM), pcr_allocation,
      &allocation_success, &max_pcr, &size_needed, &size_available,
      platform_delegate.get());
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << __func__
               << ": Error allocating PCRs: " << GetErrorString(result);
    return result;
  }
  if (allocation_success != YES) {
    LOG(ERROR) << __func__ << ": PCR allocation unsuccessful.";
    return TPM_RC_FAILURE;
  }
  return TPM_RC_SUCCESS;
}

TPM_RC TpmUtilityImpl::PrepareForPinWeaver() {
  return CreateCsmeSaltingKey();
}

TPM_RC TpmUtilityImpl::PrepareForOwnership() {
  std::unique_ptr<TpmState> tpm_state(factory_.GetTpmState());
  TPM_RC result = tpm_state->Initialize();
  if (result) {
    LOG(ERROR) << __func__
               << ": Error initializing state: " << GetErrorString(result);
    return result;
  }
  if (tpm_state->IsOwnerPasswordSet()) {
    VLOG(1) << __func__ << ": Nothing to do. Owner password is already set.";
    return TPM_RC_SUCCESS;
  }
  result = CreateStorageAndSaltingKeys();
  LOG_IF(INFO, result == TPM_RC_SUCCESS) << __func__ << ": done.";
  return result;
}

TPM_RC TpmUtilityImpl::InitializeOwnerForCsme() {
  // For GSC case, we don't have to create salting key for CSME.
  if (IsGsc() || IsSimulator()) {
    return TPM_RC_SUCCESS;
  }
  uint8_t protocol_version = 0;
  TPM_RC result = PinWeaverIsSupported(0, &protocol_version);
  // If pinweaver is not supported at all, skip the initialization.
  if (result) {
    return TPM_RC_SUCCESS;
  }
  result = CreateCsmeSaltingKey();
  if (result) {
    LOG(WARNING) << __func__ << ": Failed to create CSME Salting Key:"
                 << GetErrorString(result);
    return result;
  }
  csme::MeiClientFactory mei_client_factory;
  csme::PinWeaverProvisionClient client(&mei_client_factory);
  if (!client.InitOwner()) {
    LOG(WARNING) << "Failed to call `InitOwner()`";
    return TPM_RC_FAILURE;
  }
  return TPM_RC_SUCCESS;
}

TPM_RC TpmUtilityImpl::CreateStorageAndSaltingKeys() {
  // Perform tasks that have to be done when owner auth is still empty.
  TPM_RC result = InitializeOwnerForCsme();
  if (result != TPM_RC_SUCCESS) {
    // By design, don't hard-fail the TPM initialization flow.
    LOG(WARNING) << __func__ << ": Failed to initialize owner for csme.";
  }

  // First we set the storage hierarchy authorization to the well know default
  // password.
  result = SetKnownOwnerPassword(kWellKnownPassword);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << __func__ << ": Error injecting known password: "
               << GetErrorString(result);
    return result;
  }

  result = CreateStorageRootKeys(kWellKnownPassword);
  if (result) {
    LOG(ERROR) << __func__
               << ": Error creating SRKs: " << GetErrorString(result);
    return result;
  }

  result = CreatePersistentSaltingKey(kWellKnownPassword);
  if (result) {
    LOG(ERROR) << __func__
               << ": Error creating salting key: " << GetErrorString(result);
    return result;
  }

  return result;
}

TPM_RC TpmUtilityImpl::TakeOwnership(const std::string& owner_password,
                                     const std::string& endorsement_password,
                                     const std::string& lockout_password) {
  TPM_RC result = CreateStorageAndSaltingKeys();
  if (result != TPM_RC_SUCCESS) {
    return result;
  }
  std::unique_ptr<HmacSession> session = factory_.GetHmacSession();
  result = session->StartUnboundSession(true, true);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << __func__ << ": Error initializing AuthorizationSession: "
               << GetErrorString(result);
    return result;
  }
  std::unique_ptr<TpmState> tpm_state(factory_.GetTpmState());
  result = tpm_state->Initialize();
  if (result != TPM_RC_SUCCESS) {
    return result;
  }

  session->SetEntityAuthorizationValue("");
  if (!tpm_state->IsEndorsementPasswordSet()) {
    session->SetFutureAuthorizationValue(endorsement_password);
    result = SetHierarchyAuthorization(TPM_RH_ENDORSEMENT, endorsement_password,
                                       session->GetDelegate());
    if (result) {
      LOG(ERROR) << __func__ << ": Failed to set hierarchy authorization, "
                 << "endorsement password not set: " << GetErrorString(result);
      return result;
    }
  }
  if (!tpm_state->IsLockoutPasswordSet()) {
    session->SetFutureAuthorizationValue(lockout_password);
    result = SetHierarchyAuthorization(TPM_RH_LOCKOUT, lockout_password,
                                       session->GetDelegate());
    if (result) {
      LOG(ERROR) << __func__ << ": Failed to set hierarchy authorization, "
                 << "lockout password not set: " << GetErrorString(result);
      return result;
    }
  }
  // We take ownership of owner hierarchy last.
  session->SetEntityAuthorizationValue(kWellKnownPassword);
  session->SetFutureAuthorizationValue(owner_password);
  result = SetHierarchyAuthorization(TPM_RH_OWNER, owner_password,
                                     session->GetDelegate());
  if ((GetFormatOneError(result) == TPM_RC_BAD_AUTH) &&
      tpm_state->IsOwnerPasswordSet()) {
    LOG(WARNING) << __func__
                 << ": Error changing owner password. This probably because "
                 << "ownership is already taken.";
    return TPM_RC_SUCCESS;
  } else if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << __func__ << ": Error changing owner authorization: "
               << GetErrorString(result);
    return result;
  }
  return TPM_RC_SUCCESS;
}

TPM_RC TpmUtilityImpl::ChangeOwnerPassword(const std::string& old_password,
                                           const std::string& new_password) {
  std::unique_ptr<TpmState> tpm_state(factory_.GetTpmState());
  TPM_RC result = tpm_state->Initialize();
  if (result != TPM_RC_SUCCESS) {
    return result;
  }

  std::unique_ptr<HmacSession> session = factory_.GetHmacSession();
  result = session->StartUnboundSession(true, true);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << __func__ << ": Error initializing AuthorizationSession: "
               << GetErrorString(result);
    return result;
  }

  session->SetEntityAuthorizationValue(old_password);
  session->SetFutureAuthorizationValue(new_password);
  result = SetHierarchyAuthorization(TPM_RH_OWNER, new_password,
                                     session->GetDelegate());
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << __func__ << ": Error changing owner authorization: "
               << GetErrorString(result) << ", IsOwnerPasswordSet() : "
               << tpm_state->IsOwnerPasswordSet();
    return result;
  }
  return TPM_RC_SUCCESS;
}

TPM_RC TpmUtilityImpl::StirRandom(const std::string& entropy_data,
                                  AuthorizationDelegate* delegate) {
  std::string digest = crypto::SHA256HashString(entropy_data);
  TPM2B_SENSITIVE_DATA random_bytes = Make_TPM2B_SENSITIVE_DATA(digest);
  return factory_.GetTpm()->StirRandomSync(random_bytes, delegate);
}

TPM_RC TpmUtilityImpl::GenerateRandom(size_t num_bytes,
                                      AuthorizationDelegate* delegate,
                                      std::string* random_data) {
  CHECK(random_data);
  size_t bytes_left = num_bytes;
  random_data->clear();
  TPM_RC rc;
  TPM2B_DIGEST digest;
  while (bytes_left > 0) {
    rc = factory_.GetTpm()->GetRandomSync(bytes_left, &digest, delegate);
    if (rc) {
      LOG(ERROR) << __func__ << ": Error getting random data from tpm.";
      return rc;
    }
    random_data->append(StringFrom_TPM2B_DIGEST(digest));
    bytes_left -= digest.size;
  }
  CHECK_EQ(random_data->size(), num_bytes);
  return TPM_RC_SUCCESS;
}

TPM_RC TpmUtilityImpl::ExtendPCR(int pcr_index,
                                 const std::string& extend_data,
                                 AuthorizationDelegate* delegate) {
  if (pcr_index < 0 || pcr_index >= IMPLEMENTATION_PCR) {
    LOG(ERROR) << __func__ << ": Using a PCR index that isn't implemented.";
    return TPM_RC_FAILURE;
  }
  TPM_HANDLE pcr_handle = HR_PCR + pcr_index;
  std::string pcr_name = NameFromHandle(pcr_handle);
  TPML_DIGEST_VALUES digests;
  digests.count = 1;
  digests.digests[0].hash_alg = TPM_ALG_SHA256;
  crypto::SHA256HashString(extend_data, digests.digests[0].digest.sha256,
                           crypto::kSHA256Length);
  std::unique_ptr<AuthorizationDelegate> empty_password_delegate =
      factory_.GetPasswordAuthorization("");
  if (!delegate) {
    delegate = empty_password_delegate.get();
  }
  return factory_.GetTpm()->PCR_ExtendSync(pcr_handle, pcr_name, digests,
                                           delegate);
}

TPM_RC TpmUtilityImpl::ExtendPCRForCSME(int pcr_index,
                                        const std::string& extend_data) {
  // If csme is not applicable, just pretend it to be successful.
  if (GetPinwWeaverBackendType() != PinWeaverBackendType::kCsme) {
    return TPM_RC_SUCCESS;
  }

  csme::MeiClientFactory mei_client_factory;
  std::unique_ptr<csme::PinWeaverCoreClient> client =
      csme::PinWeaverCoreClient::Create(&mei_client_factory);
  const std::string digest = crypto::SHA256HashString(extend_data);
  if (!client->ExtendPcr(pcr_index, TPM_ALG_SHA256, digest)) {
    LOG(ERROR) << __func__ << ": Failed to extend PCR " << pcr_index
               << " for CSME.";
    return TPM_RC_FAILURE;
  }
  return TPM_RC_SUCCESS;
}

TPM_RC TpmUtilityImpl::ReadPCR(int pcr_index, std::string* pcr_value) {
  TPML_PCR_SELECTION pcr_select_in;
  uint32_t pcr_update_counter;
  TPML_PCR_SELECTION pcr_select_out;
  TPML_DIGEST pcr_values;
  // This process of selecting pcrs is highlighted in TPM 2.0 Library Spec
  // Part 2 (Section 10.5 - PCR structures).
  uint8_t pcr_select_index = pcr_index / 8;
  uint8_t pcr_select_byte = 1 << (pcr_index % 8);
  memset(&pcr_select_in, 0, sizeof(pcr_select_in));
  pcr_select_in.count = 1;
  pcr_select_in.pcr_selections[0].hash = TPM_ALG_SHA256;
  pcr_select_in.pcr_selections[0].sizeof_select = PCR_SELECT_MIN;
  pcr_select_in.pcr_selections[0].pcr_select[pcr_select_index] =
      pcr_select_byte;

  TPM_RC rc =
      factory_.GetTpm()->PCR_ReadSync(pcr_select_in, &pcr_update_counter,
                                      &pcr_select_out, &pcr_values, nullptr);
  if (rc) {
    LOG(INFO) << __func__
              << ": Error trying to read a pcr: " << GetErrorString(rc);
    return rc;
  }
  if (pcr_select_out.count != 1 ||
      pcr_select_out.pcr_selections[0].sizeof_select < (pcr_select_index + 1) ||
      pcr_select_out.pcr_selections[0].pcr_select[pcr_select_index] !=
          pcr_select_byte) {
    LOG(ERROR) << __func__ << ": TPM did not return the requested PCR";
    return TPM_RC_FAILURE;
  }
  if (pcr_values.count < 1U) {
    LOG(ERROR) << __func__ << ": Unexpected TPM reply";
    return TPM_RC_FAILURE;
  }
  pcr_value->assign(StringFrom_TPM2B_DIGEST(pcr_values.digests[0]));
  return TPM_RC_SUCCESS;
}

TPM_RC TpmUtilityImpl::ReadPCRFromCSME(int pcr_index, std::string* pcr_value) {
  csme::MeiClientFactory mei_client_factory;
  std::unique_ptr<csme::PinWeaverCoreClient> client =
      csme::PinWeaverCoreClient::Create(&mei_client_factory);
  uint32_t pcr_index_out, hash_alg_out;
  if (!client->ReadPcr(pcr_index, TPM_ALG_SHA256, &pcr_index_out, &hash_alg_out,
                       pcr_value)) {
    LOG(ERROR) << __func__ << ": Failed to read PCR " << pcr_index
               << " from CSME.";
    return TPM_RC_FAILURE;
  }
  if (pcr_index != pcr_index_out) {
    LOG(ERROR) << __func__
               << ": Output PCR index mismatched: input=" << pcr_index
               << ", output=" << pcr_index_out << ".";
    return TPM_RC_FAILURE;
  }
  if (hash_alg_out != TPM_ALG_SHA256) {
    LOG(ERROR) << __func__ << ": Unsupported algorithm ID: " << hash_alg_out
               << ".";
    return TPM_RC_FAILURE;
  }
  return TPM_RC_SUCCESS;
}

TPM_RC TpmUtilityImpl::AsymmetricEncrypt(TPM_HANDLE key_handle,
                                         TPM_ALG_ID scheme,
                                         TPM_ALG_ID hash_alg,
                                         const std::string& plaintext,
                                         AuthorizationDelegate* delegate,
                                         std::string* ciphertext) {
  TPMT_RSA_DECRYPT in_scheme;
  if (hash_alg == TPM_ALG_NULL) {
    hash_alg = TPM_ALG_SHA256;
  }
  if (scheme == TPM_ALG_RSAES) {
    in_scheme.scheme = TPM_ALG_RSAES;
  } else if (scheme == TPM_ALG_OAEP || scheme == TPM_ALG_NULL) {
    in_scheme.scheme = TPM_ALG_OAEP;
    in_scheme.details.oaep.hash_alg = hash_alg;
  } else {
    LOG(ERROR) << __func__ << ": Invalid encryption scheme used.";
    return SAPI_RC_BAD_PARAMETER;
  }

  TPMT_PUBLIC public_area;
  TPM_RC result = GetKeyPublicArea(key_handle, &public_area);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << __func__ << ": Error finding public area for: " << key_handle;
    return result;
  } else if (public_area.type != TPM_ALG_RSA) {
    LOG(ERROR) << __func__ << ": Key handle given is not an RSA key";
    return SAPI_RC_BAD_PARAMETER;
  } else if ((public_area.object_attributes & kDecrypt) == 0) {
    LOG(ERROR) << __func__ << ": Key handle given is not a decryption key";
    return SAPI_RC_BAD_PARAMETER;
  }
  if ((public_area.object_attributes & kRestricted) != 0) {
    LOG(ERROR) << __func__
               << ": Cannot use RSAES for encryption with a restricted key";
    return SAPI_RC_BAD_PARAMETER;
  }
  std::string key_name;
  result = ComputeKeyName(public_area, &key_name);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << __func__ << ": Error computing key name for: " << key_handle;
    return result;
  }

  TPM2B_DATA label;
  label.size = 0;
  TPM2B_PUBLIC_KEY_RSA in_message = Make_TPM2B_PUBLIC_KEY_RSA(plaintext);
  TPM2B_PUBLIC_KEY_RSA out_message;
  result = factory_.GetTpm()->RSA_EncryptSync(key_handle, key_name, in_message,
                                              in_scheme, label, &out_message,
                                              delegate);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << __func__
               << ": Error performing RSA encrypt: " << GetErrorString(result);
    return result;
  }
  ciphertext->assign(StringFrom_TPM2B_PUBLIC_KEY_RSA(out_message));
  return TPM_RC_SUCCESS;
}

TPM_RC TpmUtilityImpl::AsymmetricDecrypt(TPM_HANDLE key_handle,
                                         TPM_ALG_ID scheme,
                                         TPM_ALG_ID hash_alg,
                                         const std::string& ciphertext,
                                         AuthorizationDelegate* delegate,
                                         std::string* plaintext) {
  TPMT_RSA_DECRYPT in_scheme;
  if (scheme == TPM_ALG_RSAES || scheme == TPM_ALG_NULL) {
    in_scheme.scheme = scheme;
  } else if (scheme == TPM_ALG_OAEP) {
    in_scheme.scheme = TPM_ALG_OAEP;
    if (hash_alg == TPM_ALG_NULL) {
      hash_alg = TPM_ALG_SHA256;
    }
    in_scheme.details.oaep.hash_alg = hash_alg;
  } else {
    LOG(ERROR) << __func__ << ": Invalid decryption scheme used.";
    return SAPI_RC_BAD_PARAMETER;
  }
  TPM_RC result;
  if (delegate == nullptr) {
    result = SAPI_RC_INVALID_SESSIONS;
    LOG(ERROR) << __func__
               << ": This method needs a valid authorization delegate: "
               << GetErrorString(result);
    return result;
  }
  TPMT_PUBLIC public_area;
  result = GetKeyPublicArea(key_handle, &public_area);
  if (result) {
    LOG(ERROR) << __func__ << ": Error finding public area for: " << key_handle;
    return result;
  } else if (public_area.type != TPM_ALG_RSA) {
    LOG(ERROR) << __func__ << ": Key handle given is not an RSA key";
    return SAPI_RC_BAD_PARAMETER;
  } else if ((public_area.object_attributes & kDecrypt) == 0) {
    LOG(ERROR) << __func__ << ": Key handle given is not a decryption key";
    return SAPI_RC_BAD_PARAMETER;
  }
  if ((public_area.object_attributes & kRestricted) != 0) {
    LOG(ERROR) << __func__
               << ": Cannot use RSAES for encryption with a restricted key";
    return SAPI_RC_BAD_PARAMETER;
  }
  std::string key_name;
  result = ComputeKeyName(public_area, &key_name);
  if (result) {
    LOG(ERROR) << __func__ << ": Error computing key name for: " << key_handle;
    return result;
  }

  TPM2B_DATA label;
  label.size = 0;
  TPM2B_PUBLIC_KEY_RSA in_message = Make_TPM2B_PUBLIC_KEY_RSA(ciphertext);
  TPM2B_PUBLIC_KEY_RSA out_message;
  result = factory_.GetTpm()->RSA_DecryptSync(key_handle, key_name, in_message,
                                              in_scheme, label, &out_message,
                                              delegate);
  if (result) {
    LOG(ERROR) << __func__
               << ": Error performing RSA decrypt: " << GetErrorString(result);
    return result;
  }
  plaintext->assign(StringFrom_TPM2B_PUBLIC_KEY_RSA(out_message));
  return TPM_RC_SUCCESS;
}

TPM_RC TpmUtilityImpl::ECDHZGen(TPM_HANDLE key_handle,
                                const TPM2B_ECC_POINT& in_point,
                                AuthorizationDelegate* delegate,
                                TPM2B_ECC_POINT* out_point) {
  TPM_RC result;
  if (delegate == nullptr) {
    result = SAPI_RC_INVALID_SESSIONS;
    LOG(ERROR) << __func__
               << ": This method needs a valid authorization delegate: "
               << GetErrorString(result);
    return result;
  }
  TPMT_PUBLIC public_area;
  result = GetKeyPublicArea(key_handle, &public_area);
  if (result) {
    LOG(ERROR) << __func__ << ": Error finding public area for: " << key_handle
               << ", error: " << GetErrorString(result);
    return result;
  } else if (public_area.type != TPM_ALG_ECC) {
    LOG(ERROR) << __func__ << ": Key handle given is not an ECC key";
    return SAPI_RC_BAD_PARAMETER;
  } else if ((public_area.object_attributes & kDecrypt) == 0) {
    LOG(ERROR) << __func__ << ": Key handle given is not a decryption key";
    return SAPI_RC_BAD_PARAMETER;
  }
  if ((public_area.object_attributes & kRestricted) != 0) {
    LOG(ERROR) << __func__
               << ": Cannot use ECDH for ZGen with a restricted key";
    return SAPI_RC_BAD_PARAMETER;
  }
  std::string key_name;
  result = ComputeKeyName(public_area, &key_name);
  if (result) {
    LOG(ERROR) << __func__ << ": Error computing key name for: " << key_handle
               << ", error: " << GetErrorString(result);
    return result;
  }

  result = factory_.GetTpm()->ECDH_ZGenSync(key_handle, key_name, in_point,
                                            out_point, delegate);
  if (result) {
    LOG(ERROR) << __func__
               << ": Error performing ECDH ZGen: " << GetErrorString(result);
    return result;
  }
  return TPM_RC_SUCCESS;
}

TPM_RC TpmUtilityImpl::RawSign(TPM_HANDLE key_handle,
                               TPM_ALG_ID scheme,
                               TPM_ALG_ID hash_alg,
                               const std::string& plaintext,
                               bool generate_hash,
                               AuthorizationDelegate* delegate,
                               TPMT_SIGNATURE* auth) {
  TPM_RC result;
  if (delegate == nullptr) {
    result = SAPI_RC_INVALID_SESSIONS;
    LOG(ERROR) << __func__
               << ": This method needs a valid authorization delegate: "
               << GetErrorString(result);
    return result;
  }

  // Get public information of the key handle
  TPMT_PUBLIC public_area;
  result = GetKeyPublicArea(key_handle, &public_area);
  if (result) {
    LOG(ERROR) << __func__ << ": Error finding public area for: " << key_handle;
    return result;
  } else if (public_area.type != TPM_ALG_RSA &&
             public_area.type != TPM_ALG_ECC) {
    LOG(ERROR) << __func__
               << ": Key handle given is not a supported key (RSA, ECC)";
    return SAPI_RC_BAD_PARAMETER;
  } else if ((public_area.object_attributes & kSign) == 0) {
    LOG(ERROR) << __func__ << ": Key handle given is not a signging key";
    return SAPI_RC_BAD_PARAMETER;
  } else if ((public_area.object_attributes & kRestricted) != 0) {
    LOG(ERROR) << __func__ << ": Key handle references a restricted key";
    return SAPI_RC_BAD_PARAMETER;
  }

  // Default scheme is TPM_ALG_RSASSA
  if (scheme == TPM_ALG_NULL) {
    scheme = TPM_ALG_RSASSA;
  }

  // Default hash algorithm is SHA256, except TPM_ALG_RSASSA
  // For RSASSA, we allow TPM_ALG_NULL since TPMs can support padding-only
  // scheme for RSASSA which is indicated by passing TPM_ALG_NULL as a hashing
  // algorithm to TPM2_Sign.
  if (scheme != TPM_ALG_RSASSA && hash_alg == TPM_ALG_NULL) {
    hash_alg = TPM_ALG_SHA256;
  }

  // Check key type and scheme.
  std::function<std::string(const TPMT_SIGNATURE&)> unpack_helper;
  if (public_area.type == TPM_ALG_RSA) {
    if (scheme != TPM_ALG_RSAPSS && scheme != TPM_ALG_RSASSA) {
      LOG(ERROR) << __func__ << ": Invalid signing scheme used for RSA key.";
      return SAPI_RC_BAD_PARAMETER;
    }
  } else if (public_area.type == TPM_ALG_ECC) {
    if (scheme != TPM_ALG_ECDSA) {
      LOG(ERROR) << __func__ << ": Invalid signing scheme used for ECC key.";
      return SAPI_RC_BAD_PARAMETER;
    }
  }

  // Fill the checked parameters
  TPMT_SIG_SCHEME in_scheme;
  in_scheme.scheme = scheme;
  in_scheme.details.any.hash_alg = hash_alg;

  // Compute key name
  std::string key_name;
  result = ComputeKeyName(public_area, &key_name);
  if (result) {
    LOG(ERROR) << __func__ << ": Error computing key name for: " << key_handle;
    return result;
  }

  // Call TPM
  std::string digest =
      generate_hash ? HashString(plaintext, hash_alg) : plaintext;
  if (digest.size() > sizeof(TPMU_HA)) {
    LOG(ERROR) << __func__
               << ": digest is too long for TPM signing command. Input length: "
               << digest.size() << ", the limit: " << sizeof(TPMU_HA);
    return SAPI_RC_BAD_PARAMETER;
  }

  TPM2B_DIGEST tpm_digest = Make_TPM2B_DIGEST(digest);
  TPMT_TK_HASHCHECK validation;
  validation.tag = TPM_ST_HASHCHECK;
  validation.hierarchy = TPM_RH_NULL;
  validation.digest.size = 0;
  result = factory_.GetTpm()->SignSync(key_handle, key_name, tpm_digest,
                                       in_scheme, validation, auth, delegate);
  if (result) {
    LOG(ERROR) << __func__
               << ": Error signing digest: " << GetErrorString(result);
    return result;
  }

  return TPM_RC_SUCCESS;
}

TPM_RC TpmUtilityImpl::Sign(TPM_HANDLE key_handle,
                            TPM_ALG_ID scheme,
                            TPM_ALG_ID hash_alg,
                            const std::string& plaintext,
                            bool generate_hash,
                            AuthorizationDelegate* delegate,
                            std::string* signature) {
  TPM_RC result;
  TPMT_SIGNATURE signature_out;

  // Default scheme is TPM_ALG_RSASSA
  if (scheme == TPM_ALG_NULL)
    scheme = TPM_ALG_RSASSA;

  result = RawSign(key_handle, scheme, hash_alg, plaintext, generate_hash,
                   delegate, &signature_out);
  if (result) {
    LOG(ERROR) << __func__
               << ": Error from RawSign(): " << GetErrorString(result);
    return result;
  }

  // Simply check scheme and parse the output from TPM.
  switch (scheme) {
    case TPM_ALG_RSAPSS:
      *signature =
          StringFrom_TPM2B_PUBLIC_KEY_RSA(signature_out.signature.rsapss.sig);
      break;
    case TPM_ALG_RSASSA:
      *signature =
          StringFrom_TPM2B_PUBLIC_KEY_RSA(signature_out.signature.rsassa.sig);
      break;
    case TPM_ALG_ECDSA:
      Serialize_TPMT_SIGNATURE(signature_out, signature);
      break;
    default:
      LOG(ERROR) << __func__ << ": Invalid signing scheme used for the key.";
      return SAPI_RC_BAD_PARAMETER;
  }

  return TPM_RC_SUCCESS;
}

TPM_RC TpmUtilityImpl::CertifyCreation(TPM_HANDLE key_handle,
                                       const std::string& creation_blob) {
  TPM2B_CREATION_DATA creation_data;
  TPM2B_DIGEST creation_hash;
  TPMT_TK_CREATION creation_ticket;
  if (!factory_.GetBlobParser()->ParseCreationBlob(
          creation_blob, &creation_data, &creation_hash, &creation_ticket)) {
    LOG(ERROR) << __func__ << ": Error parsing CreationBlob.";
    return SAPI_RC_BAD_PARAMETER;
  }
  TPM2B_DATA qualifying_data;
  qualifying_data.size = 0;
  TPMT_SIG_SCHEME in_scheme;
  in_scheme.scheme = TPM_ALG_NULL;
  TPM2B_ATTEST certify_info;
  TPMT_SIGNATURE signature;
  std::unique_ptr<AuthorizationDelegate> delegate =
      factory_.GetPasswordAuthorization("");
  TPM_RC result = factory_.GetTpm()->CertifyCreationSync(
      TPM_RH_NULL, "", key_handle, "", qualifying_data, creation_hash,
      in_scheme, creation_ticket, &certify_info, &signature, delegate.get());
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << __func__
               << ": Error certifying key creation: " << GetErrorString(result);
    return result;
  }
  return TPM_RC_SUCCESS;
}

TPM_RC TpmUtilityImpl::ChangeKeyAuthorizationData(
    TPM_HANDLE key_handle,
    const std::string& new_password,
    AuthorizationDelegate* delegate,
    std::string* key_blob) {
  TPM_RC result;
  if (delegate == nullptr) {
    result = SAPI_RC_INVALID_SESSIONS;
    LOG(ERROR) << __func__
               << ": This method needs a valid authorization delegate: "
               << GetErrorString(result);
    return result;
  }
  std::string key_name;
  std::string parent_name;
  result = GetKeyName(key_handle, &key_name);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << __func__ << ": Error getting Key name for key_handle: "
               << GetErrorString(result);
    return result;
  }
  result = GetKeyName(kStorageRootKey, &parent_name);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << __func__ << ": Error getting Key name for RSA-SRK: "
               << GetErrorString(result);
    return result;
  }
  TPM2B_AUTH new_auth = Make_TPM2B_DIGEST(new_password);
  TPM2B_PRIVATE new_private_data;
  new_private_data.size = 0;
  result = factory_.GetTpm()->ObjectChangeAuthSync(
      key_handle, key_name, kStorageRootKey, parent_name, new_auth,
      &new_private_data, delegate);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << __func__ << ": Error changing object authorization data: "
               << GetErrorString(result);
    return result;
  }
  if (key_blob) {
    TPMT_PUBLIC public_data;
    result = GetKeyPublicArea(key_handle, &public_data);
    if (result != TPM_RC_SUCCESS) {
      return result;
    }
    if (!factory_.GetBlobParser()->SerializeKeyBlob(
            Make_TPM2B_PUBLIC(public_data), new_private_data, key_blob)) {
      return SAPI_RC_BAD_TCTI_STRUCTURE;
    }
  }
  return TPM_RC_SUCCESS;
}

TPM_RC TpmUtilityImpl::ImportRSAKey(AsymmetricKeyUsage key_type,
                                    const std::string& modulus,
                                    uint32_t public_exponent,
                                    const std::string& prime_factor,
                                    const std::string& password,
                                    AuthorizationDelegate* delegate,
                                    std::string* key_blob) {
  TPMT_PUBLIC public_area = CreateDefaultPublicArea(TPM_ALG_RSA);
  public_area.parameters.rsa_detail.key_bits = modulus.size() * 8;
  public_area.parameters.rsa_detail.exponent = public_exponent;
  public_area.unique.rsa = Make_TPM2B_PUBLIC_KEY_RSA(modulus);
  public_area.object_attributes = kUserWithAuth;

  TPMT_SENSITIVE in_sensitive;
  in_sensitive.sensitive_type = TPM_ALG_RSA;
  in_sensitive.sensitive.rsa = Make_TPM2B_PRIVATE_KEY_RSA(prime_factor);

  return ImportKeyInner(key_type, public_area, in_sensitive, password, delegate,
                        key_blob);
}

TPM_RC TpmUtilityImpl::ImportECCKey(AsymmetricKeyUsage key_type,
                                    TPMI_ECC_CURVE curve_id,
                                    const std::string& public_point_x,
                                    const std::string& public_point_y,
                                    const std::string& private_value,
                                    const std::string& password,
                                    AuthorizationDelegate* delegate,
                                    std::string* key_blob) {
  TPMT_PUBLIC public_area = CreateDefaultPublicArea(TPM_ALG_ECC);
  public_area.parameters.ecc_detail.curve_id = curve_id;
  public_area.unique.ecc.x = Make_TPM2B_ECC_PARAMETER(public_point_x);
  public_area.unique.ecc.y = Make_TPM2B_ECC_PARAMETER(public_point_y);
  public_area.object_attributes = kUserWithAuth;

  TPMT_SENSITIVE in_sensitive;
  in_sensitive.sensitive_type = TPM_ALG_ECC;
  in_sensitive.sensitive.ecc = Make_TPM2B_ECC_PARAMETER(private_value);

  return ImportKeyInner(key_type, public_area, in_sensitive, password, delegate,
                        key_blob);
}

TPM_RC TpmUtilityImpl::ImportECCKeyWithPolicyDigest(
    AsymmetricKeyUsage key_type,
    TPMI_ECC_CURVE curve_id,
    const std::string& public_point_x,
    const std::string& public_point_y,
    const std::string& private_value,
    const std::string& policy_digest,
    AuthorizationDelegate* delegate,
    std::string* key_blob) {
  if (policy_digest.empty()) {
    TPM_RC result = SAPI_RC_BAD_PARAMETER;
    LOG(ERROR) << __func__ << ": This method needs a non-empty policy digest: "
               << GetErrorString(result);
    return result;
  }

  TPMT_PUBLIC public_area = CreateDefaultPublicArea(TPM_ALG_ECC);
  public_area.parameters.ecc_detail.curve_id = curve_id;
  public_area.unique.ecc.x = Make_TPM2B_ECC_PARAMETER(public_point_x);
  public_area.unique.ecc.y = Make_TPM2B_ECC_PARAMETER(public_point_y);
  // Set policy digest
  public_area.auth_policy = Make_TPM2B_DIGEST(policy_digest);
  public_area.object_attributes = kAdminWithPolicy;

  TPMT_SENSITIVE in_sensitive;
  in_sensitive.sensitive_type = TPM_ALG_ECC;
  in_sensitive.sensitive.ecc = Make_TPM2B_ECC_PARAMETER(private_value);

  return ImportKeyInner(key_type, public_area, in_sensitive, /*password=*/"",
                        delegate, key_blob);
}

TPM_RC TpmUtilityImpl::ImportKeyInner(AsymmetricKeyUsage key_type,
                                      TPMT_PUBLIC public_area,
                                      TPMT_SENSITIVE in_sensitive,
                                      const std::string& password,
                                      AuthorizationDelegate* delegate,
                                      std::string* key_blob) {
  TPM_RC result;
  if (delegate == nullptr) {
    result = SAPI_RC_INVALID_SESSIONS;
    LOG(ERROR) << __func__
               << ": This method needs a valid authorization delegate: "
               << GetErrorString(result);
    return result;
  }

  std::string parent_name;
  result = GetKeyName(kStorageRootKey, &parent_name);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << __func__ << ": Error getting Key name for SRK: "
               << GetErrorString(result);
    return result;
  }

  // Fill the rest part of public area of the key
  // Notice that the |object_attributes| field may be prefilled, so just add
  // new setting by OR, but don't overwrite it
  public_area.object_attributes |= kNoDA;
  switch (key_type) {
    case AsymmetricKeyUsage::kDecryptKey:
      public_area.object_attributes |= kDecrypt;
      break;
    case AsymmetricKeyUsage::kSignKey:
      public_area.object_attributes |= kSign;
      break;
    case AsymmetricKeyUsage::kDecryptAndSignKey:
      public_area.object_attributes |= (kSign | kDecrypt);
      break;
  }

  TPM2B_ENCRYPTED_SECRET in_sym_seed = Make_TPM2B_ENCRYPTED_SECRET("");

  TPMT_SYM_DEF_OBJECT symmetric_alg;
  symmetric_alg.algorithm = TPM_ALG_AES;
  symmetric_alg.key_bits.aes = kAesKeySize * 8;
  symmetric_alg.mode.aes = TPM_ALG_CFB;

  in_sensitive.auth_value = Make_TPM2B_DIGEST(password);
  in_sensitive.seed_value = Make_TPM2B_DIGEST("");

  TPM2B_PUBLIC public_data = Make_TPM2B_PUBLIC(public_area);

  TPM2B_DATA encryption_key;
  encryption_key.size = kAesKeySize;
  CHECK_EQ(RAND_bytes(encryption_key.buffer, encryption_key.size), 1)
      << "Error generating a cryptographically random AES Key.";
  TPM2B_PRIVATE private_data;
  result = EncryptPrivateData(in_sensitive, public_area, &private_data,
                              &encryption_key);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << __func__ << ": Error creating encrypted private struct: "
               << GetErrorString(result);
    return result;
  }

  TPM2B_PRIVATE tpm_private_data;
  tpm_private_data.size = 0;
  result = factory_.GetTpm()->ImportSync(
      kStorageRootKey, parent_name, encryption_key, public_data, private_data,
      in_sym_seed, symmetric_alg, &tpm_private_data, delegate);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << __func__
               << ": Error importing key: " << GetErrorString(result);
    return result;
  }

  if (key_blob) {
    if (!factory_.GetBlobParser()->SerializeKeyBlob(
            public_data, tpm_private_data, key_blob)) {
      return SAPI_RC_BAD_TCTI_STRUCTURE;
    }
  }
  return TPM_RC_SUCCESS;
}

TPM_RC TpmUtilityImpl::CreateRSAKeyPair(
    AsymmetricKeyUsage key_type,
    int modulus_bits,
    uint32_t public_exponent,
    const std::string& password,
    const std::string& policy_digest,
    bool use_only_policy_authorization,
    const std::vector<uint32_t>& creation_pcr_indexes,
    AuthorizationDelegate* delegate,
    std::string* key_blob,
    std::string* creation_blob) {
  TPMT_PUBLIC public_area = CreateDefaultPublicArea(TPM_ALG_RSA);
  public_area.parameters.rsa_detail.key_bits = modulus_bits;
  public_area.parameters.rsa_detail.exponent = public_exponent;

  return CreateKeyPairInner(key_type, public_area, password, policy_digest,
                            use_only_policy_authorization, creation_pcr_indexes,
                            delegate, key_blob, creation_blob);
}

TPM_RC TpmUtilityImpl::CreateECCKeyPair(
    AsymmetricKeyUsage key_type,
    TPMI_ECC_CURVE curve_id,
    const std::string& password,
    const std::string& policy_digest,
    bool use_only_policy_authorization,
    const std::vector<uint32_t>& creation_pcr_indexes,
    AuthorizationDelegate* delegate,
    std::string* key_blob,
    std::string* creation_blob) {
  TPMT_PUBLIC public_area = CreateDefaultPublicArea(TPM_ALG_ECC);
  public_area.parameters.ecc_detail.curve_id = curve_id;

  return CreateKeyPairInner(key_type, public_area, password, policy_digest,
                            use_only_policy_authorization, creation_pcr_indexes,
                            delegate, key_blob, creation_blob);
}

TPM_RC TpmUtilityImpl::CreateRestrictedECCKeyPair(
    AsymmetricKeyUsage key_type,
    TPMI_ECC_CURVE curve_id,
    const std::string& password,
    const std::string& policy_digest,
    bool use_only_policy_authorization,
    const std::vector<uint32_t>& creation_pcr_indexes,
    AuthorizationDelegate* delegate,
    std::string* key_blob,
    std::string* creation_blob) {
  TPMT_PUBLIC public_area = CreateDefaultPublicArea(TPM_ALG_ECC);
  public_area.object_attributes |= kRestricted;
  public_area.parameters.ecc_detail.curve_id = curve_id;

  return CreateKeyPairInner(key_type, public_area, password, policy_digest,
                            use_only_policy_authorization, creation_pcr_indexes,
                            delegate, key_blob, creation_blob);
}

TPM_RC TpmUtilityImpl::CreateKeyPairInner(
    AsymmetricKeyUsage key_type,
    TPMT_PUBLIC public_area,
    const std::string& password,
    const std::string& policy_digest,
    bool use_only_policy_authorization,
    const std::vector<uint32_t>& creation_pcr_indexes,
    AuthorizationDelegate* delegate,
    std::string* key_blob,
    std::string* creation_blob) {
  CHECK(key_blob);

  TPM_RC result;
  if (delegate == nullptr) {
    result = SAPI_RC_INVALID_SESSIONS;
    LOG(ERROR) << __func__
               << ": This method needs a valid authorization delegate: "
               << GetErrorString(result);
    return result;
  }

  std::string parent_name;
  result = GetKeyName(kStorageRootKey, &parent_name);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << __func__ << ": Error getting Key name for SRK: "
               << GetErrorString(result);
    return result;
  }

  // Fill the rest part of public area of the key
  // Notice that the |object_attributes| field may be prefilled, so just add
  // new setting by OR, but don't overwrite it
  public_area.object_attributes |=
      (kSensitiveDataOrigin | kUserWithAuth | kNoDA);
  switch (key_type) {
    case AsymmetricKeyUsage::kDecryptKey:
      public_area.object_attributes |= kDecrypt;
      break;
    case AsymmetricKeyUsage::kSignKey:
      public_area.object_attributes |= kSign;
      if (public_area.type == TPM_ALG_RSA &&
          !SupportsPaddingOnlySigningScheme()) {
        public_area.object_attributes |= kDecrypt;
      }
      break;
    case AsymmetricKeyUsage::kDecryptAndSignKey:
      public_area.object_attributes |= (kSign | kDecrypt);
      break;
  }
  public_area.auth_policy = Make_TPM2B_DIGEST(policy_digest);
  if (use_only_policy_authorization && !policy_digest.empty()) {
    public_area.object_attributes |= kAdminWithPolicy;
    public_area.object_attributes &= (~kUserWithAuth);
  }

  // Match the symmetric scheme of the SRK, which is the only possible parent
  // key for now.
  if (public_area.object_attributes & kRestricted) {
    public_area.parameters.asym_detail.symmetric.algorithm = TPM_ALG_AES;
    public_area.parameters.asym_detail.symmetric.key_bits.aes = 128;
    public_area.parameters.asym_detail.symmetric.mode.aes = TPM_ALG_CFB;
  }

  TPML_PCR_SELECTION creation_pcrs = {};
  if (creation_pcr_indexes.empty()) {
    creation_pcrs.count = 0;
  } else {
    creation_pcrs.count = 1;
    creation_pcrs.pcr_selections[0].hash = TPM_ALG_SHA256;
    creation_pcrs.pcr_selections[0].sizeof_select = PCR_SELECT_MIN;
    for (uint32_t creation_pcr_index : creation_pcr_indexes) {
      if (creation_pcr_index >= 8 * PCR_SELECT_MIN) {
        LOG(ERROR) << __func__
                   << ": Creation PCR index is not within the allocated bank.";
        return SAPI_RC_BAD_PARAMETER;
      }
      creation_pcrs.pcr_selections[0].pcr_select[creation_pcr_index / 8] |=
          1 << (creation_pcr_index % 8);
    }
  }

  // allow to use this key with `password`
  TPMS_SENSITIVE_CREATE sensitive;
  sensitive.user_auth = Make_TPM2B_DIGEST(password);
  sensitive.data = Make_TPM2B_SENSITIVE_DATA("");
  TPM2B_SENSITIVE_CREATE sensitive_create =
      Make_TPM2B_SENSITIVE_CREATE(sensitive);

  // use empty outside_info
  TPM2B_DATA outside_info = Make_TPM2B_DATA("");

  // returned data
  TPM2B_PUBLIC out_public;
  out_public.size = 0;
  TPM2B_PRIVATE out_private;
  out_private.size = 0;
  TPM2B_CREATION_DATA creation_data;
  TPM2B_DIGEST creation_hash;
  TPMT_TK_CREATION creation_ticket;

  result = factory_.GetTpm()->CreateSync(
      kStorageRootKey, parent_name, sensitive_create,
      Make_TPM2B_PUBLIC(public_area), outside_info, creation_pcrs, &out_private,
      &out_public, &creation_data, &creation_hash, &creation_ticket, delegate);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << __func__
               << ": Error creating key: " << GetErrorString(result);
    return result;
  }

  // serialize the output
  if (!factory_.GetBlobParser()->SerializeKeyBlob(out_public, out_private,
                                                  key_blob)) {
    return SAPI_RC_BAD_TCTI_STRUCTURE;
  }
  if (creation_blob) {
    if (!factory_.GetBlobParser()->SerializeCreationBlob(
            creation_data, creation_hash, creation_ticket, creation_blob)) {
      return SAPI_RC_BAD_TCTI_STRUCTURE;
    }
  }
  return TPM_RC_SUCCESS;
}

TPM_RC TpmUtilityImpl::LoadKey(const std::string& key_blob,
                               AuthorizationDelegate* delegate,
                               TPM_HANDLE* key_handle) {
  CHECK(key_handle);
  TPM_RC result;
  if (delegate == nullptr) {
    result = SAPI_RC_INVALID_SESSIONS;
    LOG(ERROR) << __func__
               << ": This method needs a valid authorization delegate: "
               << GetErrorString(result);
    return result;
  }
  std::string parent_name;
  result = GetKeyName(kStorageRootKey, &parent_name);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << __func__
               << ": Error getting parent key name: " << GetErrorString(result);
    return result;
  }
  TPM2B_PUBLIC in_public;
  TPM2B_PRIVATE in_private;
  if (!factory_.GetBlobParser()->ParseKeyBlob(key_blob, &in_public,
                                              &in_private)) {
    return SAPI_RC_BAD_TCTI_STRUCTURE;
  }
  TPM2B_NAME key_name;
  key_name.size = 0;
  result =
      factory_.GetTpm()->LoadSync(kStorageRootKey, parent_name, in_private,
                                  in_public, key_handle, &key_name, delegate);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << __func__ << ": Error loading key: " << GetErrorString(result);
    return result;
  }
  return TPM_RC_SUCCESS;
}

TPM_RC TpmUtilityImpl::LoadRSAPublicKey(AsymmetricKeyUsage key_type,
                                        TPM_ALG_ID scheme,
                                        TPM_ALG_ID hash_alg,
                                        const std::string& modulus,
                                        uint32_t public_exponent,
                                        AuthorizationDelegate* delegate,
                                        TPM_HANDLE* key_handle) {
  TPM_RC result;
  TPMT_PUBLIC public_area = CreateDefaultPublicArea(TPM_ALG_RSA);
  switch (key_type) {
    case AsymmetricKeyUsage::kDecryptKey:
      public_area.object_attributes |= kDecrypt;
      if (scheme == TPM_ALG_NULL || scheme == TPM_ALG_OAEP) {
        public_area.parameters.rsa_detail.scheme.scheme = TPM_ALG_OAEP;
        public_area.parameters.rsa_detail.scheme.details.oaep.hash_alg =
            hash_alg;
      } else if (scheme == TPM_ALG_RSAES) {
        public_area.parameters.rsa_detail.scheme.scheme = TPM_ALG_RSAES;
      } else {
        LOG(ERROR) << __func__ << ": Invalid encryption scheme used.";
        return SAPI_RC_BAD_PARAMETER;
      }
      break;
    case AsymmetricKeyUsage::kSignKey:
      public_area.object_attributes |= kSign;
      if (scheme == TPM_ALG_NULL || scheme == TPM_ALG_RSASSA) {
        public_area.parameters.rsa_detail.scheme.scheme = TPM_ALG_RSASSA;
        public_area.parameters.rsa_detail.scheme.details.rsassa.hash_alg =
            hash_alg;
      } else if (scheme == TPM_ALG_RSAPSS) {
        public_area.parameters.rsa_detail.scheme.scheme = TPM_ALG_RSAPSS;
        public_area.parameters.rsa_detail.scheme.details.rsapss.hash_alg =
            hash_alg;
      } else {
        LOG(ERROR) << __func__ << ": Invalid signing scheme used.";
        return SAPI_RC_BAD_PARAMETER;
      }
      break;
    case AsymmetricKeyUsage::kDecryptAndSignKey:
      public_area.object_attributes |= (kSign | kDecrypt);
      // Note: The specs require the scheme to be TPM_ALG_NULL when the key is
      // both signing and decrypting.
      if (scheme != TPM_ALG_NULL) {
        LOG(ERROR) << __func__ << ": Scheme has to be null.";
        return SAPI_RC_BAD_PARAMETER;
      }
      if (hash_alg != TPM_ALG_NULL) {
        LOG(ERROR) << __func__ << ": Hashing algorithm has to be null.";
        return SAPI_RC_BAD_PARAMETER;
      }
      break;
  }
  public_area.parameters.rsa_detail.key_bits = modulus.size() * 8;
  public_area.parameters.rsa_detail.exponent = public_exponent;
  public_area.unique.rsa = Make_TPM2B_PUBLIC_KEY_RSA(modulus);
  const TPM2B_PUBLIC public_data = Make_TPM2B_PUBLIC(public_area);
  TPM2B_SENSITIVE private_data;
  private_data.size = 0;
  const TPMI_RH_HIERARCHY hierarchy = TPM_RH_NULL;
  TPM2B_NAME name;
  result = factory_.GetTpm()->LoadExternalSync(
      private_data, public_data, hierarchy, key_handle, &name, delegate);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << __func__
               << ": Error loading external key: " << GetErrorString(result);
    return result;
  }
  return TPM_RC_SUCCESS;
}

TPM_RC TpmUtilityImpl::LoadECPublicKey(AsymmetricKeyUsage key_type,
                                       TPM_ECC_CURVE curve_id,
                                       TPM_ALG_ID scheme,
                                       TPM_ALG_ID hash_alg,
                                       const std::string& x,
                                       const std::string& y,
                                       AuthorizationDelegate* delegate,
                                       TPM_HANDLE* key_handle) {
  TPM_RC result;
  // Create public area.
  TPMT_PUBLIC public_area = CreateDefaultPublicArea(TPM_ALG_ECC);
  public_area.parameters.ecc_detail.curve_id = curve_id;
  public_area.parameters.ecc_detail.kdf.scheme = hash_alg;
  public_area.parameters.ecc_detail.scheme.scheme = scheme;
  public_area.unique.ecc.x = Make_TPM2B_ECC_PARAMETER(x);
  public_area.unique.ecc.y = Make_TPM2B_ECC_PARAMETER(y);
  const TPM2B_PUBLIC public_data = Make_TPM2B_PUBLIC(public_area);

  // Empty sensitive area.
  TPM2B_SENSITIVE private_data;
  private_data.size = 0;
  const TPMI_RH_HIERARCHY hierachy = TPM_RH_NULL;
  TPM2B_NAME name;

  // Load the key to tpm.
  result = factory_.GetTpm()->LoadExternalSync(
      private_data, public_data, hierachy, key_handle, &name, delegate);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << __func__
               << ": Error Loading external key: " << GetErrorString(result);
    return result;
  }
  return TPM_RC_SUCCESS;
}

TPM_RC TpmUtilityImpl::GetKeyName(TPM_HANDLE handle, std::string* name) {
  CHECK(name);
  TPM_RC result;
  TPMT_PUBLIC public_data;
  result = GetKeyPublicArea(handle, &public_data);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << __func__
               << ": Error fetching public info: " << GetErrorString(result);
    return result;
  }
  result = ComputeKeyName(public_data, name);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << __func__
               << ": Error computing key name: " << GetErrorString(result);
    return result;
  }
  return TPM_RC_SUCCESS;
}

TPM_RC TpmUtilityImpl::GetKeyPublicArea(TPM_HANDLE handle,
                                        TPMT_PUBLIC* public_data) {
  CHECK(public_data);
  TPM2B_NAME out_name;
  TPM2B_PUBLIC public_area;
  TPM2B_NAME qualified_name;
  std::string handle_name;  // Unused
  TPM_RC result = factory_.GetTpm()->ReadPublicSync(
      handle, handle_name, &public_area, &out_name, &qualified_name, nullptr);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << __func__
               << ": Error getting public area for object: " << handle;
    return result;
  }
  if (!public_area.size) {
    LOG(ERROR) << __func__
               << ": Error reading key public information - empty data";
    return TPM_RC_FAILURE;
  }
  *public_data = public_area.public_area;
  return TPM_RC_SUCCESS;
}

TPM_RC TpmUtilityImpl::SealData(const std::string& data_to_seal,
                                const std::string& policy_digest,
                                const std::string& auth_value,
                                bool require_admin_with_policy,
                                AuthorizationDelegate* delegate,
                                std::string* sealed_data) {
  CHECK(sealed_data);
  TPM_RC result;
  if (delegate == nullptr) {
    result = SAPI_RC_INVALID_SESSIONS;
    LOG(ERROR) << __func__
               << ": This method needs a valid authorization delegate: "
               << GetErrorString(result);
    return result;
  }
  if (require_admin_with_policy && policy_digest.empty()) {
    result = SAPI_RC_BAD_PARAMETER;
    LOG(ERROR) << __func__
               << ": This method needs a valid policy_digest when we only use "
                  "policy session to do authorization: "
               << GetErrorString(result);
    return result;
  }
  std::string parent_name;
  result = GetKeyName(kStorageRootKey, &parent_name);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << __func__ << ": Error getting Key name for RSA-SRK: "
               << GetErrorString(result);
    return result;
  }
  // We seal data to the TPM by creating a KEYEDHASH object with sign and
  // decrypt attributes disabled.
  TPMT_PUBLIC public_area = CreateDefaultPublicArea(TPM_ALG_KEYEDHASH);
  public_area.auth_policy = Make_TPM2B_DIGEST(policy_digest);
  public_area.object_attributes = kNoDA;
  if (require_admin_with_policy) {
    public_area.object_attributes |= kAdminWithPolicy;
  } else {
    public_area.object_attributes |= kUserWithAuth;
  }
  public_area.unique.keyed_hash.size = 0;
  TPML_PCR_SELECTION creation_pcrs = {};
  TPMS_SENSITIVE_CREATE sensitive;
  sensitive.user_auth = Make_TPM2B_DIGEST(auth_value);
  sensitive.data = Make_TPM2B_SENSITIVE_DATA(data_to_seal);
  TPM2B_SENSITIVE_CREATE sensitive_create =
      Make_TPM2B_SENSITIVE_CREATE(sensitive);
  TPM2B_DATA outside_info = Make_TPM2B_DATA("");
  TPM2B_PUBLIC out_public;
  out_public.size = 0;
  TPM2B_PRIVATE out_private;
  out_private.size = 0;
  TPM2B_CREATION_DATA creation_data;
  TPM2B_DIGEST creation_hash;
  TPMT_TK_CREATION creation_ticket;
  result = factory_.GetTpm()->CreateSync(
      kStorageRootKey, parent_name, sensitive_create,
      Make_TPM2B_PUBLIC(public_area), outside_info, creation_pcrs, &out_private,
      &out_public, &creation_data, &creation_hash, &creation_ticket, delegate);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << __func__
               << ": Error creating sealed object: " << GetErrorString(result);
    return result;
  }
  if (!factory_.GetBlobParser()->SerializeKeyBlob(out_public, out_private,
                                                  sealed_data)) {
    return SAPI_RC_BAD_TCTI_STRUCTURE;
  }
  return TPM_RC_SUCCESS;
}

TPM_RC TpmUtilityImpl::UnsealData(const std::string& sealed_data,
                                  AuthorizationDelegate* delegate,
                                  std::string* unsealed_data) {
  CHECK(unsealed_data);
  TPM_RC result;
  if (delegate == nullptr) {
    result = SAPI_RC_INVALID_SESSIONS;
    LOG(ERROR) << __func__
               << ": This method needs a valid authorization delegate: "
               << GetErrorString(result);
    return result;
  }
  TPM_HANDLE object_handle;
  std::unique_ptr<AuthorizationDelegate> password_delegate =
      factory_.GetPasswordAuthorization("");
  result = LoadKey(sealed_data, password_delegate.get(), &object_handle);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << __func__
               << ": Error loading sealed object: " << GetErrorString(result);
    return result;
  }
  ScopedKeyHandle sealed_object(factory_, object_handle);

  return UnsealDataWithHandle(sealed_object.get(), delegate, unsealed_data);
}

TPM_RC TpmUtilityImpl::UnsealDataWithHandle(TPM_HANDLE object_handle,
                                            AuthorizationDelegate* delegate,
                                            std::string* unsealed_data) {
  CHECK(unsealed_data);
  TPM_RC result;
  if (delegate == nullptr) {
    result = SAPI_RC_INVALID_SESSIONS;
    LOG(ERROR) << __func__
               << ": This method needs a valid authorization delegate: "
               << GetErrorString(result);
    return result;
  }

  std::string object_name;
  result = GetKeyName(object_handle, &object_name);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << __func__
               << ": Error getting object name: " << GetErrorString(result);
    return result;
  }
  TPM2B_SENSITIVE_DATA out_data;
  result = factory_.GetTpm()->UnsealSync(object_handle, object_name, &out_data,
                                         delegate);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << __func__
               << ": Error unsealing object: " << GetErrorString(result);
    return result;
  }
  *unsealed_data = StringFrom_TPM2B_SENSITIVE_DATA(out_data);
  return TPM_RC_SUCCESS;
}

TPM_RC TpmUtilityImpl::StartSession(HmacSession* session) {
  TPM_RC result = session->StartUnboundSession(true /* salted */,
                                               true /* enable_encryption */);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << __func__ << ": Error starting unbound session: "
               << GetErrorString(result);
    return result;
  }
  session->SetEntityAuthorizationValue("");
  return TPM_RC_SUCCESS;
}

TPM_RC TpmUtilityImpl::AddPcrValuesToPolicySession(
    const std::map<uint32_t, std::string>& pcr_map,
    bool use_auth_value,
    PolicySession* policy_session) {
  CHECK(policy_session);
  // the construction of `pcr_map_with_values` can be in O(n)
  std::map<uint32_t, std::string> pcr_map_with_values = pcr_map;
  for (const auto& map_pair : pcr_map) {
    uint32_t pcr_index = map_pair.first;
    const std::string& pcr_value = map_pair.second;
    if (!pcr_value.empty()) {
      continue;
    }

    std::string mutable_pcr_value;
    TPM_RC result = ReadPCR(pcr_index, &mutable_pcr_value);
    if (result != TPM_RC_SUCCESS) {
      LOG(ERROR) << __func__
                 << ": Error reading pcr_value: " << GetErrorString(result);
      return result;
    }
    pcr_map_with_values[pcr_index] = mutable_pcr_value;
  }
  if (use_auth_value) {
    TPM_RC result = policy_session->PolicyAuthValue();
    if (result != TPM_RC_SUCCESS) {
      LOG(ERROR) << __func__ << ": Error setting session to use auth_value: "
                 << GetErrorString(result);
      return result;
    }
  }
  TPM_RC result = policy_session->PolicyPCR(pcr_map_with_values);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << __func__ << ": Error restricting policy to PCR value: "
               << GetErrorString(result);
    return result;
  }
  return TPM_RC_SUCCESS;
}

TPM_RC TpmUtilityImpl::GetPolicyDigestForPcrValues(
    const std::map<uint32_t, std::string>& pcr_map,
    bool use_auth_value,
    std::string* policy_digest) {
  CHECK(policy_digest);
  std::unique_ptr<PolicySession> policy_session = factory_.GetTrialSession();
  TPM_RC result = policy_session->StartUnboundSession(false, false);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << __func__ << ": Error starting unbound trial session: "
               << GetErrorString(result);
    return result;
  }
  result = AddPcrValuesToPolicySession(pcr_map, use_auth_value,
                                       policy_session.get());
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << __func__ << ": Error getting policy pcr session: "
               << GetErrorString(result);
    return result;
  }
  result = policy_session->GetDigest(policy_digest);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << __func__
               << ": Error getting policy digest: " << GetErrorString(result);
    return result;
  }
  return TPM_RC_SUCCESS;
}

TPM_RC TpmUtilityImpl::DefineNVSpace(uint32_t index,
                                     size_t num_bytes,
                                     TPMA_NV attributes,
                                     const std::string& authorization_value,
                                     const std::string& policy_digest,
                                     AuthorizationDelegate* delegate) {
  TPM_RC result;
  if (num_bytes > MAX_NV_INDEX_SIZE) {
    result = SAPI_RC_BAD_SIZE;
    LOG(ERROR) << __func__
               << ": Cannot define non-volatile space of given size: "
               << GetErrorString(result);
    return result;
  }
  if (index > kMaxNVSpaceIndex) {
    result = SAPI_RC_BAD_PARAMETER;
    LOG(ERROR) << __func__
               << ": Cannot define non-volatile space with the given index: "
               << GetErrorString(result);
    return result;
  }
  if (delegate == nullptr) {
    result = SAPI_RC_INVALID_SESSIONS;
    LOG(ERROR) << __func__
               << ": This method needs a valid authorization delegate: "
               << GetErrorString(result);
    return result;
  }
  uint32_t nv_index = NV_INDEX_FIRST + index;
  TPMS_NV_PUBLIC public_data;
  public_data.nv_index = nv_index;
  public_data.name_alg = TPM_ALG_SHA256;
  public_data.attributes = attributes;
  public_data.auth_policy = Make_TPM2B_DIGEST(policy_digest);
  public_data.data_size = num_bytes;
  TPM2B_AUTH authorization = Make_TPM2B_DIGEST(authorization_value);
  TPM2B_NV_PUBLIC public_area = Make_TPM2B_NV_PUBLIC(public_data);
  result = factory_.GetTpm()->NV_DefineSpaceSync(
      TPM_RH_OWNER, NameFromHandle(TPM_RH_OWNER), authorization, public_area,
      delegate);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << __func__ << ": Error defining non-volatile space: "
               << GetErrorString(result);
    return result;
  }
  nvram_public_area_map_[index] = public_data;
  return TPM_RC_SUCCESS;
}

TPM_RC TpmUtilityImpl::DestroyNVSpace(uint32_t index,
                                      AuthorizationDelegate* delegate) {
  TPM_RC result;
  if (index > kMaxNVSpaceIndex) {
    result = SAPI_RC_BAD_PARAMETER;
    LOG(ERROR) << __func__
               << ": Cannot undefine non-volatile space with the given index: "
               << GetErrorString(result);
    return result;
  }
  if (delegate == nullptr) {
    result = SAPI_RC_INVALID_SESSIONS;
    LOG(ERROR) << __func__
               << ": This method needs a valid authorization delegate: "
               << GetErrorString(result);
    return result;
  }
  std::string nv_name;
  result = GetNVSpaceName(index, &nv_name);
  if (result != TPM_RC_SUCCESS) {
    return result;
  }
  uint32_t nv_index = NV_INDEX_FIRST + index;
  result = factory_.GetTpm()->NV_UndefineSpaceSync(
      TPM_RH_OWNER, NameFromHandle(TPM_RH_OWNER), nv_index, nv_name, delegate);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << __func__ << ": Error undefining non-volatile space: "
               << GetErrorString(result);
    return result;
  }
  nvram_public_area_map_.erase(index);
  return TPM_RC_SUCCESS;
}

TPM_RC TpmUtilityImpl::LockNVSpace(uint32_t index,
                                   bool lock_read,
                                   bool lock_write,
                                   bool using_owner_authorization,
                                   AuthorizationDelegate* delegate) {
  TPM_RC result;
  if (index > kMaxNVSpaceIndex) {
    result = SAPI_RC_BAD_PARAMETER;
    LOG(ERROR) << __func__
               << ": Cannot lock non-volatile space with the given index: "
               << GetErrorString(result);
    return result;
  }
  std::string nv_name;
  result = GetNVSpaceName(index, &nv_name);
  if (result != TPM_RC_SUCCESS) {
    return result;
  }
  uint32_t nv_index = NV_INDEX_FIRST + index;
  TPMI_RH_NV_AUTH auth_target = nv_index;
  std::string auth_target_name = nv_name;
  if (using_owner_authorization) {
    auth_target = TPM_RH_OWNER;
    auth_target_name = NameFromHandle(TPM_RH_OWNER);
  }
  auto it = nvram_public_area_map_.find(index);
  if (lock_read) {
    result = factory_.GetTpm()->NV_ReadLockSync(auth_target, auth_target_name,
                                                nv_index, nv_name, delegate);
    if (result != TPM_RC_SUCCESS) {
      LOG(ERROR) << __func__ << ": Error locking non-volatile space read: "
                 << GetErrorString(result);
      return result;
    }
    if (it != nvram_public_area_map_.end()) {
      it->second.attributes |= TPMA_NV_READLOCKED;
    }
  }
  if (lock_write) {
    result = factory_.GetTpm()->NV_WriteLockSync(auth_target, auth_target_name,
                                                 nv_index, nv_name, delegate);
    if (result != TPM_RC_SUCCESS) {
      LOG(ERROR) << __func__ << ": Error locking non-volatile space write: "
                 << GetErrorString(result);
      return result;
    }
    if (it != nvram_public_area_map_.end()) {
      it->second.attributes |= TPMA_NV_WRITELOCKED;
    }
  }
  return TPM_RC_SUCCESS;
}

TPM_RC TpmUtilityImpl::WriteNVSpace(uint32_t index,
                                    uint32_t offset,
                                    const std::string& nvram_data,
                                    bool using_owner_authorization,
                                    bool extend,
                                    AuthorizationDelegate* delegate) {
  TPM_RC result;
  if (index > kMaxNVSpaceIndex) {
    result = SAPI_RC_BAD_PARAMETER;
    LOG(ERROR) << __func__
               << ": Cannot write to non-volatile space with the given index: "
               << GetErrorString(result);
    return result;
  }
  std::string nv_name;
  result = GetNVSpaceName(index, &nv_name);
  if (result != TPM_RC_SUCCESS) {
    return result;
  }
  uint32_t nv_index = NV_INDEX_FIRST + index;
  TPMI_RH_NV_AUTH auth_target = nv_index;
  std::string auth_target_name = nv_name;
  if (using_owner_authorization) {
    auth_target = TPM_RH_OWNER;
    auth_target_name = NameFromHandle(TPM_RH_OWNER);
  }
  if (extend) {
    if (nvram_data.size() > MAX_NV_BUFFER_SIZE) {
      result = SAPI_RC_BAD_SIZE;
      LOG(ERROR) << __func__
                 << ": Insufficient buffer for non-volatile extend: "
                 << GetErrorString(result);
      return result;
    }
    result = factory_.GetTpm()->NV_ExtendSync(
        auth_target, auth_target_name, nv_index, nv_name,
        Make_TPM2B_MAX_NV_BUFFER(nvram_data), delegate);
  } else {
    size_t max_chunk_size;
    result = GetMaxNVChunkSize(&max_chunk_size);
    if (result) {
      LOG(ERROR) << __func__ << ": Failed to obtain max NV chunk size: "
                 << GetErrorString(result);
      return result;
    }
    for (size_t pos = 0; pos < nvram_data.size() && result == TPM_RC_SUCCESS;) {
      std::string chunk = nvram_data.substr(pos, max_chunk_size);
      result = factory_.GetTpm()->NV_WriteSync(
          auth_target, auth_target_name, nv_index, nv_name,
          Make_TPM2B_MAX_NV_BUFFER(chunk), offset + pos, delegate);
      pos += chunk.size();
    }
  }
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << __func__ << ": Error writing to non-volatile space: "
               << GetErrorString(result);
    return result;
  }
  auto it = nvram_public_area_map_.find(index);
  if (it != nvram_public_area_map_.end()) {
    it->second.attributes |= TPMA_NV_WRITTEN;
  }
  return TPM_RC_SUCCESS;
}

TPM_RC TpmUtilityImpl::IncrementNVCounter(uint32_t index,
                                          bool using_owner_authorization,
                                          AuthorizationDelegate* delegate) {
  TPM_RC result;
  std::string nv_name;
  result = GetNVSpaceName(index, &nv_name);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << __func__ << ": Could not find space at " << index << " "
               << GetErrorString(result);
    return result;
  }
  const uint32_t nv_index = NV_INDEX_FIRST + index;
  TPMI_RH_NV_AUTH auth_target = nv_index;
  std::string auth_target_name = nv_name;
  if (using_owner_authorization) {
    auth_target = TPM_RH_OWNER;
    auth_target_name = NameFromHandle(TPM_RH_OWNER);
  }
  result = factory_.GetTpm()->NV_IncrementSync(auth_target, auth_target_name,
                                               nv_index, nv_name, delegate);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << __func__ << ": Error incrementing non-volatile space: "
               << GetErrorString(result);
    return result;
  }
  auto it = nvram_public_area_map_.find(index);
  if (it != nvram_public_area_map_.end()) {
    it->second.attributes |= TPMA_NV_WRITTEN;
  }
  return TPM_RC_SUCCESS;
}

TPM_RC TpmUtilityImpl::ReadNVSpace(uint32_t index,
                                   uint32_t offset,
                                   size_t num_bytes,
                                   bool using_owner_authorization,
                                   std::string* nvram_data,
                                   AuthorizationDelegate* delegate) {
  CHECK(nvram_data);
  TPM_RC result;
  if (index > kMaxNVSpaceIndex) {
    result = SAPI_RC_BAD_PARAMETER;
    LOG(ERROR) << __func__
               << ": Cannot read from non-volatile space with the given index: "
               << GetErrorString(result);
    return result;
  }
  std::string nv_name;
  result = GetNVSpaceName(index, &nv_name);
  if (result != TPM_RC_SUCCESS) {
    return result;
  }
  uint32_t nv_index = NV_INDEX_FIRST + index;
  TPMI_RH_NV_AUTH auth_target = nv_index;
  std::string auth_target_name = nv_name;
  if (using_owner_authorization) {
    auth_target = TPM_RH_OWNER;
    auth_target_name = NameFromHandle(TPM_RH_OWNER);
  }
  size_t max_chunk_size;
  result = GetMaxNVChunkSize(&max_chunk_size);
  if (result) {
    LOG(ERROR) << __func__ << ": Failed to obtain max NV chunk size: "
               << GetErrorString(result);
    return result;
  }
  nvram_data->clear();
  for (uint32_t chunk_offset = offset; num_bytes > 0;) {
    size_t chunk_size = std::min(num_bytes, max_chunk_size);
    TPM2B_MAX_NV_BUFFER data_buffer;
    data_buffer.size = 0;
    result = factory_.GetTpm()->NV_ReadSync(
        auth_target, auth_target_name, nv_index, nv_name, chunk_size,
        chunk_offset, &data_buffer, delegate);
    if (result != TPM_RC_SUCCESS) {
      LOG(ERROR) << __func__ << ": Error reading from non-volatile space: "
                 << GetErrorString(result);
      return result;
    }
    nvram_data->append(StringFrom_TPM2B_MAX_NV_BUFFER(data_buffer));
    num_bytes -= chunk_size;
    chunk_offset += chunk_size;
  }
  return TPM_RC_SUCCESS;
}

TPM_RC TpmUtilityImpl::GetNVSpaceName(uint32_t index, std::string* name) {
  TPM_RC result;
  if (index > kMaxNVSpaceIndex) {
    result = SAPI_RC_BAD_PARAMETER;
    LOG(ERROR) << __func__
               << ": Cannot read from non-volatile space with the given index: "
               << GetErrorString(result);
    return result;
  }
  TPMS_NV_PUBLIC nv_public_data;
  result = GetNVSpacePublicArea(index, &nv_public_data);
  if (result != TPM_RC_SUCCESS) {
    return result;
  }
  result = ComputeNVSpaceName(nv_public_data, name);
  if (result != TPM_RC_SUCCESS) {
    return result;
  }
  return TPM_RC_SUCCESS;
}

TPM_RC TpmUtilityImpl::GetNVSpacePublicArea(uint32_t index,
                                            TPMS_NV_PUBLIC* public_data) {
  TPM_RC result;
  if (index > kMaxNVSpaceIndex) {
    result = SAPI_RC_BAD_PARAMETER;
    LOG(ERROR) << __func__
               << ": Cannot read from non-volatile space with the given index: "
               << GetErrorString(result);
    return result;
  }
  auto it = nvram_public_area_map_.find(index);
  if (it != nvram_public_area_map_.end()) {
    *public_data = it->second;
    return TPM_RC_SUCCESS;
  }
  TPM2B_NAME nvram_name;
  TPM2B_NV_PUBLIC public_area;
  public_area.nv_public.nv_index = 0;
  uint32_t nv_index = NV_INDEX_FIRST + index;
  result = factory_.GetTpm()->NV_ReadPublicSync(nv_index, "", &public_area,
                                                &nvram_name, nullptr);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << __func__
               << ": Error reading non-volatile space public information: "
               << GetErrorString(result);
    return result;
  }
  if (!public_area.size) {
    LOG(ERROR)
        << __func__
        << ": Error reading non-volatile space public information - empty data";
    return TPM_RC_FAILURE;
  }
  *public_data = public_area.nv_public;
  nvram_public_area_map_[index] = public_area.nv_public;
  return TPM_RC_SUCCESS;
}

TPM_RC TpmUtilityImpl::ListNVSpaces(std::vector<uint32_t>* index_list) {
  TPM_RC result;
  TPMI_YES_NO more_data = YES;
  TPMS_CAPABILITY_DATA capability_data;
  TPM_HANDLE handle_base = HR_NV_INDEX;
  while (more_data == YES) {
    result = factory_.GetTpm()->GetCapabilitySync(
        TPM_CAP_HANDLES, handle_base, MAX_CAP_HANDLES, &more_data,
        &capability_data, nullptr /*authorization_delegate*/);
    if (result != TPM_RC_SUCCESS) {
      LOG(ERROR) << __func__
                 << ": Error querying NV spaces: " << GetErrorString(result);
      return result;
    }
    if (capability_data.capability != TPM_CAP_HANDLES) {
      LOG(ERROR) << __func__ << ": Invalid capability type.";
      return SAPI_RC_MALFORMED_RESPONSE;
    }
    TPML_HANDLE& handles = capability_data.data.handles;
    for (uint32_t i = 0; i < handles.count; ++i) {
      index_list->push_back(handles.handle[i] & HR_HANDLE_MASK);
      handle_base = handles.handle[i] + 1;
    }
  }
  return TPM_RC_SUCCESS;
}

TPM_RC TpmUtilityImpl::SetDictionaryAttackParameters(
    uint32_t max_tries,
    uint32_t recovery_time,
    uint32_t lockout_recovery,
    AuthorizationDelegate* delegate) {
  return factory_.GetTpm()->DictionaryAttackParametersSync(
      TPM_RH_LOCKOUT, NameFromHandle(TPM_RH_LOCKOUT), max_tries, recovery_time,
      lockout_recovery, delegate);
}

TPM_RC TpmUtilityImpl::ResetDictionaryAttackLock(
    AuthorizationDelegate* delegate) {
  return factory_.GetTpm()->DictionaryAttackLockResetSync(
      TPM_RH_LOCKOUT, NameFromHandle(TPM_RH_LOCKOUT), delegate);
}

TPM_RC TpmUtilityImpl::GetAuthPolicyEndorsementKey(
    TPM_ALG_ID key_type,
    const std::string& auth_policy,
    AuthorizationDelegate* endorsement_delegate,
    TPM_HANDLE* key_handle,
    TPM2B_NAME* key_name) {
  if (key_type != TPM_ALG_RSA && key_type != TPM_ALG_ECC) {
    return SAPI_RC_BAD_PARAMETER;
  }

  Tpm* tpm = factory_.GetTpm();
  TPML_PCR_SELECTION creation_pcrs;
  creation_pcrs.count = 0;
  TPMS_SENSITIVE_CREATE sensitive;
  sensitive.user_auth = Make_TPM2B_DIGEST("");
  sensitive.data = Make_TPM2B_SENSITIVE_DATA("");
  TPM_HANDLE object_handle;
  TPM2B_CREATION_DATA creation_data;
  TPM2B_DIGEST creation_digest;
  TPMT_TK_CREATION creation_ticket;
  TPMT_PUBLIC public_area = CreateDefaultPublicArea(key_type);
  public_area.object_attributes = kFixedTPM | kFixedParent |
                                  kSensitiveDataOrigin | kAdminWithPolicy |
                                  kDecrypt | kNoDA;
  public_area.auth_policy = Make_TPM2B_DIGEST(auth_policy);

  // Fix the public area to match the template if we are using the default EK
  // template.
  if (auth_policy == std::string(GetEkTemplateAuthPolicy())) {
    public_area.object_attributes = kFixedTPM | kFixedParent |
                                    kSensitiveDataOrigin | kAdminWithPolicy |
                                    kRestricted | kDecrypt;
    if (key_type == TPM_ALG_RSA) {
      public_area.parameters.rsa_detail.symmetric.algorithm = TPM_ALG_AES;
      public_area.parameters.rsa_detail.symmetric.key_bits.aes = 128;
      public_area.parameters.rsa_detail.symmetric.mode.aes = TPM_ALG_CFB;
      public_area.parameters.rsa_detail.scheme.scheme = TPM_ALG_NULL;
      public_area.parameters.rsa_detail.key_bits = 2048;
      public_area.parameters.rsa_detail.exponent = 0;
      public_area.unique.rsa = Make_TPM2B_PUBLIC_KEY_RSA(std::string(256, 0));
    } else if (key_type == TPM_ALG_ECC) {
      public_area.parameters.ecc_detail.symmetric.algorithm = TPM_ALG_AES;
      public_area.parameters.ecc_detail.symmetric.key_bits.aes = 128;
      public_area.parameters.ecc_detail.symmetric.mode.aes = TPM_ALG_CFB;
      public_area.parameters.ecc_detail.scheme.scheme = TPM_ALG_NULL;
      public_area.parameters.ecc_detail.curve_id = TPM_ECC_NIST_P256;
      public_area.parameters.ecc_detail.kdf.scheme = TPM_ALG_NULL;
      public_area.unique.ecc.x = Make_TPM2B_ECC_PARAMETER(std::string(32, 0));
      public_area.unique.ecc.y = Make_TPM2B_ECC_PARAMETER(std::string(32, 0));
    }
  }

  TPM2B_PUBLIC public_data = Make_TPM2B_PUBLIC(public_area);
  TPM_RC result = tpm->CreatePrimarySync(
      TPM_RH_ENDORSEMENT, NameFromHandle(TPM_RH_ENDORSEMENT),
      Make_TPM2B_SENSITIVE_CREATE(sensitive), public_data, Make_TPM2B_DATA(""),
      creation_pcrs, &object_handle, &public_data, &creation_data,
      &creation_digest, &creation_ticket, key_name, endorsement_delegate);
  if (result) {
    LOG(ERROR) << __func__
               << ": CreatePrimarySync failed: " << GetErrorString(result);
    return result;
  }

  *key_handle = object_handle;
  return TPM_RC_SUCCESS;
}

TPM_RC TpmUtilityImpl::GetEndorsementKey(
    TPM_ALG_ID key_type,
    AuthorizationDelegate* endorsement_delegate,
    AuthorizationDelegate* owner_delegate,
    TPM_HANDLE* key_handle) {
  // The RSA EK may have already been generated and made persistent. The ECC EK
  // is always generated on demand.
  if (key_type == TPM_ALG_RSA) {
    bool exists = false;
    TPM_RC result = DoesPersistentKeyExist(kRSAEndorsementKey, &exists);
    if (result != TPM_RC_SUCCESS) {
      LOG(ERROR) << __func__ << ": Check Peristent RSA Key failed: "
                 << GetErrorString(result);
      return result;
    }
    if (exists) {
      *key_handle = kRSAEndorsementKey;
      return TPM_RC_SUCCESS;
    }
  }

  TPM_HANDLE object_handle;
  TPM2B_NAME object_name;

  TPM_RC result = GetAuthPolicyEndorsementKey(
      key_type, std::string(GetEkTemplateAuthPolicy()), endorsement_delegate,
      &object_handle, &object_name);
  if (result) {
    LOG(ERROR) << __func__
               << ": Get auth policy EK failed: " << GetErrorString(result);
    return result;
  }

  // Only make RSA key persistent.
  if (key_type == TPM_ALG_RSA) {
    ScopedKeyHandle rsa_key(factory_, object_handle);
    result = factory_.GetTpm()->EvictControlSync(
        TPM_RH_OWNER, NameFromHandle(TPM_RH_OWNER), object_handle,
        StringFrom_TPM2B_NAME(object_name), kRSAEndorsementKey, owner_delegate);
    if (result != TPM_RC_SUCCESS) {
      LOG(ERROR) << __func__
                 << ": EvictControlSync failed: " << GetErrorString(result);
      return result;
    }
    *key_handle = kRSAEndorsementKey;
    return TPM_RC_SUCCESS;
  }

  *key_handle = object_handle;
  return TPM_RC_SUCCESS;
}

TPM_RC TpmUtilityImpl::CreateCsmeSaltingKey() {
  bool exists = false;
  TPM_RC result = DoesPersistentKeyExist(kCsmeSaltingKey, &exists);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << __func__ << ": Check Peristent CSME Salting Key failed: "
               << GetErrorString(result);
    return result;
  }
  if (exists) {
    return TPM_RC_SUCCESS;
  }

  Tpm* tpm = factory_.GetTpm();
  TPML_PCR_SELECTION creation_pcrs = {};
  creation_pcrs.count = 0;
  TPMS_SENSITIVE_CREATE sensitive;
  sensitive.user_auth = Make_TPM2B_DIGEST("");
  sensitive.data = Make_TPM2B_SENSITIVE_DATA("");
  TPM_HANDLE object_handle;
  TPM2B_CREATION_DATA creation_data;
  TPM2B_DIGEST creation_digest;
  TPMT_TK_CREATION creation_ticket;
  TPM2B_NAME object_name;
  object_name.size = 0;
  TPMT_PUBLIC public_area = CreateDefaultPublicArea(TPM_ALG_ECC);
  public_area.object_attributes = kFixedTPM | kFixedParent | kDecrypt |
                                  kSensitiveDataOrigin | kUserWithAuth | kNoDA;
  TPM2B_PUBLIC tpm2b_public = Make_TPM2B_PUBLIC(public_area);

  std::unique_ptr<AuthorizationDelegate> endorsement_delegate =
      factory_.GetPasswordAuthorization("");
  result = tpm->CreatePrimarySync(
      TPM_RH_ENDORSEMENT, NameFromHandle(TPM_RH_ENDORSEMENT),
      Make_TPM2B_SENSITIVE_CREATE(sensitive), tpm2b_public, Make_TPM2B_DATA(""),
      creation_pcrs, &object_handle, &tpm2b_public, &creation_data,
      &creation_digest, &creation_ticket, &object_name,
      endorsement_delegate.get());
  if (result) {
    LOG(ERROR) << __func__
               << ": CreatePrimarySync failed: " << GetErrorString(result);
    return result;
  }

  ScopedKeyHandle key(factory_, object_handle);

  std::unique_ptr<AuthorizationDelegate> owner_delegate =
      factory_.GetPasswordAuthorization("");
  result =
      tpm->EvictControlSync(TPM_RH_OWNER, NameFromHandle(TPM_RH_OWNER),
                            object_handle, StringFrom_TPM2B_NAME(object_name),
                            kCsmeSaltingKey, owner_delegate.get());
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << __func__
               << ": EvictControlSync failed: " << GetErrorString(result);
    return result;
  }
  LOG(INFO) << __func__ << ": Created CSME Salting Key.";
  return TPM_RC_SUCCESS;
}

TPM_RC TpmUtilityImpl::CreateIdentityKey(TPM_ALG_ID key_type,
                                         AuthorizationDelegate* delegate,
                                         std::string* key_blob) {
  CHECK(key_blob);
  if (key_type != TPM_ALG_RSA && key_type != TPM_ALG_ECC) {
    return SAPI_RC_BAD_PARAMETER;
  }
  std::string parent_name;
  TPM_RC result = GetKeyName(kStorageRootKey, &parent_name);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << __func__ << ": Error getting key name for SRK: "
               << GetErrorString(result);
    return result;
  }
  TPMT_PUBLIC public_area = CreateDefaultPublicArea(key_type);
  public_area.object_attributes |=
      (kSensitiveDataOrigin | kUserWithAuth | kNoDA | kRestricted | kSign);
  if (key_type == TPM_ALG_RSA) {
    public_area.parameters.rsa_detail.scheme.scheme = TPM_ALG_RSASSA;
    public_area.parameters.rsa_detail.scheme.details.rsassa.hash_alg =
        TPM_ALG_SHA256;
  } else {
    public_area.parameters.ecc_detail.scheme.scheme = TPM_ALG_ECDSA;
    public_area.parameters.ecc_detail.scheme.details.ecdsa.hash_alg =
        TPM_ALG_SHA256;
  }
  TPML_PCR_SELECTION creation_pcrs = {};
  creation_pcrs.count = 0;
  TPMS_SENSITIVE_CREATE sensitive;
  sensitive.user_auth = Make_TPM2B_DIGEST("");
  sensitive.data = Make_TPM2B_SENSITIVE_DATA("");
  TPM2B_SENSITIVE_CREATE sensitive_create =
      Make_TPM2B_SENSITIVE_CREATE(sensitive);
  TPM2B_DATA outside_info = Make_TPM2B_DATA("");
  TPM2B_PUBLIC out_public;
  out_public.size = 0;
  TPM2B_PRIVATE out_private;
  out_private.size = 0;
  TPM2B_CREATION_DATA creation_data;
  TPM2B_DIGEST creation_hash;
  TPMT_TK_CREATION creation_ticket;
  result = factory_.GetTpm()->CreateSync(
      kStorageRootKey, parent_name, sensitive_create,
      Make_TPM2B_PUBLIC(public_area), outside_info, creation_pcrs, &out_private,
      &out_public, &creation_data, &creation_hash, &creation_ticket, delegate);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << __func__
               << ": Error creating identity key: " << GetErrorString(result);
    return result;
  }
  if (!factory_.GetBlobParser()->SerializeKeyBlob(out_public, out_private,
                                                  key_blob)) {
    return SAPI_RC_BAD_TCTI_STRUCTURE;
  }
  return TPM_RC_SUCCESS;
}

TPM_RC TpmUtilityImpl::DeclareTpmFirmwareStable() {
  if (!IsGsc()) {
    return TPM_RC_SUCCESS;
  }
  std::string response_payload;
  TPM_RC rc = GscVendorCommand(kGscSubcmdInvalidateInactiveRW, std::string(),
                               &response_payload);
  if (rc == TPM_RC_SUCCESS) {
    LOG(INFO) << "Successfully invalidated inactive GSC RW";
  } else {
    LOG(WARNING) << "Invalidating inactive GSC RW failed: 0x" << std::hex << rc;
  }
  return rc;
}

TPM_RC TpmUtilityImpl::GetPublicRSAEndorsementKeyModulus(std::string* ekm) {
  uint32_t index = kRsaEndorsementCertificateNonRealIndex;
  trunks::TPMS_NV_PUBLIC nvram_public;
  TPM_RC result = GetNVSpacePublicArea(index, &nvram_public);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error reading NV space for index " << index
               << " with error: " << GetErrorString(result);
    return result;
  }

  std::unique_ptr<AuthorizationDelegate> password_delegate(
      factory_.GetPasswordAuthorization(""));
  std::string nvram_data;
  result = ReadNVSpace(index, 0, nvram_public.data_size, false, &nvram_data,
                       password_delegate.get());
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << "Error reading NV space for index " << index
               << " with error: " << GetErrorString(result);
    return result;
  }

  // Get the X509 object.
  const unsigned char* cert_data =
      reinterpret_cast<const unsigned char*>(nvram_data.c_str());
  crypto::ScopedOpenSSL<X509, X509_free> xcert(
      d2i_X509(nullptr, &cert_data, nvram_data.size()));
  if (!xcert) {
    LOG(ERROR) << "Failed to get EK certificate from NVRAM";
    return SAPI_RC_CORRUPTED_DATA;
  }

  // Get the public key.
  crypto::ScopedEVP_PKEY pubkey(X509_get_pubkey(xcert.get()));
  if (!pubkey || EVP_PKEY_base_id(pubkey.get()) != EVP_PKEY_RSA) {
    LOG(ERROR) << "Failed to get EK public key from NVRAM";
    return SAPI_RC_CORRUPTED_DATA;
  }

  crypto::ScopedRSA rsa(EVP_PKEY_get1_RSA(pubkey.get()));
  if (!rsa) {
    LOG(ERROR) << "Failed to get RSA from NVRAM";
    return SAPI_RC_CORRUPTED_DATA;
  }

  size_t buf_len = RSA_size(rsa.get());
  if (buf_len == 0) {
    LOG(ERROR) << "Invalid buffer size";
    return SAPI_RC_CORRUPTED_DATA;
  }

  std::vector<unsigned char> key(buf_len);
  const BIGNUM* bn;
  RSA_get0_key(rsa.get(), &bn, nullptr, nullptr);
  BN_bn2bin(bn, key.data());
  ekm->assign(reinterpret_cast<const char*>(key.data()), buf_len);

  return TPM_RC_SUCCESS;
}

TPM_RC TpmUtilityImpl::ManageCCDPwd(bool allow_pwd) {
  if (!IsGsc()) {
    return TPM_RC_SUCCESS;
  }
  std::string command_payload(1, allow_pwd ? 1 : 0);
  std::string response_payload;
  return GscVendorCommand(kGscSubcmdManageCCDPwd, command_payload,
                          &response_payload);
}

TPM_RC TpmUtilityImpl::SetKnownOwnerPassword(
    const std::string& known_owner_password) {
  std::unique_ptr<TpmState> tpm_state(factory_.GetTpmState());
  TPM_RC result = tpm_state->Initialize();
  if (result) {
    LOG(ERROR) << __func__ << ": Failed to initialize TPM state: "
               << GetErrorString(result);
    return result;
  }
  std::unique_ptr<AuthorizationDelegate> delegate =
      factory_.GetPasswordAuthorization("");
  if (tpm_state->IsOwnerPasswordSet()) {
    LOG(INFO) << __func__ << ": Owner password is already set. "
              << "This is normal if ownership is already taken.";
    return TPM_RC_SUCCESS;
  }
  result = SetHierarchyAuthorization(TPM_RH_OWNER, known_owner_password,
                                     delegate.get());
  if (result) {
    LOG(ERROR) << __func__ << ": Error setting storage hierarchy authorization "
               << "to its default value: " << GetErrorString(result);
    return result;
  }
  return TPM_RC_SUCCESS;
}

TPM_RC TpmUtilityImpl::CreateStorageRootKeys(
    const std::string& owner_password) {
  Tpm* tpm = factory_.GetTpm();
  TPML_PCR_SELECTION creation_pcrs;
  creation_pcrs.count = 0;
  TPMS_SENSITIVE_CREATE sensitive;
  sensitive.user_auth = Make_TPM2B_DIGEST("");
  sensitive.data = Make_TPM2B_SENSITIVE_DATA("");
  TPM_HANDLE object_handle;
  TPM2B_CREATION_DATA creation_data;
  TPM2B_DIGEST creation_digest;
  TPMT_TK_CREATION creation_ticket;
  TPM2B_NAME object_name;
  object_name.size = 0;
  std::unique_ptr<AuthorizationDelegate> delegate =
      factory_.GetPasswordAuthorization(owner_password);

  bool exists = false;
  TPM_RC result = DoesPersistentKeyExist(kStorageRootKey, &exists);
  if (result) {
    return result;
  }
  if (exists) {
    LOG(INFO) << __func__ << ": Skip SRK generation because it already exists.";
    return TPM_RC_SUCCESS;
  }

  TPM_ALG_ID key_type = factory_.GetTpmCache()->GetBestSupportedKeyType();
  if (key_type != TPM_ALG_ECC && key_type != TPM_ALG_RSA) {
    LOG(ERROR) << __func__ << ": Failed to get the best supported key type.";
    return TPM_RC_FAILURE;
  }

  TPMT_PUBLIC public_area = CreateDefaultPublicArea(key_type);

  // SRK specific settings
  public_area.object_attributes |=
      (kSensitiveDataOrigin | kUserWithAuth | kNoDA | kRestricted | kDecrypt);
  public_area.parameters.asym_detail.symmetric.algorithm = TPM_ALG_AES;
  public_area.parameters.asym_detail.symmetric.key_bits.aes = 128;
  public_area.parameters.asym_detail.symmetric.mode.aes = TPM_ALG_CFB;

  TPM2B_PUBLIC tpm2b_public_area = Make_TPM2B_PUBLIC(public_area);
  result = tpm->CreatePrimarySync(
      TPM_RH_OWNER, NameFromHandle(TPM_RH_OWNER),
      Make_TPM2B_SENSITIVE_CREATE(sensitive), tpm2b_public_area,
      Make_TPM2B_DATA(""), creation_pcrs, &object_handle, &tpm2b_public_area,
      &creation_data, &creation_digest, &creation_ticket, &object_name,
      delegate.get());
  if (result) {
    LOG(ERROR) << __func__ << ": Failed to create TPM primary sync: "
               << GetErrorString(result);
    return result;
  }
  ScopedKeyHandle tpm_key(factory_, object_handle);

  const std::string key_type_str = key_type == TPM_ALG_ECC ? "ECC" : "RSA";
  LOG(INFO) << __func__ << ": Created " << key_type_str << " SRK.";

  // This will make the key persistent.
  result = tpm->EvictControlSync(
      TPM_RH_OWNER, NameFromHandle(TPM_RH_OWNER), object_handle,
      StringFrom_TPM2B_NAME(object_name), kStorageRootKey, delegate.get());
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << __func__
               << ": Failed to evict control sync: " << GetErrorString(result);
    return result;
  }
  return TPM_RC_SUCCESS;
}

TPM_RC TpmUtilityImpl::CreateSaltingKey(TPM_HANDLE* key, TPM2B_NAME* key_name) {
  std::string parent_name;
  TPM_RC result = GetKeyName(kStorageRootKey, &parent_name);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << __func__ << ": Error getting Key name for SRK: "
               << GetErrorString(result);
    return result;
  }

  TPM_ALG_ID key_type = factory_.GetTpmCache()->GetBestSupportedKeyType();
  if (key_type != TPM_ALG_ECC && key_type != TPM_ALG_RSA) {
    LOG(ERROR) << __func__ << ": Failed to get the best supported key type.";
    return TPM_RC_FAILURE;
  }

  TPMT_PUBLIC public_area = CreateDefaultPublicArea(key_type);
  public_area.object_attributes |=
      kSensitiveDataOrigin | kUserWithAuth | kNoDA | kDecrypt;
  TPML_PCR_SELECTION creation_pcrs;
  creation_pcrs.count = 0;
  TPMS_SENSITIVE_CREATE sensitive;
  sensitive.user_auth = Make_TPM2B_DIGEST("");
  sensitive.data = Make_TPM2B_SENSITIVE_DATA("");
  TPM2B_SENSITIVE_CREATE sensitive_create =
      Make_TPM2B_SENSITIVE_CREATE(sensitive);
  TPM2B_DATA outside_info = Make_TPM2B_DATA("");

  TPM2B_PRIVATE out_private;
  out_private.size = 0;
  TPM2B_PUBLIC out_public;
  out_public.size = 0;
  TPM2B_CREATION_DATA creation_data;
  TPM2B_DIGEST creation_hash;
  TPMT_TK_CREATION creation_ticket;
  // TODO(usanghi): MITM vulnerability with SaltingKey creation.
  // Currently we cannot verify the key returned by the TPM.
  // crbug.com/442331
  std::unique_ptr<AuthorizationDelegate> delegate =
      factory_.GetPasswordAuthorization("");
  result = factory_.GetTpm()->CreateSync(
      kStorageRootKey, parent_name, sensitive_create,
      Make_TPM2B_PUBLIC(public_area), outside_info, creation_pcrs, &out_private,
      &out_public, &creation_data, &creation_hash, &creation_ticket,
      delegate.get());
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << __func__
               << ": Error creating salting key: " << GetErrorString(result);
    return result;
  }

  const std::string key_type_str = key_type == TPM_ALG_ECC ? "ECC" : "RSA";
  LOG(INFO) << __func__ << ": Created " << key_type_str << " salting key.";

  key_name->size = 0;
  TPM_HANDLE key_handle;
  result = factory_.GetTpm()->LoadSync(kStorageRootKey, parent_name,
                                       out_private, out_public, &key_handle,
                                       key_name, delegate.get());
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << __func__
               << ": Error loading salting key: " << GetErrorString(result);
    return result;
  }

  *key = key_handle;
  return TPM_RC_SUCCESS;
}

TPM_RC TpmUtilityImpl::CreatePersistentSaltingKey(
    const std::string& owner_password) {
  bool exists = false;
  TPM_RC result = DoesPersistentKeyExist(kSaltingKey, &exists);
  if (result != TPM_RC_SUCCESS) {
    return result;
  }
  if (exists) {
    LOG(INFO) << __func__ << ": Salting key already exists.";
    return TPM_RC_SUCCESS;
  }

  TPM2B_NAME key_name;
  TPM_HANDLE key_handle;
  result = CreateSaltingKey(&key_handle, &key_name);
  if (result != TPM_RC_SUCCESS) {
    return result;
  }

  ScopedKeyHandle key(factory_, key_handle);

  std::unique_ptr<AuthorizationDelegate> owner_delegate =
      factory_.GetPasswordAuthorization(owner_password);
  result = factory_.GetTpm()->EvictControlSync(
      TPM_RH_OWNER, NameFromHandle(TPM_RH_OWNER), key.get(),
      StringFrom_TPM2B_NAME(key_name), kSaltingKey, owner_delegate.get());
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << __func__
               << ": Failed to evict control sync: " << GetErrorString(result);
    return result;
  }
  return TPM_RC_SUCCESS;
}

TPMT_PUBLIC TpmUtilityImpl::CreateDefaultPublicArea(TPM_ALG_ID key_alg) {
  TPMT_PUBLIC public_area;
  memset(&public_area, 0, sizeof(public_area));
  public_area.type = key_alg;
  public_area.name_alg = TPM_ALG_SHA256;
  public_area.auth_policy = Make_TPM2B_DIGEST("");
  public_area.object_attributes = kFixedTPM | kFixedParent;
  if (key_alg == TPM_ALG_RSA) {
    public_area.parameters.rsa_detail.scheme.scheme = TPM_ALG_NULL;
    public_area.parameters.rsa_detail.symmetric.algorithm = TPM_ALG_NULL;
    public_area.parameters.rsa_detail.key_bits = 2048;
    public_area.parameters.rsa_detail.exponent = 0;
    public_area.unique.rsa = Make_TPM2B_PUBLIC_KEY_RSA("");
  } else if (key_alg == TPM_ALG_ECC) {
    public_area.parameters.ecc_detail.scheme.scheme = TPM_ALG_NULL;
    public_area.parameters.ecc_detail.symmetric.algorithm = TPM_ALG_NULL;
    public_area.parameters.ecc_detail.curve_id = TPM_ECC_NIST_P256;
    public_area.parameters.ecc_detail.kdf.scheme = TPM_ALG_NULL;
    public_area.unique.ecc.x = Make_TPM2B_ECC_PARAMETER("");
    public_area.unique.ecc.y = Make_TPM2B_ECC_PARAMETER("");
  } else if (key_alg == TPM_ALG_KEYEDHASH) {
    public_area.parameters.keyed_hash_detail.scheme.scheme = TPM_ALG_NULL;
  } else {
    LOG(WARNING) << __func__
                 << ": Unrecognized key_type. Not filling parameters.";
  }
  return public_area;
}

TPM_RC TpmUtilityImpl::SetHierarchyAuthorization(
    TPMI_RH_HIERARCHY_AUTH hierarchy,
    const std::string& password,
    AuthorizationDelegate* authorization) {
  if (password.size() > kMaxPasswordLength) {
    LOG(ERROR) << __func__ << ": Hierarchy passwords can be at most "
               << kMaxPasswordLength
               << " bytes. Current password length is: " << password.size();
    return SAPI_RC_BAD_SIZE;
  }
  return factory_.GetTpm()->HierarchyChangeAuthSync(
      hierarchy, NameFromHandle(hierarchy), Make_TPM2B_DIGEST(password),
      authorization);
}

TPM_RC TpmUtilityImpl::DisablePlatformHierarchy(
    AuthorizationDelegate* authorization) {
  return factory_.GetTpm()->HierarchyControlSync(
      TPM_RH_PLATFORM,  // The authorizing entity.
      NameFromHandle(TPM_RH_PLATFORM),
      TPM_RH_PLATFORM,  // The target hierarchy.
      0,                // Disable.
      authorization);
}

TPM_RC TpmUtilityImpl::ComputeKeyName(const TPMT_PUBLIC& public_area,
                                      std::string* object_name) {
  CHECK(object_name);
  if (public_area.type == TPM_ALG_ERROR) {
    // We do not compute a name for empty public area.
    object_name->clear();
    return TPM_RC_SUCCESS;
  }
  std::string serialized_public_area;
  TPM_RC result = Serialize_TPMT_PUBLIC(public_area, &serialized_public_area);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << __func__
               << ": Error serializing public area: " << GetErrorString(result);
    return result;
  }
  std::string serialized_name_alg;
  result = Serialize_TPM_ALG_ID(TPM_ALG_SHA256, &serialized_name_alg);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << __func__
               << ": Error serializing public area: " << GetErrorString(result);
    return result;
  }
  object_name->assign(serialized_name_alg +
                      crypto::SHA256HashString(serialized_public_area));
  return TPM_RC_SUCCESS;
}

TPM_RC TpmUtilityImpl::ComputeNVSpaceName(const TPMS_NV_PUBLIC& nv_public_area,
                                          std::string* nv_name) {
  CHECK(nv_name);
  if ((nv_public_area.nv_index & NV_INDEX_FIRST) == 0) {
    // If the index is not an nvram index, we do not compute a name.
    nv_name->clear();
    return TPM_RC_SUCCESS;
  }
  std::string serialized_public_area;
  TPM_RC result =
      Serialize_TPMS_NV_PUBLIC(nv_public_area, &serialized_public_area);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << __func__
               << ": Error serializing public area: " << GetErrorString(result);
    return result;
  }
  std::string serialized_name_alg;
  result = Serialize_TPM_ALG_ID(TPM_ALG_SHA256, &serialized_name_alg);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << __func__
               << ": Error serializing public area: " << GetErrorString(result);
    return result;
  }
  nv_name->assign(serialized_name_alg +
                  crypto::SHA256HashString(serialized_public_area));
  return TPM_RC_SUCCESS;
}

TPM_RC TpmUtilityImpl::EncryptPrivateData(const TPMT_SENSITIVE& sensitive_area,
                                          const TPMT_PUBLIC& public_area,
                                          TPM2B_PRIVATE* encrypted_private_data,
                                          TPM2B_DATA* encryption_key) {
  TPM2B_SENSITIVE sensitive_data = Make_TPM2B_SENSITIVE(sensitive_area);
  std::string serialized_sensitive_data;
  TPM_RC result =
      Serialize_TPM2B_SENSITIVE(sensitive_data, &serialized_sensitive_data);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << __func__ << ": Error serializing sensitive data: "
               << GetErrorString(result);
    return result;
  }
  std::string object_name;
  result = ComputeKeyName(public_area, &object_name);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << __func__
               << ": Error computing object name: " << GetErrorString(result);
    return result;
  }
  TPM2B_DIGEST inner_integrity = Make_TPM2B_DIGEST(
      crypto::SHA256HashString(serialized_sensitive_data + object_name));
  std::string serialized_inner_integrity;
  result = Serialize_TPM2B_DIGEST(inner_integrity, &serialized_inner_integrity);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << __func__ << ": Error serializing inner integrity: "
               << GetErrorString(result);
    return result;
  }
  std::string unencrypted_private_data =
      serialized_inner_integrity + serialized_sensitive_data;
  AES_KEY key;
  AES_set_encrypt_key(encryption_key->buffer, kAesKeySize * 8, &key);
  std::string private_data_string(unencrypted_private_data.size(), 0);
  int iv_in = 0;
  unsigned char iv[MAX_AES_BLOCK_SIZE_BYTES] = {0};
  AES_cfb128_encrypt(
      reinterpret_cast<const unsigned char*>(unencrypted_private_data.data()),
      reinterpret_cast<unsigned char*>(std::data(private_data_string)),
      unencrypted_private_data.size(), &key, iv, &iv_in, AES_ENCRYPT);
  *encrypted_private_data = Make_TPM2B_PRIVATE(private_data_string);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << __func__
               << ": Error making private area: " << GetErrorString(result);
    return result;
  }
  return TPM_RC_SUCCESS;
}

TPM_RC TpmUtilityImpl::DoesPersistentKeyExist(TPMI_DH_PERSISTENT key_handle,
                                              bool* exists) {
  TPM_RC result;
  TPMI_YES_NO more_data = YES;
  TPMS_CAPABILITY_DATA capability_data;
  result = factory_.GetTpm()->GetCapabilitySync(
      TPM_CAP_HANDLES, key_handle, 1 /*property_count*/, &more_data,
      &capability_data, nullptr /*authorization_delegate*/);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << __func__
               << ": Error querying handles: " << GetErrorString(result);
    return result;
  }
  TPML_HANDLE& handles = capability_data.data.handles;
  *exists = (handles.count == 1 && handles.handle[0] == key_handle);
  return TPM_RC_SUCCESS;
}

TPM_RC TpmUtilityImpl::GetAlertsData(TpmAlertsData* alerts) {
  memset(alerts, 0, sizeof(TpmAlertsData));

  if (!IsGsc()) {
    alerts->chip_family = kFamilyUndefined;
    return TPM_RC_SUCCESS;
  }
  std::string out;
  TPM_RC rc = GscVendorCommand(kGscSubcmdGetAlertsData, std::string(), &out);
  if (rc != TPM_RC_SUCCESS) {
    LOG(WARNING) << "Unable to read alerts data: 0x" << std::hex << rc;
    return rc;
  }

  if (out.size() < 2 * sizeof(uint16_t)) {
    // 2 * sizeof represents TpmAlertsData first 2 required fields
    LOG(WARNING) << "TPM AlertsData response is too short";
    return TPM_RC_FAILURE;
  }

  const TpmAlertsData* received_alerts =
      reinterpret_cast<const TpmAlertsData*>(out.data());

  // convert byte-order from one specified by TPM specification to host order
  alerts->chip_family = base::NetToHost16(received_alerts->chip_family);
  if (alerts->chip_family != kFamilyH1) {
    LOG(WARNING) << "TPM AlertsData unsupported TPM family identifier "
                 << alerts->chip_family;

    // return kFamilyUndefined to tell CrOS to stop querying alerts data
    alerts->chip_family = kFamilyUndefined;
    return TPM_RC_SUCCESS;
  }

  alerts->alerts_num = base::NetToHost16(received_alerts->alerts_num);
  if (alerts->alerts_num > kAlertsMaxSize) {
    LOG(WARNING) << "TPM AlertsData response is too long";
    return TPM_RC_FAILURE;
  }

  size_t expected_size =
      2 * sizeof(uint16_t) + alerts->alerts_num * sizeof(uint16_t);
  if (out.size() != expected_size) {
    LOG(WARNING) << "TPM AlertsData response size does not match alerts_num "
                 << out.size() << " vs " << expected_size;
    return TPM_RC_FAILURE;
  }

  for (int i = 0; i < alerts->alerts_num; i++) {
    alerts->counters[i] = base::NetToHost16(received_alerts->counters[i]);
  }

  return TPM_RC_SUCCESS;
}

TPM_RC TpmUtilityImpl::PinWeaverIsSupported(uint8_t request_version,
                                            uint8_t* protocol_version) {
  return PinWeaverCommand(
      __func__,
      [request_version](std::string* in) -> TPM_RC {
        return Serialize_pw_ping_t(request_version, in);
      },
      [protocol_version](const std::string& out) -> TPM_RC {
        return Parse_pw_pong_t(out, protocol_version);
      });
}

TPM_RC TpmUtilityImpl::PinWeaverResetTree(uint8_t protocol_version,
                                          uint8_t bits_per_level,
                                          uint8_t height,
                                          uint32_t* result_code,
                                          std::string* root_hash) {
  return PinWeaverCommand(
      __func__,
      [protocol_version, bits_per_level, height](std::string* in) -> TPM_RC {
        return Serialize_pw_reset_tree_t(protocol_version, bits_per_level,
                                         height, in);
      },
      [result_code, root_hash](const std::string& out) -> TPM_RC {
        return Parse_pw_short_message(out, result_code, root_hash);
      });
}

TPM_RC TpmUtilityImpl::PinWeaverInsertLeaf(
    uint8_t protocol_version,
    uint64_t label,
    const std::string& h_aux,
    const brillo::SecureBlob& le_secret,
    const brillo::SecureBlob& he_secret,
    const brillo::SecureBlob& reset_secret,
    const std::map<uint32_t, uint32_t>& delay_schedule,
    const ValidPcrCriteria& valid_pcr_criteria,
    std::optional<uint32_t> expiration_delay,
    uint32_t* result_code,
    std::string* root_hash,
    std::string* cred_metadata,
    std::string* mac) {
  return PinWeaverCommand(
      __func__,
      [protocol_version, label, h_aux, le_secret, he_secret, reset_secret,
       delay_schedule, valid_pcr_criteria,
       expiration_delay](std::string* in) -> TPM_RC {
        return Serialize_pw_insert_leaf_t(
            protocol_version, label, h_aux, le_secret, he_secret, reset_secret,
            delay_schedule, valid_pcr_criteria, expiration_delay,
            kPwLeafTypeNormal, std::nullopt, in);
      },
      [result_code, root_hash, cred_metadata,
       mac](const std::string& out) -> TPM_RC {
        return Parse_pw_insert_leaf_t(out, result_code, root_hash,
                                      cred_metadata, mac);
      });
}

TPM_RC TpmUtilityImpl::PinWeaverRemoveLeaf(uint8_t protocol_version,
                                           uint64_t label,
                                           const std::string& h_aux,
                                           const std::string& mac,
                                           uint32_t* result_code,
                                           std::string* root_hash) {
  return PinWeaverCommand(
      __func__,
      [protocol_version, label, h_aux, mac](std::string* in) -> TPM_RC {
        return Serialize_pw_remove_leaf_t(protocol_version, label, h_aux, mac,
                                          in);
      },
      [result_code, root_hash](const std::string& out) -> TPM_RC {
        return Parse_pw_short_message(out, result_code, root_hash);
      });
}

TPM_RC TpmUtilityImpl::PinWeaverTryAuth(uint8_t protocol_version,
                                        const brillo::SecureBlob& le_secret,
                                        const std::string& h_aux,
                                        const std::string& cred_metadata,
                                        uint32_t* result_code,
                                        std::string* root_hash,
                                        uint32_t* seconds_to_wait,
                                        brillo::SecureBlob* he_secret,
                                        brillo::SecureBlob* reset_secret,
                                        std::string* cred_metadata_out,
                                        std::string* mac_out) {
  return PinWeaverCommand(
      __func__,
      [protocol_version, le_secret, h_aux,
       cred_metadata](std::string* in) -> TPM_RC {
        return Serialize_pw_try_auth_t(protocol_version, le_secret, h_aux,
                                       cred_metadata, in);
      },
      [result_code, root_hash, seconds_to_wait, he_secret, reset_secret,
       cred_metadata_out, mac_out](const std::string& out) -> TPM_RC {
        return Parse_pw_try_auth_t(out, result_code, root_hash, seconds_to_wait,
                                   he_secret, reset_secret, cred_metadata_out,
                                   mac_out);
      });
}

TPM_RC TpmUtilityImpl::PinWeaverResetAuth(
    uint8_t protocol_version,
    const brillo::SecureBlob& reset_secret,
    bool strong_reset,
    const std::string& h_aux,
    const std::string& cred_metadata,
    uint32_t* result_code,
    std::string* root_hash,
    std::string* cred_metadata_out,
    std::string* mac_out) {
  return PinWeaverCommand(
      __func__,
      [protocol_version, reset_secret, strong_reset, h_aux,
       cred_metadata](std::string* in) -> TPM_RC {
        return Serialize_pw_reset_auth_t(protocol_version, reset_secret,
                                         strong_reset, h_aux, cred_metadata,
                                         in);
      },
      [result_code, root_hash, cred_metadata_out,
       mac_out](const std::string& out) -> TPM_RC {
        return Parse_pw_reset_auth_t(out, result_code, root_hash,
                                     cred_metadata_out, mac_out);
      });
}

TPM_RC TpmUtilityImpl::PinWeaverGetLog(
    uint8_t protocol_version,
    const std::string& root,
    uint32_t* result_code,
    std::string* root_hash,
    std::vector<trunks::PinWeaverLogEntry>* log) {
  return PinWeaverCommand(
      __func__,
      [protocol_version, root](std::string* in) -> TPM_RC {
        return Serialize_pw_get_log_t(protocol_version, root, in);
      },
      [result_code, root_hash, log](const std::string& out) -> TPM_RC {
        return Parse_pw_get_log_t(out, result_code, root_hash, log);
      });
}

TPM_RC TpmUtilityImpl::PinWeaverLogReplay(uint8_t protocol_version,
                                          const std::string& log_root,
                                          const std::string& h_aux,
                                          const std::string& cred_metadata,
                                          uint32_t* result_code,
                                          std::string* root_hash,
                                          std::string* cred_metadata_out,
                                          std::string* mac_out) {
  return PinWeaverCommand(
      __func__,
      [protocol_version, log_root, h_aux,
       cred_metadata](std::string* in) -> TPM_RC {
        return Serialize_pw_log_replay_t(protocol_version, log_root, h_aux,
                                         cred_metadata, in);
      },
      [result_code, root_hash, cred_metadata_out,
       mac_out](const std::string& out) -> TPM_RC {
        return Parse_pw_log_replay_t(out, result_code, root_hash,
                                     cred_metadata_out, mac_out);
      });
}

TPM_RC TpmUtilityImpl::PinWeaverSysInfo(uint8_t protocol_version,
                                        uint32_t* result_code,
                                        std::string* root_hash,
                                        uint32_t* boot_count,
                                        uint64_t* seconds_since_boot) {
  return PinWeaverCommand(
      __func__,
      [protocol_version](std::string* in) -> TPM_RC {
        return Serialize_pw_sys_info_t(protocol_version, in);
      },
      [result_code, root_hash, boot_count,
       seconds_since_boot](const std::string& out) -> TPM_RC {
        return Parse_pw_sys_info_t(out, result_code, root_hash, boot_count,
                                   seconds_since_boot);
      });
}

TPM_RC TpmUtilityImpl::PinWeaverGenerateBiometricsAuthPk(
    uint8_t protocol_version,
    uint8_t auth_channel,
    const PinWeaverEccPoint& client_public_key,
    uint32_t* result_code,
    std::string* root_hash,
    PinWeaverEccPoint* server_public_key) {
  return PinWeaverCommand(
      __func__,
      [protocol_version, auth_channel,
       client_public_key](std::string* in) -> TPM_RC {
        return Serialize_pw_generate_ba_pk_t(protocol_version, auth_channel,
                                             client_public_key, in);
      },
      [result_code, root_hash,
       server_public_key](const std::string& out) -> TPM_RC {
        return Parse_pw_generate_ba_pk_t(out, result_code, root_hash,
                                         server_public_key);
      });
}

TPM_RC TpmUtilityImpl::PinWeaverCreateBiometricsAuthRateLimiter(
    uint8_t protocol_version,
    uint8_t auth_channel,
    uint64_t label,
    const std::string& h_aux,
    const brillo::SecureBlob& reset_secret,
    const std::map<uint32_t, uint32_t>& delay_schedule,
    const ValidPcrCriteria& valid_pcr_criteria,
    std::optional<uint32_t> expiration_delay,
    uint32_t* result_code,
    std::string* root_hash,
    std::string* cred_metadata,
    std::string* mac) {
  return PinWeaverCommand(
      __func__,
      [protocol_version, auth_channel, label, h_aux, reset_secret,
       delay_schedule, valid_pcr_criteria,
       expiration_delay](std::string* in) -> TPM_RC {
        brillo::SecureBlob zeroes(kPwSecretSize, 0);
        return Serialize_pw_insert_leaf_t(
            protocol_version, label, h_aux, zeroes, zeroes, reset_secret,
            delay_schedule, valid_pcr_criteria, expiration_delay,
            kPwLeafTypeBiometrics, auth_channel, in);
      },
      [result_code, root_hash, cred_metadata,
       mac](const std::string& out) -> TPM_RC {
        return Parse_pw_insert_leaf_t(out, result_code, root_hash,
                                      cred_metadata, mac);
      });
}

TPM_RC TpmUtilityImpl::PinWeaverStartBiometricsAuth(
    uint8_t protocol_version,
    uint8_t auth_channel,
    const brillo::Blob& client_nonce,
    const std::string& h_aux,
    const std::string& cred_metadata,
    uint32_t* result_code,
    std::string* root_hash,
    brillo::Blob* server_nonce,
    brillo::Blob* encrypted_high_entropy_secret,
    brillo::Blob* iv,
    std::string* cred_metadata_out,
    std::string* mac_out) {
  return PinWeaverCommand(
      __func__,
      [protocol_version, auth_channel, client_nonce, h_aux,
       cred_metadata](std::string* in) -> TPM_RC {
        return Serialize_pw_start_bio_auth_t(protocol_version, auth_channel,
                                             client_nonce, h_aux, cred_metadata,
                                             in);
      },
      [result_code, root_hash, server_nonce, encrypted_high_entropy_secret, iv,
       cred_metadata_out, mac_out](const std::string& out) -> TPM_RC {
        return Parse_pw_start_bio_auth_t(
            out, result_code, root_hash, server_nonce,
            encrypted_high_entropy_secret, iv, cred_metadata_out, mac_out);
      });
}

TPM_RC TpmUtilityImpl::PinWeaverBlockGenerateBiometricsAuthPk(
    uint8_t protocol_version, uint32_t* result_code, std::string* root_hash) {
  return PinWeaverCommand(
      __func__,
      [protocol_version](std::string* in) -> TPM_RC {
        return Serialize_pw_block_generate_ba_pk_t(protocol_version, in);
      },
      [result_code, root_hash](const std::string& out) -> TPM_RC {
        return Parse_pw_short_message(out, result_code, root_hash);
      });
}

TPM_RC TpmUtilityImpl::U2fGenerate(
    uint8_t version,
    const brillo::Blob& app_id,
    const brillo::SecureBlob& user_secret,
    bool consume,
    bool up_required,
    const std::optional<brillo::Blob>& auth_time_secret_hash,
    brillo::Blob* public_key,
    brillo::Blob* key_handle) {
  return U2fCommand(
      __func__, kGscSubcmdU2fGenerate,
      [version, app_id, user_secret, consume, up_required,
       auth_time_secret_hash](std::string* in) -> TPM_RC {
        return Serialize_u2f_generate_t(version, app_id, user_secret, consume,
                                        up_required, auth_time_secret_hash, in);
      },
      [version, public_key, key_handle](const std::string& out) -> TPM_RC {
        return Parse_u2f_generate_t(out, version, public_key, key_handle);
      });
}

TPM_RC TpmUtilityImpl::U2fSign(
    uint8_t version,
    const brillo::Blob& app_id,
    const brillo::SecureBlob& user_secret,
    const std::optional<brillo::SecureBlob>& auth_time_secret,
    const std::optional<brillo::Blob>& hash_to_sign,
    bool check_only,
    bool consume,
    bool up_required,
    const brillo::Blob& key_handle,
    brillo::Blob* sig_r,
    brillo::Blob* sig_s) {
  return U2fCommand(
      __func__, kGscSubcmdU2fSign,
      [version, app_id, user_secret, auth_time_secret, hash_to_sign, check_only,
       consume, up_required, key_handle](std::string* in) -> TPM_RC {
        return Serialize_u2f_sign_t(version, app_id, user_secret,
                                    auth_time_secret, hash_to_sign, check_only,
                                    consume, up_required, key_handle, in);
      },
      [check_only, sig_r, sig_s](const std::string& out) -> TPM_RC {
        if (check_only) {
          return TPM_RC_SUCCESS;
        }
        return Parse_u2f_sign_t(out, sig_r, sig_s);
      });
}

TPM_RC TpmUtilityImpl::U2fAttest(const brillo::SecureBlob& user_secret,
                                 uint8_t format,
                                 const brillo::Blob& data,
                                 brillo::Blob* sig_r,
                                 brillo::Blob* sig_s) {
  return U2fCommand(
      __func__, kGscSubcmdU2fAttest,
      [user_secret, format, data](std::string* in) -> TPM_RC {
        return Serialize_u2f_attest_t(user_secret, format, data, in);
      },
      [sig_r, sig_s](const std::string& out) -> TPM_RC {
        return Parse_u2f_sign_t(out, sig_r, sig_s);
      });
}

void TpmUtilityImpl::CacheVendorId() {
  if (vendor_id_.has_value()) {
    return;
  }
  std::unique_ptr<TpmState> tpm_state(factory_.GetTpmState());
  TPM_RC result = tpm_state->Initialize();
  if (result) {
    LOG(ERROR) << __func__ << ": TpmState initialization failed: "
               << GetErrorString(result);
    return;
  }
  uint32_t vendor_id;
  if (!tpm_state->GetTpmProperty(TPM_PT_MANUFACTURER, &vendor_id)) {
    LOG(WARNING) << __func__ << ": Error getting TPM_PT_MANUFACTURER property";
    return;
  }
  VLOG(1) << __func__ << ": TPM_PT_MANUFACTURER = 0x" << std::hex << vendor_id;
  vendor_id_ = vendor_id;
}

bool TpmUtilityImpl::IsGsc() {
  CacheVendorId();
  return vendor_id_.has_value() && *vendor_id_ == kVendorIdGsc;
}

bool TpmUtilityImpl::IsSimulator() {
  CacheVendorId();
  return vendor_id_.has_value() && *vendor_id_ == kVendorIdSimulator;
}

std::string TpmUtilityImpl::SendCommandAndWait(const std::string& command) {
  return factory_.GetTpm()->get_transceiver()->SendCommandAndWait(command);
}

TPM_RC TpmUtilityImpl::SerializeCommand_GscVendor(
    uint16_t subcommand,
    const std::string& command_payload,
    std::string* serialized_command) {
  VLOG(3) << __func__;

  UINT32 command_size = 12 + command_payload.size();
  Serialize_TPMI_ST_COMMAND_TAG(TPM_ST_NO_SESSIONS, serialized_command);
  Serialize_UINT32(command_size, serialized_command);
  Serialize_TPM_CC(kGscVendorCC, serialized_command);
  Serialize_UINT16(subcommand, serialized_command);
  serialized_command->append(command_payload);
  VLOG(2) << "Command: "
          << base::HexEncode(serialized_command->data(),
                             serialized_command->size());

  // We didn't check the return statuses of Serialize_Xxx routines above, which
  // in practice always succeed. Let's at least check the resulting command
  // size to make sure all fields were indeed serialized in.
  if (serialized_command->size() != command_size) {
    LOG(ERROR) << "Bad GSC vendor command size: expected = " << command_size
               << ", actual = " << serialized_command->size();
    return TPM_RC_INSUFFICIENT;
  }
  return TPM_RC_SUCCESS;
}

TPM_RC TpmUtilityImpl::ParseResponse_GscVendor(const std::string& response,
                                               std::string* response_payload) {
  VLOG(3) << __func__;
  VLOG(2) << "Response: " << base::HexEncode(response.data(), response.size());
  response_payload->assign(response);

  TPM_ST tag;
  TPM_RC rc = Parse_TPM_ST(response_payload, &tag, nullptr);
  if (rc != TPM_RC_SUCCESS) {
    return rc;
  }
  if (tag != TPM_ST_NO_SESSIONS) {
    LOG(ERROR) << "Bad GSC vendor response tag: 0x" << std::hex << tag;
    return TPM_RC_AUTH_CONTEXT;
  }

  UINT32 response_size;
  rc = Parse_UINT32(response_payload, &response_size, nullptr);
  if (rc != TPM_RC_SUCCESS) {
    return rc;
  }
  if (response_size != response.size()) {
    LOG(ERROR) << "Bad GSC vendor response size: expected = " << response_size
               << ", actual = " << response.size();
    return TPM_RC_SIZE;
  }

  TPM_RC response_code;
  rc = Parse_TPM_RC(response_payload, &response_code, nullptr);
  if (rc != TPM_RC_SUCCESS) {
    return rc;
  }

  UINT16 subcommand_code;
  rc = Parse_UINT16(response_payload, &subcommand_code, nullptr);
  if (rc != TPM_RC_SUCCESS) {
    return rc;
  }

  return response_code;
}

TPM_RC TpmUtilityImpl::GscVendorCommand(uint16_t subcommand,
                                        const std::string& command_payload,
                                        std::string* response_payload) {
  VLOG(1) << __func__ << "(subcommand: " << subcommand << ")";
  std::string command;
  TPM_RC rc = SerializeCommand_GscVendor(subcommand, command_payload, &command);
  if (rc != TPM_RC_SUCCESS) {
    return rc;
  }
  std::string response = SendCommandAndWait(command);
  rc = ParseResponse_GscVendor(response, response_payload);
  return rc;
}

template <typename S, typename P>
TPM_RC TpmUtilityImpl::PinWeaverCommand(const std::string& tag,
                                        S serialize,
                                        P parse) {
  std::string in;
  TPM_RC rc = serialize(&in);
  if (rc) {
    LOG(ERROR) << tag << ": Serialize failed: 0x" << std::hex << rc
               << GetErrorString(rc) << std::dec;
    return rc;
  }

  std::string out;
  CacheVendorId();
  const VendorVariant vendor_variant = ToVendorVariant(vendor_id_);
  switch (vendor_variant) {
    case VendorVariant::kGsc:
    case VendorVariant::kSimulator:
      rc = GscVendorCommand(kGscSubcmdPinWeaver, in, &out);
      break;
    case VendorVariant::kOther:
      rc = PinWeaverCsmeCommand(in, &out);
      break;
    default:
      LOG(WARNING) << "Pinweaver not supported with vendor variant: "
                   << static_cast<int>(vendor_variant);
      rc = TPM_RC_FAILURE;
  }

  if (rc != TPM_RC_SUCCESS) {
    LOG(WARNING) << tag << ": command failed: 0x" << std::hex << rc << " "
                 << GetErrorString(rc);
  } else {
    rc = parse(out);
  }
  return rc;
}

// Should copy the logic of ec/common/base32.c
static const unsigned char crc5_table1[] = {0x00, 0x0E, 0x1C, 0x12, 0x11, 0x1F,
                                            0x0D, 0x03, 0x0B, 0x05, 0x17, 0x19,
                                            0x1A, 0x14, 0x06, 0x08};

static const unsigned char crc5_table0[] = {0x00, 0x16, 0x05, 0x13, 0x0A, 0x1C,
                                            0x0F, 0x19, 0x14, 0x02, 0x11, 0x07,
                                            0x1E, 0x08, 0x1B, 0x0D};

uint8_t crc5_sym(uint8_t sym, uint8_t previous_crc) {
  uint8_t tmp = sym ^ previous_crc;
  return crc5_table1[tmp & 0x0F] ^ crc5_table0[(tmp >> 4) & 0x0F];
}

// This should be exactly the same as platform/ec/common/base32.c

// A-Z0-9 with I,O,0,1 removed
// const char base32_map[33] = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

// Decodes a base32 symbol.
// Returns the symbol value or -1 if error.
static int decode_sym(int sym) {
  if (sym >= 'A' && sym <= 'H') {
    return sym - 'A';
  }
  if (sym >= 'J' && sym <= 'N') {
    return sym - 'J' + 8;
  }
  if (sym >= 'P' && sym <= 'Z') {
    return sym - 'P' + 13;
  }
  if (sym >= '2' && sym <= '9') {
    return sym - '2' + 24;
  }
  return -1;
}

int base32_decode(uint8_t* dest,
                  int destlen_bits,
                  const char* src,
                  int crc_after_every) {
  int crc = 0, crc_count = 0;
  int out_bits = 0;

  for (; *src; src++) {
    int sym, sbits, dbits, b;

    if (isspace(*src) || *src == '-')
      continue;

    sym = decode_sym(*src);
    if (sym < 0)
      return -1; /* Bad input symbol */

    /* Check CRC if needed */
    if (crc_after_every) {
      if (crc_count == crc_after_every) {
        if (crc != sym)
          return -1;
        crc_count = crc = 0;
        continue;
      } else {
        crc = crc5_sym(sym, crc);
        crc_count++;
      }
    }

    /*
     * Stop if we're out of space. Have to do this after checking
     * the CRC, or we might not check the last CRC.
     */
    if (out_bits >= destlen_bits)
      break;

    /* See how many bits we get to use from this symbol */
    sbits = std::min(5, destlen_bits - out_bits);
    if (sbits < 5)
      sym >>= (5 - sbits);

    /* Fill up the rest of the current byte */
    dbits = 8 - (out_bits & 7);
    b = std::min(dbits, sbits);
    if (dbits == 8)
      dest[out_bits / 8] = 0; /* Starting a new byte */
    dest[out_bits / 8] |= (sym << (dbits - b)) >> (sbits - b);
    out_bits += b;
    sbits -= b;

    /* Start the next byte if there's space */
    if (sbits > 0) {
      dest[out_bits / 8] = sym << (8 - sbits);
      out_bits += sbits;
    }
  }

  /* If we have CRCs, should have a full group */
  if (crc_after_every && crc_count)
    return -1;

  return out_bits;
}

TPM_RC TpmUtilityImpl::GetRsuDeviceIdInternal(std::string* device_id) {
  if (!IsGsc()) {
    return TPM_RC_FAILURE;
  }
  struct __packed rma_challenge {
    uint8_t version_key_id;
    uint8_t device_pub_key[32];
    uint8_t board_id[4];
    uint8_t device_id[8];
  } c;
  uint8_t* cptr = reinterpret_cast<uint8_t*>(&c);

  std::string res;
  TPM_RC result = GscVendorCommand(kGscGetRmaChallenge, std::string(), &res);
  if (result != TPM_RC_SUCCESS) {
    return result;
  }
  if (base32_decode(cptr, 8 * sizeof(c), res.data(), 9) != 8 * sizeof(c)) {
    return TPM_RC_FAILURE;
  }
  *device_id = crypto::SHA256HashString(
      std::string(reinterpret_cast<const char*>(c.device_id),
                  std::size(c.device_id)) +
      kRsuSalt);
  return result;
}

TPM_RC TpmUtilityImpl::GetRsuDeviceId(std::string* device_id) {
  TPM_RC result = TPM_RC_SUCCESS;
  if (cached_rsu_device_id_.empty())
    result = GetRsuDeviceIdInternal(&cached_rsu_device_id_);
  *device_id = cached_rsu_device_id_;
  return result;
}

TPM_RC TpmUtilityImpl::GetRoVerificationStatus(ap_ro_status* status) {
  if (!IsGsc()) {
    *status = AP_RO_NOT_RUN;
    return TPM_RC_SUCCESS;
  }
  std::string res;
  TPM_RC result = GscVendorCommand(kGscSubcmdGetRoStatus, std::string(), &res);
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << __func__ << ": GscVendorCommand failed";
    return result;
  }
  if (res.size() < 1) {
    LOG(ERROR) << __func__ << ": empty response";
    return TPM_RC_FAILURE;
  }
  *status = static_cast<ap_ro_status>(res[0]);
  return TPM_RC_SUCCESS;
}

TPM_RC TpmUtilityImpl::PinWeaverCsmeCommand(const std::string& in,
                                            std::string* out) {
  csme::MeiClientFactory mei_client_factory;
  std::unique_ptr<csme::PinWeaverCoreClient> client =
      csme::PinWeaverCoreClient::Create(&mei_client_factory);
  if (!client->PinWeaverCommand(in, out)) {
    LOG(ERROR) << __func__ << ": Failed to call pinweaver-csme.";
    return TPM_RC_FAILURE;
  }
  return TPM_RC_SUCCESS;
}

TpmUtilityImpl::PinWeaverBackendType
TpmUtilityImpl::GetPinwWeaverBackendType() {
  if (pinweaver_backend_type_ != PinWeaverBackendType::kUnknown) {
    return pinweaver_backend_type_;
  }
  uint8_t protocol_version;
  if (PinWeaverIsSupported(0, &protocol_version) != TPM_RC_SUCCESS) {
    pinweaver_backend_type_ = PinWeaverBackendType::kNotSupported;
  } else {
    pinweaver_backend_type_ = (IsGsc() || IsSimulator())
                                  ? PinWeaverBackendType::kGsc
                                  : PinWeaverBackendType::kCsme;
  }
  return pinweaver_backend_type_;
}

TPM_RC TpmUtilityImpl::GetMaxNVChunkSize(size_t* size) {
  CHECK(size);
  if (!max_nv_chunk_size_) {
    std::unique_ptr<TpmState> tpm_state(factory_.GetTpmState());
    TPM_RC result = tpm_state->Initialize();
    if (result) {
      LOG(ERROR) << __func__ << ": Failed to initialize TPM state: "
                 << GetErrorString(result);
      return result;
    }
    max_nv_chunk_size_ =
        std::min((size_t)tpm_state->GetMaxNVSize(), (size_t)MAX_NV_BUFFER_SIZE);
  }
  *size = max_nv_chunk_size_;
  return TPM_RC_SUCCESS;
}

TPM_RC TpmUtilityImpl::GetTi50Stats(uint32_t* fs_init_time,
                                    uint32_t* fs_size,
                                    uint32_t* aprov_time,
                                    uint32_t* aprov_status) {
  CHECK(fs_init_time);
  CHECK(fs_size);
  CHECK(aprov_time);
  CHECK(aprov_status);
  std::string res;
  TPM_RC result = GscVendorCommand(kTi50GetMetrics, std::string(), &res);
  if (result != TPM_RC_SUCCESS)
    return result;

  result = Parse_UINT32(&res, fs_init_time, nullptr);
  if (result != TPM_RC_SUCCESS)
    return result;

  result = Parse_UINT32(&res, fs_size, nullptr);
  if (result != TPM_RC_SUCCESS)
    return result;

  result = Parse_UINT32(&res, aprov_time, nullptr);
  if (result != TPM_RC_SUCCESS)
    return result;

  result = Parse_UINT32(&res, aprov_status, nullptr);
  return result;
}
}  // namespace trunks
