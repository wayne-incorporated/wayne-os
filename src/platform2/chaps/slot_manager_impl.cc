// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chaps/slot_manager_impl.h"

#include <string.h>

#include <iterator>
#include <limits>
#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <base/check.h>
#include <base/check_op.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/functional/bind.h>
#include <base/functional/callback_helpers.h>
#include <base/logging.h>
#include <brillo/message_loops/base_message_loop.h>
#include <brillo/secure_blob.h>
#include <libhwsec/frontend/chaps/frontend.h>
#include <libhwsec-foundation/status/status_chain_macros.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include "chaps/chaps_metrics.h"
#include "chaps/chaps_utility.h"
#include "chaps/isolate.h"
#include "chaps/session.h"
#include "chaps/slot_policy_default.h"
#include "chaps/slot_policy_shared_slot.h"
#include "pkcs11/cryptoki.h"

using base::FilePath;
using brillo::SecureBlob;
using hwsec::TPMError;
using std::map;
using std::shared_ptr;
using std::string;
using std::vector;

namespace chaps {

namespace {

// I18N Note: The descriptive strings are needed for PKCS #11 compliance but
// they should not appear on any UI.
constexpr base::TimeDelta kTokenInitBlockSystemShutdownFallbackTimeout =
    base::Seconds(10);
constexpr CK_VERSION kDefaultVersion = {1, 0};
constexpr char kManufacturerID[] = "Chromium OS";
constexpr CK_ULONG kMaxPinLen = 127;
constexpr CK_ULONG kMinPinLen = 6;
constexpr char kSlotDescription[] = "TPM Slot";
constexpr char kSystemTokenAuthData[] = "000000";
constexpr char kSystemTokenLabel[] = "System TPM Token";
constexpr char kTokenLabel[] = "User-Specific TPM Token";
constexpr char kTokenModel[] = "";
constexpr char kTokenSerialNumber[] = "Not Available";
constexpr int kUserKeySize = 32;
constexpr int kAuthDataHashVersion = 1;
constexpr char kKeyPurposeEncrypt[] = "encrypt";
constexpr char kKeyPurposeMac[] = "mac";
constexpr char kAuthKeyMacInput[] = "arbitrary";
constexpr char kTokenReinitializedFlagFilePath[] =
    "/var/lib/chaps/debug_token_reinitialized";

constexpr CK_FLAGS kCommonECParameters =
    CKF_EC_F_P | CKF_EC_F_2M | CKF_EC_NAMEDCURVE | CKF_EC_ECPARAMETERS |
    CKF_EC_UNCOMPRESS;

typedef std::pair<CK_MECHANISM_TYPE, CK_MECHANISM_INFO> MechanismInfoPair;

constexpr MechanismInfoPair kDefaultMechanismInfo[] = {
    {CKM_RSA_PKCS_KEY_PAIR_GEN, {512, 2048, CKF_GENERATE_KEY_PAIR | CKF_HW}},
    {CKM_RSA_PKCS,
     {512, 2048, CKF_HW | CKF_ENCRYPT | CKF_DECRYPT | CKF_SIGN | CKF_VERIFY}},
    {CKM_MD5_RSA_PKCS, {512, 2048, CKF_HW | CKF_SIGN | CKF_VERIFY}},
    {CKM_SHA1_RSA_PKCS, {512, 2048, CKF_HW | CKF_SIGN | CKF_VERIFY}},
    {CKM_SHA256_RSA_PKCS, {512, 2048, CKF_HW | CKF_SIGN | CKF_VERIFY}},
    {CKM_SHA384_RSA_PKCS, {512, 2048, CKF_HW | CKF_SIGN | CKF_VERIFY}},
    {CKM_SHA512_RSA_PKCS, {512, 2048, CKF_HW | CKF_SIGN | CKF_VERIFY}},

    {CKM_MD5, {0, 0, CKF_DIGEST}},
    {CKM_SHA_1, {0, 0, CKF_DIGEST}},
    {CKM_SHA256, {0, 0, CKF_DIGEST}},
    {CKM_SHA384, {0, 0, CKF_DIGEST}},
    {CKM_SHA512, {0, 0, CKF_DIGEST}},

    {CKM_GENERIC_SECRET_KEY_GEN, {8, 1024, CKF_GENERATE}},

    {CKM_MD5_HMAC, {0, 0, CKF_SIGN | CKF_VERIFY}},
    {CKM_SHA_1_HMAC, {0, 0, CKF_SIGN | CKF_VERIFY}},
    {CKM_SHA256_HMAC, {0, 0, CKF_SIGN | CKF_VERIFY}},
    {CKM_SHA512_HMAC, {0, 0, CKF_SIGN | CKF_VERIFY}},
    {CKM_SHA384_HMAC, {0, 0, CKF_SIGN | CKF_VERIFY}},

    {CKM_DES_KEY_GEN, {0, 0, CKF_GENERATE}},
    {CKM_DES_ECB, {0, 0, CKF_ENCRYPT | CKF_DECRYPT}},
    {CKM_DES_CBC, {0, 0, CKF_ENCRYPT | CKF_DECRYPT}},
    {CKM_DES_CBC_PAD, {0, 0, CKF_ENCRYPT | CKF_DECRYPT}},

    {CKM_DES3_KEY_GEN, {0, 0, CKF_GENERATE}},
    {CKM_DES3_ECB, {0, 0, CKF_ENCRYPT | CKF_DECRYPT}},
    {CKM_DES3_CBC, {0, 0, CKF_ENCRYPT | CKF_DECRYPT}},
    {CKM_DES3_CBC_PAD, {0, 0, CKF_ENCRYPT | CKF_DECRYPT}},

    {CKM_AES_KEY_GEN, {16, 32, CKF_GENERATE}},
    {CKM_AES_ECB, {16, 32, CKF_ENCRYPT | CKF_DECRYPT}},
    {CKM_AES_CBC, {16, 32, CKF_ENCRYPT | CKF_DECRYPT}},
    {CKM_AES_CBC_PAD, {16, 32, CKF_ENCRYPT | CKF_DECRYPT}},
};

constexpr MechanismInfoPair kTPM2OnlyMechanismInfo[] = {
    // RSA PSS is TPM2 only.
    {CKM_RSA_PKCS_PSS, {512, 2048, CKF_HW | CKF_SIGN | CKF_VERIFY}},
    {CKM_SHA1_RSA_PKCS_PSS, {512, 2048, CKF_HW | CKF_SIGN | CKF_VERIFY}},
    {CKM_SHA256_RSA_PKCS_PSS, {512, 2048, CKF_HW | CKF_SIGN | CKF_VERIFY}},
    {CKM_SHA384_RSA_PKCS_PSS, {512, 2048, CKF_HW | CKF_SIGN | CKF_VERIFY}},
    {CKM_SHA512_RSA_PKCS_PSS, {512, 2048, CKF_HW | CKF_SIGN | CKF_VERIFY}},

    // Elliptic Curve related mechanisms are TPM2 only.
    {CKM_EC_KEY_PAIR_GEN,
     {256, 256, CKF_GENERATE_KEY_PAIR | CKF_HW | kCommonECParameters}},
    {CKM_ECDSA,
     {256, 256, CKF_HW | CKF_SIGN | CKF_VERIFY | kCommonECParameters}},
    {CKM_ECDSA_SHA1,
     {256, 256, CKF_HW | CKF_SIGN | CKF_VERIFY | kCommonECParameters}},
    {CKM_ECDSA_SHA256,
     {256, 256, CKF_HW | CKF_SIGN | CKF_VERIFY | kCommonECParameters}},
    {CKM_ECDSA_SHA384,
     {256, 256, CKF_HW | CKF_SIGN | CKF_VERIFY | kCommonECParameters}},
    {CKM_ECDSA_SHA512,
     {256, 256, CKF_HW | CKF_SIGN | CKF_VERIFY | kCommonECParameters}},
};

// The TPM_SPEC_FAMILY of TPM2.0.
// ASCII "2.0" with null terminator.
constexpr uint32_t kTpm2Family = 0x322E3000;

// Computes an authorization data hash as it is stored in the database.
string HashAuthData(const SecureBlob& auth_data) {
  string version(1, kAuthDataHashVersion);
  SecureBlob hash = Sha512(auth_data);
  string hash_byte(1, static_cast<const char>(hash[0]));
  return version + hash_byte;
}

// Checks authorization data by comparing against a hash stored in the token
// database. Args:
//   auth_data_hash - A hash of the authorization data to be verified.
//   saved_auth_data_hash - The hash currently stored in the database.
// Returns:
//   False if both hash values are valid and they do not match.
bool CheckAuthDataValid(const string& auth_data_hash,
                        const string& saved_auth_data_hash) {
  CHECK_EQ(auth_data_hash.length(), 2u);
  if (saved_auth_data_hash.length() != 2 ||
      saved_auth_data_hash[0] != kAuthDataHashVersion)
    return true;
  return (auth_data_hash[1] == saved_auth_data_hash[1]);
}

// TODO(https://crbug.com/844537): Remove when the root cause of disappearing
// system token certificates is found.
// Creates a persistent flag file containing the path of the token that has been
// reinitialized. The purpose is to know if this has happened even if syslog is
// not available at the time when token reinitialization is triggered (e.g.
// because the machine is shutting down). The file will be read by
// |LogTokenReinitializedFromFlagFile|.
void CreateTokenReinitializedFlagFile(const FilePath& token_path) {
  const FilePath flag_file_path(kTokenReinitializedFlagFilePath);
  const std::string& token_path_value = token_path.value();
  base::WriteFile(flag_file_path, token_path_value.c_str(),
                  static_cast<int>(token_path_value.length()));
}

// TODO(https://crbug.com/844537): Remove when the root cause of disappearing
// system token certificates is found.
// Reads the flag file written by |CreateTokenReinitizliedFlagFile| if it exists
// and logs a message if it indicates that a token has been reinitialized.
void LogTokenReinitializedFromFlagFile() {
  const FilePath flag_file_path(kTokenReinitializedFlagFilePath);
  if (!base::PathExists(flag_file_path)) {
    return;
  }

  std::string reinitialized_token_path;
  if (!base::ReadFileToStringWithMaxSize(flag_file_path,
                                         &reinitialized_token_path, 4096)) {
    PLOG(ERROR) << "Could not read flag file " << flag_file_path.value();
    return;
  }
  base::File::Info flag_file_info;
  if (!base::GetFileInfo(flag_file_path, &flag_file_info)) {
    PLOG(ERROR) << "Could not get info for flag file "
                << flag_file_path.value();
    return;
  }
  if (!base::DeleteFile(flag_file_path)) {
    PLOG(ERROR) << "Could not delete flag file " << flag_file_path.value();
  }
  LOG(WARNING) << "Flag file with timestamp " << flag_file_info.last_modified
               << " indicated that token " << reinitialized_token_path
               << " has been reinitialized.";
}

}  // namespace

SlotManagerImpl::SlotManagerImpl(ChapsFactory* factory,
                                 const hwsec::ChapsFrontend* hwsec,
                                 bool auto_load_system_token,
                                 SystemShutdownBlocker* system_shutdown_blocker,
                                 ChapsMetrics* chaps_metrics)
    : factory_(factory),
      last_handle_(0),
      hwsec_(hwsec),
      auto_load_system_token_(auto_load_system_token),
      is_initialized_(false),
      hwsec_enabled_(std::nullopt),
      hwsec_ready_(false),
      system_shutdown_blocker_(system_shutdown_blocker),
      chaps_metrics_(chaps_metrics) {
  CHECK(factory_);
  CHECK(hwsec_);
  CHECK(chaps_metrics_);

  // Populate mechanism info for mechanisms supported by all possible HWSec chip
  // family.
  mechanism_info_.insert(std::begin(kDefaultMechanismInfo),
                         std::end(kDefaultMechanismInfo));

  hwsec::StatusOr<uint32_t> family = hwsec_->GetFamily();
  if (family.ok()) {
    if (family.value() == kTpm2Family) {
      // Populate mechanism info for mechanisms supported by TPM2.0 only.
      mechanism_info_.insert(std::begin(kTPM2OnlyMechanismInfo),
                             std::end(kTPM2OnlyMechanismInfo));
    }
  } else {
    LOG(WARNING) << "Failed to get the hwsec chip family: " << family.status();
  }

  // Add default isolate.
  AddIsolate(IsolateCredentialManager::GetDefaultIsolateCredential());

  // By default we'll start with two slots.  This allows for one 'system' slot
  // which always has a token available, and one 'user' slot which will have no
  // token until a login event is received.
  AddSlots(2);
}

SlotManagerImpl::~SlotManagerImpl() {}

bool SlotManagerImpl::HwsecIsEnabled() {
  if (hwsec_enabled_.has_value()) {
    return hwsec_enabled_.value();
  }

  ASSIGN_OR_RETURN(hwsec_enabled_, hwsec_->IsEnabled(),
                   _.WithStatus<TPMError>("Failed to get hwsec enabled status")
                       .LogError()
                       .As(false));

  return hwsec_enabled_.value();
}

bool SlotManagerImpl::HwsecIsReady() {
  if (hwsec_ready_) {
    return true;
  }

  ASSIGN_OR_RETURN(hwsec_ready_, hwsec_->IsReady(),
                   _.WithStatus<TPMError>("Failed to get hwsec ready status")
                       .LogError()
                       .As(false));

  return hwsec_ready_;
}

bool SlotManagerImpl::Init() {
  LogTokenReinitializedFromFlagFile();

  // If the SRK is ready we expect the rest of the init work to succeed.
  bool tpm_available = HwsecIsEnabled();
  bool expect_success = tpm_available && HwsecIsReady();

  chaps_metrics_->ReportTPMAvailabilityStatus(
      tpm_available ? TPMAvailabilityStatus::kTPMAvailable
                    : TPMAvailabilityStatus::kTPMUnavailable);

  if (!InitStage2() && expect_success) {
    return false;
  }

  return true;
}

bool SlotManagerImpl::InitStage2() {
  if (is_initialized_)
    return true;

  if (HwsecIsEnabled()) {
    if (!HwsecIsReady()) {
      LOG(ERROR) << "InitStage2 failed because HWSec is not ready";
      return false;
    }
    // Mix in some random bytes from the secure element to the openssl prng.
    ASSIGN_OR_RETURN(brillo::Blob data, hwsec_->GetRandomBlob(128),
                     _.LogError().As(false));
    RAND_seed(data.data(), data.size());
  }

  if (auto_load_system_token_) {
    if (base::DirectoryExists(FilePath(kSystemTokenPath))) {
      // Setup the system token.
      int system_slot_id = 0;
      if (!LoadTokenInternal(
              IsolateCredentialManager::GetDefaultIsolateCredential(),
              FilePath(kSystemTokenPath), SecureBlob(kSystemTokenAuthData),
              kSystemTokenLabel, &system_slot_id)) {
        LOG(ERROR) << "Failed to load the system token.";
        return false;
      }
    } else {
      LOG(WARNING) << "System token not loaded because " << kSystemTokenPath
                   << " does not exist.";
    }
  }
  is_initialized_ = true;
  return true;
}

int SlotManagerImpl::GetSlotCount() {
  InitStage2();
  return slot_list_.size();
}

bool SlotManagerImpl::IsTokenAccessible(const SecureBlob& isolate_credential,
                                        int slot_id) const {
  map<SecureBlob, Isolate>::const_iterator isolate_iter =
      isolate_map_.find(isolate_credential);
  if (isolate_iter == isolate_map_.end()) {
    return false;
  }
  const Isolate& isolate = isolate_iter->second;
  return isolate.slot_ids.find(slot_id) != isolate.slot_ids.end();
}

bool SlotManagerImpl::IsTokenPresent(const SecureBlob& isolate_credential,
                                     int slot_id) const {
  CHECK(IsTokenAccessible(isolate_credential, slot_id));
  return IsTokenPresent(slot_id);
}

void SlotManagerImpl::GetSlotInfo(const SecureBlob& isolate_credential,
                                  int slot_id,
                                  CK_SLOT_INFO* slot_info) const {
  CHECK(slot_info);
  CHECK_LT(static_cast<size_t>(slot_id), slot_list_.size());
  CHECK(IsTokenAccessible(isolate_credential, slot_id));

  *slot_info = slot_list_[slot_id].slot_info;
}

void SlotManagerImpl::GetTokenInfo(const SecureBlob& isolate_credential,
                                   int slot_id,
                                   CK_TOKEN_INFO* token_info) const {
  CHECK(token_info);
  CHECK_LT(static_cast<size_t>(slot_id), slot_list_.size());
  CHECK(IsTokenAccessible(isolate_credential, slot_id));
  CHECK(IsTokenPresent(slot_id));

  *token_info = slot_list_[slot_id].token_info;
}

const MechanismMap* SlotManagerImpl::GetMechanismInfo(
    const SecureBlob& isolate_credential, int slot_id) const {
  CHECK_LT(static_cast<size_t>(slot_id), slot_list_.size());
  CHECK(IsTokenAccessible(isolate_credential, slot_id));
  CHECK(IsTokenPresent(slot_id));

  return &mechanism_info_;
}

int SlotManagerImpl::OpenSession(const SecureBlob& isolate_credential,
                                 int slot_id,
                                 bool is_read_only) {
  CHECK_LT(static_cast<size_t>(slot_id), slot_list_.size());
  CHECK(IsTokenAccessible(isolate_credential, slot_id));
  CHECK(IsTokenPresent(slot_id));

  shared_ptr<Session> session(factory_->CreateSession(
      slot_id, slot_list_[slot_id].token_object_pool.get(),
      HwsecIsEnabled() ? hwsec_ : nullptr, this, is_read_only));
  CHECK(session.get());
  int session_id = CreateHandle();
  slot_list_[slot_id].sessions[session_id] = session;
  session_slot_map_[session_id] = slot_id;
  return session_id;
}

bool SlotManagerImpl::CloseSession(const SecureBlob& isolate_credential,
                                   int session_id) {
  Session* session = NULL;
  if (!GetSession(isolate_credential, session_id, &session))
    return false;
  CHECK(session);
  int slot_id = session_slot_map_[session_id];
  CHECK_LT(static_cast<size_t>(slot_id), slot_list_.size());
  CHECK(IsTokenAccessible(isolate_credential, slot_id));
  session_slot_map_.erase(session_id);
  slot_list_[slot_id].sessions.erase(session_id);
  return true;
}

void SlotManagerImpl::CloseAllSessions(const SecureBlob& isolate_credential,
                                       int slot_id) {
  CHECK_LT(static_cast<size_t>(slot_id), slot_list_.size());
  CHECK(IsTokenAccessible(isolate_credential, slot_id));

  for (map<int, shared_ptr<Session>>::iterator iter =
           slot_list_[slot_id].sessions.begin();
       iter != slot_list_[slot_id].sessions.end(); ++iter) {
    session_slot_map_.erase(iter->first);
  }
  slot_list_[slot_id].sessions.clear();
}

bool SlotManagerImpl::GetSession(const SecureBlob& isolate_credential,
                                 int session_id,
                                 Session** session) const {
  CHECK(session);

  // Lookup which slot this session belongs to.
  map<int, int>::const_iterator session_slot_iter =
      session_slot_map_.find(session_id);
  if (session_slot_iter == session_slot_map_.end())
    return false;
  int slot_id = session_slot_iter->second;
  CHECK_LT(static_cast<size_t>(slot_id), slot_list_.size());
  if (!IsTokenAccessible(isolate_credential, slot_id)) {
    return false;
  }

  // Lookup the session instance.
  map<int, shared_ptr<Session>>::const_iterator session_iter =
      slot_list_[slot_id].sessions.find(session_id);
  if (session_iter == slot_list_[slot_id].sessions.end())
    return false;
  *session = session_iter->second.get();
  return true;
}

bool SlotManagerImpl::OpenIsolate(SecureBlob* isolate_credential,
                                  bool* new_isolate_created) {
  VLOG(1) << "SlotManagerImpl::OpenIsolate enter";

  CHECK(new_isolate_created);
  if (isolate_map_.find(*isolate_credential) != isolate_map_.end()) {
    VLOG(1) << "Incrementing open count for existing isolate.";
    Isolate& isolate = isolate_map_[*isolate_credential];
    ++isolate.open_count;
    *new_isolate_created = false;
  } else {
    VLOG(1) << "Creating new isolate.";
    SecureBlob new_isolate_credential;
    if (HwsecIsEnabled()) {
      ASSIGN_OR_RETURN(new_isolate_credential,
                       hwsec_->GetRandomSecureBlob(kIsolateCredentialBytes),
                       _.LogError().As(false));
    } else {
      new_isolate_credential.resize(kIsolateCredentialBytes);
      RAND_bytes(new_isolate_credential.data(), kIsolateCredentialBytes);
    }

    if (isolate_map_.find(new_isolate_credential) != isolate_map_.end()) {
// TODO(b/211950732, b/211951349): Remove the compilation flag and FATAL once we
// do better error handling.
#if !USE_FUZZER
      // A collision on 128 bits should be extremely unlikely if the random
      // number generator is working properly. If there is a problem with the
      // random number generator we want to get out.
      LOG(FATAL) << "Collision when trying to create new isolate credential.";
#endif  // !USE_FUZZER
      return false;
    }

    AddIsolate(new_isolate_credential);
    isolate_credential->swap(new_isolate_credential);
    *new_isolate_created = true;
  }
  VLOG(1) << "SlotManagerImpl::OpenIsolate success";
  return true;
}

void SlotManagerImpl::CloseIsolate(const SecureBlob& isolate_credential) {
  VLOG(1) << "SlotManagerImpl::CloseIsolate enter";
  if (isolate_map_.find(isolate_credential) == isolate_map_.end()) {
    LOG(ERROR) << "Attempted Close isolate with invalid isolate credential";
    return;
  }
  Isolate& isolate = isolate_map_[isolate_credential];
  CHECK_GT(isolate.open_count, 0);
  --isolate.open_count;
  if (isolate.open_count == 0) {
    DestroyIsolate(isolate);
  }
  VLOG(1) << "SlotManagerImpl::CloseIsolate success";
}

bool SlotManagerImpl::LoadToken(const SecureBlob& isolate_credential,
                                const FilePath& path,
                                const SecureBlob& auth_data,
                                const string& label,
                                int* slot_id) {
  if (!InitStage2()) {
    chaps_metrics_->ReportChapsTokenManagerStatus(
        "LoadToken", TokenManagerStatus::kInitStage2Failed);
    return false;
  }
  return LoadTokenInternal(isolate_credential, path, auth_data, label, slot_id);
}

bool SlotManagerImpl::LoadTokenInternal(const SecureBlob& isolate_credential,
                                        const FilePath& path,
                                        const SecureBlob& auth_data,
                                        const string& label,
                                        int* slot_id) {
  CHECK(slot_id);
  VLOG(1) << "SlotManagerImpl::LoadToken enter";
  if (isolate_map_.find(isolate_credential) == isolate_map_.end()) {
    LOG(ERROR) << "Invalid isolate credential for LoadToken.";
    chaps_metrics_->ReportChapsTokenManagerStatus(
        "LoadToken", TokenManagerStatus::kInvalidIsolateCredential);
    return false;
  }
  Isolate& isolate = isolate_map_[isolate_credential];

  // If we're already managing this token, just send back the existing slot.
  if (path_slot_map_.find(path) != path_slot_map_.end()) {
    // TODO(rmcilroy): Consider allowing tokens to be loaded in multiple
    // isolates.
    LOG(WARNING) << "Load token event received for existing token.";
    *slot_id = path_slot_map_[path];
    chaps_metrics_->ReportChapsTokenManagerStatus(
        "LoadToken", TokenManagerStatus::kLoadExistingToken);
    return true;
  }

  shared_ptr<SlotPolicy> slot_policy(
      factory_->CreateSlotPolicy(IsSharedSlot(path)));

  // Setup the object pool.
  *slot_id = FindEmptySlot();
  shared_ptr<ObjectPool> object_pool(factory_->CreateObjectPool(
      this, slot_policy.get(), factory_->CreateObjectStore(path)));
  CHECK(object_pool.get());

  if (HwsecIsEnabled()) {
    if (!MigrateTokenIfNeeded(path, auth_data, object_pool)) {
      // Asynchronously Decrypting (or creating) the root key.
      // This has the effect that queries for public objects are responsive but
      // queries for private objects will be waiting for the root key to be
      // ready.
      LoadHwsecToken(base::DoNothing(), *slot_id, path, auth_data, object_pool);
    }
  } else {
    // Load a software-only token.
    LOG(WARNING) << "No HWSec is available. Loading a software-only token.";
    if (!LoadSoftwareToken(auth_data, object_pool.get())) {
      chaps_metrics_->ReportChapsTokenManagerStatus(
          "LoadToken", TokenManagerStatus::kFailedToLoadSoftwareToken);
      return false;
    }
  }

  // Insert the new token into the empty slot.
  slot_list_[*slot_id].slot_policy = slot_policy;
  slot_list_[*slot_id].token_object_pool = object_pool;
  slot_list_[*slot_id].slot_info.flags |= CKF_TOKEN_PRESENT;
  path_slot_map_[path] = *slot_id;
  CopyStringToCharBuffer(label, slot_list_[*slot_id].token_info.label,
                         std::size(slot_list_[*slot_id].token_info.label));

  // Insert slot into the isolate.
  isolate.slot_ids.insert(*slot_id);
  LOG(INFO) << "Slot " << *slot_id << " ready for token at " << path.value();
  VLOG(1) << "SlotManagerImpl::LoadToken success";
  chaps_metrics_->ReportChapsTokenManagerStatus(
      "LoadToken", TokenManagerStatus::kCommandSuccess);
  return true;
}

bool SlotManagerImpl::MigrateTokenIfNeeded(const base::FilePath& path,
                                           const SecureBlob& auth_data,
                                           shared_ptr<ObjectPool> object_pool) {
  if (USE_TPM_INSECURE_FALLBACK) {
    SecureBlob auth_key_encrypt =
        Sha256(SecureBlob::Combine(auth_data, SecureBlob(kKeyPurposeEncrypt)));
    SecureBlob auth_key_mac =
        Sha256(SecureBlob::Combine(auth_data, SecureBlob(kKeyPurposeMac)));
    string encrypted_root_key;
    string saved_mac;

    if (!object_pool->GetInternalBlob(kEncryptedRootKey, &encrypted_root_key) ||
        !object_pool->GetInternalBlob(kAuthDataHash, &saved_mac)) {
      return false;
    }

    if (HmacSha512(kAuthKeyMacInput, auth_key_mac) != saved_mac) {
      return false;
    }

    // Decrypt the root key with the auth data.
    string root_key_str;
    if (!RunCipher(false,  // Decrypt.
                   auth_key_encrypt,
                   std::string(),  // Use a random IV.
                   encrypted_root_key, &root_key_str)) {
      return false;
    }

    LOG(INFO) << "Migrating software token to hardware token.";

    SecureBlob root_key(root_key_str);
    brillo::SecureClearContainer(root_key_str);

    // Asynchronously migrate the root key to be backed by secure element.
    // This has the effect that queries for public objects are responsive but
    // queries for private objects will be waiting for the root key to be
    // ready.
    InitializeHwsecTokenWithRootKey(base::DoNothing(), path, auth_data,
                                    object_pool, root_key);
    return true;
  }

  return false;
}

void SlotManagerImpl::LoadHwsecToken(base::OnceCallback<void(bool)> callback,
                                     int slot_id,
                                     const base::FilePath& path,
                                     const brillo::SecureBlob& auth_data,
                                     std::shared_ptr<ObjectPool> object_pool) {
  if (system_shutdown_blocker_) {
    base::OnceClosure unblock_closure =
        base::BindOnce(&SystemShutdownBlocker::Unblock,
                       base::Unretained(system_shutdown_blocker_), slot_id);

    // Hook the unblock callback into the final callback.
    callback = base::BindOnce(
        [](base::OnceClosure unblock, base::OnceCallback<void(bool)> callback,
           bool result) {
          std::move(unblock).Run();
          std::move(callback).Run(result);
        },
        std::move(unblock_closure), std::move(callback));

    system_shutdown_blocker_->Block(
        slot_id, kTokenInitBlockSystemShutdownFallbackTimeout);
  }

  string auth_data_hash = HashAuthData(auth_data);
  string saved_auth_data_hash;
  string auth_key_blob;
  string encrypted_root_key;
  // Determine whether the key hierarchy has already been initialized based on
  // whether the relevant blobs exist.
  if (!object_pool->GetInternalBlob(kEncryptedAuthKey, &auth_key_blob) ||
      !object_pool->GetInternalBlob(kEncryptedRootKey, &encrypted_root_key)) {
    LOG(INFO) << "Initializing key hierarchy for token at " << path.value();
    InitializeHwsecToken(std::move(callback), path, auth_data, object_pool);
    return;
  }

  // Don't send the auth data to the secure element if it fails to verify
  // against the saved hash.
  object_pool->GetInternalBlob(kAuthDataHash, &saved_auth_data_hash);
  if (!CheckAuthDataValid(auth_data_hash, saved_auth_data_hash)) {
    LOG(ERROR) << "Failed to check the auth data is valid for token at "
               << path.value() << ", reinitializing token.";
    chaps_metrics_->ReportReinitializingTokenStatus(
        ReinitializingTokenStatus::kFailedToValidate);
    CreateTokenReinitializedFlagFile(path);
    if (object_pool->DeleteAll() != ObjectPool::Result::Success)
      LOG(WARNING) << "Failed to delete all existing objects.";

    InitializeHwsecToken(std::move(callback), path, auth_data, object_pool);
    return;
  }

  hwsec::ChapsFrontend::UnsealDataCallback unseal_callback = base::BindOnce(
      &SlotManagerImpl::LoadHwsecTokenAfterUnseal, base::Unretained(this),
      std::move(callback), path, auth_data, object_pool);

  hwsec_->UnsealDataAsync(
      hwsec::ChapsSealedData{
          .key_blob = brillo::BlobFromString(auth_key_blob),
          .encrypted_data = brillo::BlobFromString(encrypted_root_key),
      },
      Sha1(auth_data), std::move(unseal_callback));

  return;
}

void SlotManagerImpl::LoadHwsecTokenAfterUnseal(
    base::OnceCallback<void(bool)> callback,
    const base::FilePath& path,
    const brillo::SecureBlob& auth_data,
    std::shared_ptr<ObjectPool> object_pool,
    hwsec::StatusOr<brillo::SecureBlob> unsealed_data) {
  if (!unsealed_data.ok()) {
    LOG(ERROR) << "Failed to unseal for token at " << path.value() << ": "
               << unsealed_data.status() << ", reinitializing token.";
    chaps_metrics_->ReportReinitializingTokenStatus(
        ReinitializingTokenStatus::kFailedToUnseal);
    CreateTokenReinitializedFlagFile(path);
    if (object_pool->DeleteAll() != ObjectPool::Result::Success)
      LOG(WARNING) << "Failed to delete all existing objects.";

    InitializeHwsecToken(std::move(callback), path, auth_data, object_pool);
    return;
  }
  LoadHwsecTokenFinal(std::move(callback), path, auth_data, object_pool,
                      unsealed_data.value());
}

void SlotManagerImpl::LoadHwsecTokenFinal(
    base::OnceCallback<void(bool)> callback,
    const base::FilePath& path,
    const brillo::SecureBlob& auth_data,
    std::shared_ptr<ObjectPool> object_pool,
    brillo::SecureBlob root_key) {
  if (!object_pool->SetEncryptionKey(root_key)) {
    LOG(ERROR) << "SetEncryptionKey failed for token at " << path.value();
    std::move(callback).Run(false);
    return;
  }
  if (!root_key.empty()) {
    string auth_data_hash = HashAuthData(auth_data);
    string saved_auth_data_hash;
    object_pool->GetInternalBlob(kAuthDataHash, &saved_auth_data_hash);
    if (auth_data_hash != saved_auth_data_hash) {
      object_pool->SetInternalBlob(kAuthDataHash, auth_data_hash);
    }
    LOG(INFO) << "Root key is ready for token at " << path.value();
    std::move(callback).Run(true);
    return;
  }
  std::move(callback).Run(false);
}

void SlotManagerImpl::InitializeHwsecToken(
    base::OnceCallback<void(bool)> callback,
    const base::FilePath& path,
    const brillo::SecureBlob& auth_data,
    std::shared_ptr<ObjectPool> object_pool) {
  hwsec::ChapsFrontend::GetRandomSecureBlobCallback gen_rand_callback =
      base::BindOnce(&SlotManagerImpl::InitializeHwsecTokenAfterGenerateRandom,
                     base::Unretained(this), std::move(callback), path,
                     auth_data, object_pool);
  hwsec_->GetRandomSecureBlobAsync(kUserKeySize, std::move(gen_rand_callback));
}

void SlotManagerImpl::InitializeHwsecTokenAfterGenerateRandom(
    base::OnceCallback<void(bool)> callback,
    const base::FilePath& path,
    const brillo::SecureBlob& auth_data,
    std::shared_ptr<ObjectPool> object_pool,
    hwsec::StatusOr<brillo::SecureBlob> random_data) {
  if (!random_data.ok()) {
    LOG(ERROR) << "Failed to generate user encryption key: "
               << random_data.status();
    std::move(callback).Run(false);
    return;
  }

  InitializeHwsecTokenWithRootKey(std::move(callback), path, auth_data,
                                  object_pool, random_data.value());
}

void SlotManagerImpl::InitializeHwsecTokenWithRootKey(
    base::OnceCallback<void(bool)> callback,
    const base::FilePath& path,
    const brillo::SecureBlob& auth_data,
    std::shared_ptr<ObjectPool> object_pool,
    brillo::SecureBlob root_key) {
  hwsec::ChapsFrontend::SealDataCallback seal_callback =
      base::BindOnce(&SlotManagerImpl::InitializeHwsecTokenAfterSealData,
                     base::Unretained(this), std::move(callback), path,
                     auth_data, object_pool, root_key);

  hwsec_->SealDataAsync(root_key, Sha1(auth_data), std::move(seal_callback));
}

void SlotManagerImpl::InitializeHwsecTokenAfterSealData(
    base::OnceCallback<void(bool)> callback,
    const base::FilePath& path,
    const brillo::SecureBlob& auth_data,
    std::shared_ptr<ObjectPool> object_pool,
    brillo::SecureBlob root_key,
    hwsec::StatusOr<hwsec::ChapsSealedData> sealed_data) {
  if (!sealed_data.ok()) {
    LOG(ERROR) << "Failed to seal user encryption key: "
               << sealed_data.status();
    std::move(callback).Run(false);
    return;
  }

  if (!object_pool->SetInternalBlob(
          kEncryptedAuthKey, brillo::BlobToString(sealed_data->key_blob)) ||
      !object_pool->SetInternalBlob(
          kEncryptedRootKey,
          brillo::BlobToString(sealed_data->encrypted_data))) {
    LOG(ERROR) << "Failed to write key hierarchy blobs.";
    std::move(callback).Run(false);
    return;
  }

  LoadHwsecTokenFinal(std::move(callback), path, auth_data, object_pool,
                      root_key);
}

bool SlotManagerImpl::LoadSoftwareToken(const SecureBlob& auth_data,
                                        ObjectPool* object_pool) {
  SecureBlob auth_key_encrypt =
      Sha256(SecureBlob::Combine(auth_data, SecureBlob(kKeyPurposeEncrypt)));
  SecureBlob auth_key_mac =
      Sha256(SecureBlob::Combine(auth_data, SecureBlob(kKeyPurposeMac)));
  string encrypted_root_key;
  string saved_mac;

  string key_blob;
  if (object_pool->GetInternalBlob(kEncryptedAuthKey, &key_blob)) {
    LOG(ERROR) << "Trying to load software token with the hardware token "
                  "existing, ignoring the request.";
    return false;
  }

  if (!object_pool->GetInternalBlob(kEncryptedRootKey, &encrypted_root_key) ||
      !object_pool->GetInternalBlob(kAuthDataHash, &saved_mac)) {
    return InitializeSoftwareToken(auth_data, object_pool);
  }
  if (HmacSha512(kAuthKeyMacInput, auth_key_mac) != saved_mac) {
    LOG(ERROR) << "Bad authorization data, reinitializing token.";
    chaps_metrics_->ReportReinitializingTokenStatus(
        ReinitializingTokenStatus::kBadAuthorizationData);
    if (object_pool->DeleteAll() != ObjectPool::Result::Success)
      LOG(WARNING) << "Failed to delete all existing objects.";
    return InitializeSoftwareToken(auth_data, object_pool);
  }
  // Decrypt the root key with the auth data.
  string root_key_str;
  if (!RunCipher(false,  // Decrypt.
                 auth_key_encrypt,
                 std::string(),  // Use a random IV.
                 encrypted_root_key, &root_key_str)) {
    LOG(ERROR) << "Failed to decrypt root key, reinitializing token.";
    chaps_metrics_->ReportReinitializingTokenStatus(
        ReinitializingTokenStatus::kFailedToDecryptRootKey);
    if (object_pool->DeleteAll() != ObjectPool::Result::Success)
      LOG(WARNING) << "Failed to delete all existing objects.";
    return InitializeSoftwareToken(auth_data, object_pool);
  }
  SecureBlob root_key(root_key_str);
  brillo::SecureClearContainer(root_key_str);
  if (!object_pool->SetEncryptionKey(root_key)) {
    LOG(ERROR) << "SetEncryptionKey failed.";
    return false;
  }
  return true;
}

bool SlotManagerImpl::InitializeSoftwareToken(const SecureBlob& auth_data,
                                              ObjectPool* object_pool) {
  // Generate a new random root key and encrypt it with the auth data.
  SecureBlob root_key(kUserKeySize);
  if (1 != RAND_bytes(root_key.data(), kUserKeySize)) {
    LOG(ERROR) << "RAND_bytes failed: " << GetOpenSSLError();
    return false;
  }
  SecureBlob auth_key_encrypt =
      Sha256(SecureBlob::Combine(auth_data, SecureBlob(kKeyPurposeEncrypt)));
  string encrypted_root_key;
  if (!RunCipher(true,  // Encrypt.
                 auth_key_encrypt,
                 std::string(),  // Use a random IV.
                 root_key.to_string(), &encrypted_root_key)) {
    LOG(ERROR) << "Failed to encrypt new root key.";
    return false;
  }
  SecureBlob auth_key_mac =
      Sha256(SecureBlob::Combine(auth_data, SecureBlob(kKeyPurposeMac)));
  if (!object_pool->SetInternalBlob(kEncryptedRootKey, encrypted_root_key) ||
      !object_pool->SetInternalBlob(
          kAuthDataHash, HmacSha512(kAuthKeyMacInput, auth_key_mac))) {
    LOG(ERROR) << "Failed to write new root key blobs.";
    return false;
  }
  if (!object_pool->SetEncryptionKey(root_key)) {
    LOG(ERROR) << "SetEncryptionKey failed.";
    return false;
  }
  return true;
}

bool SlotManagerImpl::IsSharedSlot(const FilePath& path) {
  return path == FilePath(kSystemTokenPath);
}

bool SlotManagerImpl::UnloadToken(const SecureBlob& isolate_credential,
                                  const FilePath& path) {
  VLOG(1) << "SlotManagerImpl::UnloadToken";
  if (isolate_map_.find(isolate_credential) == isolate_map_.end()) {
    LOG(WARNING) << "Invalid isolate credential for UnloadToken.";
    chaps_metrics_->ReportChapsTokenManagerStatus(
        "UnloadToken", TokenManagerStatus::kInvalidIsolateCredential);
    return false;
  }
  Isolate& isolate = isolate_map_[isolate_credential];

  // If we're not managing this token, ignore the event.
  if (path_slot_map_.find(path) == path_slot_map_.end()) {
    LOG(WARNING) << "Unload Token event received for unknown path: "
                 << path.value();
    chaps_metrics_->ReportChapsTokenManagerStatus(
        "UnloadToken", TokenManagerStatus::kUnknownPath);
    return false;
  }
  int slot_id = path_slot_map_[path];
  if (!IsTokenAccessible(isolate_credential, slot_id)) {
    LOG(WARNING) << "Attempted to unload token with invalid isolate credential";
    chaps_metrics_->ReportChapsTokenManagerStatus(
        "UnloadToken", TokenManagerStatus::kInvalidIsolateCredential);
    return false;
  }

  CloseAllSessions(isolate_credential, slot_id);
  slot_list_[slot_id].token_object_pool.reset();
  slot_list_[slot_id].slot_info.flags &= ~CKF_TOKEN_PRESENT;
  path_slot_map_.erase(path);
  // Remove slot from the isolate.
  isolate.slot_ids.erase(slot_id);
  LOG(INFO) << "Token at " << path.value() << " has been removed from slot "
            << slot_id;
  VLOG(1) << "SlotManagerImpl::Unload token success";
  chaps_metrics_->ReportChapsTokenManagerStatus(
      "UnloadToken", TokenManagerStatus::kCommandSuccess);
  return true;
}

bool SlotManagerImpl::GetTokenPath(const SecureBlob& isolate_credential,
                                   int slot_id,
                                   FilePath* path) {
  if (!IsTokenAccessible(isolate_credential, slot_id))
    return false;
  if (!IsTokenPresent(slot_id))
    return false;
  return PathFromSlotId(slot_id, path);
}

bool SlotManagerImpl::IsTokenPresent(int slot_id) const {
  CHECK_LT(static_cast<size_t>(slot_id), slot_list_.size());

  return ((slot_list_[slot_id].slot_info.flags & CKF_TOKEN_PRESENT) ==
          CKF_TOKEN_PRESENT);
}

int SlotManagerImpl::CreateHandle() {
  // If we use this many handles, we have a problem.
  CHECK(last_handle_ < std::numeric_limits<int>::max());
  return ++last_handle_;
}

void SlotManagerImpl::GetDefaultInfo(CK_SLOT_INFO* slot_info,
                                     CK_TOKEN_INFO* token_info) {
  memset(slot_info, 0, sizeof(CK_SLOT_INFO));
  CopyStringToCharBuffer(kSlotDescription, slot_info->slotDescription,
                         std::size(slot_info->slotDescription));
  CopyStringToCharBuffer(kManufacturerID, slot_info->manufacturerID,
                         std::size(slot_info->manufacturerID));
  // By default private key objects stored in this token is hardware backed and
  // unextractable, so the absence of CKF_HW_SLOT doesn't indicate a lowered
  // security guarantee.
  slot_info->flags = CKF_REMOVABLE_DEVICE;
  slot_info->hardwareVersion = kDefaultVersion;
  slot_info->firmwareVersion = kDefaultVersion;

  memset(token_info, 0, sizeof(CK_TOKEN_INFO));
  CopyStringToCharBuffer(kTokenLabel, token_info->label,
                         std::size(token_info->label));
  CopyStringToCharBuffer(kManufacturerID, token_info->manufacturerID,
                         std::size(token_info->manufacturerID));
  CopyStringToCharBuffer(kTokenModel, token_info->model,
                         std::size(token_info->model));
  CopyStringToCharBuffer(kTokenSerialNumber, token_info->serialNumber,
                         std::size(token_info->serialNumber));
  token_info->flags = CKF_RNG | CKF_USER_PIN_INITIALIZED |
                      CKF_PROTECTED_AUTHENTICATION_PATH | CKF_TOKEN_INITIALIZED;
  token_info->ulMaxSessionCount = CK_EFFECTIVELY_INFINITE;
  token_info->ulSessionCount = CK_UNAVAILABLE_INFORMATION;
  token_info->ulMaxRwSessionCount = CK_EFFECTIVELY_INFINITE;
  token_info->ulRwSessionCount = CK_UNAVAILABLE_INFORMATION;
  token_info->ulMaxPinLen = kMaxPinLen;
  token_info->ulMinPinLen = kMinPinLen;
  token_info->ulTotalPublicMemory = CK_UNAVAILABLE_INFORMATION;
  token_info->ulFreePublicMemory = CK_UNAVAILABLE_INFORMATION;
  token_info->ulTotalPrivateMemory = CK_UNAVAILABLE_INFORMATION;
  token_info->ulFreePrivateMemory = CK_UNAVAILABLE_INFORMATION;
  token_info->hardwareVersion = kDefaultVersion;
  token_info->firmwareVersion = kDefaultVersion;
}

int SlotManagerImpl::FindEmptySlot() {
  size_t i = 0;
  for (; i < slot_list_.size(); ++i) {
    if (!IsTokenPresent(i))
      return i;
  }
  // Add a new slot.
  AddSlots(1);
  return i;
}

void SlotManagerImpl::AddSlots(int num_slots) {
  for (int i = 0; i < num_slots; ++i) {
    Slot slot;
    GetDefaultInfo(&slot.slot_info, &slot.token_info);
    LOG(INFO) << "Adding slot: " << slot_list_.size();
    slot_list_.push_back(slot);
  }
}

void SlotManagerImpl::AddIsolate(const SecureBlob& isolate_credential) {
  Isolate isolate;
  isolate.credential = isolate_credential;
  isolate.open_count = 1;
  isolate_map_[isolate_credential] = isolate;
}

void SlotManagerImpl::DestroyIsolate(const Isolate& isolate) {
  CHECK_EQ(isolate.open_count, 0);

  // Unload any existing tokens in this isolate.
  while (!isolate.slot_ids.empty()) {
    int slot_id = *isolate.slot_ids.begin();
    FilePath path;
    CHECK(PathFromSlotId(slot_id, &path));
    UnloadToken(isolate.credential, path);
  }

  isolate_map_.erase(isolate.credential);
}

bool SlotManagerImpl::PathFromSlotId(int slot_id, FilePath* path) const {
  CHECK(path);
  map<FilePath, int>::const_iterator path_iter;
  for (path_iter = path_slot_map_.begin(); path_iter != path_slot_map_.end();
       ++path_iter) {
    if (path_iter->second == slot_id) {
      *path = path_iter->first;
      return true;
    }
  }
  return false;
}

}  // namespace chaps
