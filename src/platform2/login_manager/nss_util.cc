// Copyright (c) 2011 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "login_manager/nss_util.h"

#include <stdint.h>
#include <stdlib.h>

#include <memory>
#include <string>
#include <utility>

#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/memory/ptr_util.h>
#include <base/notreached.h>
#include <base/strings/stringprintf.h>
#include <crypto/nss_util.h>
#include <crypto/nss_util_internal.h>
#include <crypto/rsa_private_key.h>
#include <crypto/scoped_nss_types.h>
#include <crypto/signature_creator.h>
#include <crypto/signature_verifier.h>
#include <brillo/scoped_mount_namespace.h>
#include <keyhi.h>
#include <pk11pub.h>
#include <prerror.h>
#include <secmod.h>
#include <secmodt.h>

using brillo::ScopedMountNamespace;

using crypto::RSAPrivateKey;
using crypto::ScopedPK11Slot;
using crypto::ScopedSECItem;
using crypto::ScopedSECKEYPrivateKey;
using crypto::ScopedSECKEYPublicKey;

namespace {
// This should match the same constant in Chrome tree:
// chrome/browser/chromeos/settings/owner_key_util.cc
const char kOwnerKeyFile[] = "/var/lib/whitelist/owner.key";

// TODO(hidehiko): Move this to scoped_nss_types.h.
struct CERTSubjectPublicKeyInfoDeleter {
  void operator()(CERTSubjectPublicKeyInfo* ptr) const {
    SECKEY_DestroySubjectPublicKeyInfo(ptr);
  }
};
using ScopedCERTSubjectPublicKeyInfo =
    std::unique_ptr<CERTSubjectPublicKeyInfo, CERTSubjectPublicKeyInfoDeleter>;

}  // namespace

namespace login_manager {
///////////////////////////////////////////////////////////////////////////
// NssUtil

NssUtil::NssUtil() = default;

NssUtil::~NssUtil() = default;

///////////////////////////////////////////////////////////////////////////
// NssUtilImpl

class NssUtilImpl : public NssUtil {
 public:
  NssUtilImpl();
  NssUtilImpl(const NssUtilImpl&) = delete;
  NssUtilImpl& operator=(const NssUtilImpl&) = delete;

  ~NssUtilImpl() override;

  ScopedPK11SlotDescriptor OpenUserDB(
      const base::FilePath& user_homedir,
      const OptionalFilePath& ns_mnt_path) override;

  std::unique_ptr<RSAPrivateKey> GetPrivateKeyForUser(
      const std::vector<uint8_t>& public_key_der,
      PK11SlotDescriptor* user_slot) override;

  std::unique_ptr<RSAPrivateKey> GenerateKeyPairForUser(
      PK11SlotDescriptor* user_slot) override;

  base::FilePath GetOwnerKeyFilePath() override;

  base::FilePath GetNssdbSubpath() override;

  bool CheckPublicKeyBlob(const std::vector<uint8_t>& blob) override;

  bool Verify(const std::vector<uint8_t>& signature,
              const std::vector<uint8_t>& data,
              const std::vector<uint8_t>& public_key) override;

  bool Sign(const std::vector<uint8_t>& data,
            RSAPrivateKey* key,
            std::vector<uint8_t>* out_signature) override;

 private:
  static const uint16_t kKeySizeInBits;
  static const char kNssdbSubpath[];
};

// Defined here, instead of up above, because we need NssUtilImpl.
// static
std::unique_ptr<NssUtil> NssUtil::Create() {
  return std::make_unique<NssUtilImpl>();
}

// We're generating and using 2048-bit RSA keys.
// static
const uint16_t NssUtilImpl::kKeySizeInBits = 2048;
// static
const char NssUtilImpl::kNssdbSubpath[] = ".pki/nssdb";

NssUtilImpl::NssUtilImpl() {
  if (setenv("NSS_SDB_USE_CACHE", "no", 1) == -1)
    PLOG(WARNING) << "Can't set NSS_SDB_USE_CACHE=no in the environment!";
  crypto::EnsureNSSInit();
}

NssUtilImpl::~NssUtilImpl() = default;

ScopedPK11SlotDescriptor NssUtilImpl::OpenUserDB(
    const base::FilePath& user_homedir, const OptionalFilePath& ns_mnt_path) {
  // TODO(cmasone): If we ever try to keep the session_manager alive across
  // user sessions, we'll need to close these persistent DBs.
  base::FilePath db_path(user_homedir.AppendASCII(kNssdbSubpath));
  const std::string modspec =
      base::StringPrintf("configDir='sql:%s' tokenDescription='%s'",
                         db_path.value().c_str(), user_homedir.value().c_str());

  // If necessary, enter the mount namespace where the user mounts exist.
  std::unique_ptr<ScopedMountNamespace> ns_mnt;
  if (ns_mnt_path) {
    ns_mnt = ScopedMountNamespace::CreateFromPath(ns_mnt_path.value());
  }

  ScopedPK11SlotDescriptor res = std::make_unique<PK11SlotDescriptor>();
  res->ns_mnt_path = ns_mnt_path;

  ScopedPK11Slot db_slot(SECMOD_OpenUserDB(modspec.c_str()));
  if (!db_slot.get()) {
    LOG(ERROR) << "Error opening persistent database (" << modspec
               << "): " << PR_GetError();
    res->slot = ScopedPK11Slot();
    return res;
  }

  if (PK11_NeedUserInit(db_slot.get()))
    PK11_InitPin(db_slot.get(), nullptr, nullptr);

  // If we opened successfully, we will have a non-default private key slot.
  if (PK11_IsInternalKeySlot(db_slot.get())) {
    res->slot = ScopedPK11Slot();
    return res;
  }

  res->slot = std::move(db_slot);
  return res;
}

std::unique_ptr<RSAPrivateKey> NssUtilImpl::GetPrivateKeyForUser(
    const std::vector<uint8_t>& public_key_der, PK11SlotDescriptor* desc) {
  if (public_key_der.size() == 0) {
    LOG(ERROR) << "Not checking key because size is 0";
    return nullptr;
  }

  // First, decode and save the public key.
  SECItem key_der;
  key_der.type = siBuffer;
  key_der.data = const_cast<unsigned char*>(&public_key_der[0]);
  key_der.len = public_key_der.size();

  ScopedCERTSubjectPublicKeyInfo spki(
      SECKEY_DecodeDERSubjectPublicKeyInfo(&key_der));
  if (!spki) {
    NOTREACHED();
    return nullptr;
  }

  ScopedSECKEYPublicKey public_key(SECKEY_ExtractPublicKey(spki.get()));
  if (!public_key) {
    NOTREACHED();
    return nullptr;
  }

  // Make sure the key is an RSA key.  If not, that's an error
  if (SECKEY_GetPublicKeyType(public_key.get()) != rsaKey) {
    NOTREACHED();
    return nullptr;
  }

  ScopedSECItem ck_id(PK11_MakeIDFromPubKey(&(public_key->u.rsa.modulus)));
  if (!ck_id) {
    NOTREACHED();
    return nullptr;
  }

  // Search in just the user slot for the key with the given ID.
  // If necessary, enter the mount namespace where the user mounts exist.
  std::unique_ptr<ScopedMountNamespace> ns_mnt;
  if (desc->ns_mnt_path) {
    ns_mnt = ScopedMountNamespace::CreateFromPath(desc->ns_mnt_path.value());
  }
  ScopedSECKEYPrivateKey key(
      PK11_FindKeyByKeyID(desc->slot.get(), ck_id.get(), nullptr));
  if (!key) {
    // We didn't find the key.
    return nullptr;
  }

  return base::WrapUnique(RSAPrivateKey::CreateFromKey(key.get()));
}

std::unique_ptr<RSAPrivateKey> NssUtilImpl::GenerateKeyPairForUser(
    PK11SlotDescriptor* desc) {
  PK11RSAGenParams param;
  param.keySizeInBits = kKeySizeInBits;
  param.pe = 65537L;
  SECKEYPublicKey* public_key_ptr = nullptr;

  // If necessary, enter the mount namespace where the user mounts exist.
  std::unique_ptr<ScopedMountNamespace> ns_mnt;
  if (desc->ns_mnt_path) {
    ns_mnt = ScopedMountNamespace::CreateFromPath(desc->ns_mnt_path.value());
  }

  ScopedSECKEYPrivateKey key(PK11_GenerateKeyPair(
      desc->slot.get(), CKM_RSA_PKCS_KEY_PAIR_GEN, &param, &public_key_ptr,
      PR_TRUE /* permanent */, PR_TRUE /* sensitive */, nullptr));
  ScopedSECKEYPublicKey public_key(public_key_ptr);
  if (!key)
    return nullptr;

  return base::WrapUnique(RSAPrivateKey::CreateFromKey(key.get()));
}

base::FilePath NssUtilImpl::GetOwnerKeyFilePath() {
  return base::FilePath(kOwnerKeyFile);
}

base::FilePath NssUtilImpl::GetNssdbSubpath() {
  return base::FilePath(kNssdbSubpath);
}

bool NssUtilImpl::CheckPublicKeyBlob(const std::vector<uint8_t>& blob) {
  SECItem spki_der;
  spki_der.type = siBuffer;
  spki_der.data = const_cast<uint8_t*>(&blob[0]);
  spki_der.len = blob.size();
  ScopedCERTSubjectPublicKeyInfo spki(
      SECKEY_DecodeDERSubjectPublicKeyInfo(&spki_der));
  if (!spki)
    return false;

  ScopedSECKEYPublicKey public_key(SECKEY_ExtractPublicKey(spki.get()));
  return static_cast<bool>(public_key);
}

// This is pretty much just a blind passthrough, so I won't test it
// in the NssUtil unit tests.  I'll test it from a class that uses this API.
bool NssUtilImpl::Verify(const std::vector<uint8_t>& signature,
                         const std::vector<uint8_t>& data,
                         const std::vector<uint8_t>& public_key) {
  crypto::SignatureVerifier verifier;

  if (!verifier.VerifyInit(crypto::SignatureVerifier::RSA_PKCS1_SHA1,
                           signature.data(), signature.size(),
                           public_key.data(), public_key.size())) {
    LOG(ERROR) << "Could not initialize verifier";
    return false;
  }

  verifier.VerifyUpdate(data.data(), data.size());
  return verifier.VerifyFinal();
}

// This is pretty much just a blind passthrough, so I won't test it
// in the NssUtil unit tests.  I'll test it from a class that uses this API.
bool NssUtilImpl::Sign(const std::vector<uint8_t>& data,
                       RSAPrivateKey* key,
                       std::vector<uint8_t>* out_signature) {
  std::unique_ptr<crypto::SignatureCreator> signer(
      crypto::SignatureCreator::Create(key, crypto::SignatureCreator::SHA1));
  if (!signer->Update(data.data(), data.size()))
    return false;
  return signer->Final(out_signature);
}

}  // namespace login_manager
