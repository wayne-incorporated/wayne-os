// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/store/pkcs11_cert_store.h"

#include <base/logging.h>
#include <base/strings/string_number_conversions.h>

#include "shill/store/pkcs11_util.h"

namespace {

constexpr int kMaxObjectCount = 64;

}  // namespace

namespace shill {

bool Pkcs11CertStore::Delete(CK_SLOT_ID slot, const std::string& cka_id) {
  pkcs11::ScopedSession session(slot);
  if (!session.IsValid()) {
    LOG(ERROR) << "Pkcs11CertStore: Failed to open token session with slot "
               << slot;
    return false;
  }

  CK_ULONG count = 0;
  CK_OBJECT_HANDLE handles[kMaxObjectCount];
  if (!FindObjects(session.handle(), cka_id, kMaxObjectCount, handles, count)) {
    LOG(ERROR) << "Failed to find objects with ID: "
               << base::HexEncode(cka_id.data(), cka_id.length());
    return false;
  }

  bool success = true;
  for (CK_ULONG i = 0; i < count; i++) {
    CK_OBJECT_CLASS object_class;
    if (!GetObjectClass(session.handle(), handles[i], &object_class)) {
      LOG(WARNING) << "Failed to get object class with ID: "
                   << base::HexEncode(cka_id.data(), cka_id.length());
      continue;
    }
    if (object_class != CKO_PRIVATE_KEY && object_class != CKO_CERTIFICATE) {
      LOG(WARNING) << "Unexpected object class " << object_class << " with ID: "
                   << base::HexEncode(cka_id.data(), cka_id.length());
      continue;
    }
    if (C_DestroyObject(session.handle(), handles[i]) != CKR_OK) {
      LOG(ERROR) << "C_DestroyObject failed for object class " << object_class
                 << " with ID: "
                 << base::HexEncode(cka_id.data(), cka_id.length());
      success = false;
    }
  }
  return success;
}

bool Pkcs11CertStore::FindObjects(CK_SESSION_HANDLE session_handle,
                                  const std::string& cka_id,
                                  CK_ULONG max_object_count,
                                  CK_OBJECT_HANDLE_PTR object_handles,
                                  CK_ULONG& out_count) {
  // Assemble a search template.
  std::string mutable_id(cka_id);
  CK_ATTRIBUTE attributes[] = {{CKA_ID, mutable_id.data(), mutable_id.size()}};
  if ((C_FindObjectsInit(session_handle, attributes, std::size(attributes)) !=
       CKR_OK) ||
      (C_FindObjects(session_handle, object_handles, max_object_count,
                     &out_count) != CKR_OK) ||
      (C_FindObjectsFinal(session_handle) != CKR_OK)) {
    LOG(ERROR) << "ID search failed: "
               << base::HexEncode(cka_id.data(), cka_id.length());
    return false;
  }
  return true;
}

bool Pkcs11CertStore::GetObjectClass(CK_SESSION_HANDLE session_handle,
                                     CK_OBJECT_HANDLE object_handle,
                                     CK_OBJECT_CLASS_PTR object_class) {
  CK_ATTRIBUTE attributes[] = {
      {CKA_CLASS, object_class, sizeof(CK_OBJECT_CLASS)}};
  if (C_GetAttributeValue(session_handle, object_handle, attributes,
                          std::size(attributes)) != CKR_OK) {
    LOG(ERROR) << "Get attribute failed";
    return false;
  }
  return true;
}
}  // namespace shill
