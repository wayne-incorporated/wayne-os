// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "arc/keymaster/context/chaps_client.h"

#include <iterator>
#include <optional>

#include <base/logging.h>
#include <chaps/pkcs11/cryptoki.h>
#include <chaps/proto_bindings/key_permissions.pb.h>
#include <chromeos/constants/pkcs11_custom_attributes.h>
#include <crypto/scoped_openssl_types.h>
#include <openssl/x509.h>

#include "arc/keymaster/context/context_adaptor.h"

namespace arc {
namespace keymaster {
namespace context {

namespace {

constexpr char kApplicationID[] =
    "CrOS_d5bbc079d2497110feadfc97c40d718ae46f4658";
constexpr char kEncryptKeyLabel[] = "arc-keymasterd_AES_key";

// Largest attribute retrieved is a certificate X509. Consider anything larger
// than 10KB an error.
constexpr size_t kMaxAttributeSize = 10240;
// Arbitrary number of object handles to retrieve on a search.
constexpr CK_ULONG kMaxHandles = 100;
// Max retries for invalid session handle errors.
//
// PKCS #11 calls taking a CK_SESSION_HANDLE may fail when the handle is
// invalidated, and should be retried with a new session. This may happen e.g.
// when cryptohome or attestation install a new key.
constexpr size_t kMaxAttemps = 10;
// The maximum length in bytes expected for signatures.
constexpr size_t kMaxSignatureSize = 512;

}  // anonymous namespace

namespace internal {

// Manages a PKCS #11 session by tying its lifecycle to scope.
class ScopedSession {
 public:
  explicit ScopedSession(CK_SLOT_ID slot) : handle_(CK_INVALID_HANDLE) {
    // Ensure connection to the PKCS #11 token is initialized.
    CK_RV rv = C_Initialize(/* pInitArgs */ nullptr);
    if (CKR_OK != rv && CKR_CRYPTOKI_ALREADY_INITIALIZED != rv) {
      // May happen in a test environment.
      LOG(INFO) << "PKCS #11 is not available.";
      return;
    }

    // Start a new session.
    CK_FLAGS flags = CKF_RW_SESSION | CKF_SERIAL_SESSION;
    if (CKR_OK != C_OpenSession(slot, flags, /* pApplication */ nullptr,
                                /* Notify */ nullptr, &handle_)) {
      LOG(ERROR) << "Failed to open PKCS #11 session.";
      return;
    }
  }

  ~ScopedSession() {
    // Close current session, if it exists.
    if (CK_INVALID_HANDLE != handle_ && CKR_OK != C_CloseSession(handle_)) {
      LOG(WARNING) << "Failed to close PKCS #11 session.";
      handle_ = CK_INVALID_HANDLE;
    }
  }

  // Not copyable nor assignable.
  ScopedSession(const ScopedSession&) = delete;
  ScopedSession& operator=(const ScopedSession&) = delete;

  std::optional<CK_SESSION_HANDLE> handle() const {
    if (CK_INVALID_HANDLE == handle_)
      return std::nullopt;
    return handle_;
  }

 private:
  CK_SESSION_HANDLE handle_;
};

}  // namespace internal

ChapsClient::ChapsClient(base::WeakPtr<ContextAdaptor> context_adaptor,
                         ContextAdaptor::Slot slot)
    : context_adaptor_(context_adaptor), slot_(slot) {}

ChapsClient::~ChapsClient() = default;

std::optional<brillo::SecureBlob> ChapsClient::ExportOrGenerateEncryptionKey() {
  if (!context_adaptor_)
    return std::nullopt;
  if (!context_adaptor_->encryption_key().has_value()) {
    for (size_t attempts = 0; attempts < kMaxAttemps; ++attempts) {
      std::optional<CK_OBJECT_HANDLE> handle = FindKey(kEncryptKeyLabel);
      if (!handle.has_value())
        handle = GenerateEncryptionKey();
      if (handle.has_value()) {
        brillo::SecureBlob exported_key;
        const CK_RV rv = ExportKey(handle.value(), &exported_key);

        if (CKR_SESSION_HANDLE_INVALID == rv) {
          session_.reset();
          continue;
        }

        if (CKR_OK == rv)
          context_adaptor_->set_encryption_key(exported_key);
      }

      break;
    }

    // Release allocated resources once the adaptor cache has been set. This can
    // be done here for now because ChapsClient is only used to export the
    // encryption key at the moment.
    if (context_adaptor_->encryption_key().has_value()) {
      session_.reset();
      C_Finalize(/* pReserved */ nullptr);
    }
  }

  return context_adaptor_->encryption_key();
}

std::optional<CK_SESSION_HANDLE> ChapsClient::session_handle() {
  if (!session_ && context_adaptor_) {
    std::optional<CK_SLOT_ID> slot_id = context_adaptor_->FetchSlotId(slot_);
    if (slot_id.has_value())
      session_ = std::make_unique<internal::ScopedSession>(slot_id.value());
  }

  return session_ ? session_->handle() : std::nullopt;
}

bool ChapsClient::InitializeSignature(CK_MECHANISM_TYPE mechanism_type,
                                      CK_OBJECT_HANDLE key_handle) {
  if (!session_handle().has_value() || !VerifyArcPermissionForKey(key_handle))
    return false;

  CK_MECHANISM mechanism = {mechanism_type, /*pParameter=*/NULL_PTR,
                            /*ulParameterLen=*/0};

  CK_RV rv = C_SignInit(*session_handle(), &mechanism, key_handle);
  if (CKR_OK != rv) {
    LOG(ERROR) << "Failed to initialize signature: " << rv;
    return false;
  }

  return true;
}

bool ChapsClient::UpdateSignature(const brillo::Blob& input) {
  if (!session_handle().has_value())
    return false;

  // Nothing to do if input is empty.
  if (input.empty())
    return false;

  CK_RV rv = C_SignUpdate(*session_handle(), const_cast<uint8_t*>(input.data()),
                          input.size());
  if (CKR_OK != rv) {
    LOG(ERROR) << "Failed to update signature: " << rv;
    return false;
  }

  return true;
}

std::optional<brillo::Blob> ChapsClient::FinalizeSignature() {
  if (!session_handle().has_value())
    return std::nullopt;

  brillo::Blob output(kMaxSignatureSize);
  CK_ULONG output_len = output.size();

  CK_RV rv = C_SignFinal(*session_handle(), output.data(), &output_len);
  if (CKR_OK != rv) {
    LOG(ERROR) << "Failed to finalize signature: " << rv;
    return std::nullopt;
  }

  output.resize(output_len);
  return output;
}

std::optional<CK_OBJECT_HANDLE> ChapsClient::FindKey(const std::string& label) {
  if (!session_handle().has_value())
    return std::nullopt;

  std::string mutable_application_id(kApplicationID);
  std::string mutable_label(label);

  // Assemble a search template.
  CK_OBJECT_CLASS object_class = CKO_SECRET_KEY;
  CK_BBOOL true_value = CK_TRUE;
  CK_BBOOL false_value = CK_FALSE;
  CK_ATTRIBUTE attributes[] = {
      {CKA_APPLICATION, std::data(mutable_application_id),
       mutable_application_id.size()},
      {CKA_CLASS, &object_class, sizeof(object_class)},
      {CKA_TOKEN, &true_value, sizeof(true_value)},
      {CKA_LABEL, std::data(mutable_label), mutable_label.size()},
      {CKA_PRIVATE, &true_value, sizeof(true_value)},
      {CKA_MODIFIABLE, &false_value, sizeof(false_value)}};
  CK_OBJECT_HANDLE handles[kMaxHandles];
  CK_ULONG count = 0;

  for (size_t attempts = 0; attempts < kMaxAttemps; ++attempts) {
    CK_RV rv =
        C_FindObjectsInit(*session_handle(), attributes, std::size(attributes));
    if (CKR_SESSION_HANDLE_INVALID == rv) {
      session_.reset();
      continue;
    }
    if (CKR_OK != rv) {
      LOG(ERROR) << "Key search init failed for label=" << label;
      return std::nullopt;
    }

    count = 0;
    rv = C_FindObjects(*session_handle(), handles, std::size(handles), &count);
    if (CKR_SESSION_HANDLE_INVALID == rv) {
      session_.reset();
      continue;
    }
    if (CKR_OK != rv) {
      LOG(ERROR) << "Key search failed for label=" << label;
      return std::nullopt;
    }

    rv = C_FindObjectsFinal(*session_handle());
    if (CKR_SESSION_HANDLE_INVALID == rv) {
      session_.reset();
      continue;
    }
    if (CKR_OK != rv)
      LOG(INFO) << "Could not finalize key search, proceeding anyways.";

    break;
  }

  if (count == 0) {
    LOG(INFO) << "No objects found with label=" << label;
    return std::nullopt;
  } else if (count > 1) {
    LOG(WARNING) << count << " objects found with label=" << label
                 << ", returning the first one.";
  }

  return handles[0];
}

CK_RV ChapsClient::ExportKey(CK_OBJECT_HANDLE key_handle,
                             brillo::SecureBlob* exported_key) {
  brillo::SecureBlob material;
  CK_RV rv = GetBytesAttribute(key_handle, CKA_VALUE, &material);
  if (CKR_OK != rv) {
    LOG(INFO) << "Failed to retrieve key material.";
    return rv;
  }

  exported_key->assign(material.begin(), material.end());
  return CKR_OK;
}

std::optional<CK_OBJECT_HANDLE> ChapsClient::FindObject(
    CK_OBJECT_CLASS object_class,
    const std::string& label,
    const brillo::Blob& id) {
  if (!session_handle().has_value())
    return std::nullopt;

  // Assemble a search template.
  std::string mutable_label(label);
  CK_ATTRIBUTE attributes[] = {
      {CKA_CLASS, &object_class, sizeof(object_class)},
      {CKA_LABEL, std::data(mutable_label), mutable_label.size()},
      {CKA_ID, const_cast<uint8_t*>(id.data()), id.size()},
  };
  constexpr CK_ULONG kMaxHandles = 100;  // Arbitrary.
  CK_OBJECT_HANDLE handles[kMaxHandles];
  CK_ULONG count = 0;

  for (size_t attempts = 0; attempts < kMaxAttemps; ++attempts) {
    CK_RV rv =
        C_FindObjectsInit(*session_handle(), attributes, std::size(attributes));
    if (CKR_SESSION_HANDLE_INVALID == rv) {
      session_.reset();
      continue;
    }
    if (CKR_OK != rv) {
      LOG(ERROR) << "Failed to initialize find object call: " << rv;
      return std::nullopt;
    }

    count = 0;
    rv = C_FindObjects(*session_handle(), handles, kMaxHandles, &count);
    if (CKR_SESSION_HANDLE_INVALID == rv) {
      session_.reset();
      continue;
    }
    if (CKR_OK != rv) {
      LOG(ERROR) << "Find objects call failed: " << rv;
      return std::nullopt;
    }

    break;
  }

  if (count == 0) {
    LOG(INFO) << "No objects found for label=" << label;
    return std::nullopt;
  } else if (count > 1) {
    LOG(WARNING) << count << " objects found with label=" << label
                 << ", returning the first one.";
  }

  return handles[0];
}

std::optional<brillo::Blob> ChapsClient::ExportSubjectPublicKeyInfo(
    const std::string& label, const brillo::Blob& id) {
  brillo::SecureBlob cert_x509_der_encoded;
  for (size_t attempts = 0; attempts < kMaxAttemps; ++attempts) {
    // Get a handle to the certificate object.
    std::optional<CK_OBJECT_HANDLE> cert_handle =
        FindObject(CKO_CERTIFICATE, label, id);
    if (!cert_handle.has_value())
      return std::nullopt;

    // Fetch the DER encoded certificate in x509 format.
    CK_RV rv = GetBytesAttribute(cert_handle.value(), CKA_VALUE,
                                 &cert_x509_der_encoded);
    if (CKR_SESSION_HANDLE_INVALID == rv) {
      session_.reset();
      continue;
    }
    if (CKR_OK != rv) {
      LOG(ERROR) << "Failed to export certificate x509 from chaps: " << rv;
      return std::nullopt;
    }

    break;
  }

  // Parse the x509.
  const uint8_t* cert_der = cert_x509_der_encoded.data();
  crypto::ScopedOpenSSL<X509, X509_free> cert_x509(
      d2i_X509(/*px=*/nullptr, &cert_der, cert_x509_der_encoded.size()));
  if (!cert_x509) {
    LOG(ERROR) << "Failed to parse certificate x509.";
    return std::nullopt;
  }

  // Export the SubjectPublicKeyInfo from the x509.
  uint8_t* spki = nullptr;
  int length = i2d_X509_PUBKEY(X509_get_X509_PUBKEY(cert_x509.get()), &spki);
  if (length < 0) {
    LOG(ERROR) << "Failed to parse SubjectPublicKeyInfo from x509.";
    return std::nullopt;
  }
  crypto::ScopedOpenSSLBytes scoped_pubkey_buffer(spki);

  return brillo::Blob(spki, spki + length);
}

std::optional<CK_OBJECT_HANDLE> ChapsClient::GenerateEncryptionKey() {
  if (!session_handle().has_value())
    return std::nullopt;

  std::string mutable_application_id(kApplicationID);
  std::string mutable_label(kEncryptKeyLabel);

  CK_OBJECT_CLASS object_class = CKO_SECRET_KEY;
  CK_ULONG key_length = 32;
  CK_BBOOL true_value = CK_TRUE;
  CK_BBOOL false_value = CK_FALSE;
  CK_ATTRIBUTE attributes[] = {
      {CKA_APPLICATION, std::data(mutable_application_id),
       mutable_application_id.size()},
      {CKA_CLASS, &object_class, sizeof(object_class)},
      {CKA_TOKEN, &true_value, sizeof(true_value)},
      {CKA_LABEL, std::data(mutable_label), mutable_label.size()},
      {CKA_PRIVATE, &true_value, sizeof(true_value)},
      {CKA_MODIFIABLE, &false_value, sizeof(false_value)},
      {CKA_EXTRACTABLE, &true_value, sizeof(true_value)},
      {CKA_SENSITIVE, &false_value, sizeof(false_value)},
      {CKA_VALUE_LEN, &key_length, sizeof(key_length)}};

  CK_OBJECT_HANDLE key_handle;
  CK_MECHANISM mechanism = {CKM_AES_KEY_GEN, /* pParameter */ nullptr,
                            /* ulParameterLen*/ 0};

  for (size_t attempts = 0; attempts < kMaxAttemps; ++attempts) {
    CK_RV rv = C_GenerateKey(*session_handle(), &mechanism, attributes,
                             std::size(attributes), &key_handle);
    if (CKR_SESSION_HANDLE_INVALID == rv) {
      session_.reset();
      continue;
    }
    if (CKR_OK != rv) {
      LOG(ERROR) << "Failed to generate encryption key.";
      return std::nullopt;
    }

    break;
  }
  LOG(INFO) << "Encryption key generated successfully.";
  return key_handle;
}

CK_RV ChapsClient::GetBytesAttribute(CK_OBJECT_HANDLE object_handle,
                                     CK_ATTRIBUTE_TYPE attribute_type,
                                     brillo::SecureBlob* attribute_value) {
  if (!session_handle().has_value())
    return CKR_GENERAL_ERROR;

  CK_ATTRIBUTE attribute = {attribute_type, /* pValue */ nullptr,
                            /* ulValueLen */ 0};
  CK_RV rv = C_GetAttributeValue(*session_handle(), object_handle, &attribute,
                                 /* ulCount */ 1);
  if (CKR_OK != rv) {
    LOG(ERROR) << "Failed to retrieve attribute length.";
    return rv;
  }

  if (attribute.ulValueLen <= 0 || attribute.ulValueLen > kMaxAttributeSize) {
    LOG(ERROR) << "Invalid attribute length (" << attribute.ulValueLen << ")";
    return CKR_GENERAL_ERROR;
  }

  attribute_value->resize(attribute.ulValueLen);
  attribute.pValue = attribute_value->data();
  rv = C_GetAttributeValue(*session_handle(), object_handle, &attribute,
                           /* ulCount */ 1);
  if (CKR_OK != rv) {
    LOG(ERROR) << "Failed to retrieve attribute value.";
    return rv;
  }
  return CKR_OK;
}

bool ChapsClient::VerifyArcPermissionForKey(CK_OBJECT_HANDLE key_handle) {
  brillo::SecureBlob key_permissions_blob;
  if (CKR_OK !=
      GetBytesAttribute(key_handle,
                        pkcs11_custom_attributes::kCkaChromeOsKeyPermissions,
                        &key_permissions_blob)) {
    LOG(INFO) << "Could not retrieve key permissions, will deny key access.";
    return false;
  }

  std::string serialized_key_permissions(key_permissions_blob.begin(),
                                         key_permissions_blob.end());
  chaps::KeyPermissions key_permissions;
  bool parse_did_work = key_permissions.ParseFromArray(
      key_permissions_blob.data(), key_permissions_blob.size());

  return parse_did_work && key_permissions.key_usages().arc();
}

}  // namespace context
}  // namespace keymaster
}  // namespace arc
