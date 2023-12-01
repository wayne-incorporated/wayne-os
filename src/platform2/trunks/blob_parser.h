// Copyright 2015 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TRUNKS_BLOB_PARSER_H_
#define TRUNKS_BLOB_PARSER_H_

#include <string>

#include "trunks/tpm_generated.h"
#include "trunks/trunks_export.h"

namespace trunks {

class TRUNKS_EXPORT BlobParser {
 public:
  BlobParser() = default;
  BlobParser(const BlobParser&) = delete;
  BlobParser& operator=(const BlobParser&) = delete;

  virtual ~BlobParser() = default;

  // This method is used to construct a |key_blob| given the associated key's
  // TPM2B_PUBLIC and TPM2B_PRIVATE structs. Returns true on successful
  // serialization, else false.
  virtual bool SerializeKeyBlob(const TPM2B_PUBLIC& public_info,
                                const TPM2B_PRIVATE& private_info,
                                std::string* key_blob);

  // This method returns the Public and Private structs associated with a given
  // |key_blob|. Returns true on success, else false.
  virtual bool ParseKeyBlob(const std::string& key_blob,
                            TPM2B_PUBLIC* public_info,
                            TPM2B_PRIVATE* private_info);

  // This method is used to construct a |creation_blob| given the associated
  // key's |creation_data|, |creation_hash| and |creation_ticket| structs.
  // Returns true on successful serializtion, else false.
  virtual bool SerializeCreationBlob(const TPM2B_CREATION_DATA& creation_data,
                                     const TPM2B_DIGEST& creation_hash,
                                     const TPMT_TK_CREATION& creation_ticket,
                                     std::string* creation_blob);

  // This method returns the creation structures associated with a given
  // |creation_blob|. Returns true on success, else false.
  virtual bool ParseCreationBlob(const std::string& creation_blob,
                                 TPM2B_CREATION_DATA* creation_data,
                                 TPM2B_DIGEST* creation_hash,
                                 TPMT_TK_CREATION* creation_ticket);
};

}  // namespace trunks

#endif  // TRUNKS_BLOB_PARSER_H_
