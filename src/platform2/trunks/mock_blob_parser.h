// Copyright 2015 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TRUNKS_MOCK_BLOB_PARSER_H_
#define TRUNKS_MOCK_BLOB_PARSER_H_

#include <string>

#include <gmock/gmock.h>

#include "trunks/blob_parser.h"

namespace trunks {

class MockBlobParser : public BlobParser {
 public:
  MockBlobParser();
  ~MockBlobParser() override;

  MOCK_METHOD3(SerializeKeyBlob,
               bool(const TPM2B_PUBLIC&, const TPM2B_PRIVATE&, std::string*));
  MOCK_METHOD3(ParseKeyBlob,
               bool(const std::string&, TPM2B_PUBLIC*, TPM2B_PRIVATE*));
  MOCK_METHOD4(SerializeCreationBlob,
               bool(const TPM2B_CREATION_DATA&,
                    const TPM2B_DIGEST&,
                    const TPMT_TK_CREATION&,
                    std::string*));
  MOCK_METHOD4(ParseCreationBlob,
               bool(const std::string&,
                    TPM2B_CREATION_DATA*,
                    TPM2B_DIGEST*,
                    TPMT_TK_CREATION*));
};

}  // namespace trunks

#endif  // TRUNKS_MOCK_BLOB_PARSER_H_
