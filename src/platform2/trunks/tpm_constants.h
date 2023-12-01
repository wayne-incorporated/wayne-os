// Copyright 2015 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TRUNKS_TPM_CONSTANTS_H_
#define TRUNKS_TPM_CONSTANTS_H_

#include <iterator>
#include <string_view>

#include "trunks/tpm_generated.h"

namespace trunks {

// TPM Object Attributes.
constexpr TPMA_OBJECT kFixedTPM = 1U << 1;
constexpr TPMA_OBJECT kFixedParent = 1U << 4;
constexpr TPMA_OBJECT kSensitiveDataOrigin = 1U << 5;
constexpr TPMA_OBJECT kUserWithAuth = 1U << 6;
constexpr TPMA_OBJECT kAdminWithPolicy = 1U << 7;
constexpr TPMA_OBJECT kNoDA = 1U << 10;
constexpr TPMA_OBJECT kRestricted = 1U << 16;
constexpr TPMA_OBJECT kDecrypt = 1U << 17;
constexpr TPMA_OBJECT kSign = 1U << 18;

// TPM NV Index Attributes, defined in TPM Spec Part 2 section 13.2.
constexpr TPMA_NV TPMA_NV_PPWRITE = 1U << 0;
constexpr TPMA_NV TPMA_NV_OWNERWRITE = 1U << 1;
constexpr TPMA_NV TPMA_NV_AUTHWRITE = 1U << 2;
constexpr TPMA_NV TPMA_NV_POLICYWRITE = 1U << 3;
constexpr TPMA_NV TPMA_NV_COUNTER = 1U << 4;
constexpr TPMA_NV TPMA_NV_BITS = 1U << 5;
constexpr TPMA_NV TPMA_NV_EXTEND = 1U << 6;
constexpr TPMA_NV TPMA_NV_POLICY_DELETE = 1U << 10;
constexpr TPMA_NV TPMA_NV_WRITELOCKED = 1U << 11;
constexpr TPMA_NV TPMA_NV_WRITEALL = 1U << 12;
constexpr TPMA_NV TPMA_NV_WRITEDEFINE = 1U << 13;
constexpr TPMA_NV TPMA_NV_WRITE_STCLEAR = 1U << 14;
constexpr TPMA_NV TPMA_NV_GLOBALLOCK = 1U << 15;
constexpr TPMA_NV TPMA_NV_PPREAD = 1U << 16;
constexpr TPMA_NV TPMA_NV_OWNERREAD = 1U << 17;
constexpr TPMA_NV TPMA_NV_AUTHREAD = 1U << 18;
constexpr TPMA_NV TPMA_NV_POLICYREAD = 1U << 19;
constexpr TPMA_NV TPMA_NV_NO_DA = 1U << 25;
constexpr TPMA_NV TPMA_NV_ORDERLY = 1U << 26;
constexpr TPMA_NV TPMA_NV_CLEAR_STCLEAR = 1U << 27;
constexpr TPMA_NV TPMA_NV_READLOCKED = 1U << 28;
constexpr TPMA_NV TPMA_NV_WRITTEN = 1U << 29;
constexpr TPMA_NV TPMA_NV_PLATFORMCREATE = 1U << 30;
constexpr TPMA_NV TPMA_NV_READ_STCLEAR = 1U << 31;

// TPM Vendor-Specific commands (TPM Spec Part 2, section 6.5.1)
constexpr TPM_CC TPM_CC_VENDOR_SPECIFIC_MASK = 1U << 29;

// This needs to be used to be backwards compatible with older Cr50 versions.
constexpr TPM_CC TPM_CC_CR50_EXTENSION_COMMAND = 0xbaccd00a;

// Auth policy used in RSA and ECC templates for EK keys generation.
// From TCG Credential Profile EK 2.0. Section 2.1.5.
constexpr inline char kEKTemplateAuthPolicy[] = {
    '\x83', '\x71', '\x97', '\x67', '\x44', '\x84', '\xB3', '\xF8',
    '\x1A', '\x90', '\xCC', '\x8D', '\x46', '\xA5', '\xD7', '\x24',
    '\xFD', '\x52', '\xD7', '\x6E', '\x06', '\x52', '\x0B', '\x64',
    '\xF2', '\xA1', '\xDA', '\x1B', '\x33', '\x14', '\x69', '\xAA',
};

static_assert(sizeof(kEKTemplateAuthPolicy) == SHA256_DIGEST_SIZE,
              "auth policy not a sha256 digest.");

// Returns a `std::string_view` of `kEKTemplateAuthPolicy`.
constexpr inline std::string_view GetEkTemplateAuthPolicy() {
  return std::string_view(kEKTemplateAuthPolicy,
                          std::size(kEKTemplateAuthPolicy));
}

}  // namespace trunks

#endif  // TRUNKS_TPM_CONSTANTS_H_
