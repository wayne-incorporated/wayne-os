// Copyright 2011 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHAPS_CHAPS_H_
#define CHAPS_CHAPS_H_

#include "pkcs11/cryptoki.h"

// Chaps-specific return values:
#define CKR_CHAPS_SPECIFIC_FIRST (CKR_VENDOR_DEFINED + 0x47474c00)
// Error code returned in case if the operation would block waiting
// for private objects to load for the token. This value is persisted to logs
// and should not be renumbered and numeric values should never be reused.
// Please keep in sync with "ChapsSessionStatus" in
// tools/metrics/histograms/enums.xml in the Chromium repo.
#define CKR_WOULD_BLOCK_FOR_PRIVATE_OBJECTS (CKR_CHAPS_SPECIFIC_FIRST + 0)

namespace chaps {

inline constexpr char kSystemTokenPath[] = "/var/lib/chaps";

inline constexpr size_t kTokenLabelSize = 32;
inline constexpr CK_ATTRIBUTE_TYPE kKeyBlobAttribute = CKA_VENDOR_DEFINED + 1;
inline constexpr CK_ATTRIBUTE_TYPE kAuthDataAttribute = CKA_VENDOR_DEFINED + 2;
// If this attribute is set to true at creation or generation time, then the
// object will not be stored/wrapped in hardware-backed security element, and
// will remain purely in software.
inline constexpr CK_ATTRIBUTE_TYPE kForceSoftwareAttribute =
    CKA_VENDOR_DEFINED + 4;
// This attribute is set to false if the key is stored in hardware-backed
// security element, and true otherwise.
inline constexpr CK_ATTRIBUTE_TYPE kKeyInSoftware = CKA_VENDOR_DEFINED + 5;
// If this attribute is set to true at creation or generation time, then the
// object may be generated in software, but still stored/wrapped in the
// hardware-backed security element.
inline constexpr CK_ATTRIBUTE_TYPE kAllowSoftwareGenAttribute =
    CKA_VENDOR_DEFINED + 6;

}  // namespace chaps

#endif  // CHAPS_CHAPS_H_
