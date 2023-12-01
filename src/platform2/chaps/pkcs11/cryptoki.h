// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHAPS_PKCS11_CRYPTOKI_H_
#define CHAPS_PKCS11_CRYPTOKI_H_

#define EXPORT_SPEC __attribute__ ((visibility ("default")))

#ifndef NULL_PTR
#define NULL_PTR 0
#endif

// Note that this file is not the only entrypoint for including pkcs11.h.
// chaps.cc also includes pkcs11f.h.
// Return values defined in pkcs11.h are persisted to logs and should not
// be renumbered and numeric values should never be reused.
// Please keep in sync with "ChapsSessionStatus" in
// tools/metrics/histograms/enums.xml in the Chromium repo.
#include <nss/pkcs11.h>

// Below are some workaround due to problems in the copy of pkcs11.h that we
// are including.

#ifndef CKK_INVALID_KEY_TYPE
#define CKK_INVALID_KEY_TYPE (CKK_VENDOR_DEFINED + 0)
#endif

// chaps is currently coded to PKCS#11 v3.0.

// CKM for ECDSA+SHA2 is only available on Cryptoki V3 or above,
// so we temporarily define them here.
#ifndef CKM_ECDSA_SHA256
#define CKM_ECDSA_SHA256 0x1044
#define CKM_ECDSA_SHA384 0x1045
#define CKM_ECDSA_SHA512 0x1046
#endif  // CKM_ECDSA_SHA256

#endif  // CHAPS_PKCS11_CRYPTOKI_H_
