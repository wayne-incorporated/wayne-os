// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBARC_ATTESTATION_LIB_EXPORT_H_
#define LIBARC_ATTESTATION_LIB_EXPORT_H_

// Use ARC_ATTESTATION_EXPORT to decorate APIs methods for export.
// This is similar to the BRILLO_EXPORT macro in libbrillo and see libbrillo's
// documentation for more info.
#define ARC_ATTESTATION_EXPORT __attribute__((__visibility__("default")))

#endif  // LIBARC_ATTESTATION_LIB_EXPORT_H_
