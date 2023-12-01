// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TRUNKS_COMMAND_CODES_H_
#define TRUNKS_COMMAND_CODES_H_

#include <string>

#include "trunks/tpm_generated.h"  // For TPM_CC.
#include "trunks/trunks_export.h"

namespace trunks {

// Returns a description of |command|;
TRUNKS_EXPORT std::string GetCommandString(TPM_CC command);

// Creates a command with the given |command_code|.
TRUNKS_EXPORT std::string CreateCommand(TPM_CC command_code);

// Retrieves command code, |cc|, from the command string, |command|.
// Return TPM_RC_SUCCESS iff success.
TRUNKS_EXPORT TPM_RC GetCommandCode(const std::string& command, TPM_CC& cc);

// Return True iff the command is supported by all the TPMs.
TRUNKS_EXPORT bool IsGenericTpmCommand(TPM_CC command_code);

}  // namespace trunks

#endif  // TRUNKS_COMMAND_CODES_H_
