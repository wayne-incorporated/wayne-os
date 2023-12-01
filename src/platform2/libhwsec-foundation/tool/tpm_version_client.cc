// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <base/logging.h>
#include <brillo/syslog_logging.h>

#include "libhwsec-foundation/tpm/tpm_version.h"

int main(int argc, char* argv[]) {
  brillo::InitLog(brillo::kLogToSyslog | brillo::kLogToStderr);

  TPM_SELECT_BEGIN;
  TPM1_SECTION({ printf("1\n"); });
  TPM2_SECTION({ printf("2\n"); });
  NO_TPM_SECTION({ printf("0\n"); });
  OTHER_TPM_SECTION({
    LOG(ERROR) << "Unknown TPM";
    return 1;
  });
  TPM_SELECT_END;

  return 0;
}
