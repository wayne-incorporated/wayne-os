// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// The name of this file must not be modified

#ifndef HWSEC_OPTEE_TA_USER_TA_HEADER_DEFINES_H_
#define HWSEC_OPTEE_TA_USER_TA_HEADER_DEFINES_H_

#include "hwsec-optee-ta/hwsec_ta.h"

#define TA_UUID HWSEC_TA_UUID

#define TA_FLAGS 0

// Provisioned stack size
#define TA_STACK_SIZE (2 * 1024)

// Provisioned heap size for TEE_Malloc() and friends
#define TA_DATA_SIZE (32 * 1024)

// The gpd.ta.version property
#define TA_VERSION "1.0"

// The gpd.ta.description property
#define TA_DESCRIPTION "HWSec Trusted Application"

#endif  // HWSEC_OPTEE_TA_USER_TA_HEADER_DEFINES_H_
