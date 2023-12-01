#!/usr/bin/env bash
# Copyright 2022 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
set -euo pipefail

export BINDGEN_HEADER="// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(dead_code)]
"

bindgen_generate() {
    # Path to platform2 required for header resolution.
    search_root="$(dirname "$0")/../.."

    echo "${BINDGEN_HEADER}"
    bindgen \
        --disable-header-comment \
        --no-layout-tests \
        --size_t-is-usize \
        --allowlist-type='.*Feature.*' \
        --allowlist-function='.*Feature.*' \
        --allowlist-var='.*Feature.*' \
        "../c_fake_feature_library.h" \
        -- \
        -I "${search_root}"
}

bindgen_generate | rustfmt > src/bindings.rs
