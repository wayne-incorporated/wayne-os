// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#[cfg(not(any(
    all(feature = "ti50_onboard", not(feature = "cr50_onboard")),
    all(not(feature = "ti50_onboard"), feature = "cr50_onboard")
)))]
compile_error!(
    "exactly one of the two features \
`ti50_onboard`, `cr50_onboard` should be specified"
);

#[cfg(feature = "ti50_onboard")]
pub const GSC_NAME: &str = "ti50";
#[cfg(not(feature = "ti50_onboard"))]
pub const GSC_NAME: &str = "cr50";

#[cfg(feature = "ti50_onboard")]
pub const GSC_IMAGE_BASE_NAME: &str = "/opt/google/cr50/firmware/ti50.bin";
#[cfg(not(feature = "ti50_onboard"))]
pub const GSC_IMAGE_BASE_NAME: &str = "/opt/google/cr50/firmware/cr50.bin";

#[cfg(feature = "ti50_onboard")]
pub const GSC_METRICS_PREFIX: &str = "Platform.Ti50";
#[cfg(not(feature = "ti50_onboard"))]
pub const GSC_METRICS_PREFIX: &str = "Platform.Cr50";

pub const GSCTOOL_CMD_NAME: &str = "/usr/sbin/gsctool";
