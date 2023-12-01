// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use featured::{CheckFeature, Feature, PlatformFeatures};
use log::info;

fn main() {
    let features = PlatformFeatures::get().expect("Unable to get client");

    let feature =
        Feature::new("CrOSLateBootMyAwesomeFeature", false).expect("Unable to create feature");
    let is_enabled = features.is_feature_enabled_blocking(&feature);
    info!("Feature is enabled: {}", is_enabled);

    let status = features
        .get_params_and_enabled(&[&feature])
        .expect("Unable to fetch feature status");
    info!("Feature params: {:?}", status.get_params(&feature).unwrap());
}
