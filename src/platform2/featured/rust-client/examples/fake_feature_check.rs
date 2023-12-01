// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use featured::{CheckFeature, FakePlatformFeatures, Feature};

fn main() {
    let feature =
        Feature::new("CrOSLateBootMyAwesomeFeature", false).expect("Unable create feature");

    let mut features = FakePlatformFeatures::new().expect("Unable to create client");

    // Will use default value
    assert!(!features.is_feature_enabled_blocking(&feature));

    // Override to true
    features.set_feature_enabled(&feature, true);
    assert!(features.is_feature_enabled_blocking(&feature));

    // Set parameters
    let param_key = "key".to_string();
    let param_value = "value".to_string();
    features.set_param(&feature, &param_key, &param_value);
    let status = features
        .get_params_and_enabled(&[&feature])
        .expect("Unable to fetch feature status");
    assert_eq!(status.get_param(&feature, &param_key), Some(&param_value));

    // Clear parameters
    features.clear_params(&feature);
    let status = features
        .get_params_and_enabled(&[&feature])
        .expect("Unable to fetch feature status");
    assert_eq!(status.get_param(&feature, &param_key), None);

    // Override to false
    features.set_feature_enabled(&feature, false);
    assert!(!features.is_feature_enabled_blocking(&feature));

    // Reset to default value
    features.clear_feature_enabled(&feature);
    assert!(!features.is_feature_enabled_blocking(&feature));
}
