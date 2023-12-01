// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
#ifndef FEATURED_C_FAKE_FEATURE_LIBRARY_H_
#define FEATURED_C_FAKE_FEATURE_LIBRARY_H_

#include "featured/c_feature_library.h"
#include "featured/feature_export.h"

#if defined(__cplusplus)
extern "C" {
#endif

// C wrapper for `new FakePlatformFeatures()`
CFeatureLibrary FEATURE_EXPORT FakeCFeatureLibraryNew();

// Used only for freeing dynamically allocated resources in the fake.
void FEATURE_EXPORT FakeCFeatureLibraryDelete(CFeatureLibrary handle);

// C wrapper for FakePlatformFeatures::SetEnabled()
void FEATURE_EXPORT FakeCFeatureLibrarySetEnabled(CFeatureLibrary handle,
                                                  const char* const feature,
                                                  int enabled);

// C wrapper for FakePlatformFeatures::ClearEnabled()
void FEATURE_EXPORT FakeCFeatureLibraryClearEnabled(CFeatureLibrary handle,
                                                    const char* const feature);

// C wrapper for FakePlatformFeatures::SetParam()
void FEATURE_EXPORT FakeCFeatureLibrarySetParam(CFeatureLibrary handle,
                                                const char* const feature,
                                                const char* const key,
                                                const char* const value);

// C wrapper for FakePlatformFeatures::ClearParams()
void FEATURE_EXPORT FakeCFeatureLibraryClearParams(CFeatureLibrary handle,
                                                   const char* const feature);
#if defined(__cplusplus)
}  // extern "C"
#endif
#endif  // FEATURED_C_FAKE_FEATURE_LIBRARY_H_
