// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
#ifndef FEATURED_C_FEATURE_LIBRARY_H_
#define FEATURED_C_FEATURE_LIBRARY_H_

#include <stdbool.h>
#include <stddef.h>

#include "featured/feature_export.h"

#if defined(__cplusplus)
extern "C" {
#endif

// Specifies whether a given feature is enabled or disabled by default.
// NOTE: The actual runtime state may be different, due to a field trial or a
// command line switch.
enum FEATURE_EXPORT FeatureState {
  FEATURE_DISABLED_BY_DEFAULT,
  FEATURE_ENABLED_BY_DEFAULT,
};

// The VariationsFeature struct is used to define the default state for a
// feature. See comment below for more details. There must only ever be one
// struct instance for a given feature name - generally defined as a constant
// global variable or file static. It should never be used as a constexpr as it
// breaks pointer-based identity lookup.
struct FEATURE_EXPORT VariationsFeature {
  // The name of the feature. This should be unique to each feature and is used
  // for enabling/disabling features via command line flags and experiments.
  // It is strongly recommended to use CamelCase style for feature names, e.g.
  // "MyGreatFeature".
  // In almost all cases, your feature name should start with "CrOSLateBoot",
  // otherwise the lookup will fail.
  const char* const name;

  // The default state (i.e. enabled or disabled) for this feature.
  // NOTE: The actual runtime state may be different, due to a field trial or a
  // command line switch.
  const enum FeatureState default_state;
};

struct FEATURE_EXPORT VariationsFeatureParam {
  char* key;
  char* value;
};

struct FEATURE_EXPORT VariationsFeatureGetParamsResponseEntry {
  char* name;
  int is_enabled;
  struct VariationsFeatureParam* params;
  size_t num_params;
};

typedef struct CFeatureLibraryOpaque* CFeatureLibrary;

// C wrapper for PlatformFeatures::Initialize()
bool FEATURE_EXPORT CFeatureLibraryInitialize();

// C wrapper for PlatformFeatures::Get()
CFeatureLibrary FEATURE_EXPORT CFeatureLibraryGet();

// C wrapper for PlatformFeatures::IsEnabled is NOT defined, since different
// language thread runtimes will likely be incompatible with C++'s
// SequencedTaskRunner.

// C wrapper for PlatformFeatures::IsEnabledBlocking, with the default timeout.
int FEATURE_EXPORT CFeatureLibraryIsEnabledBlocking(
    CFeatureLibrary handle, const struct VariationsFeature* const feature);

// C wrapper for PlatformFeatures::IsEnabledBlocking, with a timeout.
int FEATURE_EXPORT CFeatureLibraryIsEnabledBlockingWithTimeout(
    CFeatureLibrary handle,
    const struct VariationsFeature* const feature,
    int timeout_ms);

// C wrapper for PlatformFeatures::GetParamsAndEnabled is NOT defined, since
// different language thread runtimes will likely be incompatible with C++'s
// SequencedTaskRunner.

// Looks up the parameters for the given features, populating |entries| with
// |num_features| responses, as appropriate.
// |entries| must point to at least
// |num_features*sizeof(VariationsFeatureGetParamsResponseEntry)| allocated
// bytes.
//
// |features| should be an array of pointers to VariationsFeature objects
//
// If this function returns 0, it will populate |entries| and |num_params|. The
// caller is responsible for calling CFeatureLibraryFreeEntries() to deallocate
// any allocated memory internal to the struct.
// If this function returns -1, it will free any memory allocated. The value of
// |entries| is unspecified.
//
// The caller retains ownership of |entries| and is responsible for deallocating
// it, if necessary.
int FEATURE_EXPORT CFeatureLibraryGetParamsAndEnabledBlocking(
    CFeatureLibrary handle,
    const struct VariationsFeature* const* features,
    size_t num_features,
    struct VariationsFeatureGetParamsResponseEntry* entries);

// Free the contents of the entries structure allocated by
// CFeatureLibraryGetParamsBlocking.
// Does *not* free entries--caller is responsible for managing that memory.
void FEATURE_EXPORT CFeatureLibraryFreeEntries(
    struct VariationsFeatureGetParamsResponseEntry* entries,
    size_t num_features);

#if defined(__cplusplus)
}  // extern "C"
#endif
#endif  // FEATURED_C_FEATURE_LIBRARY_H_
