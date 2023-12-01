// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
#include <stdio.h>

#include "c_feature_library.h"

const struct VariationsFeature kCrOSLateBootMyAwesomeFeature = {
    .name = "CrOSLateBootMyAwesomeFeature",
    .default_state = FEATURE_DISABLED_BY_DEFAULT,
};

int main(int argc, char* argv[]) {
  if (!CFeatureLibraryInitialize()) {
    printf("Error initializing library. Exiting program\n");
    return 1;
  }
  CFeatureLibrary lib = CFeatureLibraryGet();
  printf("%d\n",
         CFeatureLibraryIsEnabledBlocking(lib, &kCrOSLateBootMyAwesomeFeature));

  const struct VariationsFeature* const arr[] = {
      &kCrOSLateBootMyAwesomeFeature};
  struct VariationsFeatureGetParamsResponseEntry entry;
  if (!CFeatureLibraryGetParamsAndEnabledBlocking(lib, arr, 1, &entry)) {
    printf("name: %s\n", entry.name);
    printf("   enabled: %d\n", entry.is_enabled);
    for (size_t i = 0; i < entry.num_params; i++) {
      printf("    params[%zu] = {key: '%s', value: '%s'}\n", i,
             entry.params[i].key, entry.params[i].value);
    }
    CFeatureLibraryFreeEntries(&entry, 1);
  } else {
    printf("Error getting feature\n");
  }
}
