// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
#include "featured/c_fake_feature_library.h"

#include <stdio.h>

#include "featured/c_feature_library.h"

const struct VariationsFeature kCrOSLateBootMyAwesomeFeature = {
    .name = "CrOSLateBootMyAwesomeFeature",
    .default_state = FEATURE_DISABLED_BY_DEFAULT,
};

void GetParams(CFeatureLibrary lib) {
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

int main(int argc, char* argv[]) {
  CFeatureLibrary lib = FakeCFeatureLibraryNew();

  // Will use default value
  printf("%d\n",
         CFeatureLibraryIsEnabledBlocking(lib, &kCrOSLateBootMyAwesomeFeature));

  // Override to true
  FakeCFeatureLibrarySetEnabled(lib, kCrOSLateBootMyAwesomeFeature.name, 1);
  printf("%d\n",
         CFeatureLibraryIsEnabledBlocking(lib, &kCrOSLateBootMyAwesomeFeature));

  FakeCFeatureLibrarySetParam(lib, kCrOSLateBootMyAwesomeFeature.name, "key",
                              "value");
  GetParams(lib);
  FakeCFeatureLibraryClearParams(lib, kCrOSLateBootMyAwesomeFeature.name);
  GetParams(lib);

  // Override to false
  FakeCFeatureLibrarySetEnabled(lib, kCrOSLateBootMyAwesomeFeature.name, 0);
  printf("%d\n",
         CFeatureLibraryIsEnabledBlocking(lib, &kCrOSLateBootMyAwesomeFeature));

  // Reset to default value
  FakeCFeatureLibraryClearEnabled(lib, kCrOSLateBootMyAwesomeFeature.name);
  printf("%d\n",
         CFeatureLibraryIsEnabledBlocking(lib, &kCrOSLateBootMyAwesomeFeature));

  FakeCFeatureLibraryDelete(lib);
}
