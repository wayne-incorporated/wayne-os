// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
#include "featured/c_feature_library.h"

#include <stdlib.h>
#include <strings.h>

#include <vector>

#include <dbus/bus.h>

#include "featured/feature_library.h"

extern "C" bool CFeatureLibraryInitialize() {
  dbus::Bus::Options options;
  options.bus_type = dbus::Bus::SYSTEM;
  scoped_refptr<dbus::Bus> bus(new dbus::Bus(options));

  return feature::PlatformFeatures::Initialize(bus);
}

extern "C" CFeatureLibrary CFeatureLibraryGet() {
  return reinterpret_cast<CFeatureLibrary>(feature::PlatformFeatures::Get());
}

extern "C" int CFeatureLibraryIsEnabledBlocking(
    CFeatureLibrary handle, const struct VariationsFeature* const feature) {
  auto* library = reinterpret_cast<feature::PlatformFeaturesInterface*>(handle);
  return library->IsEnabledBlocking(*feature);
}

extern "C" int CFeatureLibraryIsEnabledBlockingWithTimeout(
    CFeatureLibrary handle,
    const struct VariationsFeature* const feature,
    int timeout_ms) {
  auto* library = reinterpret_cast<feature::PlatformFeaturesInterface*>(handle);
  return library->IsEnabledBlockingWithTimeout(*feature, timeout_ms);
}

extern "C" int CFeatureLibraryGetParamsAndEnabledBlocking(
    CFeatureLibrary handle,
    const struct VariationsFeature* const* features,
    size_t num_features,
    struct VariationsFeatureGetParamsResponseEntry* entries) {
  auto* library = reinterpret_cast<feature::PlatformFeaturesInterface*>(handle);

  // Initialize vector from C-style array
  std::vector<const VariationsFeature*> features_vec(features,
                                                     &features[num_features]);
  auto result = library->GetParamsAndEnabledBlocking(features_vec);
  CHECK_EQ(result.size(), num_features);

  // Zero out memory to avoid uninitialized reads later (e.g. from num_params or
  // params) and to simplify cleanup logic on errors.
  bzero(entries, num_features * sizeof(*entries));

  size_t i = 0;
  for (const auto& [name, entry] : result) {
    // Allocate and copy name
    size_t size = name.size() + 1;
    entries[i].name = reinterpret_cast<char*>(calloc(size, sizeof(char)));
    if (!entries[i].name) {
      // Clean up all previously-allocated memory.
      CFeatureLibraryFreeEntries(entries, i);
      return -1;
    }
    strncpy(entries[i].name, name.c_str(), size);

    entries[i].is_enabled = entry.enabled;

    entries[i].num_params = entry.params.size();

    entries[i].params = reinterpret_cast<struct VariationsFeatureParam*>(
        calloc(entries[i].num_params, sizeof(VariationsFeatureParam)));
    if (!entries[i].params) {
      // Clean up all allocated memory, including that allocated on this
      // iteration.
      // (This is safe because free(nullptr) is a no-op.)
      CFeatureLibraryFreeEntries(entries, i + 1);
      return -1;
    }

    size_t j = 0;
    for (const auto& [key, value] : entry.params) {
      entries[i].params[j].key =
          reinterpret_cast<char*>(calloc(key.size() + 1, sizeof(char)));
      entries[i].params[j].value =
          reinterpret_cast<char*>(calloc(value.size() + 1, sizeof(char)));

      if (!(entries[i].params[j].key) || !(entries[i].params[j].value)) {
        // Clean up all allocated memory on failure to allocate, including that
        // allocated on this iteration.
        // (free(nullptr) is defined to be a noop).
        CFeatureLibraryFreeEntries(entries, i + 1);
        return -1;
      }

      // Copy, including null terminator.
      strncpy(entries[i].params[j].key, key.c_str(), key.size() + 1);
      strncpy(entries[i].params[j].value, value.c_str(), value.size() + 1);

      j++;
    }
    i++;
  }

  return 0;
}

extern "C" void CFeatureLibraryFreeEntries(
    struct VariationsFeatureGetParamsResponseEntry* entries,
    size_t num_features) {
  for (size_t i = 0; i < num_features; i++) {
    free(entries[i].name);
    entries[i].name = nullptr;
    for (size_t j = 0; j < entries[i].num_params; j++) {
      free(entries[i].params[j].key);
      entries[i].params[j].key = nullptr;
      free(entries[i].params[j].value);
      entries[i].params[j].value = nullptr;
    }
    free(entries[i].params);
    entries[i].params = nullptr;
  }
  bzero(entries, num_features * sizeof(*entries));
}
