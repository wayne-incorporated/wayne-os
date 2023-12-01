/*
 * Copyright 2020 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include <algorithm>
#include <utility>
#include <vector>

#include "common/libcamera_connector/camera_metadata_utils.h"

namespace cros {

mojom::CameraMetadataEntryPtr* GetMetadataEntry(
    const mojom::CameraMetadataPtr& camera_metadata,
    mojom::CameraMetadataTag tag) {
  if (!camera_metadata || !camera_metadata->entries.has_value()) {
    return nullptr;
  }
  for (auto& entry : camera_metadata->entries.value()) {
    if (entry->tag == tag) {
      return &entry;
    }
  }
  return nullptr;
}

void AddOrUpdateMetadataEntry(mojom::CameraMetadataPtr* to,
                              mojom::CameraMetadataEntryPtr entry) {
  auto* e = GetMetadataEntry(*to, entry->tag);
  if (e) {
    (*to)->data_count += entry->data.size() - (*e)->data.size();
    (*to)->data_capacity = std::max((*to)->data_capacity, (*to)->data_count);
    (*e)->count = entry->count;
    (*e)->data = std::move(entry->data);
  } else {
    entry->index = (*to)->entries->size();
    (*to)->entry_count += 1;
    (*to)->entry_capacity = std::max((*to)->entry_capacity, (*to)->entry_count);
    (*to)->data_count += entry->data.size();
    (*to)->data_capacity = std::max((*to)->data_capacity, (*to)->data_count);
    if (!(*to)->entries) {
      (*to)->entries = std::vector<mojom::CameraMetadataEntryPtr>();
    }
    (*to)->entries->push_back(std::move(entry));
  }
}

void SetFpsRangeInMetadata(mojom::CameraMetadataPtr* settings,
                           int32_t frame_rate) {
  const int32_t entry_length = 2;

  // CameraMetadata is represented as an uint8 array. According to the
  // definition of the FPS metadata tag, its data type is int32, so we
  // reinterpret_cast here.
  std::vector<uint8_t> fps_range(sizeof(int32_t) * entry_length);
  auto* fps_ptr = reinterpret_cast<int32_t*>(fps_range.data());
  fps_ptr[0] = fps_ptr[1] = frame_rate;
  mojom::CameraMetadataEntryPtr e = mojom::CameraMetadataEntry::New();
  e->tag = mojom::CameraMetadataTag::ANDROID_CONTROL_AE_TARGET_FPS_RANGE;
  e->type = mojom::EntryType::TYPE_INT32;
  e->count = entry_length;
  e->data = std::move(fps_range);

  AddOrUpdateMetadataEntry(settings, std::move(e));
}

}  // namespace cros
