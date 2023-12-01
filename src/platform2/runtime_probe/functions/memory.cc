// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "runtime_probe/functions/memory.h"
#include "runtime_probe/system/context.h"

#include <algorithm>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/strings/stringprintf.h>
#include <base/values.h>

namespace runtime_probe {

namespace {

constexpr char kSysfsDmiPath[] = "sys/firmware/dmi/entries";
constexpr auto kMemoryType = 17;

// Refer to SMBIOS specification.
/*
https://www.dmtf.org/sites/default/files/standards/documents/DSP0134_3.3.0.pdf
*/
struct DmiMemoryRaw {
  // Header
  uint8_t type;
  uint8_t length;
  uint16_t handle;

  // Memory attributes
  uint8_t pad_1[8];       // skipped values
  uint16_t size;          // bit15: 0=MiB, 1=KiB
  uint8_t pad_2[2];       // skipped values
  uint8_t locator;        // string
  uint8_t pad_3[4];       // skipped values
  uint16_t speed;         // in MHz
  uint8_t manufacturer;   // string
  uint8_t serial_number;  // string
  uint8_t asset_tag;      // string
  uint8_t part_number;    // string
} __attribute__((packed));

struct DmiMemory {
  uint16_t size;
  uint16_t speed;
  std::string locator;
  std::string part_number;
};

uint16_t MemorySize(uint16_t size) {
  // bit 15: 0=MB, 1=KB
  if (size & (1UL << 15)) {
    size = (size ^ (1UL << 15)) >> 10;
  }
  return size;
}

// SmbiosString gets the string associated with the given SMBIOS raw data.
// If the arguments are valid, |id|-th string in the SMBIOS string table is
// returned; otherwise, nullptr is returned.
// See 6.1.3 Text strings in SMBIOS specification for more information.
std::unique_ptr<std::string> SmbiosString(const std::vector<uint8_t>& blob,
                                          uint8_t skip_bytes,
                                          uint8_t id) {
  auto output = std::make_unique<std::string>();
  if (id == 0)
    return output;
  uint8_t count = 0;
  auto data = reinterpret_cast<const char*>(blob.data());
  for (size_t i = skip_bytes, start_i = i; i < blob.size(); ++i) {
    if (data[i] == '\0') {
      ++count;
      if (count == id) {
        output->assign(data + start_i, i - start_i);
        return output;
      }
      start_i = i + 1;
    }
  }
  return nullptr;
}

std::unique_ptr<DmiMemory> GetDmiMemoryFromBlobData(
    const std::vector<uint8_t>& blob) {
  if (blob.size() < sizeof(DmiMemoryRaw))
    return nullptr;

  DmiMemoryRaw dmi_memory_raw;
  std::copy(blob.begin(), blob.begin() + sizeof(DmiMemoryRaw),
            reinterpret_cast<uint8_t*>(&dmi_memory_raw));

  if (dmi_memory_raw.length < sizeof(DmiMemoryRaw))
    return nullptr;

  auto dmi_memory = std::make_unique<DmiMemory>();
  dmi_memory->size = MemorySize(dmi_memory_raw.size);
  dmi_memory->speed = dmi_memory_raw.speed;

  auto ret = SmbiosString(blob, dmi_memory_raw.length, dmi_memory_raw.locator);
  if (!ret)
    return nullptr;
  dmi_memory->locator = std::move(*ret);

  ret = SmbiosString(blob, dmi_memory_raw.length, dmi_memory_raw.part_number);
  if (!ret)
    return nullptr;
  dmi_memory->part_number = std::move(*ret);
  return dmi_memory;
}

MemoryFunction::DataType GetMemoryInfo() {
  MemoryFunction::DataType results{};

  const base::FilePath dmi_dirname(
      Context::Get()->root_dir().Append(kSysfsDmiPath));
  for (int entry = 0;; ++entry) {
    const base::FilePath dmi_basename(
        base::StringPrintf("%d-%d", kMemoryType, entry));
    auto dmi_path = dmi_dirname.Append(dmi_basename);
    if (!base::DirectoryExists(dmi_path))
      break;
    std::string raw_bytes;
    if (!base::ReadFileToString(dmi_path.Append("raw"), &raw_bytes)) {
      LOG(ERROR) << "Failed to read file in sysfs: " << dmi_path.value();
      continue;
    }

    auto dmi_memory = GetDmiMemoryFromBlobData(
        std::vector<uint8_t>(raw_bytes.begin(), raw_bytes.end()));
    if (!dmi_memory) {
      LOG(ERROR) << "Failed to parse DMI raw data: " << dmi_path.value();
      continue;
    }

    // The field "slot" denotes to the entry number instead of the physical slot
    // number, which refers to mosys' output. To be compatible with current
    // HWID, we still preserve this field.
    auto info = base::Value::Dict()
                    .Set("slot", entry)
                    .Set("path", dmi_path.value())
                    .Set("size", dmi_memory->size)
                    .Set("speed", dmi_memory->speed)
                    .Set("locator", dmi_memory->locator)
                    .Set("part", dmi_memory->part_number);
    results.Append(std::move(info));
  }

  return results;
}

}  // namespace

MemoryFunction::DataType MemoryFunction::EvalImpl() const {
  return GetMemoryInfo();
}

}  // namespace runtime_probe
