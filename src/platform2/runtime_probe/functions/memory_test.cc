// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <base/containers/span.h>
#include <base/files/file_path.h>
#include <base/strings/stringprintf.h>
#include <gtest/gtest.h>

#include <algorithm>
#include <map>
#include <string>
#include <vector>

#include "runtime_probe/functions/memory.h"
#include "runtime_probe/probe_function.h"
#include "runtime_probe/utils/file_test_utils.h"
#include "runtime_probe/utils/function_test_utils.h"

namespace runtime_probe {
namespace {

constexpr auto kTestLength = 40;  // Should be >= DmiMemoryRaw in bytes.
constexpr auto kKbMask = 1UL << 15;
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

class MemoryTest : public BaseFunctionTest {
 protected:
  // @param text_strings: <string number, text string>, map string numbers in
  // dmi_memory to given strings.
  void SetDmiData(int slot_id,
                  DmiMemoryRaw dmi_memory,
                  std::map<int, std::string> text_strings) {
    std::vector<uint8_t> buffer(dmi_memory.length);

    uint8_t* ptr = reinterpret_cast<uint8_t*>(&dmi_memory);
    CHECK(buffer.size() >= sizeof(dmi_memory));
    std::copy(ptr, ptr + sizeof(dmi_memory), buffer.data());

    int current_index = 1;
    const std::string dont_care_text("don't care");
    for (const auto& [index, text] : text_strings) {
      for (; current_index < index; ++current_index) {
        // Text strings not in the map.
        buffer.insert(buffer.end(), dont_care_text.begin(),
                      dont_care_text.end());
        buffer.push_back('\0');
      }
      buffer.insert(buffer.end(), text.begin(), text.end());
      buffer.push_back('\0');
      current_index = index + 1;
    }

    SetFile({base::StringPrintf("sys/firmware/dmi/entries/%d-%d/raw",
                                kMemoryType, slot_id)},
            base::span<uint8_t>(buffer));
  }
};

TEST_F(MemoryTest, ProbeMemory) {
  const int locator_1 = 4;
  const int part_number_1 = 6;
  std::map<int, std::string> text_strings_1{{locator_1, "Channel-0-DIMM-0"},
                                            {part_number_1, "WXYZ1234-ABC"}};
  auto dmi_memory_raw_1 = DmiMemoryRaw{.length = kTestLength,
                                       .size = 4096,
                                       .locator = locator_1,
                                       .speed = 2933,
                                       .part_number = part_number_1};
  SetDmiData(0, dmi_memory_raw_1, text_strings_1);

  const int locator_2 = 4;
  const int part_number_2 = 6;
  std::map<int, std::string> text_strings_2{{locator_2, "Channel-1-DIMM-0"},
                                            {part_number_2, "WXYZ5678-ABC"}};
  auto dmi_memory_raw_2 = DmiMemoryRaw{.length = kTestLength,
                                       .size = 4096,
                                       .locator = locator_2,
                                       .speed = 2933,
                                       .part_number = part_number_2};
  SetDmiData(1, dmi_memory_raw_2, text_strings_2);

  auto ans = CreateProbeResultFromJson(R"JSON(
    [
      {
        "locator": "Channel-0-DIMM-0",
        "part": "WXYZ1234-ABC",
        "size": 4096,
        "slot": 0,
        "speed": 2933
      },
      {
        "locator": "Channel-1-DIMM-0",
        "part": "WXYZ5678-ABC",
        "size": 4096,
        "slot": 1,
        "speed": 2933
      }
    ]
  )JSON");
  ans[0].GetDict().Set(
      "path",
      GetPathUnderRoot(
          {base::StringPrintf("sys/firmware/dmi/entries/%d-0", kMemoryType)})
          .value());
  ans[1].GetDict().Set(
      "path",
      GetPathUnderRoot(
          {base::StringPrintf("sys/firmware/dmi/entries/%d-1", kMemoryType)})
          .value());

  auto probe_function = CreateProbeFunction<MemoryFunction>();
  auto result = probe_function->Eval();
  EXPECT_EQ(result, ans);
}

TEST_F(MemoryTest, ProbeKbMemory) {
  const int locator = 4;
  const int part_number = 6;
  std::map<int, std::string> text_strings{{locator, "Channel-0-DIMM-0"},
                                          {part_number, "WXYZ1234-ABC"}};
  auto dmi_memory_raw = DmiMemoryRaw{.length = kTestLength,
                                     .size = 4096 | kKbMask,
                                     .locator = locator,
                                     .speed = 2933,
                                     .part_number = part_number};
  SetDmiData(0, dmi_memory_raw, text_strings);

  auto ans = CreateProbeResultFromJson(R"JSON(
    [
      {
        "locator": "Channel-0-DIMM-0",
        "part": "WXYZ1234-ABC",
        "size": 4,
        "slot": 0,
        "speed": 2933
      }
    ]
  )JSON");
  ans[0].GetDict().Set(
      "path",
      GetPathUnderRoot(
          {base::StringPrintf("sys/firmware/dmi/entries/%d-0", kMemoryType)})
          .value());

  auto probe_function = CreateProbeFunction<MemoryFunction>();
  auto result = probe_function->Eval();
  EXPECT_EQ(result, ans);
}

TEST_F(MemoryTest, NoDmiData) {
  auto ans = CreateProbeResultFromJson(R"JSON(
    []
  )JSON");

  auto probe_function = CreateProbeFunction<MemoryFunction>();
  auto result = probe_function->Eval();
  EXPECT_EQ(result, ans);
}

TEST_F(MemoryTest, InvalidDmiData) {
  SetFile(
      {base::StringPrintf("sys/firmware/dmi/entries/%d-0/raw", kMemoryType)},
      base::span<uint8_t>{});  // Invalid data.

  const int locator = 4;
  const int part_number = 6;
  std::map<int, std::string> text_strings{{locator, "Channel-0-DIMM-0"},
                                          {part_number, "WXYZ1234-ABC"}};
  auto dmi_memory_raw = DmiMemoryRaw{.length = kTestLength,
                                     .size = 4096,
                                     .locator = locator,
                                     .speed = 2933,
                                     .part_number = part_number};
  SetDmiData(1, dmi_memory_raw, text_strings);

  // Return the valid one.
  auto ans = CreateProbeResultFromJson(R"JSON(
    [
      {
        "locator": "Channel-0-DIMM-0",
        "part": "WXYZ1234-ABC",
        "size": 4096,
        "slot": 1,
        "speed": 2933
      }
    ]
  )JSON");
  ans[0].GetDict().Set(
      "path",
      GetPathUnderRoot(
          {base::StringPrintf("sys/firmware/dmi/entries/%d-1", kMemoryType)})
          .value());

  auto probe_function = CreateProbeFunction<MemoryFunction>();
  auto result = probe_function->Eval();
  EXPECT_EQ(result, ans);
}

}  // namespace
}  // namespace runtime_probe
