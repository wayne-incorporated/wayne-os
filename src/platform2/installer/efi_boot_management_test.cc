// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <cros_config/fake_cros_config.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <list>
#include <map>
#include <optional>
#include <vector>

#include "installer/efi_boot_management.cc"
#include "installer/efivar.cc"
#include "installer/mock_metrics.h"

using testing::Contains;
using testing::Key;
using testing::NiceMock;
using testing::Pair;
using testing::Return;
using testing::UnorderedElementsAre;

namespace {

// Actual device data to satisfy checks libefivar does internally.
// Grabbed these from my vm.
const uint8_t kExampleDataQemuDisk[] =
    "\x01\x00\x00\x00\x1E\x00\x55\x00\x45\x00\x46\x00\x49\x00\x20\x00\x51\x00"
    "\x45\x00\x4D\x00\x55\x00\x20\x00\x48\x00\x41\x00\x52\x00\x44\x00\x44\x00"
    "\x49\x00\x53\x00\x4B\x00\x20\x00\x51\x00\x4D\x00\x30\x00\x30\x00\x30\x00"
    "\x30\x00\x31\x00\x20\x00\x00\x00\x02\x01\x0C\x00\xD0\x41\x03\x0A\x00\x00"
    "\x00\x00\x01\x01\x06\x00\x01\x01\x03\x01\x08\x00\x00\x00\x00\x00\x7F\xFF"
    "\x04\x00\x4E\xAC\x08\x81\x11\x9F\x59\x4D\x85\x0E\xE2\x1A\x52\x2C\x59\xB2";
const char kExampleDescriptionQemuDisk[] = "UEFI QEMU HARDDISK QM00001 ";
const uint8_t kExamplePathQemuDisk[] =
    "\x02\x01\x0C\x00\xD0\x41\x03\x0A\x00\x00\x00\x00\x01\x01\x06\x00\x01\x01"
    "\x03\x01\x08\x00\x00\x00\x00\x00\x7F\xFF\x04";

const uint8_t kExampleDataQemuPXE[] =
    "\x01\x00\x00\x00\x56\x00\x55\x00\x45\x00\x46\x00\x49\x00\x20\x00\x50\x00"
    "\x58\x00\x45\x00\x76\x00\x34\x00\x20\x00\x28\x00\x4d\x00\x41\x00\x43\x00"
    "\x3a\x00\x41\x00\x41\x00\x41\x00\x41\x00\x41\x00\x41\x00\x30\x00\x35\x00"
    "\x34\x00\x37\x00\x37\x00\x37\x00\x29\x00\x00\x00\x02\x01\x0c\x00\xd0\x41"
    "\x03\x0a\x00\x00\x00\x00\x01\x01\x06\x00\x00\x03\x03\x0b\x25\x00\xaa\xaa"
    "\xaa\x05\x47\x77\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x03\x0c\x1b\x00\x00"
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    "\x00\x00\x00\x00\x7f\xff\x04\x00\x4e\xac\x08\x81\x11\x9f\x59\x4d\x85\x0e"
    "\xe2\x1a\x52\x2c\x59\xb2";
const char kExampleDescriptionQemuPXE[] = "UEFI PXEv4 (MAC:AAAAAA054777)";
const uint8_t kExamplePathQemuPXE[] =
    "\x02\x01\x0c\x00\xd0\x41\x03\x0a\x00\x00\x00\x00\x01\x01\x06\x00\x00\x03"
    "\x03\x0b\x25\x00\xaa\xaa\xaa\x05\x47\x77\x00\x00\x00\x00\x00\x00\x00\x00"
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    "\x01\x03\x0c\x1b\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x7f\xff\x04";

const uint8_t kExampleDataLinux[] =
    "\x01\x00\x00\x00\x5C\x00\x4C\x00\x69\x00\x6E\x00\x75\x00\x78\x00\x00\x00"
    "\x04\x01\x2A\x00\x01\x00\x00\x00\x00\xA0\x4E\x00\x00\x00\x00\x00\x81\x30"
    "\x80\x00\x00\x00\x00\x00\x5A\x0C\x9F\x8D\x75\x4C\x44\x09\x86\xCD\x6E\x51"
    "\x01\xAC\xE7\x5A\x02\x02\x04\x04\x2E\x00\x5C\x00\x45\x00\x46\x00\x49\x00"
    "\x5C\x00\x47\x00\x65\x00\x6E\x00\x74\x00\x6F\x00\x6F\x00\x5C\x00\x67\x00"
    "\x72\x00\x75\x00\x62\x00\x2E\x00\x65\x00\x66\x00\x69\x00\x00\x00\x7F\xFF"
    "\x04";

const uint8_t kExampleDataCros[] =
    "\x01\x00\x00\x00\x5E\x00\x43\x00\x68\x00\x72\x00\x6F\x00\x6D\x00\x69\x00"
    "\x75\x00\x6D\x00\x4F\x00\x53\x00\x00\x00\x04\x01\x2A\x00\x0C\x00\x00\x00"
    "\x00\x90\x01\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x34\xEB"
    "\x97\xB6\x17\xB3\x43\xA6\x97\xDE\x49\x70\x9D\xF0\xB6\x03\x02\x02\x04\x04"
    "\x30\x00\x5C\x00\x65\x00\x66\x00\x69\x00\x5C\x00\x62\x00\x6F\x00\x6F\x00"
    "\x74\x00\x5C\x00\x62\x00\x6F\x00\x6F\x00\x74\x00\x78\x00\x36\x00\x34\x00"
    "\x2E\x00\x65\x00\x66\x00\x69\x00\x00\x00\x7F\xFF\x04";
const char kExampleDescriptionCros[] = "ChromiumOS";
const uint8_t kExamplePathCros[] =
    "\x04\x01\x2A\x00\x0C\x00\x00\x00\x00\x90\x01\x00\x00\x00\x00\x00\x00\x00"
    "\x02\x00\x00\x00\x00\x00\x34\xEB\x97\xB6\x17\xB3\x43\xA6\x97\xDE\x49\x70"
    "\x9D\xF0\xB6\x03\x02\x02\x04\x04\x30\x00\x5C\x00\x65\x00\x66\x00\x69\x00"
    "\x5C\x00\x62\x00\x6F\x00\x6F\x00\x74\x00\x5C\x00\x62\x00\x6F\x00\x6F\x00"
    "\x74\x00\x78\x00\x36\x00\x34\x00\x2E\x00\x65\x00\x66\x00\x69\x00\x00\x00"
    "\x7F\xFF\x04";

const uint8_t kExampleBootOrder123[] = "\x01\x00\x02\x00\x03\x00";
const uint8_t kExampleBootOrderDuplicate[] = "\x01\x00\x02\x00\x01\x00";
const uint8_t kRawBootOrderSentinel[] = "\xBA\xAD\xF0\x0D";

class EfiVarFake : public EfiVarInterface {
 public:
  bool EfiVariablesSupported() override { return true; }

  std::optional<std::string> GetNextVariableName() override {
    if (variable_names_.size() == 0) {
      return std::nullopt;
    }

    std::optional<std::string> result(variable_names_.back());
    variable_names_.pop_back();
    return result;
  }

  bool GetVariable(const std::string& name,
                   Bytes& output_data,
                   size_t* data_size) override {
    auto pair = data_.find(name);

    if (pair == data_.end()) {
      return false;
    }

    auto value = pair->second;

    *data_size = value.size();
    uint8_t* data_ptr = reinterpret_cast<uint8_t*>(malloc(value.size()));
    std::copy(value.begin(), value.end(), data_ptr);
    output_data.reset(data_ptr);

    return true;
  }

  std::optional<EfiVarError> SetVariable(const std::string& name,
                                         uint32_t attributes,
                                         std::vector<uint8_t>& data) override {
    // Read desired return from our list of results.
    std::optional<EfiVarError> result = std::nullopt;
    if (!set_variable_result_.empty()) {
      result = set_variable_result_.front();
      set_variable_result_.pop_front();
    }

    // Simulated success.
    if (!result) {
      // Store in `data_` for checking later.
      data_.insert_or_assign(name, data);
    }

    return result;
  }

  bool DelVariable(const std::string& name) override {
    data_.erase(name);
    return true;
  }

  bool GenerateFileDevicePathFromEsp(
      const base::FilePath& device_path,
      PartitionNum esp_partition,
      const base::FilePath& boot_file,
      std::vector<uint8_t>& efidp_data) override {
    // Put our "cros" data in there
    efidp_data.assign(kExamplePathCros,
                      kExamplePathCros + sizeof(kExamplePathCros));
    return true;
  }

  void SetData(const std::map<std::string, std::vector<uint8_t>>& data) {
    data_ = data;
    for (const auto& [key, _] : data_) {
      variable_names_.push_back(key);
    }
  }

  std::map<std::string, std::vector<uint8_t>> data_;
  // Hang onto these for `GetNextVariableName`
  std::vector<std::string> variable_names_;

  // Allows setting return value on `SetVariable`.
  // I suspect there's a way to get gMock to handle this.
  std::list<std::optional<EfiVarError>> set_variable_result_;
};

// Helpers for quick/clear construction of test data.
std::vector<uint8_t> VecU8From(const uint8_t* ex, const size_t size) {
  return std::vector<uint8_t>(ex, ex + size);
}

std::pair<EfiBootNumber, EfiBootEntryContents> BootPair(
    uint16_t num,
    const std::string& desc,
    const std::vector<uint8_t>& device_path) {
  return std::make_pair(EfiBootNumber(num),
                        EfiBootEntryContents(desc, device_path));
}

BootOrder BootOrderFromExample(const uint8_t* ex, const size_t size) {
  EfiVarFake efivar;
  BootOrder boot_order;

  efivar.data_.insert({"BootOrder", VecU8From(ex, size)});

  boot_order.Load(efivar);

  return boot_order;
}

std::vector<uint8_t> BootOrderData(const std::vector<uint16_t>& input) {
  return std::vector<uint8_t>(reinterpret_cast<const uint8_t*>(input.data()),
                              reinterpret_cast<const uint8_t*>(input.data()) +
                                  (input.size() * sizeof(uint16_t)));
}

}  // namespace

TEST(EfiDescriptionTest, Default) {
  EXPECT_EQ(kCrosEfiDefaultDescription, EfiDescription());
}

TEST(EfiDescriptionTest, Override) {
  auto cros_config = std::make_unique<brillo::FakeCrosConfig>();

  cros_config->SetString(kCrosConfigEfiDescriptionPath,
                         kCrosConfigEfiDescriptionKey, "test override");

  EXPECT_EQ("test override", EfiDescription(std::move(cros_config)));
}

TEST(EfiBootEntryContentsTest, Equals) {
  EfiBootEntryContents entryLinux(
      kExampleDescriptionQemuPXE,
      VecU8From(kExamplePathQemuPXE, sizeof(kExamplePathQemuPXE)));
  EfiBootEntryContents entryCrosA(
      kExampleDescriptionCros,
      VecU8From(kExamplePathCros, sizeof(kExamplePathCros)));
  EfiBootEntryContents entryCrosB(
      kExampleDescriptionCros,
      VecU8From(kExamplePathCros, sizeof(kExamplePathCros)));

  EXPECT_FALSE(entryCrosA == entryLinux);
  EXPECT_TRUE(entryCrosA == entryCrosB);
}

class BootOrderTest : public ::testing::Test {
 protected:
  BootOrderTest() {}

  EfiVarFake efivar_;
  BootOrder boot_order_;
};

TEST_F(BootOrderTest, Load) {
  efivar_.SetData({{"BootOrder", VecU8From(kExampleBootOrder123,
                                           sizeof(kExampleBootOrder123))}});

  boot_order_.Load(efivar_);

  EXPECT_EQ(boot_order_.Data(), std::vector<uint16_t>({1, 2, 3}));
}

TEST_F(BootOrderTest, LoadNothing) {
  efivar_.SetData({});

  boot_order_.Load(efivar_);

  EXPECT_EQ(boot_order_.Data(), std::vector<uint16_t>());
}

TEST_F(BootOrderTest, NoWriteNeeded) {
  efivar_.SetData({{"BootOrder", VecU8From(kExampleBootOrder123,
                                           sizeof(kExampleBootOrder123))}});

  boot_order_.Load(efivar_);

  // Clear with sentinel
  efivar_.SetData({{"BootOrder", VecU8From(kRawBootOrderSentinel,
                                           sizeof(kRawBootOrderSentinel))}});

  std::optional<EfiVarError> error = boot_order_.WriteIfNeeded(efivar_);
  EXPECT_FALSE(error);
  // Confirm it's still set to the sentinel.
  EXPECT_THAT(
      efivar_.data_,
      Contains(Pair("BootOrder", VecU8From(kRawBootOrderSentinel,
                                           sizeof(kRawBootOrderSentinel)))));
}

TEST_F(BootOrderTest, Remove) {
  efivar_.SetData({{"BootOrder", VecU8From(kExampleBootOrder123,
                                           sizeof(kExampleBootOrder123))}});

  boot_order_.Load(efivar_);
  boot_order_.Remove(EfiBootNumber(1));

  std::optional<EfiVarError> error = boot_order_.WriteIfNeeded(efivar_);
  EXPECT_FALSE(error);
  EXPECT_THAT(efivar_.data_,
              Contains(Pair("BootOrder", BootOrderData({2, 3}))));
}

TEST_F(BootOrderTest, RemoveDuplicate) {
  efivar_.SetData(
      {{"BootOrder", VecU8From(kExampleBootOrderDuplicate,
                               sizeof(kExampleBootOrderDuplicate))}});

  boot_order_.Load(efivar_);
  boot_order_.Remove(EfiBootNumber(1));

  std::optional<EfiVarError> error = boot_order_.WriteIfNeeded(efivar_);
  EXPECT_FALSE(error);
  EXPECT_THAT(efivar_.data_, Contains(Pair("BootOrder", BootOrderData({2}))));
}

TEST_F(BootOrderTest, Add) {
  efivar_.SetData({{"BootOrder", VecU8From(kExampleBootOrder123,
                                           sizeof(kExampleBootOrder123))}});

  boot_order_.Load(efivar_);
  boot_order_.Add(EfiBootNumber(4));

  std::optional<EfiVarError> error = boot_order_.WriteIfNeeded(efivar_);
  EXPECT_FALSE(error);
  EXPECT_THAT(efivar_.data_,
              Contains(Pair("BootOrder", BootOrderData({4, 1, 2, 3}))));
}

TEST_F(BootOrderTest, Contains) {
  efivar_.SetData({{"BootOrder", VecU8From(kExampleBootOrder123,
                                           sizeof(kExampleBootOrder123))}});

  boot_order_.Load(efivar_);

  EXPECT_FALSE(boot_order_.Contains(EfiBootNumber(0)));
  EXPECT_TRUE(boot_order_.Contains(EfiBootNumber(1)));
  EXPECT_TRUE(boot_order_.Contains(EfiBootNumber(3)));
  EXPECT_FALSE(boot_order_.Contains(EfiBootNumber(9)));
}

class EfiBootManagerTest : public ::testing::Test {
 protected:
  void SetUp() override {
    efi_boot_manager_ = std::make_unique<EfiBootManager>(
        std::make_unique<EfiVarFake>(),
        std::make_unique<NiceMock<MockMetrics>>(), kCrosEfiDefaultDescription);
    // We know these casts are safe because we just created the objects.
    efivar_ = static_cast<EfiVarFake*>(efi_boot_manager_->EfiVar());
    metrics_ = static_cast<MockMetrics*>(efi_boot_manager_->Metrics());
  }

  // Store as a pointer because we can't reassign in SetUp: EfiBootManager has
  // no copy constructor.
  std::unique_ptr<EfiBootManager> efi_boot_manager_;
  // Store pointers to these, which live in efi_boot_manager.
  EfiVarFake* efivar_;
  MockMetrics* metrics_;
};

TEST_F(EfiBootManagerTest, LoadEntry) {
  efivar_->SetData({{"BootFFFF", VecU8From(kExampleDataQemuDisk,
                                           sizeof(kExampleDataQemuDisk))}});

  auto result = efi_boot_manager_->LoadEntry(EfiBootNumber(0xFFFF));

  ASSERT_TRUE(result.has_value());
  EXPECT_EQ(result->Description(), kExampleDescriptionQemuDisk);
  EXPECT_EQ(result->DevicePath(),
            VecU8From(kExamplePathQemuDisk, sizeof(kExamplePathQemuDisk)));
}

TEST_F(EfiBootManagerTest, LoadNonDiskEntry) {
  efivar_->SetData({{"BootFFFF", VecU8From(kExampleDataQemuPXE,
                                           sizeof(kExampleDataQemuPXE))}});

  auto result = efi_boot_manager_->LoadEntry(EfiBootNumber(0xFFFF));

  ASSERT_TRUE(result.has_value());
  EXPECT_EQ(result->Description(), kExampleDescriptionQemuPXE);
  EXPECT_EQ(result->DevicePath(),
            VecU8From(kExamplePathQemuPXE, sizeof(kExamplePathQemuPXE)));
}

TEST_F(EfiBootManagerTest, LoadEntryFail) {
  // Don't inject anything, so it fails.
  auto result = efi_boot_manager_->LoadEntry(EfiBootNumber(0xFFFF));

  EXPECT_FALSE(result.has_value());
}

TEST_F(EfiBootManagerTest, EntryRoundTrip) {
  efivar_->SetData(
      {{"BootFFFF", VecU8From(kExampleDataLinux, sizeof(kExampleDataLinux))}});

  auto contents = efi_boot_manager_->LoadEntry(EfiBootNumber(0xFFFF));
  ASSERT_TRUE(contents.has_value());

  // Clear so that we can check what gets written to it.
  efivar_->data_.clear();

  EfiVarError error = 0;
  bool success = efi_boot_manager_->WriteEntry(EfiBootNumber(0xFFFF),
                                               contents.value(), &error);
  ASSERT_TRUE(success);
  ASSERT_EQ(error, 0);
  EXPECT_THAT(efivar_->data_,
              Contains(Pair("BootFFFF", VecU8From(kExampleDataLinux,
                                                  sizeof(kExampleDataLinux)))));
}

TEST_F(EfiBootManagerTest, NextAvailableBootNum) {
  std::optional<EfiBootNumber> boot_num;
  // Test an empty list.
  efi_boot_manager_->SetEntries({});
  boot_num = efi_boot_manager_->NextAvailableBootNum();
  EXPECT_TRUE(boot_num.has_value());
  EXPECT_EQ(boot_num->Number(), 0);
  // Test that it picks an available number.
  efi_boot_manager_->SetEntries({BootPair(0, {}, {})});
  boot_num = efi_boot_manager_->NextAvailableBootNum();
  EXPECT_TRUE(boot_num.has_value());
  EXPECT_EQ(boot_num->Number(), 1);
  // Test that it picks the lowest available.
  efi_boot_manager_->SetEntries(
      {BootPair(0, {}, {}), BootPair(1, {}, {}), BootPair(9, {}, {})});
  boot_num = efi_boot_manager_->NextAvailableBootNum();
  EXPECT_TRUE(boot_num.has_value());
  EXPECT_EQ(boot_num->Number(), 2);

  // Test that it handles none available.
  // No hardware we're likely to run on will be able to hit this state.
  EfiBootManager::EntriesMap full;
  for (uint16_t num = 0; num < 0xFFFF; ++num) {
    full.emplace(EfiBootNumber(num), EfiBootEntryContents({}, {}));
  }

  efi_boot_manager_->SetEntries(full);
  boot_num = efi_boot_manager_->NextAvailableBootNum();
  EXPECT_FALSE(boot_num.has_value());
}

TEST_F(EfiBootManagerTest, FindContentsInBootOrder) {
  const EfiBootEntryContents desired(
      kCrosEfiDefaultDescription,
      VecU8From(kExamplePathCros, sizeof(kExamplePathCros)));
  std::optional<EfiBootNumber> entry;

  // Desired not present in entries
  efi_boot_manager_->SetBootOrder(
      BootOrderFromExample(kExampleBootOrder123, sizeof(kExampleBootOrder123)));
  efi_boot_manager_->SetEntries({
      BootPair(1, kExampleDescriptionQemuDisk,
               VecU8From(kExamplePathQemuDisk, sizeof(kExamplePathQemuDisk))),
      BootPair(2, kExampleDescriptionQemuPXE,
               VecU8From(kExamplePathQemuPXE, sizeof(kExamplePathQemuPXE))),
  });
  entry = efi_boot_manager_->FindContentsInBootOrder(desired);
  EXPECT_FALSE(entry.has_value());

  // Desired is present in entries, but not boot order
  efi_boot_manager_->SetBootOrder(
      BootOrderFromExample(kExampleBootOrder123, sizeof(kExampleBootOrder123)));
  efi_boot_manager_->SetEntries({
      BootPair(1, kExampleDescriptionQemuDisk,
               VecU8From(kExamplePathQemuDisk, sizeof(kExamplePathQemuDisk))),
      BootPair(2, kExampleDescriptionQemuPXE,
               VecU8From(kExamplePathQemuPXE, sizeof(kExamplePathQemuPXE))),
      BootPair(4, kExampleDescriptionCros,
               VecU8From(kExamplePathCros, sizeof(kExamplePathCros))),
  });
  entry = efi_boot_manager_->FindContentsInBootOrder(desired);
  EXPECT_FALSE(entry.has_value());

  // Desired is present in entries and boot order
  efi_boot_manager_->SetBootOrder(
      BootOrderFromExample(kExampleBootOrder123, sizeof(kExampleBootOrder123)));
  efi_boot_manager_->SetEntries({
      BootPair(1, kExampleDescriptionQemuDisk,
               VecU8From(kExamplePathQemuDisk, sizeof(kExamplePathQemuDisk))),
      BootPair(2, kExampleDescriptionQemuPXE,
               VecU8From(kExamplePathQemuPXE, sizeof(kExamplePathQemuPXE))),
      BootPair(3, kExampleDescriptionCros,
               VecU8From(kExamplePathCros, sizeof(kExamplePathCros))),
  });
  EfiBootNumber entry_num(3);

  entry = efi_boot_manager_->FindContentsInBootOrder(desired);
  EXPECT_TRUE(entry.has_value());
  EXPECT_EQ(entry.value().Number(), 3);
}

TEST_F(EfiBootManagerTest, FindContents) {
  const EfiBootEntryContents desired(
      kCrosEfiDefaultDescription,
      VecU8From(kExamplePathCros, sizeof(kExamplePathCros)));
  std::optional<EfiBootNumber> entry;

  // Desired not present in entries
  efi_boot_manager_->SetEntries({
      BootPair(1, {},
               VecU8From(kExamplePathQemuDisk, sizeof(kExamplePathQemuDisk))),
      BootPair(2, {},
               VecU8From(kExamplePathQemuPXE, sizeof(kExamplePathQemuPXE))),
  });
  entry = efi_boot_manager_->FindContents(desired);
  EXPECT_FALSE(entry.has_value());

  // Desired is present in entries
  efi_boot_manager_->SetEntries({
      BootPair(1, kExampleDescriptionQemuDisk,
               VecU8From(kExamplePathQemuDisk, sizeof(kExamplePathQemuDisk))),
      BootPair(2, kExampleDescriptionQemuPXE,
               VecU8From(kExamplePathQemuPXE, sizeof(kExamplePathQemuPXE))),
      BootPair(3, kExampleDescriptionCros,
               VecU8From(kExamplePathCros, sizeof(kExamplePathCros))),
  });
  EfiBootNumber entry_num(3);

  entry = efi_boot_manager_->FindContents(desired);
  EXPECT_TRUE(entry.has_value());
  EXPECT_EQ(entry.value().Number(), 3);
}

TEST_F(EfiBootManagerTest, RemoveAllManagedEntries) {
  efi_boot_manager_->SetBootOrder(
      BootOrderFromExample(kExampleBootOrder123, sizeof(kExampleBootOrder123)));

  // Set up to also empty the boot order.
  efi_boot_manager_->SetEntries({
      BootPair(0x0001, kCrosEfiDefaultDescription, {}),
      BootPair(0xA000, "Chromium", {}),
      BootPair(0x0002, kCrosEfiDefaultDescription, {}),
      BootPair(0xB000, "Chromium OS", {}),
      BootPair(0xC000, "something", {}),
      BootPair(0x0003, kCrosEfiDefaultDescription, {}),
      BootPair(0xD000, "Linux", {}),
      BootPair(0xE000, "Linux", {}),
  });

  // Set these to check for erasure/nonerasure
  efivar_->SetData({
      {"Boot0001", {}},
      {"Boot0002", {}},
      {"Boot0003", {}},
      {"BootA000", {}},
      {"BootB000", {}},
      {"BootC000", {}},
      {"BootD000", {}},
      {"BootE000", {}},
  });

  efi_boot_manager_->RemoveAllManagedEntries();

  EXPECT_THAT(
      efivar_->data_,
      UnorderedElementsAre(Key("BootA000"), Key("BootB000"), Key("BootC000"),
                           Key("BootD000"), Key("BootE000")));

  EXPECT_TRUE(efi_boot_manager_->Order().Data().empty());
}

TEST_F(EfiBootManagerTest, UpdateEfiBootEntries_NoBootEntries) {
  efivar_->SetData({{"BootOrder", {}}});
  InstallConfig install_config;

  bool success = efi_boot_manager_->UpdateEfiBootEntries(install_config, 64);

  EXPECT_TRUE(success);
  EXPECT_THAT(efivar_->data_, Contains(Pair("BootOrder", BootOrderData({0}))));
  EXPECT_THAT(efivar_->data_, Contains(Key("Boot0000")));
}

TEST_F(EfiBootManagerTest, UpdateEfiBootEntries_NoCrosEntry) {
  efivar_->SetData({
      {"BootOrder", BootOrderData({0})},
      {"Boot0000", VecU8From(kExampleDataQemuPXE, sizeof(kExampleDataQemuPXE))},
      {"Boot0001", VecU8From(kExampleDataLinux, sizeof(kExampleDataLinux))},
  });
  InstallConfig install_config;

  bool success = efi_boot_manager_->UpdateEfiBootEntries(install_config, 64);

  EXPECT_TRUE(success);
  EXPECT_THAT(efivar_->data_,
              UnorderedElementsAre(
                  Pair("BootOrder", BootOrderData({2, 0})),
                  Pair("Boot0000", VecU8From(kExampleDataQemuPXE,
                                             sizeof(kExampleDataQemuPXE))),
                  Pair("Boot0001",
                       VecU8From(kExampleDataLinux, sizeof(kExampleDataLinux))),
                  Key("Boot0002")));
}

TEST_F(EfiBootManagerTest, UpdateEfiBootEntries_CrosEntryNotInBootOrder) {
  efivar_->SetData({
      {"BootOrder", BootOrderData({1, 0})},
      {"Boot0000", VecU8From(kExampleDataQemuPXE, sizeof(kExampleDataQemuPXE))},
      {"Boot0001", VecU8From(kExampleDataLinux, sizeof(kExampleDataLinux))},
      {"Boot0002", VecU8From(kExampleDataCros, sizeof(kExampleDataCros))},
  });
  InstallConfig install_config;

  bool success = efi_boot_manager_->UpdateEfiBootEntries(install_config, 64);

  EXPECT_TRUE(success);
  EXPECT_THAT(efivar_->data_,
              UnorderedElementsAre(
                  Pair("BootOrder", BootOrderData({2, 1, 0})),
                  Pair("Boot0000", VecU8From(kExampleDataQemuPXE,
                                             sizeof(kExampleDataQemuPXE))),
                  Pair("Boot0001",
                       VecU8From(kExampleDataLinux, sizeof(kExampleDataLinux))),
                  Pair("Boot0002",
                       VecU8From(kExampleDataCros, sizeof(kExampleDataCros)))));
}

TEST_F(EfiBootManagerTest, UpdateEfiBootEntries_CrosInBootOrder) {
  efivar_->SetData({
      {"BootOrder", BootOrderData({1, 0, 2})},
      {"Boot0000", VecU8From(kExampleDataQemuPXE, sizeof(kExampleDataQemuPXE))},
      {"Boot0001", VecU8From(kExampleDataLinux, sizeof(kExampleDataLinux))},
      {"Boot0002", VecU8From(kExampleDataCros, sizeof(kExampleDataCros))},
  });
  InstallConfig install_config;

  bool success = efi_boot_manager_->UpdateEfiBootEntries(install_config, 64);

  EXPECT_TRUE(success);
  EXPECT_THAT(efivar_->data_,
              UnorderedElementsAre(
                  Pair("BootOrder", BootOrderData({1, 0, 2})),
                  Pair("Boot0000", VecU8From(kExampleDataQemuPXE,
                                             sizeof(kExampleDataQemuPXE))),
                  Pair("Boot0001",
                       VecU8From(kExampleDataLinux, sizeof(kExampleDataLinux))),
                  Pair("Boot0002",
                       VecU8From(kExampleDataCros, sizeof(kExampleDataCros)))));
}

TEST_F(EfiBootManagerTest, UpdateEfiBootEntries_ExcessCrosEntries) {
  efivar_->SetData({
      {"BootOrder", BootOrderData({1, 0, 2})},
      {"Boot0001", VecU8From(kExampleDataCros, sizeof(kExampleDataCros))},
      {"Boot0002", VecU8From(kExampleDataQemuPXE, sizeof(kExampleDataQemuPXE))},
      {"Boot0003", VecU8From(kExampleDataCros, sizeof(kExampleDataCros))},
      {"Boot0004", VecU8From(kExampleDataLinux, sizeof(kExampleDataLinux))},
      {"Boot0005", VecU8From(kExampleDataCros, sizeof(kExampleDataCros))},
  });
  InstallConfig install_config;

  bool success = efi_boot_manager_->UpdateEfiBootEntries(install_config, 64);

  EXPECT_TRUE(success);
  EXPECT_THAT(efivar_->data_,
              UnorderedElementsAre(
                  Pair("BootOrder", BootOrderData({1, 0, 2})),
                  Pair("Boot0002", VecU8From(kExampleDataQemuPXE,
                                             sizeof(kExampleDataQemuPXE))),
                  Pair("Boot0004",
                       VecU8From(kExampleDataLinux, sizeof(kExampleDataLinux))),
                  Pair(testing::_,
                       VecU8From(kExampleDataCros, sizeof(kExampleDataCros)))));
}

TEST_F(EfiBootManagerTest, UpdateEfiBootEntries_WriteFail) {
  efivar_->SetData({{"BootOrder", {}}});
  efivar_->set_variable_result_ = {EPERM};
  InstallConfig install_config;

  bool success = efi_boot_manager_->UpdateEfiBootEntries(install_config, 64);

  EXPECT_FALSE(success);
  EXPECT_THAT(efivar_->data_,
              UnorderedElementsAre(Pair("BootOrder", BootOrderData({}))));
}

TEST_F(EfiBootManagerTest, UpdateEfiBootEntries_AcceptableWriteFail) {
  efivar_->SetData({{"BootOrder", {}}});
  // ENOSPC is an acceptable fail, says b/226935367.
  efivar_->set_variable_result_ = {ENOSPC};
  InstallConfig install_config;

  bool success = efi_boot_manager_->UpdateEfiBootEntries(install_config, 64);

  EXPECT_TRUE(success);
  EXPECT_THAT(efivar_->data_,
              UnorderedElementsAre(Pair("BootOrder", BootOrderData({}))));
}

TEST_F(EfiBootManagerTest, UpdateEfiBootEntries_AcceptableWriteEintrFail) {
  efivar_->SetData({{"BootOrder", {}}});
  // EINTR is an acceptable fail says b/264907147.
  efivar_->set_variable_result_ = {EINTR};
  InstallConfig install_config;

  bool success = efi_boot_manager_->UpdateEfiBootEntries(install_config, 64);

  EXPECT_TRUE(success);
  EXPECT_THAT(efivar_->data_,
              UnorderedElementsAre(Pair("BootOrder", BootOrderData({}))));
}

TEST_F(EfiBootManagerTest, UpdateEfiBootEntries_BootWriteFail) {
  efivar_->SetData({{"BootOrder", {}}});
  efivar_->set_variable_result_ = {std::nullopt, EPERM};
  InstallConfig install_config;

  bool success = efi_boot_manager_->UpdateEfiBootEntries(install_config, 64);

  EXPECT_FALSE(success);
  EXPECT_THAT(efivar_->data_,
              UnorderedElementsAre(
                  Pair("BootOrder", BootOrderData({})),
                  Pair("Boot0000",
                       VecU8From(kExampleDataCros, sizeof(kExampleDataCros)))));
}

TEST_F(EfiBootManagerTest, UpdateEfiBootEntries_AcceptableBootWriteFail) {
  efivar_->SetData({{"BootOrder", {}}});
  // ENOSPC is an acceptable fail, says b/226935367.
  efivar_->set_variable_result_ = {std::nullopt, ENOSPC};
  InstallConfig install_config;

  bool success = efi_boot_manager_->UpdateEfiBootEntries(install_config, 64);

  EXPECT_TRUE(success);
  EXPECT_THAT(efivar_->data_,
              UnorderedElementsAre(
                  Pair("BootOrder", BootOrderData({})),
                  Pair("Boot0000",
                       VecU8From(kExampleDataCros, sizeof(kExampleDataCros)))));
}

TEST_F(EfiBootManagerTest, UpdateEfiBootEntries_EntryCountMetrics) {
  efivar_->SetData({
      {"BootOrder", BootOrderData({1, 0, 2})},
      {"Boot0001", VecU8From(kExampleDataCros, sizeof(kExampleDataCros))},
      {"Boot0002", VecU8From(kExampleDataQemuPXE, sizeof(kExampleDataQemuPXE))},
      {"Boot0003", VecU8From(kExampleDataCros, sizeof(kExampleDataCros))},
      {"Boot0004", VecU8From(kExampleDataLinux, sizeof(kExampleDataLinux))},
      {"Boot0005", VecU8From(kExampleDataCros, sizeof(kExampleDataCros))},
  });

  const int total_boot_entries = 5;
  const int failed_loads = 0;
  const int managed_entries = 3;

  InstallConfig install_config;

  EXPECT_CALL(*metrics_, SendMetric(kUMAEfiEntryCountName, total_boot_entries,
                                    kUMAEfiEntryCountMin, kUMAEfiEntryCountMax,
                                    kUMAEfiEntryCountBuckets));
  EXPECT_CALL(*metrics_,
              SendMetric(kUMAEfiEntryFailedLoadName, failed_loads,
                         kUMAEfiEntryFailedLoadMin, kUMAEfiEntryFailedLoadMax,
                         kUMAEfiEntryFailedLoadBuckets));
  EXPECT_CALL(*metrics_,
              SendLinearMetric(kUMAManagedEfiEntryCountName, managed_entries,
                               kUMAManagedEfiEntryCountMax));

  efi_boot_manager_->UpdateEfiBootEntries(install_config, 64);
}

TEST_F(EfiBootManagerTest, UpdateEfiBootEntries_LoadFailMetrics) {
  efivar_->SetData({
      {"BootOrder", BootOrderData({1, 0, 2})},
      {"Boot0001", VecU8From(kExampleDataCros, sizeof(kExampleDataCros))},
      {"Boot0002", VecU8From(kExampleDataQemuPXE, sizeof(kExampleDataQemuPXE))},
      {"Boot0003", VecU8From(kExampleDataCros, sizeof(kExampleDataCros))},
      {"Boot0004", VecU8From(kExampleDataLinux, sizeof(kExampleDataLinux))},
      {"Boot0005", VecU8From(kExampleDataCros, sizeof(kExampleDataCros))},
  });
  // Simulate a filed load.
  efivar_->variable_names_.push_back("Boot0BAD");

  const int total_boot_entries = 6;
  const int failed_loads = 1;

  InstallConfig install_config;

  EXPECT_CALL(*metrics_, SendMetric(kUMAEfiEntryCountName, total_boot_entries,
                                    kUMAEfiEntryCountMin, kUMAEfiEntryCountMax,
                                    kUMAEfiEntryCountBuckets));
  EXPECT_CALL(*metrics_,
              SendMetric(kUMAEfiEntryFailedLoadName, failed_loads,
                         kUMAEfiEntryFailedLoadMin, kUMAEfiEntryFailedLoadMax,
                         kUMAEfiEntryFailedLoadBuckets));
  EXPECT_CALL(*metrics_, SendLinearMetric).Times(0);

  efi_boot_manager_->UpdateEfiBootEntries(install_config, 64);
}

TEST(EfiVarTest, IsEfiGlobalGUID) {
  efi_guid_t guid = EFI_GLOBAL_GUID;
  EXPECT_TRUE(IsEfiGlobalGUID(&guid));

  guid.e[4] = 0;
  EXPECT_FALSE(IsEfiGlobalGUID(&guid));
}
