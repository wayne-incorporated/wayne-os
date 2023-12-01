// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <utility>
#include <vector>

#include <base/test/task_environment.h>
#include <base/test/test_future.h>
#include <fwupd/dbus-proxy-mocks.h>
#include <gtest/gtest.h>

#include "diagnostics/base/file_test_utils.h"
#include "diagnostics/cros_healthd/fetchers/audio_hardware_fetcher.h"
#include "diagnostics/cros_healthd/fetchers/bus_fetcher_constants.h"
#include "diagnostics/cros_healthd/system/mock_context.h"

namespace diagnostics {
namespace {

namespace mojom = ::ash::cros_healthd::mojom;
using ::testing::AnyNumber;
using ::testing::Invoke;
using ::testing::WithArg;

constexpr char kAsoundPath[] = "/proc/asound";
constexpr char kFakeAlsaId[] = "FakeId";
constexpr char kFakePciDevicePath[] = "/sys/devices/pci0000:00";
constexpr char kFakePciDeviceDirName[] = "0000:12:34.5";

class AudioHardwareFetcherTest : public BaseFileTest {
 protected:
  void SetUp() override {
    SetTestRoot(mock_context_.root_dir());
    ON_CALL(*mock_context_.mock_fwupd_proxy(), GetDevicesAsync)
        .WillByDefault(WithArg<0>(Invoke(
            [](base::OnceCallback<void(
                   const std::vector<brillo::VariantDictionary>&)> callback) {
              std::move(callback).Run({});
            })));
    EXPECT_CALL(*mock_context_.mock_fwupd_proxy(), GetDevicesAsync)
        .Times(AnyNumber());

    // Set id so by default we can get valid result.
    SetFile({kAsoundPath, "card0", "id"}, kFakeAlsaId);
    // Set symbolic links to emulate real sysfs.
    SetSymbolicLink({"../../..", kFakePciDeviceDirName},
                    {kFakePciDevicePath, kFakePciDeviceDirName, "sound",
                     "card0", "device"});
    SetSymbolicLink(
        {"../../devices/pci0000:00", kFakePciDeviceDirName, "sound", "card0"},
        "/sys/class/sound/card0");
  }

  mojom::AudioHardwareResultPtr FetchAudioHardwareInfoSync() {
    base::test::TestFuture<mojom::AudioHardwareResultPtr> future;
    FetchAudioHardwareInfo(&mock_context_, future.GetCallback());
    return future.Take();
  }

 private:
  base::test::SingleThreadTaskEnvironment env_;
  MockContext mock_context_;
};

TEST_F(AudioHardwareFetcherTest, FetchAudioCardsId) {
  SetFile({kAsoundPath, "card0", "id"}, kFakeAlsaId);

  auto result = FetchAudioHardwareInfoSync();
  EXPECT_EQ(result->get_audio_hardware_info()->audio_cards[0]->alsa_id,
            kFakeAlsaId);
}

TEST_F(AudioHardwareFetcherTest, FetchAudioCardsNoId) {
  UnsetPath({kAsoundPath, "card0", "id"});

  auto result = FetchAudioHardwareInfoSync();
  EXPECT_TRUE(result->is_error());
}

TEST_F(AudioHardwareFetcherTest, FetchAudioCardsCodec) {
  // Test the parser with syntax found in a real HDA codec file.
  SetFile({kAsoundPath, "card0", "codec#2"},
          R"CODEC(Codec: Test Codec Name
Address: 2
Field A: A
  Indended Field B: B
  Attr = Value, Attr = Value
  Field: value: another value
    value
)CODEC");

  auto result = FetchAudioHardwareInfoSync();
  const auto& codec =
      result->get_audio_hardware_info()->audio_cards[0]->hd_audio_codecs[0];
  EXPECT_EQ(codec->name, "Test Codec Name");
  EXPECT_EQ(codec->address, 2);
}

TEST_F(AudioHardwareFetcherTest, FetchAudioCardsCodecNoName) {
  // Missing "Codec:" field.
  SetFile({kAsoundPath, "card0", "codec#0"},
          R"CODEC(Address: 0
)CODEC");

  auto result = FetchAudioHardwareInfoSync();
  EXPECT_TRUE(result->is_error());
}

TEST_F(AudioHardwareFetcherTest, FetchAudioCardsCodecNoAddress) {
  // Missing "Address:" field.
  SetFile({kAsoundPath, "card0", "codec#0"},
          R"CODEC(Codec: Test Codec Name
)CODEC");

  auto result = FetchAudioHardwareInfoSync();
  EXPECT_TRUE(result->is_error());
}

TEST_F(AudioHardwareFetcherTest, FetchAudioCardsBusDevice) {
  // Set fake pci device.
  SetSymbolicLink({"../../../devices/pci0000:00", kFakePciDeviceDirName},
                  {kPathSysPci, kFakePciDeviceDirName});
  SetFile({kFakePciDevicePath, kFakePciDeviceDirName, kFilePciClass},
          "0x123456");
  SetFile({kFakePciDevicePath, kFakePciDeviceDirName, kFilePciVendor},
          "0x1234");
  SetFile({kFakePciDevicePath, kFakePciDeviceDirName, kFilePciDevice},
          "0x1234");

  auto result = FetchAudioHardwareInfoSync();
  EXPECT_FALSE(
      result->get_audio_hardware_info()->audio_cards[0]->bus_device.is_null());
}

}  // namespace
}  // namespace diagnostics
