// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/cros_healthd/fetchers/audio_hardware_fetcher.h"

#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include <base/files/file_enumerator.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_split.h>

#include "diagnostics/base/file_utils.h"
#include "diagnostics/cros_healthd/fetchers/bus_fetcher.h"
#include "diagnostics/cros_healthd/utils/error_utils.h"

namespace diagnostics {

namespace {

namespace mojom = ::ash::cros_healthd::mojom;

std::tuple<mojom::HDAudioCodecPtr, mojom::ProbeErrorPtr> FetchCodec(
    const base::FilePath& codec_file) {
  auto codec = mojom::HDAudioCodec::New();
  std::string codec_str;
  if (!ReadAndTrimString(codec_file, &codec_str)) {
    return {nullptr, mojom::ProbeError::New(
                         mojom::ErrorType::kFileReadError,
                         "Failed to read file: " + codec_file.value())};
  }

  base::StringPairs pairs;
  base::SplitStringIntoKeyValuePairs(codec_str, ':', '\n', &pairs);
  bool flag_codec = false;
  bool flag_address = false;
  for (const auto& key_value : pairs) {
    std::string key;
    base::TrimWhitespaceASCII(key_value.first, base::TRIM_ALL, &key);
    std::string value;
    base::TrimWhitespaceASCII(key_value.second, base::TRIM_ALL, &value);
    if (key == "Codec") {
      codec->name = value;
      flag_codec = true;
    }
    if (key == "Address") {
      unsigned num;
      if (!base::StringToUint(value, &num) || num >= 1u << 8) {
        return {nullptr, mojom::ProbeError::New(
                             mojom::ErrorType::kParseError,
                             "Failed to parse value to uint8_t: " + value)};
      }
      codec->address = static_cast<uint8_t>(num);
      flag_address = true;
    }
  }
  if (!flag_codec)
    return {nullptr, mojom::ProbeError::New(mojom::ErrorType::kParseError,
                                            "Missing field: Codec")};
  if (!flag_address)
    return {nullptr, mojom::ProbeError::New(mojom::ErrorType::kParseError,
                                            "Missing field: Address")};
  return {std::move(codec), nullptr};
}

std::tuple<mojom::AudioCardPtr, mojom::ProbeErrorPtr> FetchAudioCard(
    const base::FilePath& asound_path) {
  auto audio_card = mojom::AudioCard::New();
  if (!ReadAndTrimString(asound_path, "id", &audio_card->alsa_id)) {
    return {nullptr,
            mojom::ProbeError::New(
                mojom::ErrorType::kFileReadError,
                "Failed to read file: " + asound_path.Append("id").value())};
  }
  base::FileEnumerator file_enum(asound_path, /*recursive=*/false,
                                 base::FileEnumerator::FileType::FILES,
                                 "codec#*");
  for (auto path = file_enum.Next(); !path.empty(); path = file_enum.Next()) {
    auto [codec, err] = FetchCodec(path);
    if (!err.is_null()) {
      return {nullptr,
              WrapProbeError(std::move(err),
                             "Failed to parse codec file" + path.value())};
    }
    audio_card->hd_audio_codecs.push_back(std::move(codec));
  }
  return {std::move(audio_card), nullptr};
}

std::tuple<base::FilePath, mojom::ProbeErrorPtr> GetAudioCardSysfsRealPath(
    const base::FilePath& root_dir, const std::string& card_dir_name) {
  // This path is a symbolic link to the real sysfs device path.
  auto path =
      root_dir.Append("sys/class/sound").Append(card_dir_name).Append("device");
  auto result = base::MakeAbsoluteFilePath(path);
  if (result.empty())
    return {base::FilePath{},
            mojom::ProbeError::New(mojom::ErrorType::kParseError,
                                   "File not found: " + path.value())};
  return {result, nullptr};
}

std::tuple<std::vector<mojom::AudioCardPtr>, mojom::ProbeErrorPtr>
FetchAudioCards(
    const base::FilePath& root_dir,
    base::flat_map<base::FilePath, mojom::BusDevicePtr> bus_device_map) {
  std::vector<mojom::AudioCardPtr> audio_cards;

  const base::FilePath asound_dir = root_dir.Append("proc/asound");
  base::FileEnumerator file_enum(asound_dir, /*recursive=*/false,
                                 base::FileEnumerator::FileType::DIRECTORIES,
                                 "card*");
  for (auto path = file_enum.Next(); !path.empty(); path = file_enum.Next()) {
    auto [audio_card, audio_card_err] = FetchAudioCard(path);
    if (!audio_card_err.is_null()) {
      return {std::vector<mojom::AudioCardPtr>{},
              WrapProbeError(std::move(audio_card_err),
                             "Failed to parse audio card " + path.value())};
    }
    auto [device_path, device_path_err] =
        GetAudioCardSysfsRealPath(root_dir, path.BaseName().value());
    if (!device_path_err.is_null()) {
      return {std::vector<mojom::AudioCardPtr>{},
              WrapProbeError(std::move(device_path_err),
                             "Failed to parse audio card " + path.value())};
    }

    auto it = bus_device_map.find(device_path);
    if (it != bus_device_map.end()) {
      audio_card->bus_device = it->second.Clone();
    }
    audio_cards.push_back(std::move(audio_card));
  }
  return {std::move(audio_cards), nullptr};
}

mojom::AudioHardwareResultPtr FetchAudioHardwareInfoInner(
    Context* context,
    base::flat_map<base::FilePath, mojom::BusDevicePtr> bus_device_map) {
  auto hardware_info = mojom::AudioHardwareInfo::New();
  mojom::ProbeErrorPtr error;
  std::tie(hardware_info->audio_cards, error) =
      FetchAudioCards(context->root_dir(), std::move(bus_device_map));
  if (!error.is_null()) {
    LOG(ERROR) << error->msg;
    return mojom::AudioHardwareResult::NewError(std::move(error));
  }

  return mojom::AudioHardwareResult::NewAudioHardwareInfo(
      std::move(hardware_info));
}

}  // namespace

void FetchAudioHardwareInfo(Context* context,
                            FetchAudioHardwareInfoCallback callback) {
  FetchSysfsPathsBusDeviceMap(
      context, base::BindOnce(&FetchAudioHardwareInfoInner, context)
                   .Then(std::move(callback)));
}

}  // namespace diagnostics
