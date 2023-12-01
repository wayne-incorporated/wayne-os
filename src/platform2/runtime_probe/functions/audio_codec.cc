// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "runtime_probe/functions/audio_codec.h"

#include <string>
#include <utility>

#include <base/containers/contains.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/strings/string_split.h>
#include <base/values.h>

#include "runtime_probe/utils/file_utils.h"

namespace runtime_probe {
namespace {

constexpr size_t kAscoFileMaxSize = 65536;

AudioCodecFunction::DataType ProbeCodecFromFile(
    const base::FilePath& asoc_path) {
  std::string asoc_content;
  if (!base::ReadFileToStringWithMaxSize(asoc_path, &asoc_content,
                                         kAscoFileMaxSize)) {
    if (asoc_content.size() == kAscoFileMaxSize) {
      LOG(ERROR) << "Cannot read " << asoc_path
                 << " because its size is greater than " << kAscoFileMaxSize;
    } else {
      PLOG(ERROR) << "Cannot read " << asoc_path;
    }
    return {};
  }

  AudioCodecFunction::DataType result{};
  for (base::StringPiece codec :
       base::SplitStringPiece(asoc_content, "\n", base::TRIM_WHITESPACE,
                              base::SPLIT_WANT_NONEMPTY)) {
    if (base::Contains(kKnownInvalidCodecNames, codec))
      continue;

    base::Value::Dict value;
    value.Set("name", codec);
    result.Append(std::move(value));
  }
  return result;
}

}  // namespace

AudioCodecFunction::DataType AudioCodecFunction::EvalImpl() const {
  DataType result{};

  for (const auto& asoc_path_str : kAsocPaths) {
    base::FilePath asoc_path = GetRootedPath(asoc_path_str);
    if (!PathExists(asoc_path))
      continue;
    return ProbeCodecFromFile(asoc_path);
  }

  LOG(ERROR) << "Cannot find any asoc files which contain the codecs.";
  return DataType{};
}

}  // namespace runtime_probe
