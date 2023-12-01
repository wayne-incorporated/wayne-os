// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef RUNTIME_PROBE_FUNCTIONS_AUDIO_CODEC_H_
#define RUNTIME_PROBE_FUNCTIONS_AUDIO_CODEC_H_

#include <base/strings/string_piece.h>

#include "runtime_probe/probe_function.h"

namespace runtime_probe {

inline constexpr const base::StringPiece kKnownInvalidCodecNames[] = {
    "dw-hdmi-audio",
    "snd-soc-dummy",
};
inline constexpr const base::StringPiece kAsocPaths[] = {
    "/sys/kernel/debug/asoc/components",  // for kernel version >= 4.14
    "/sys/kernel/debug/asoc/codecs",      // for kernel version <= 4.4
};

class AudioCodecFunction final : public PrivilegedProbeFunction {
  using PrivilegedProbeFunction::PrivilegedProbeFunction;

 public:
  NAME_PROBE_FUNCTION("audio_codec");

 private:
  DataType EvalImpl() const override;
};

}  // namespace runtime_probe

#endif  // RUNTIME_PROBE_FUNCTIONS_AUDIO_CODEC_H_
