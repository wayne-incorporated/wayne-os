// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBEC_FINGERPRINT_FP_FRAME_COMMAND_H_
#define LIBEC_FINGERPRINT_FP_FRAME_COMMAND_H_

#include <array>
#include <memory>
#include <vector>

#include <base/memory/ptr_util.h>
#include <base/time/time.h>
#include <brillo/brillo_export.h>
#include <brillo/secure_blob.h>
#include "libec/ec_command.h"

namespace ec {

using FpFramePacket = std::array<uint8_t, kMaxPacketSize>;

class BRILLO_EXPORT FpFrameCommand
    : public EcCommand<struct ec_params_fp_frame, FpFramePacket> {
 public:
  template <typename T = FpFrameCommand>
  static std::unique_ptr<T> Create(int index,
                                   uint32_t frame_size,
                                   uint16_t max_read_size) {
    static_assert(std::is_base_of<FpFrameCommand, T>::value,
                  "Only classes derived from FpFrameCommand can use Create");

    if (frame_size == 0 || max_read_size == 0 ||
        max_read_size > kMaxPacketSize) {
      return nullptr;
    }

    // Using new to access non-public constructor. See
    // https://abseil.io/tips/134.
    return base::WrapUnique(new T(index, frame_size, max_read_size));
  }

  ~FpFrameCommand() override = default;

  bool Run(int fd) override;

  // This transfers ownership of |frame_data_|. FpFrameCommand no longer has a
  // copy of the frame after calling this.
  std::unique_ptr<std::vector<uint8_t>> frame();

 protected:
  FpFrameCommand(int index, uint32_t frame_size, uint16_t max_read_size)
      : EcCommand(EC_CMD_FP_FRAME),
        frame_index_(index),
        max_read_size_(max_read_size),
        frame_data_(std::make_unique<std::vector<uint8_t>>(frame_size)) {}
  virtual bool EcCommandRun(int fd);
  // Sleep is needed during retry. Tests might want to override this method.
  virtual void Sleep(base::TimeDelta duration);

 private:
  constexpr static int kMaxRetries = 50;
  constexpr static int kRetryDelayMs = 100;

  int frame_index_ = 0;
  uint16_t max_read_size_ = 0;
  std::unique_ptr<std::vector<uint8_t>> frame_data_;
};

static_assert(!std::is_copy_constructible<FpFrameCommand>::value,
              "EcCommands are not copyable by default");
static_assert(!std::is_copy_assignable<FpFrameCommand>::value,
              "EcCommands are not copy-assignable by default");

}  // namespace ec

#endif  // LIBEC_FINGERPRINT_FP_FRAME_COMMAND_H_
