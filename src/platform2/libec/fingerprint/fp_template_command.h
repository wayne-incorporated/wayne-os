// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBEC_FINGERPRINT_FP_TEMPLATE_COMMAND_H_
#define LIBEC_FINGERPRINT_FP_TEMPLATE_COMMAND_H_

#include <array>
#include <memory>
#include <utility>
#include <vector>

#include <base/memory/ptr_util.h>
#include <brillo/brillo_export.h>
#include "libec/ec_command.h"
#include "libec/fingerprint/fp_template_params.h"

namespace ec {

class BRILLO_EXPORT FpTemplateCommand
    : public EcCommand<fp_template::Params, EmptyParam> {
 public:
  template <typename T = FpTemplateCommand>
  static std::unique_ptr<T> Create(std::vector<uint8_t> tmpl,
                                   uint16_t max_write_size) {
    static_assert(std::is_base_of<FpTemplateCommand, T>::value,
                  "Only classes derived from FpTemplateCommand can use Create");

    if (tmpl.empty() || max_write_size == 0 ||
        max_write_size > kMaxPacketSize) {
      return nullptr;
    }

    // Using new to access non-public constructor. See
    // https://abseil.io/tips/134.
    return base::WrapUnique(new T(tmpl, max_write_size));
  }

  ~FpTemplateCommand() override = default;

  bool Run(int fd) override;

 protected:
  FpTemplateCommand(std::vector<uint8_t> tmpl, uint16_t max_write_size)
      : EcCommand(EC_CMD_FP_TEMPLATE),
        template_data_(std::move(tmpl)),
        max_write_size_(max_write_size) {}
  virtual bool EcCommandRun(int fd);

 private:
  std::vector<uint8_t> template_data_;
  uint16_t max_write_size_;
};

static_assert(!std::is_copy_constructible<FpTemplateCommand>::value,
              "EcCommands are not copyable by default");
static_assert(!std::is_copy_assignable<FpTemplateCommand>::value,
              "EcCommands are not copy-assignable by default");

}  // namespace ec

#endif  // LIBEC_FINGERPRINT_FP_TEMPLATE_COMMAND_H_
