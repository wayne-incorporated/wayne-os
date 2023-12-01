// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <algorithm>
#include <string>

#include <base/sys_byteorder.h>
#include <pinweaver/pinweaver_eal.h>
#include <tpm2/BaseTypes.h>
#include <tpm2/Capabilities.h>
#include <tpm2/Implementation.h>
#include <tpm2/tpm_types.h>

#include "tpm2-simulator/tpm_command_utils.h"
#include "tpm2-simulator/tpm_vendor_cmd_pinweaver.h"

namespace tpm2_simulator {

namespace {

struct VendorCommandHeader {
  CommandHeader header;
  uint16_t subcommand_code;
} __attribute__((packed));

constexpr size_t kVendorHeaderSize = 12;
static_assert(kVendorHeaderSize == sizeof(VendorCommandHeader));

constexpr uint32_t kTpmCcVendorBit = 0x20000000;
constexpr uint32_t kTpmCcVendorCr50 = 0x0000;
constexpr uint16_t kVendorCcPinweaver = 37;

}  // namespace

bool TpmVendorCommandPinweaver::Init() {
  pinweaver_init();
  return true;
}

bool TpmVendorCommandPinweaver::IsVendorCommand(const std::string& command) {
  if (command.size() < kVendorHeaderSize) {
    return false;
  }

  const VendorCommandHeader* header =
      reinterpret_cast<const VendorCommandHeader*>(command.data());

  if (base::NetToHost32(header->header.code) !=
      (kTpmCcVendorBit | kTpmCcVendorCr50)) {
    return false;
  }
  return base::NetToHost16(header->subcommand_code) == kVendorCcPinweaver;
}

std::string TpmVendorCommandPinweaver::RunCommand(const std::string& command) {
  std::string command_copy = command.substr(kVendorHeaderSize);
  std::string response;
  response.resize(PW_MAX_MESSAGE_SIZE);
  std::copy(command_copy.begin(), command_copy.end(), response.begin());
  void* request_buf = reinterpret_cast<void*>(response.data());
  size_t request_size = command_copy.size();
  void* response_buf = request_buf;
  size_t response_size = 0;
  pinweaver_command(request_buf, request_size, response_buf, &response_size);

  response =
      std::string(kVendorHeaderSize, '\0') + response.substr(0, response_size);

  VendorCommandHeader* header =
      reinterpret_cast<VendorCommandHeader*>(response.data());
  header->header.tag = base::HostToNet16(TPM_ST_NO_SESSIONS);
  header->header.size = base::HostToNet32(response.size());
  header->header.code = base::HostToNet32(0);
  header->subcommand_code = base::HostToNet16(kVendorCcPinweaver);

  return response;
}

}  // namespace tpm2_simulator
