// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "hwsec-optee-plugin/hwsec-optee-plugin.h"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>

#include <base/logging.h>
#include <base/sys_byteorder.h>
#include <brillo/syslog_logging.h>
#include <libhwsec/factory/factory_impl.h>
#include <libhwsec-foundation/status/status_chain_macros.h>

extern "C" {
#include <tee_plugin_method.h>
}

// OPTEE has access to the plugin by the UUID
#define HWSEC_PLUGIN_UUID                            \
  {                                                  \
    0x69b7c987, 0x4a1a, 0x4953, {                    \
      0xb6, 0x47, 0x0c, 0xf7, 0x9e, 0xb3, 0x97, 0xb9 \
    }                                                \
  }

#define SEND_RAW_COMMAND 0

namespace {

static const hwsec::OpteePluginFrontend& GetHwsec() {
  static thread_local hwsec::FactoryImpl hwsec_factory(
      hwsec::ThreadingMode::kCurrentThread);
  static thread_local std::unique_ptr<const hwsec::OpteePluginFrontend> hwsec =
      hwsec_factory.GetOpteePluginFrontend();
  return *hwsec;
}

static TEEC_Result HwsecPluginInit(void) {
  brillo::InitLog(brillo::kLogToSyslog | brillo::kLogToStderr);
  return TEEC_SUCCESS;
}

static TEEC_Result GetInputLen(uint8_t* data,
                               size_t data_len,
                               uint32_t& input_len) {
  if (data_len < 10) {
    LOG(ERROR) << "The input is too short!";
    return TEEC_ERROR_BAD_PARAMETERS;
  }

  memcpy(&input_len, data + 2, sizeof(uint32_t));
  input_len = base::NetToHost32(input_len);
  return TEEC_SUCCESS;
}

static TEEC_Result SendRawCommand(unsigned int sub_cmd,
                                  uint8_t* data,
                                  size_t data_len,
                                  size_t* out_len) {
  uint32_t input_len;
  if (TEEC_Result result = GetInputLen(data, data_len, input_len);
      result != TEEC_SUCCESS) {
    return result;
  }

  brillo::Blob input(data, data + input_len);

  ASSIGN_OR_RETURN(const brillo::Blob& output, GetHwsec().SendRawCommand(input),
                   _.LogError().As(TEEC_ERROR_BAD_STATE));

  if (output.size() > data_len) {
    LOG(ERROR) << "The input buffer is not enough for output!";
    return TEEC_ERROR_SHORT_BUFFER;
  }

  *out_len = output.size();
  memcpy(data, output.data(), output.size());

  return TEEC_SUCCESS;
}

static TEEC_Result HwsecPluginInvoke(unsigned int cmd,
                                     unsigned int sub_cmd,
                                     void* data,
                                     size_t data_len,
                                     size_t* out_len) {
  switch (cmd) {
    case SEND_RAW_COMMAND:
      return SendRawCommand(sub_cmd, static_cast<uint8_t*>(data), data_len,
                            out_len);
    default:
      return TEEC_ERROR_NOT_SUPPORTED;
  }
}

}  // namespace

extern "C" struct plugin_method plugin_method = {
    .name = "hwsec",
    .uuid = HWSEC_PLUGIN_UUID,
    .init = HwsecPluginInit,
    .invoke = HwsecPluginInvoke,
};
