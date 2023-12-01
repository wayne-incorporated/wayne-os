// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBEC_EC_COMMAND_ASYNC_H_
#define LIBEC_EC_COMMAND_ASYNC_H_

#include <base/check_op.h>
#include <base/logging.h>
#include <base/threading/thread.h>
#include <base/time/time.h>

#include "libec/ec_command.h"

namespace ec {

/**
 * Represents an "async" EC command. Note that the EC codebase does not
 * support true asynchronous commands. All commands are expected to return
 * within a certain deadline (currently 200 ms). To handle longer-running
 * commands, the EC codebase has adopted a style where a command is first
 * started and then the result is polled for by specifying an |action| in the
 * command's request parameters. See EC_CMD_FLASH_ERASE and EC_CMD_ADD_ENTROPY
 * for examples.
 */
template <typename O, typename I>
class EcCommandAsync : public EcCommand<O, I> {
 public:
  struct Options {
    int poll_for_result_num_attempts = 20;
    base::TimeDelta poll_interval = base::Milliseconds(100);
    /**
     * When polling for the result, the EC should normally return EC_RES_BUSY
     * when the command is still being processed. However, some commands
     * cause the EC to temporarily stop responding to EC commands and the ioctl
     * times out. Those commands should set validate_poll_result to false to
     * ignore that error and continue polling until the timeout is hit.
     */
    bool validate_poll_result = true;
  };

  EcCommandAsync(uint32_t cmd,
                 uint8_t async_result_action,
                 const Options& options,
                 uint32_t ver = 0,
                 const O& req = {})
      : EcCommand<O, I>(cmd, ver, req),
        async_result_action_(async_result_action),
        options_(options) {}

  bool Run(int fd) override {
    CHECK_GT(options_.poll_for_result_num_attempts, 0);

    /*
     * Force the insize of the first async BaseCmd to be zero because the first
     * async command only schedules the command and does not return any response
     * with a meaningful size.
     */
    uint32_t original_insize = BaseCmd::RespSize();
    BaseCmd::SetRespSize(0);

    if (!BaseCmd::Run(fd)) {
      LOG(ERROR) << "Failed to start command";
      BaseCmd::SetRespSize(original_insize);
      return false;
    }

    /*
     * Restore the insize to its original value before the execution of the
     * second async command because this is the command that will return the
     * actual response.
     */
    BaseCmd::SetRespSize(original_insize);
    int num_attempts = options_.poll_for_result_num_attempts;
    while (num_attempts--) {
      base::PlatformThread::Sleep(options_.poll_interval);

      BaseCmd::Req()->action = async_result_action_;

      if (BaseCmd::Run(fd)) {
        return true;
      }

      auto ret = BaseCmd::Result();

      if (options_.validate_poll_result && ret != EC_RES_BUSY) {
        LOG(ERROR) << "Failed to get command result, ret: " << ret;
        return false;
      }
    }

    LOG(ERROR) << "Timed out polling for command 0x" << std::hex
               << BaseCmd::Command();
    return false;
  }

  const Options& options() const { return options_; }

 private:
  using BaseCmd = EcCommand<O, I>;
  uint8_t async_result_action_ = 0;
  Options options_;
};

}  // namespace ec

#endif  // LIBEC_EC_COMMAND_ASYNC_H_
