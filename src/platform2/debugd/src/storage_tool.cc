// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "debugd/src/storage_tool.h"

#include <fstream>
#include <iostream>
#include <linux/limits.h>
#include <mntent.h>
#include <string>
#include <unistd.h>
#include <utility>
#include <vector>

#include <base/base64.h>
#include <base/files/file.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/strings/string_split.h>
#include <base/strings/string_util.h>
#include <rootdev/rootdev.h>

#include "debugd/src/helper_utils.h"
#include "debugd/src/process_with_id.h"
#include "debugd/src/process_with_output.h"

namespace debugd {

namespace {

const char kSmartctl[] = "/usr/sbin/smartctl";
const char kBadblocks[] = "/sbin/badblocks";
const char kMmc[] = "/usr/bin/mmc";
const char kNvme[] = "/usr/sbin/nvme";
const char kSgSendDiag[] = "/usr/bin/sg_senddiag";

}  // namespace

const base::FilePath StorageTool::GetRootDevice() {
  char root_device[PATH_MAX];
  int ret = rootdev(root_device, sizeof(root_device),
                    true,   // Do full resolution.
                    true);  // Remove partition number.
  if (ret != 0) {
    PLOG(WARNING) << "rootdev failed with error code " << ret;
    return base::FilePath();
  }

  return base::FilePath(root_device);
}

// This function is called by Smartctl to check for ATA devices.
// Smartctl is only supported on ATA devices, so this function
// will return false when other devices are used.
bool StorageTool::IsSupported(const base::FilePath typeFile,
                              const base::FilePath vendFile,
                              std::string* errorMsg) {
  base::FilePath r;
  bool link = base::NormalizeFilePath(typeFile, &r);
  if (!link) {
    PLOG(ERROR) << "Failed to read device type link";
    errorMsg->assign("<Failed to read device type link>");
    return false;
  }

  size_t target = r.value().find("target");
  if (target == -1) {
    errorMsg->assign("<This feature is not supported>");
    return false;
  }

  std::string vend;

  if (!base::ReadFileToString(vendFile, &vend)) {
    PLOG(ERROR) << "Failed to open " << vendFile.value();
    errorMsg->assign("<Failed to open vendor file>");
    return false;
  }

  if (vend.empty()) {
    errorMsg->assign("<Failed to find device type>");
    return false;
  }

  if (vend.compare(0, 3, "ATA") != 0) {
    errorMsg->assign("<This feature is not supported>");
    return false;
  }

  return true;
}

std::string StorageTool::Smartctl(const std::string& option) {
  const base::FilePath device = GetRootDevice();

  if (device.empty()) {
    LOG(ERROR) << "Failed to find root device";
    return "<Failed to find device>";
  }

  base::FilePath bname = device.BaseName();

  std::string path;
  if (!GetHelperPath("storage", &path))
    return "<path too long>";

  ProcessWithOutput process;
  // Disabling sandboxing since smartctl requires higher privileges.
  process.DisableSandbox();
  if (!process.Init())
    return "<process init failed>";

  if (bname.value().compare(0, 4, "nvme") == 0) {
    process.AddArg(kSmartctl);

    if (option == "attributes")
      process.AddArg("-A");
    if (option == "capabilities")
      process.AddArg("-c");
    if (option == "error")
      process.AddStringOption("-l", "error");
    if (option == "abort_test" || option == "health" || option == "selftest" ||
        option == "short_test")
      return "<Option not supported>";

  } else {
    const base::FilePath dir =
        base::FilePath("/sys/block/" + bname.value() + "/device/");
    const base::FilePath typeFile = dir.Append("type");
    const base::FilePath vendFile = dir.Append("vendor");
    std::string message;

    if (!IsSupported(typeFile, vendFile, &message)) {
      return message;
    }

    process.AddArg(kSmartctl);

    if (option == "abort_test")
      process.AddArg("-X");
    if (option == "attributes")
      process.AddArg("-A");
    if (option == "capabilities")
      process.AddArg("-c");
    if (option == "error")
      process.AddStringOption("-l", "error");
    if (option == "health")
      process.AddArg("-H");
    if (option == "selftest")
      process.AddStringOption("-l", "selftest");
    if (option == "short_test")
      process.AddStringOption("-t", "short");
  }

  process.AddArg(device.value());
  process.Run();
  std::string output;
  process.GetOutput(&output);
  return output;
}

std::string StorageTool::Start(const base::ScopedFD& outfd) {
  const base::FilePath device = GetRootDevice();

  if (device.empty()) {
    LOG(ERROR) << "Failed to find root device";
    return "<Failed to find device>";
  }

  ProcessWithId* p =
      CreateProcess(false /* sandboxed */, false /* access_root_mount_ns */);
  if (!p)
    return "";

  p->AddArg(kBadblocks);
  p->AddArg("-sv");
  p->AddArg(device.value());
  p->BindFd(outfd.get(), STDOUT_FILENO);
  p->BindFd(outfd.get(), STDERR_FILENO);
  LOG(INFO) << "badblocks: running process id: " << p->id();
  p->Start();
  return p->id();
}

std::string StorageTool::Mmc(const std::string& option) {
  ProcessWithOutput process;
  process.DisableSandbox();
  if (!process.Init())
    return "<process init failed>";

  process.AddArg(kMmc);

  if (option == "extcsd_read") {
    process.AddArg("extcsd");
    process.AddArg("read");
  } else if (option == "extcsd_dump") {
    process.AddArg("extcsd");
    process.AddArg("dump");
  } else {
    return "<Option not supported>";
  }

  const base::FilePath rootdev = GetRootDevice();
  process.AddArg(rootdev.value());
  process.Run();
  std::string output;
  process.GetOutput(&output);
  return output;
}

std::string StorageTool::Ufs(const std::string& option) {
  ProcessWithOutput process;
  process.DisableSandbox();
  if (!process.Init())
    return "<process init failed>";

  const base::FilePath rootdev = GetRootDevice();

  if (option == "info") {
    process.AddArg(kSmartctl);
    process.AddArg("--all");
    process.AddArg(rootdev.value());
  } else if (option == "short_self_test") {
    process.AddArg(kSgSendDiag);
    process.AddArg("--test");
    process.AddArg(rootdev.value());
  } else {
    return "<Option not supported>";
  }

  process.Run();
  std::string output;
  process.GetOutput(&output);
  return output;
}

std::string StorageTool::Nvme(const std::string& option) {
  ProcessWithOutput process;
  // Disabling sandboxing since nvme requires higher privileges.
  process.DisableSandbox();
  if (!process.Init())
    return "<process init failed>";

  process.AddArg(kNvme);

  const base::FilePath rootdev = GetRootDevice();
  if (option == "identify_controller") {
    process.AddArg("id-ctrl");
    process.AddArg("--vendor-specific");
    process.AddArg(rootdev.value());
  } else if (option == "short_self_test") {
    // Command for selftest
    process.AddArg("device-self-test");
    // Namespace of NVMe
    process.AddStringOption("-n", "1");
    // type of selftest: short
    process.AddStringOption("-s", "1");
    process.AddArg(rootdev.value());
  } else if (option == "long_self_test") {
    // command for selftest
    process.AddArg("device-self-test");
    // Namespace of NVMe
    process.AddStringOption("-n", "1");
    // type of selftest: long
    process.AddStringOption("-s", "2");
    process.AddArg(rootdev.value());
  } else if (option == "stop_self_test") {
    // command for selftest
    process.AddArg("device-self-test");
    // Namespace of NVMe
    process.AddStringOption("-n", "1");
    // type of selftest: abort
    process.AddStringOption("-s", "0xf");
    process.AddArg(rootdev.value());
  } else if (option == "list") {
    // command for list all the nvme devices and their properties
    process.AddArg("list");
    // output format json
    process.AddStringOption("-o", "json");
  } else {
    return "<Option not supported>";
  }

  process.Run();
  std::string output;
  process.GetOutput(&output);
  return output;
}

std::string StorageTool::NvmeLog(const uint32_t& page_id,
                                 const uint32_t& length,
                                 bool raw_binary) {
  ProcessWithOutput process;
  // Disabling sandboxing since nvme requires higher privileges.
  process.DisableSandbox();
  if (!process.Init())
    return "<process init failed>";

  process.AddArg(kNvme);
  process.AddArg("get-log");

  // Log page ID ranging from 0 to 255.
  if (page_id <= 0xff) {
    process.AddArg(base::StringPrintf("--log-id=%u", page_id));
  } else {
    return "<Page ID invalid>";
  }

  // Length of byte-data must be larger than 3.
  if (length >= 4) {
    process.AddArg(base::StringPrintf("--log-len=%u", length));
  } else {
    return "<Length of byte-data invalid. At least 4 bytes for a request>";
  }

  // Output in raw format.
  if (raw_binary) {
    process.AddArg("--raw-binary");
  }

  const base::FilePath rootdev = GetRootDevice();
  process.AddArg(rootdev.value());
  process.Run();
  std::string output;
  process.GetOutput(&output);

  if (raw_binary) {
    std::string input = std::move(output);
    // Encode output as base64 in case D-Bus drops invalid UTF8 string.
    base::Base64Encode(input, &output);
  }

  return output;
}

}  // namespace debugd
