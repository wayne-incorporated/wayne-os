// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <base/command_line.h>
#include <base/logging.h>
#include <brillo/syslog_logging.h>

#include "trunks/csme/pinweaver_provision.h"
#include "trunks/csme/pinweaver_provision_impl.h"
#include "trunks/trunks_factory_impl.h"

namespace {

constexpr char kProvisionCmd[] = "provision";
constexpr char kInitOwnerCmd[] = "init_owner";

void PrintUsage(const char* exec_name) {
  printf("Usage:\n");
  printf("%s --%s: provision the TPM salting key.\n", exec_name, kProvisionCmd);
  printf(
      "%s --%s: init csme after TPM clear (requires owner password to be "
      "empty).\n",
      exec_name, kInitOwnerCmd);
  fflush(stdout);
}

}  // namespace

int main(int argc, char** argv) {
  base::CommandLine::Init(argc, argv);
  brillo::InitLog(brillo::kLogToStderr);
  base::CommandLine* cl = base::CommandLine::ForCurrentProcess();

  trunks::TrunksFactoryImpl factory;
  CHECK(factory.Initialize()) << "Failed to initialize trunks factory.";
  trunks::csme::PinWeaverProvisionImpl provision(factory);

  if (cl->HasSwitch("provision")) {
    return provision.Provision() ? 0 : 1;
  } else if (cl->HasSwitch("init_owner")) {
    return provision.InitOwner() ? 0 : 1;
  }
  PrintUsage(argv[0]);
  return 1;
}
