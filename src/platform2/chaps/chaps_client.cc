// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// This is the Chaps client. It sends calls to the Chaps daemon via D-Bus.

#include <stdio.h>
#include <stdlib.h>

#include <string>
#include <vector>

#include <base/command_line.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <base/time/time.h>
#include <brillo/syslog_logging.h>

#include "chaps/chaps_proxy.h"
#include "chaps/chaps_utility.h"
#include "chaps/isolate.h"
#include "chaps/token_manager_client.h"

using base::FilePath;
using brillo::SecureBlob;
using chaps::IsolateCredentialManager;
using std::string;
using std::vector;

namespace {

void PrintHelp() {
  printf("Usage: chaps_client COMMAND [ARGUMENTS]\n");
  printf("Commands:\n");
  printf("  --ping : Checks that the Chaps daemon is available.\n");
  printf(
      "  --load --path=<path> --auth=<auth> [--label=<label>]"
      " : Loads the token at the given path.\n");
  printf("  --unload --path=<path> : Unloads the token at the given path.\n");
  printf(
      "  --set_log_level=<level> : Sets the chapsd logging level.\n"
      "    Levels: \n      2 - Errors Only\n      1 - Warnings and Errors\n"
      "      0 - Normal\n     -1 - Verbose (Logs PKCS #11 calls.)\n"
      "     -2 - More Verbose (Logs PKCS #11 calls and arguments.)\n");
  printf("  --list : Lists all loaded token paths.\n");
}

int Ping() {
  auto proxy = chaps::ChapsProxyImpl::Create(
      /*shadow_at_exit=*/false, chaps::ThreadingMode::kCurrentThread);
  if (!proxy)
    return -1;
  vector<uint64_t> slot_list;
  if (proxy->GetSlotList(
          IsolateCredentialManager::GetDefaultIsolateCredential(), true,
          &slot_list) != 0) {
    LOG(ERROR) << "Chaps is available but failed to provide a token list.";
    return -1;
  }
  LOG(INFO) << "Chaps is available with " << slot_list.size() << " token(s).";
  return 0;
}

// Loads a token given a path and auth data.
int LoadToken(const string& path, const string& auth, const string& label) {
  chaps::TokenManagerClient client;
  int slot_id = -1;
  if (client.LoadToken(IsolateCredentialManager::GetDefaultIsolateCredential(),
                       FilePath(path), SecureBlob(auth.begin(), auth.end()),
                       label, &slot_id) == false) {
    LOG(ERROR) << "LoadToken: " << path << " - slot = " << slot_id << " failed";
    return -1;
  }
  LOG(INFO) << "LoadToken: " << path << " - slot = " << slot_id;
  return 0;
}

// Unloads a token given a path.
int UnloadToken(const string& path) {
  chaps::TokenManagerClient client;
  if (client.UnloadToken(
          IsolateCredentialManager::GetDefaultIsolateCredential(),
          FilePath(path)) == false) {
    LOG(ERROR) << "Sent Event: Logout: " << path << " failed";
    return -1;
  }
  LOG(INFO) << "Sent Event: Logout: " << path;
  return 0;
}

// Sets the logging level.
int SetLogLevel(int level) {
  auto proxy = chaps::ChapsProxyImpl::Create(
      /*shadow_at_exit=*/false, chaps::ThreadingMode::kCurrentThread);
  if (!proxy) {
    LOG(ERROR) << "Set log level failed.";
    return -1;
  }
  proxy->SetLogLevel(level);
  return 0;
}

int ListTokens() {
  auto proxy = chaps::ChapsProxyImpl::Create(
      /*shadow_at_exit=*/false, chaps::ThreadingMode::kCurrentThread);
  if (!proxy)
    return -1;
  vector<uint64_t> slot_list;
  uint32_t result = proxy->GetSlotList(
      IsolateCredentialManager::GetDefaultIsolateCredential(), true,
      &slot_list);
  if (result != 0)
    return -1;
  chaps::TokenManagerClient client;
  for (size_t i = 0; i < slot_list.size(); ++i) {
    int slot = slot_list[i];
    FilePath path;
    if (client.GetTokenPath(
            IsolateCredentialManager::GetDefaultIsolateCredential(), slot,
            &path)) {
      LOG(INFO) << "Slot " << slot << ": " << path.value();
    } else {
      LOG(INFO) << "Slot " << slot << ": Empty";
    }
  }
  return 0;
}

}  // namespace

int main(int argc, char** argv) {
  base::AtExitManager at_exit;
  base::CommandLine::Init(argc, argv);
  base::CommandLine* cl = base::CommandLine::ForCurrentProcess();
  brillo::InitLog(brillo::kLogToSyslog | brillo::kLogToStderr);

  bool ping = cl->HasSwitch("ping");
  bool load =
      (cl->HasSwitch("load") && cl->HasSwitch("path") && cl->HasSwitch("auth"));
  bool unload = cl->HasSwitch("unload") && cl->HasSwitch("path");
  bool set_log_level = cl->HasSwitch("set_log_level");
  bool list = cl->HasSwitch("list");
  int result = 0;

  if (ping + load + unload + set_log_level + list != 1) {
    PrintHelp();
    exit(-1);
  }
  if (ping) {
    result = Ping();
  } else if (load) {
    string label = "Default Token";
    if (cl->HasSwitch("label"))
      label = cl->GetSwitchValueASCII("label");
    result = LoadToken(cl->GetSwitchValueASCII("path"),
                       cl->GetSwitchValueASCII("auth"), label);
  } else if (unload) {
    result = UnloadToken(cl->GetSwitchValueASCII("path"));
  } else if (set_log_level) {
    int level = 0;
    if (!base::StringToInt(cl->GetSwitchValueASCII("set_log_level"), &level)) {
      LOG(ERROR) << "Invalid argument.";
      result = -1;
    } else {
      result = SetLogLevel(level);
    }
  } else if (list) {
    result = ListTokens();
  }
  return result;
}
