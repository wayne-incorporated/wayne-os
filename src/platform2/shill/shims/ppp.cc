// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// pppd.h, which is required by lcp.h, is not C++ compatible.  The following
// contortions are required before including anything else to ensure that we
// control the definition of bool before stdbool get indirectly included so that
// we can redefine it.

#include <sys/types.h>

#include <base/check.h>

extern "C" {
#include <pppd/fsm.h>
#include <pppd/ipcp.h>

#define class class_num
#define bool pppd_bool_t
#include <pppd/pppd.h>
#undef bool
#undef class
#undef STOPPED
#include <pppd/lcp.h>
}

#include "shill/shims/ppp.h"

#include <arpa/inet.h>
#include <netinet/in.h>

#include <map>

#include <base/command_line.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <brillo/syslog_logging.h>

#include "shill/ppp_daemon.h"
#include "shill/rpc_task.h"
#include "shill/shims/environment.h"
#include "shill/shims/task_proxy.h"

namespace shill {

namespace shims {

static base::LazyInstance<PPP>::DestructorAtExit g_ppp =
    LAZY_INSTANCE_INITIALIZER;

PPP::PPP() : running_(false) {}

PPP::~PPP() = default;

// static
PPP* PPP::GetInstance() {
  return g_ppp.Pointer();
}

void PPP::Init() {
  if (running_) {
    return;
  }
  running_ = true;
  base::CommandLine::Init(0, nullptr);
  brillo::InitLog(brillo::kLogToSyslog | brillo::kLogHeader);
  LOG(INFO) << "PPP started.";
}

bool PPP::GetSecret(std::string* username, std::string* password) {
  LOG(INFO) << __func__;
  if (!CreateProxy()) {
    return false;
  }
  bool success = proxy_->GetSecret(username, password);
  DestroyProxy();
  return success;
}

void PPP::OnAuthenticateStart() {
  LOG(INFO) << __func__;
  if (CreateProxy()) {
    std::map<std::string, std::string> details;
    proxy_->Notify(kPPPReasonAuthenticating, details);
    DestroyProxy();
  }
}

void PPP::OnAuthenticateDone() {
  LOG(INFO) << __func__;
  if (CreateProxy()) {
    std::map<std::string, std::string> details;
    proxy_->Notify(kPPPReasonAuthenticated, details);
    DestroyProxy();
  }
}

void PPP::OnConnect(const std::string& ifname) {
  LOG(INFO) << __func__ << "(" << ifname << ")";
  if (!ipcp_gotoptions[0].ouraddr) {
    LOG(ERROR) << "ouraddr not set.";
    return;
  }
  std::map<std::string, std::string> dict;
  dict[kPPPInterfaceName] = ifname;
  dict[kPPPInternalIP4Address] = ConvertIPToText(&ipcp_gotoptions[0].ouraddr);
  dict[kPPPExternalIP4Address] = ConvertIPToText(&ipcp_hisoptions[0].hisaddr);
  if (ipcp_gotoptions[0].default_route) {
    dict[kPPPGatewayAddress] = dict[kPPPExternalIP4Address];
  }
  if (ipcp_gotoptions[0].dnsaddr[0]) {
    dict[kPPPDNS1] = ConvertIPToText(&ipcp_gotoptions[0].dnsaddr[0]);
  }
  if (ipcp_gotoptions[0].dnsaddr[1]) {
    dict[kPPPDNS2] = ConvertIPToText(&ipcp_gotoptions[0].dnsaddr[1]);
  }
  if (lcp_gotoptions[0].mru) {
    dict[kPPPMRU] = base::NumberToString(lcp_gotoptions[0].mru);
  }
  std::string lns_address;
  if (Environment::GetInstance()->GetVariable("LNS_ADDRESS", &lns_address)) {
    // Really an L2TP/IPsec option rather than a PPP one. But oh well.
    dict[kPPPLNSAddress] = lns_address;
  }
  if (CreateProxy()) {
    proxy_->Notify(kPPPReasonConnect, dict);
    DestroyProxy();
  }
}

void PPP::OnDisconnect() {
  LOG(INFO) << __func__;
  if (CreateProxy()) {
    std::map<std::string, std::string> dict;
    proxy_->Notify(kPPPReasonDisconnect, dict);
    DestroyProxy();
  }
}

void PPP::OnExit(int exit_status) {
  LOG(INFO) << __func__ << "(" << exit_status << ")";
  if (CreateProxy()) {
    std::map<std::string, std::string> dict;
    dict[kPPPExitStatus] = base::NumberToString(exit_status);
    proxy_->Notify(kPPPReasonExit, dict);
    DestroyProxy();
  }
}

bool PPP::CreateProxy() {
  Environment* environment = Environment::GetInstance();
  std::string service, path;
  if (!environment->GetVariable(kRpcTaskServiceVariable, &service) ||
      !environment->GetVariable(kRpcTaskPathVariable, &path)) {
    LOG(ERROR) << "Environment variables not available.";
    return false;
  }

  dbus::Bus::Options options;
  options.bus_type = dbus::Bus::SYSTEM;
  bus_ = new dbus::Bus(options);
  CHECK(bus_->Connect());

  proxy_.reset(new TaskProxy(bus_, path, service));

  LOG(INFO) << "Task proxy created: " << service << " - " << path;
  return true;
}

void PPP::DestroyProxy() {
  proxy_.reset();
  if (bus_) {
    bus_->ShutdownAndBlock();
  }
  LOG(INFO) << "Task proxy destroyed.";
}

// static
std::string PPP::ConvertIPToText(const void* addr) {
  char text[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, addr, text, INET_ADDRSTRLEN);
  return text;
}

}  // namespace shims

}  // namespace shill
