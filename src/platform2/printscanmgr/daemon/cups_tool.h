// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef PRINTSCANMGR_DAEMON_CUPS_TOOL_H_
#define PRINTSCANMGR_DAEMON_CUPS_TOOL_H_

#include "printscanmgr/daemon/lp_tools.h"

#include <string>
#include <memory>

#include <printscanmgr/proto_bindings/printscanmgr_service.pb.h>

namespace printscanmgr {

class CupsTool {
 public:
  CupsTool() = default;
  CupsTool(const CupsTool&) = delete;
  CupsTool& operator=(const CupsTool&) = delete;

  ~CupsTool() = default;

  // Add a printer that can be configured automatically.
  CupsAddAutoConfiguredPrinterResponse AddAutoConfiguredPrinter(
      const CupsAddAutoConfiguredPrinterRequest& request);

  // Add a printer configured with the ppd found in |ppd_contents|.
  CupsAddManuallyConfiguredPrinterResponse AddManuallyConfiguredPrinter(
      const CupsAddManuallyConfiguredPrinterRequest& request);

  // Remove a printer from CUPS using lpadmin.
  CupsRemovePrinterResponse RemovePrinter(
      const CupsRemovePrinterRequest& request);

  // Retrieve the PPD from CUPS for a given printer.
  CupsRetrievePpdResponse RetrievePpd(const CupsRetrievePpdRequest& request);

  // Run lpstat -l -r -v -a -p -o and pass the stdout to output.
  bool RunLpstat(std::string* output);

  // Evaluates true if the |uri| (fed to lpadmin) seems valid.
  // Valid-looking URIs take the form "scheme://host..." for
  // which the trailing port spec is optional. In addition, they must
  // already be appropriately percent-encoded.
  bool UriSeemsReasonable(const std::string& uri);

  // Used to specify a specific implementation of LpTools (mainly for testing).
  void SetLpToolsForTesting(std::unique_ptr<LpTools> lptools);

 private:
  std::unique_ptr<LpTools> lp_tools_ = std::make_unique<LpToolsImpl>();
};

}  // namespace printscanmgr

#endif  // PRINTSCANMGR_DAEMON_CUPS_TOOL_H_
