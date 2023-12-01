// Copyright 2016 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DEBUGD_SRC_CUPS_TOOL_H_
#define DEBUGD_SRC_CUPS_TOOL_H_

#include "debugd/src/lp_tools.h"

#include <stdint.h>

#include <string>
#include <vector>
#include <memory>

namespace debugd {

class CupsTool {
 public:
  CupsTool() = default;
  CupsTool(const CupsTool&) = delete;
  CupsTool& operator=(const CupsTool&) = delete;

  ~CupsTool() = default;

  // Add a printer that can be configured automatically.
  int32_t AddAutoConfiguredPrinter(const std::string& name,
                                   const std::string& uri,
                                   const std::string& language);

  // Add a printer configured with the ppd found in |ppd_contents|.
  int32_t AddManuallyConfiguredPrinter(
      const std::string& name,
      const std::string& uri,
      const std::string& language,
      const std::vector<uint8_t>& ppd_contents);

  // Remove a printer from CUPS using lpadmin.
  bool RemovePrinter(const std::string& name);

  // Retrieve the PPD from CUPS for a given printer.
  std::vector<uint8_t> RetrievePpd(const std::string& name);

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

}  // namespace debugd

#endif  // DEBUGD_SRC_CUPS_TOOL_H_
