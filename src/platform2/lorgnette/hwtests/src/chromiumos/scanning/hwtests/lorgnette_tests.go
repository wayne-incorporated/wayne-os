// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package hwtests

import (
	"fmt"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"chromiumos/scanning/utils"
)

// MatchesLorgnetteCapabilitiesTest checks that `scannerCaps` advertises the
// same capabilities as `rawLorgnetteCaps`. One "needs audit" failure will be
// returned if the advertised capabilities differ. `scannerCaps` should be a
// scanner's capabilities read from XML, and `rawLorgnetteCaps` should be the
// output from a call to utils.LorgnetteCLIGetJSONCaps() for that same scanner.
func MatchesLorgnetteCapabilitiesTest(scannerCaps utils.ScannerCapabilities, rawLorgnetteCaps string) utils.TestFunction {
	return func() (result utils.TestResult, failures []utils.TestFailure, err error) {
		lorgnetteCaps, err := utils.ParseLorgnetteCapabilities(rawLorgnetteCaps)
		if err != nil {
			result = utils.Error
			return
		}

		if !cmp.Equal(scannerCaps.ToLorgnetteCaps(), lorgnetteCaps, cmpopts.EquateApprox(0, 0.001), cmpopts.SortSlices(func(a, b string) bool { return a < b })) {
			failures = append(failures, utils.TestFailure{Type: utils.NeedsAudit, Message: fmt.Sprintf("XML Capabilities (%v) do not match lorgnette capabilities (%v)", scannerCaps.ToLorgnetteCaps(), lorgnetteCaps)})
			result = utils.Failed
			return
		}

		result = utils.Passed
		return
	}
}
