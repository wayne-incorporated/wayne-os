// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package hwtests

import (
	"chromiumos/scanning/utils"
)

// NoCameraSourceTest checks if `cameraCapabilities` is the zero value. If it
// isn't, the test returns a critical failure. Else it returns no failures.
func NoCameraSourceTest(cameraCapabilities utils.SourceCapabilities) utils.TestFunction {
	return func() (result utils.TestResult, failures []utils.TestFailure, err error) {
		result = utils.Passed
		if cameraCapabilities.IsPopulated() {
			failures = append(failures, utils.TestFailure{Type: utils.CriticalFailure, Message: "Scanner advertises camera capabilities."})
			result = utils.Failed
		}
		return
	}
}

// HasSupportedDocumentSourceTest passes if at least one of `platenCaps`,
// `adfSimplexCaps` and `adfDuplexCaps` is non-empty. If all three of the input
// sources are empty, the test will fail and a single critical failure will be
// returned.
func HasSupportedDocumentSourceTest(platenCaps utils.SourceCapabilities, adfSimplexCaps utils.SourceCapabilities, adfDuplexCaps utils.SourceCapabilities) utils.TestFunction {
	return func() (result utils.TestResult, failures []utils.TestFailure, err error) {
		if !platenCaps.IsPopulated() && !adfSimplexCaps.IsPopulated() && !adfDuplexCaps.IsPopulated() {
			failures = append(failures, utils.TestFailure{Type: utils.CriticalFailure, Message: "Scanner advertises no supported document sources."})
			result = utils.Failed
		} else {
			result = utils.Passed
		}
		return
	}
}
