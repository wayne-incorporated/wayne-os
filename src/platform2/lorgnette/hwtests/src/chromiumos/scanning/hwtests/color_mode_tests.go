// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package hwtests

import (
	"fmt"

	"chromiumos/scanning/utils"
)

var supportedColorModes = []string{"BlackAndWhite1", "Grayscale8", "RGB24"}

// containsSupportedColorMode returns true if `sourceColorModes` contains at
// least one supported color mode.
func containsSupportedColorMode(sourceColorModes []string) bool {
	for _, sourceColorMode := range sourceColorModes {
		for _, supportedColorMode := range supportedColorModes {
			if sourceColorMode == supportedColorMode {
				return true
			}
		}
	}

	return false
}

// listUnsupportedColorModes returns a list of unsupported color modes contained
// in `colorModes`.
func listUnsupportedColorModes(colorModes []string) (unsupportedColorModes []string) {
	for _, colorMode := range colorModes {
		isSupported := false
		for _, supportedColorMode := range supportedColorModes {
			if colorMode == supportedColorMode {
				isSupported = true
				break
			}
		}

		if !isSupported {
			unsupportedColorModes = append(unsupportedColorModes, colorMode)
		}
	}

	return
}

// HasSupportedColorModeTest checks that each supported document source
// advertises at least one supported color mode. One critical failure will be
// returned for each supported document source which does not advertise any of
// the supported color modes.
func HasSupportedColorModeTest(platenCaps utils.SourceCapabilities, adfSimplexCaps utils.SourceCapabilities, adfDuplexCaps utils.SourceCapabilities) utils.TestFunction {
	return func() (result utils.TestResult, failures []utils.TestFailure, err error) {
		if !platenCaps.IsPopulated() && !adfSimplexCaps.IsPopulated() && !adfDuplexCaps.IsPopulated() {
			result = utils.Skipped
			return
		}

		if platenCaps.IsPopulated() && !containsSupportedColorMode(platenCaps.SettingProfile.ColorModes) {
			failures = append(failures, utils.TestFailure{Type: utils.CriticalFailure, Message: fmt.Sprintf("Platen source advertises only unsupported color modes: %v", platenCaps.SettingProfile.ColorModes)})
		}
		if adfSimplexCaps.IsPopulated() && !containsSupportedColorMode(adfSimplexCaps.SettingProfile.ColorModes) {
			failures = append(failures, utils.TestFailure{Type: utils.CriticalFailure, Message: fmt.Sprintf("ADF simplex source advertises only unsupported color modes: %v", adfSimplexCaps.SettingProfile.ColorModes)})
		}
		if adfDuplexCaps.IsPopulated() && !containsSupportedColorMode(adfDuplexCaps.SettingProfile.ColorModes) {
			failures = append(failures, utils.TestFailure{Type: utils.CriticalFailure, Message: fmt.Sprintf("ADF duplex source advertises only unsupported color modes: %v", adfDuplexCaps.SettingProfile.ColorModes)})
		}

		if len(failures) == 0 {
			result = utils.Passed
		} else {
			result = utils.Failed
		}

		return
	}
}

// NoUnsupportedColorModeTest checks that each supported document source
// advertises only supported color modes. One critical failure will be returned
// for each supported document source which advertises any unsupported color
// mode.
func NoUnsupportedColorModeTest(platenCaps utils.SourceCapabilities, adfSimplexCaps utils.SourceCapabilities, adfDuplexCaps utils.SourceCapabilities) utils.TestFunction {
	return func() (result utils.TestResult, failures []utils.TestFailure, err error) {
		if !platenCaps.IsPopulated() && !adfSimplexCaps.IsPopulated() && !adfDuplexCaps.IsPopulated() {
			result = utils.Skipped
			return
		}

		if unsupportedColorModes := listUnsupportedColorModes(platenCaps.SettingProfile.ColorModes); len(unsupportedColorModes) != 0 {
			failures = append(failures, utils.TestFailure{Type: utils.CriticalFailure, Message: fmt.Sprintf("Platen source advertises unsupported color modes: %v", unsupportedColorModes)})
		}
		if unsupportedColorModes := listUnsupportedColorModes(adfSimplexCaps.SettingProfile.ColorModes); len(unsupportedColorModes) != 0 {
			failures = append(failures, utils.TestFailure{Type: utils.CriticalFailure, Message: fmt.Sprintf("ADF simplex source advertises unsupported color modes: %v", unsupportedColorModes)})
		}
		if unsupportedColorModes := listUnsupportedColorModes(adfDuplexCaps.SettingProfile.ColorModes); len(unsupportedColorModes) != 0 {
			failures = append(failures, utils.TestFailure{Type: utils.CriticalFailure, Message: fmt.Sprintf("ADF duplex source advertises unsupported color modes: %v", unsupportedColorModes)})
		}

		if len(failures) == 0 {
			result = utils.Passed
		} else {
			result = utils.Failed
		}

		return
	}
}
