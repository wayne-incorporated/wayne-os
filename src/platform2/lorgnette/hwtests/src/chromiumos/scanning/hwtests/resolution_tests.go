// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package hwtests

import (
	"fmt"
	"math"

	"chromiumos/scanning/utils"
)

// checkForSupportedResolution returns true if `sourceResolutions` advertises at
// least one supported resolution, which must be advertised for both X and Y
// resolutions.
func checkForSupportedResolution(sourceResolutions utils.SupportedResolutions) bool {
	lorgnetteResolutions := sourceResolutions.ToLorgnetteResolutions()

	if len(lorgnetteResolutions) == 0 {
		return false
	}

	return true
}

// isHighestResolutionSupported returns true iff the highest resolution
// advertised by `sourceResolutions` is supported.
func isHighestResolutionSupported(sourceResolutions utils.SupportedResolutions) bool {
	res := sourceResolutions.XResolutionRange.Max

	if sourceResolutions.YResolutionRange.Max > res {
		res = sourceResolutions.YResolutionRange.Max
	}

	for _, discreteResolution := range sourceResolutions.DiscreteResolutions {
		if discreteResolution.XResolution > res {
			res = discreteResolution.XResolution
		}
		if discreteResolution.YResolution > res {
			res = discreteResolution.YResolution
		}
	}

	for _, supportedResolution := range sourceResolutions.ToLorgnetteResolutions() {
		if supportedResolution == res {
			return true
		}
	}

	return false
}

// isLowestResolutionSupported returns true iff the lowest resolution advertised
// by `sourceResolutions` is supported.
func isLowestResolutionSupported(sourceResolutions utils.SupportedResolutions) bool {
	res := math.MaxInt32

	if sourceResolutions.XResolutionRange.Min > 0 && sourceResolutions.XResolutionRange.Min < res {
		res = sourceResolutions.XResolutionRange.Min
	}

	if sourceResolutions.YResolutionRange.Min > 0 && sourceResolutions.YResolutionRange.Min < res {
		res = sourceResolutions.YResolutionRange.Min
	}

	for _, discreteResolution := range sourceResolutions.DiscreteResolutions {
		if discreteResolution.XResolution < res {
			res = discreteResolution.XResolution
		}
		if discreteResolution.YResolution < res {
			res = discreteResolution.YResolution
		}
	}

	for _, supportedResolution := range sourceResolutions.ToLorgnetteResolutions() {
		if supportedResolution == res {
			return true
		}
	}

	return false
}

// HasSupportedResolutionTest checks that each supported document source
// advertises at least one supported resolution. One critical failure will be
// returned for each supported document source which does not advertise any of
// the supported resolutions.
func HasSupportedResolutionTest(platenCaps utils.SourceCapabilities, adfSimplexCaps utils.SourceCapabilities, adfDuplexCaps utils.SourceCapabilities) utils.TestFunction {
	return func() (result utils.TestResult, failures []utils.TestFailure, err error) {
		if !platenCaps.IsPopulated() && !adfSimplexCaps.IsPopulated() && !adfDuplexCaps.IsPopulated() {
			result = utils.Skipped
			return
		}

		if platenCaps.IsPopulated() && !checkForSupportedResolution(platenCaps.SettingProfile.SupportedResolutions) {
			failures = append(failures, utils.TestFailure{Type: utils.CriticalFailure, Message: fmt.Sprintf("Platen source advertises only unsupported resolutions: %v", platenCaps.SettingProfile.SupportedResolutions)})
		}
		if adfSimplexCaps.IsPopulated() && !checkForSupportedResolution(adfSimplexCaps.SettingProfile.SupportedResolutions) {
			failures = append(failures, utils.TestFailure{Type: utils.CriticalFailure, Message: fmt.Sprintf("ADF simplex source advertises only unsupported resolutions: %v", adfSimplexCaps.SettingProfile.SupportedResolutions)})
		}
		if adfDuplexCaps.IsPopulated() && !checkForSupportedResolution(adfDuplexCaps.SettingProfile.SupportedResolutions) {
			failures = append(failures, utils.TestFailure{Type: utils.CriticalFailure, Message: fmt.Sprintf("ADF duplex source advertises only unsupported resolutions: %v", adfDuplexCaps.SettingProfile.SupportedResolutions)})
		}

		if len(failures) == 0 {
			result = utils.Passed
		} else {
			result = utils.Failed
		}

		return
	}
}

// HighestResolutionIsSupportedTest checks that the highest resolution
// advertised by each supported document source is supported. One "needs audit"
// failure will be returned for each supported document source whose highest
// advertised resolution is unsupported.
func HighestResolutionIsSupportedTest(platenCaps utils.SourceCapabilities, adfSimplexCaps utils.SourceCapabilities, adfDuplexCaps utils.SourceCapabilities) utils.TestFunction {
	return func() (result utils.TestResult, failures []utils.TestFailure, err error) {
		if !platenCaps.IsPopulated() && !adfSimplexCaps.IsPopulated() && !adfDuplexCaps.IsPopulated() {
			result = utils.Skipped
			return
		}

		if platenCaps.IsPopulated() && !isHighestResolutionSupported(platenCaps.SettingProfile.SupportedResolutions) {
			failures = append(failures, utils.TestFailure{Type: utils.NeedsAudit, Message: fmt.Sprintf("Platen source's highest resolution is unsupported: %v", platenCaps.SettingProfile.SupportedResolutions)})
		}
		if adfSimplexCaps.IsPopulated() && !isHighestResolutionSupported(adfSimplexCaps.SettingProfile.SupportedResolutions) {
			failures = append(failures, utils.TestFailure{Type: utils.NeedsAudit, Message: fmt.Sprintf("ADF simplex source's highest resolution is unsupported: %v", adfSimplexCaps.SettingProfile.SupportedResolutions)})
		}
		if adfDuplexCaps.IsPopulated() && !isHighestResolutionSupported(adfDuplexCaps.SettingProfile.SupportedResolutions) {
			failures = append(failures, utils.TestFailure{Type: utils.NeedsAudit, Message: fmt.Sprintf("ADF duplex source's highest resolution is unsupported: %v", adfDuplexCaps.SettingProfile.SupportedResolutions)})
		}

		if len(failures) == 0 {
			result = utils.Passed
		} else {
			result = utils.Failed
		}

		return
	}
}

// LowestResolutionIsSupportedTest checks that the lowest resolution advertised
// by each supported document source is supported. One "needs audit" failure
// will be returned for each supported document source whose lowest advertised
// resolution is unsupported.
func LowestResolutionIsSupportedTest(platenCaps utils.SourceCapabilities, adfSimplexCaps utils.SourceCapabilities, adfDuplexCaps utils.SourceCapabilities) utils.TestFunction {
	return func() (result utils.TestResult, failures []utils.TestFailure, err error) {
		if !platenCaps.IsPopulated() && !adfSimplexCaps.IsPopulated() && !adfDuplexCaps.IsPopulated() {
			result = utils.Skipped
			return
		}

		if platenCaps.IsPopulated() && !isLowestResolutionSupported(platenCaps.SettingProfile.SupportedResolutions) {
			failures = append(failures, utils.TestFailure{Type: utils.NeedsAudit, Message: fmt.Sprintf("Platen source's lowest resolution is unsupported: %v", platenCaps.SettingProfile.SupportedResolutions)})
		}
		if adfSimplexCaps.IsPopulated() && !isLowestResolutionSupported(adfSimplexCaps.SettingProfile.SupportedResolutions) {
			failures = append(failures, utils.TestFailure{Type: utils.NeedsAudit, Message: fmt.Sprintf("ADF simplex source's lowest resolution is unsupported: %v", adfSimplexCaps.SettingProfile.SupportedResolutions)})
		}
		if adfDuplexCaps.IsPopulated() && !isLowestResolutionSupported(adfDuplexCaps.SettingProfile.SupportedResolutions) {
			failures = append(failures, utils.TestFailure{Type: utils.NeedsAudit, Message: fmt.Sprintf("ADF duplex source's lowest resolution is unsupported: %v", adfDuplexCaps.SettingProfile.SupportedResolutions)})
		}

		if len(failures) == 0 {
			result = utils.Passed
		} else {
			result = utils.Failed
		}

		return
	}
}
