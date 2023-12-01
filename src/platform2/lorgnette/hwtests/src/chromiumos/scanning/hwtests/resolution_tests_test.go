// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package hwtests

import (
	"testing"

	"chromiumos/scanning/utils"
)

// TestHasSupportedResolutionTest tests that HasSupportedResolutionTest
// functions correctly.
func TestHasSupportedResolutionTest(t *testing.T) {
	tests := []struct {
		platenCaps     utils.SourceCapabilities
		adfSimplexCaps utils.SourceCapabilities
		adfDuplexCaps  utils.SourceCapabilities
		result         utils.TestResult
		failures       []utils.FailureType
	}{
		{
			// Should pass: both resolutions ranges include 75.
			platenCaps: utils.SourceCapabilities{
				MaxWidth:       1200,
				MinWidth:       16,
				MaxHeight:      2800,
				MinHeight:      32,
				MaxScanRegions: 2,
				SettingProfile: utils.SettingProfile{
					Name:            "",
					Ref:             "",
					ColorModes:      []string{"RGB24"},
					DocumentFormats: []string{"application/octet-stream"},
					SupportedResolutions: utils.SupportedResolutions{
						XResolutionRange: utils.ResolutionRange{
							Min:    65,
							Max:    85,
							Normal: 75,
							Step:   10},
						YResolutionRange: utils.ResolutionRange{
							Min:    60,
							Max:    105,
							Normal: 90,
							Step:   15}}},
				MaxOpticalXResolution: 85,
				MaxOpticalYResolution: 105,
				MaxPhysicalWidth:      1200,
				MaxPhysicalHeight:     2800},
			// Should pass: [300, 300] is an allowed discrete resolution.
			adfSimplexCaps: utils.SourceCapabilities{
				MaxWidth:       1200,
				MinWidth:       16,
				MaxHeight:      2800,
				MinHeight:      32,
				MaxScanRegions: 2,
				SettingProfile: utils.SettingProfile{
					Name:            "",
					Ref:             "",
					ColorModes:      []string{"RGB24"},
					DocumentFormats: []string{"application/octet-stream"},
					SupportedResolutions: utils.SupportedResolutions{
						DiscreteResolutions: []utils.DiscreteResolution{
							utils.DiscreteResolution{
								XResolution: 100,
								YResolution: 200},
							utils.DiscreteResolution{
								XResolution: 300,
								YResolution: 300}}}},
				MaxOpticalXResolution: 800,
				MaxOpticalYResolution: 1200,
				MaxPhysicalWidth:      1200,
				MaxPhysicalHeight:     2800},
			// Should pass: zero-value SourceCapabilities aren't checked.
			adfDuplexCaps: utils.SourceCapabilities{},
			result:        utils.Passed,
			failures:      []utils.FailureType{},
		},
		{
			// Should fail: no resolutions specified for non-zero-value struct.
			platenCaps: utils.SourceCapabilities{
				MaxWidth:       1200,
				MinWidth:       16,
				MaxHeight:      2800,
				MinHeight:      32,
				MaxScanRegions: 2,
				SettingProfile: utils.SettingProfile{
					Name:            "",
					Ref:             "",
					ColorModes:      []string{"RGB24"},
					DocumentFormats: []string{"application/octet-stream"},
					SupportedResolutions: utils.SupportedResolutions{
						XResolutionRange: utils.ResolutionRange{},
						YResolutionRange: utils.ResolutionRange{}}},
				MaxOpticalXResolution: 85,
				MaxOpticalYResolution: 105,
				MaxPhysicalWidth:      1200,
				MaxPhysicalHeight:     2800},
			// Should fail: no matching allowable X and Y resolutions.
			adfSimplexCaps: utils.SourceCapabilities{
				MaxWidth:       1200,
				MinWidth:       16,
				MaxHeight:      2800,
				MinHeight:      32,
				MaxScanRegions: 2,
				SettingProfile: utils.SettingProfile{
					Name:            "",
					Ref:             "",
					ColorModes:      []string{"RGB24"},
					DocumentFormats: []string{"application/octet-stream"},
					SupportedResolutions: utils.SupportedResolutions{
						DiscreteResolutions: []utils.DiscreteResolution{
							utils.DiscreteResolution{
								XResolution: 100,
								YResolution: 200},
							utils.DiscreteResolution{
								XResolution: 1200,
								YResolution: 1200}}}},
				MaxOpticalXResolution: 800,
				MaxOpticalYResolution: 1200,
				MaxPhysicalWidth:      1200,
				MaxPhysicalHeight:     2800},
			// Should fail: X and Y resolution ranges do not overlap.
			adfDuplexCaps: utils.SourceCapabilities{
				MaxWidth:       1200,
				MinWidth:       16,
				MaxHeight:      2800,
				MinHeight:      32,
				MaxScanRegions: 2,
				SettingProfile: utils.SettingProfile{
					Name:            "",
					Ref:             "",
					ColorModes:      []string{"RGB24"},
					DocumentFormats: []string{"application/octet-stream"},
					SupportedResolutions: utils.SupportedResolutions{
						XResolutionRange: utils.ResolutionRange{
							Min:    65,
							Max:    85,
							Normal: 75,
							Step:   10},
						YResolutionRange: utils.ResolutionRange{
							Min:    200,
							Max:    600,
							Normal: 300,
							Step:   100}}},
				MaxOpticalXResolution: 85,
				MaxOpticalYResolution: 600,
				MaxPhysicalWidth:      1200,
				MaxPhysicalHeight:     2800},
			result:   utils.Failed,
			failures: []utils.FailureType{utils.CriticalFailure, utils.CriticalFailure, utils.CriticalFailure},
		},
		{
			platenCaps:     utils.SourceCapabilities{},
			adfSimplexCaps: utils.SourceCapabilities{},
			adfDuplexCaps:  utils.SourceCapabilities{},
			result:         utils.Skipped,
			failures:       []utils.FailureType{},
		},
	}

	for _, tc := range tests {
		result, failures, err := HasSupportedResolutionTest(tc.platenCaps, tc.adfSimplexCaps, tc.adfDuplexCaps)()

		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}

		if result != tc.result {
			t.Errorf("Result: expected %d, got %d", tc.result, result)
		}

		if len(failures) != len(tc.failures) {
			t.Errorf("Number of failures: expected %d, got %d", len(tc.failures), len(failures))
		}
		for i, failure := range failures {
			if failure.Type != tc.failures[i] {
				t.Errorf("FailureType: expected %d, got %d", tc.failures[i], failure.Type)
			}
		}
	}
}

// TestHighestResolutionIsSupportedTest tests that
// HighestResolutionIsSupportedTest functions correctly.
func TestHighestResolutionIsSupportedTest(t *testing.T) {
	tests := []struct {
		platenCaps     utils.SourceCapabilities
		adfSimplexCaps utils.SourceCapabilities
		adfDuplexCaps  utils.SourceCapabilities
		result         utils.TestResult
		failures       []utils.FailureType
	}{
		{
			// Should pass: highest resolution is 600 for both resolution
			// ranges.
			platenCaps: utils.SourceCapabilities{
				SettingProfile: utils.SettingProfile{
					SupportedResolutions: utils.SupportedResolutions{
						XResolutionRange: utils.ResolutionRange{
							Min:    75,
							Max:    600,
							Normal: 85,
							Step:   5},
						YResolutionRange: utils.ResolutionRange{
							Min:    75,
							Max:    600,
							Normal: 85,
							Step:   5}}}},
			// Should pass: highest resolution is [300, 300].
			adfSimplexCaps: utils.SourceCapabilities{
				SettingProfile: utils.SettingProfile{
					SupportedResolutions: utils.SupportedResolutions{
						DiscreteResolutions: []utils.DiscreteResolution{
							utils.DiscreteResolution{
								XResolution: 150,
								YResolution: 200},
							utils.DiscreteResolution{
								XResolution: 300,
								YResolution: 300}}}}},
			// Should pass: zero-value SourceCapabilities aren't checked.
			adfDuplexCaps: utils.SourceCapabilities{},
			result:        utils.Passed,
			failures:      []utils.FailureType{},
		},
		{
			// Should fail: [1500, 1500] is unsupported.
			platenCaps: utils.SourceCapabilities{
				SettingProfile: utils.SettingProfile{
					SupportedResolutions: utils.SupportedResolutions{
						XResolutionRange: utils.ResolutionRange{
							Min:    50,
							Max:    1500,
							Normal: 85,
							Step:   5},
						YResolutionRange: utils.ResolutionRange{
							Min:    50,
							Max:    1500,
							Normal: 85,
							Step:   5}}}},
			// Should fail: [2000, 2000] is unsupported.
			adfSimplexCaps: utils.SourceCapabilities{
				SettingProfile: utils.SettingProfile{
					SupportedResolutions: utils.SupportedResolutions{
						DiscreteResolutions: []utils.DiscreteResolution{
							utils.DiscreteResolution{
								XResolution: 150,
								YResolution: 150},
							utils.DiscreteResolution{
								XResolution: 2000,
								YResolution: 2000}}}}},
			// Should fail: [300, 600] is unsupported. Here, each of 300 and 600
			// is only supported by either XResolution or YResolution but not
			// both.
			adfDuplexCaps: utils.SourceCapabilities{
				SettingProfile: utils.SettingProfile{
					SupportedResolutions: utils.SupportedResolutions{
						DiscreteResolutions: []utils.DiscreteResolution{
							utils.DiscreteResolution{
								XResolution: 200,
								YResolution: 200},
							utils.DiscreteResolution{
								XResolution: 300,
								YResolution: 600}}}}},
			result:   utils.Failed,
			failures: []utils.FailureType{utils.NeedsAudit, utils.NeedsAudit, utils.NeedsAudit},
		},
		{
			platenCaps:     utils.SourceCapabilities{},
			adfSimplexCaps: utils.SourceCapabilities{},
			adfDuplexCaps:  utils.SourceCapabilities{},
			result:         utils.Skipped,
			failures:       []utils.FailureType{},
		},
	}

	for _, tc := range tests {
		result, failures, err := HighestResolutionIsSupportedTest(tc.platenCaps, tc.adfSimplexCaps, tc.adfDuplexCaps)()

		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}

		if result != tc.result {
			t.Errorf("Result: expected %d, got %d", tc.result, result)
		}

		if len(failures) != len(tc.failures) {
			t.Errorf("Number of failures: expected %d, got %d", len(tc.failures), len(failures))
		}
		for i, failure := range failures {
			if failure.Type != tc.failures[i] {
				t.Errorf("FailureType: expected %d, got %d", tc.failures[i], failure.Type)
			}
		}
	}
}

// TestLowestResolutionIsSupportedTest tests that
// LowestResolutionIsSupportedTest functions correctly.
func TestLowestResolutionIsSupportedTest(t *testing.T) {
	tests := []struct {
		platenCaps     utils.SourceCapabilities
		adfSimplexCaps utils.SourceCapabilities
		adfDuplexCaps  utils.SourceCapabilities
		result         utils.TestResult
		failures       []utils.FailureType
	}{
		{
			// Should pass: lowest resolution is 75 for both resolution ranges.
			platenCaps: utils.SourceCapabilities{
				SettingProfile: utils.SettingProfile{
					SupportedResolutions: utils.SupportedResolutions{
						XResolutionRange: utils.ResolutionRange{
							Min:    75,
							Max:    95,
							Normal: 85,
							Step:   10},
						YResolutionRange: utils.ResolutionRange{
							Min:    75,
							Max:    95,
							Normal: 85,
							Step:   10}}}},
			// Should pass: lowest resolution is [150, 150].
			adfSimplexCaps: utils.SourceCapabilities{
				SettingProfile: utils.SettingProfile{
					SupportedResolutions: utils.SupportedResolutions{
						DiscreteResolutions: []utils.DiscreteResolution{
							utils.DiscreteResolution{
								XResolution: 150,
								YResolution: 150},
							utils.DiscreteResolution{
								XResolution: 200,
								YResolution: 300}}}}},
			// Should pass: zero-value SourceCapabilities aren't checked.
			adfDuplexCaps: utils.SourceCapabilities{},
			result:        utils.Passed,
			failures:      []utils.FailureType{},
		},
		{
			// Should fail: [50, 50] is unsupported.
			platenCaps: utils.SourceCapabilities{
				SettingProfile: utils.SettingProfile{
					SupportedResolutions: utils.SupportedResolutions{
						XResolutionRange: utils.ResolutionRange{
							Min:    50,
							Max:    95,
							Normal: 85,
							Step:   5},
						YResolutionRange: utils.ResolutionRange{
							Min:    50,
							Max:    95,
							Normal: 85,
							Step:   5}}}},
			// Should fail: [25, 25] is unsupported.
			adfSimplexCaps: utils.SourceCapabilities{
				SettingProfile: utils.SettingProfile{
					SupportedResolutions: utils.SupportedResolutions{
						DiscreteResolutions: []utils.DiscreteResolution{
							utils.DiscreteResolution{
								XResolution: 25,
								YResolution: 25},
							utils.DiscreteResolution{
								XResolution: 150,
								YResolution: 150}}}}},
			// Should fail: [150, 200] is unsupported. Here, each of 150 and 200
			// is only supported by either XResolution or YResolution but not
			// both.
			adfDuplexCaps: utils.SourceCapabilities{
				SettingProfile: utils.SettingProfile{
					SupportedResolutions: utils.SupportedResolutions{
						DiscreteResolutions: []utils.DiscreteResolution{
							utils.DiscreteResolution{
								XResolution: 150,
								YResolution: 200},
							utils.DiscreteResolution{
								XResolution: 300,
								YResolution: 300}}}}},
			result:   utils.Failed,
			failures: []utils.FailureType{utils.NeedsAudit, utils.NeedsAudit, utils.NeedsAudit},
		},
		{
			platenCaps:     utils.SourceCapabilities{},
			adfSimplexCaps: utils.SourceCapabilities{},
			adfDuplexCaps:  utils.SourceCapabilities{},
			result:         utils.Skipped,
			failures:       []utils.FailureType{},
		},
	}

	for _, tc := range tests {
		result, failures, err := LowestResolutionIsSupportedTest(tc.platenCaps, tc.adfSimplexCaps, tc.adfDuplexCaps)()

		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}

		if result != tc.result {
			t.Errorf("Result: expected %d, got %d", tc.result, result)
		}

		if len(failures) != len(tc.failures) {
			t.Errorf("Number of failures: expected %d, got %d", len(tc.failures), len(failures))
		}
		for i, failure := range failures {
			if failure.Type != tc.failures[i] {
				t.Errorf("FailureType: expected %d, got %d", tc.failures[i], failure.Type)
			}
		}
	}
}
