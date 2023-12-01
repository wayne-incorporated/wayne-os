// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package hwtests

import (
	"testing"

	"chromiumos/scanning/utils"
)

// TestHasSupportedColorModeTest tests that HasSupportedColorModeTest functions
// correctly.
func TestHasSupportedColorModeTest(t *testing.T) {
	tests := []struct {
		platenCaps     utils.SourceCapabilities
		adfSimplexCaps utils.SourceCapabilities
		adfDuplexCaps  utils.SourceCapabilities
		result         utils.TestResult
		failures       []utils.FailureType
	}{
		{
			platenCaps: utils.SourceCapabilities{
				MaxWidth:       1200,
				MinWidth:       16,
				MaxHeight:      2800,
				MinHeight:      32,
				MaxScanRegions: 2,
				SettingProfile: utils.SettingProfile{
					Name:            "",
					Ref:             "",
					ColorModes:      []string{"RGB24", "RGB48"},
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
			adfSimplexCaps: utils.SourceCapabilities{
				MaxWidth:       1200,
				MinWidth:       16,
				MaxHeight:      2800,
				MinHeight:      32,
				MaxScanRegions: 2,
				SettingProfile: utils.SettingProfile{
					Name:            "",
					Ref:             "",
					ColorModes:      []string{"BlackAndWhite1", "Grayscale16"},
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
			adfDuplexCaps: utils.SourceCapabilities{},
			result:        utils.Passed,
			failures:      []utils.FailureType{},
		},
		{
			platenCaps: utils.SourceCapabilities{
				MaxWidth:       1200,
				MinWidth:       16,
				MaxHeight:      2800,
				MinHeight:      32,
				MaxScanRegions: 2,
				SettingProfile: utils.SettingProfile{
					Name:            "",
					Ref:             "",
					ColorModes:      []string{"Grayscale8"},
					DocumentFormats: []string{"application/octet-stream"},
					SupportedResolutions: utils.SupportedResolutions{
						XResolutionRange: utils.ResolutionRange{},
						YResolutionRange: utils.ResolutionRange{}}},
				MaxOpticalXResolution: 85,
				MaxOpticalYResolution: 105,
				MaxPhysicalWidth:      1200,
				MaxPhysicalHeight:     2800},
			adfSimplexCaps: utils.SourceCapabilities{
				MaxWidth:       1200,
				MinWidth:       16,
				MaxHeight:      2800,
				MinHeight:      32,
				MaxScanRegions: 2,
				SettingProfile: utils.SettingProfile{
					Name:            "",
					Ref:             "",
					ColorModes:      []string{"RGB48"},
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
			adfDuplexCaps: utils.SourceCapabilities{
				MaxWidth:       1200,
				MinWidth:       16,
				MaxHeight:      2800,
				MinHeight:      32,
				MaxScanRegions: 2,
				SettingProfile: utils.SettingProfile{
					Name:            "",
					Ref:             "",
					ColorModes:      []string{"Grayscale16"},
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
			failures: []utils.FailureType{utils.CriticalFailure, utils.CriticalFailure},
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
		result, failures, err := HasSupportedColorModeTest(tc.platenCaps, tc.adfSimplexCaps, tc.adfDuplexCaps)()

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

// TestNoUnsupportedColorModeTest tests that NoUnsupportedColorModeTest
// functions correctly.
func TestNoUnsupportedColorModeTest(t *testing.T) {
	tests := []struct {
		platenCaps     utils.SourceCapabilities
		adfSimplexCaps utils.SourceCapabilities
		adfDuplexCaps  utils.SourceCapabilities
		result         utils.TestResult
		failures       []utils.FailureType
	}{
		{
			platenCaps: utils.SourceCapabilities{
				MaxWidth:       1200,
				MinWidth:       16,
				MaxHeight:      2800,
				MinHeight:      32,
				MaxScanRegions: 2,
				SettingProfile: utils.SettingProfile{
					Name:            "",
					Ref:             "",
					ColorModes:      []string{"RGB24", "Grayscale8", "BlackAndWhite1"},
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
			adfSimplexCaps: utils.SourceCapabilities{
				MaxWidth:       1200,
				MinWidth:       16,
				MaxHeight:      2800,
				MinHeight:      32,
				MaxScanRegions: 2,
				SettingProfile: utils.SettingProfile{
					Name:            "",
					Ref:             "",
					ColorModes:      []string{},
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
			adfDuplexCaps: utils.SourceCapabilities{},
			result:        utils.Passed,
			failures:      []utils.FailureType{},
		},
		{
			platenCaps: utils.SourceCapabilities{
				MaxWidth:       1200,
				MinWidth:       16,
				MaxHeight:      2800,
				MinHeight:      32,
				MaxScanRegions: 2,
				SettingProfile: utils.SettingProfile{
					Name:            "",
					Ref:             "",
					ColorModes:      []string{"Grayscale8", "Grayscale16"},
					DocumentFormats: []string{"application/octet-stream"},
					SupportedResolutions: utils.SupportedResolutions{
						XResolutionRange: utils.ResolutionRange{},
						YResolutionRange: utils.ResolutionRange{}}},
				MaxOpticalXResolution: 85,
				MaxOpticalYResolution: 105,
				MaxPhysicalWidth:      1200,
				MaxPhysicalHeight:     2800},
			adfSimplexCaps: utils.SourceCapabilities{
				MaxWidth:       1200,
				MinWidth:       16,
				MaxHeight:      2800,
				MinHeight:      32,
				MaxScanRegions: 2,
				SettingProfile: utils.SettingProfile{
					Name:            "",
					Ref:             "",
					ColorModes:      []string{"RGB48", "RGB24"},
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
			adfDuplexCaps: utils.SourceCapabilities{
				MaxWidth:       1200,
				MinWidth:       16,
				MaxHeight:      2800,
				MinHeight:      32,
				MaxScanRegions: 2,
				SettingProfile: utils.SettingProfile{
					Name:            "",
					Ref:             "",
					ColorModes:      []string{"Unknown Color Mode"},
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
		result, failures, err := NoUnsupportedColorModeTest(tc.platenCaps, tc.adfSimplexCaps, tc.adfDuplexCaps)()

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
