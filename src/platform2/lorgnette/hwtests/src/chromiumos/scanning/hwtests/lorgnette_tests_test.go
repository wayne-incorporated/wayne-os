// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package hwtests

import (
	"testing"

	"chromiumos/scanning/utils"
)

// Valid JSON data from `lorgnette CLI get_json_caps`.
const rawLorgnetteCaps = `{
"SOURCE_ADF_DUPLEX":{
	"ColorModes":["MODE_COLOR","MODE_GRAYSCALE"],
	"Name":"ADF Duplex",
	"Resolutions":[300],
	"ScannableArea":{
		"Height":355.6,
		"Width":215.985}},
"SOURCE_ADF_SIMPLEX":{
	"ColorModes":["MODE_COLOR","MODE_GRAYSCALE"],
	"Name":"ADF","Resolutions":[300],
	"ScannableArea":{
		"Height":355.6,
		"Width":215.985}},
"SOURCE_PLATEN":{
	"ColorModes":["MODE_COLOR","MODE_GRAYSCALE"],
	"Name":"Flatbed",
	"Resolutions":[300],
	"ScannableArea":{
		"Height":355.6,
		"Width":215.985}}
}`

// invalidJSONString is an example of incorrectly formatted JSON data.
const invalidJSONString = `{Not valid JSON!`

// TestMatchesLorgnetteCapabilitiesTest tests that
// MatchesLorgnetteCapabilitiesTest functions correctly.
func TestMatchesLorgnetteCapabilitiesTest(t *testing.T) {
	tests := []struct {
		scannerCaps      utils.ScannerCapabilities
		rawLorgnetteCaps string
		result           utils.TestResult
		failures         []utils.FailureType
	}{
		{
			scannerCaps: utils.ScannerCapabilities{
				Version:      "2.63",
				MakeAndModel: "MF741C/743C",
				Manufacturer: "Canon",
				PlatenInputCaps: utils.SourceCapabilities{
					MaxWidth:       2551,
					MinWidth:       32,
					MaxHeight:      4200,
					MinHeight:      32,
					MaxScanRegions: 1,
					SettingProfile: utils.SettingProfile{
						Name:               "",
						Ref:                "",
						ColorModes:         []string{"Grayscale8", "RGB24"},
						DocumentFormats:    []string{"image/jpeg", "application/pdf", "application/octet-stream"},
						DocumentFormatsExt: []string{"image/jpeg", "application/pdf"},
						SupportedResolutions: utils.SupportedResolutions{
							DiscreteResolutions: []utils.DiscreteResolution{
								utils.DiscreteResolution{
									XResolution: 300,
									YResolution: 300}}}},
					MaxOpticalXResolution: 300,
					MaxOpticalYResolution: 300,
					MaxPhysicalWidth:      2551,
					MaxPhysicalHeight:     4200},
				AdfCapabilities: utils.AdfCapabilities{
					AdfSimplexInputCaps: utils.SourceCapabilities{
						MaxWidth:       2551,
						MinWidth:       32,
						MaxHeight:      4200,
						MinHeight:      32,
						MaxScanRegions: 1,
						SettingProfile: utils.SettingProfile{
							Name:               "",
							Ref:                "",
							ColorModes:         []string{"Grayscale8", "RGB24"},
							DocumentFormats:    []string{"image/jpeg", "application/pdf", "application/octet-stream"},
							DocumentFormatsExt: []string{"image/jpeg", "application/pdf"},
							SupportedResolutions: utils.SupportedResolutions{
								DiscreteResolutions: []utils.DiscreteResolution{
									utils.DiscreteResolution{
										XResolution: 300,
										YResolution: 300}}}},
						MaxOpticalXResolution: 300,
						MaxOpticalYResolution: 300,
						MaxPhysicalWidth:      2551,
						MaxPhysicalHeight:     4200},
					AdfDuplexInputCaps: utils.SourceCapabilities{
						MaxWidth:       2551,
						MinWidth:       32,
						MaxHeight:      4200,
						MinHeight:      32,
						MaxScanRegions: 1,
						SettingProfile: utils.SettingProfile{
							Name:               "",
							Ref:                "",
							ColorModes:         []string{"Grayscale8", "RGB24"},
							DocumentFormats:    []string{"image/jpeg", "application/pdf", "application/octet-stream"},
							DocumentFormatsExt: []string{"image/jpeg", "application/pdf"},
							SupportedResolutions: utils.SupportedResolutions{
								DiscreteResolutions: []utils.DiscreteResolution{
									utils.DiscreteResolution{
										XResolution: 300,
										YResolution: 300}}}},
						MaxOpticalXResolution: 300,
						MaxOpticalYResolution: 300,
						MaxPhysicalWidth:      2551,
						MaxPhysicalHeight:     4200},
					AdfOptions: []string{"DetectPaperLoaded", "Duplex"}},
				CameraInputCaps:         utils.SourceCapabilities{},
				StoredJobRequestSupport: utils.StoredJobRequestSupport{}},
			rawLorgnetteCaps: rawLorgnetteCaps,
			result:           utils.Passed,
			failures:         []utils.FailureType{},
		},
		{
			scannerCaps:      utils.ScannerCapabilities{},
			rawLorgnetteCaps: rawLorgnetteCaps,
			result:           utils.Failed,
			failures:         []utils.FailureType{utils.NeedsAudit},
		},
	}

	for _, tc := range tests {
		result, failures, err := MatchesLorgnetteCapabilitiesTest(tc.scannerCaps, tc.rawLorgnetteCaps)()

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

// TestMatchesLorgnetteCapabilitiesTestInvalidJSON tests that
// MatchesLorgnetteCapabilitiesTest reports an error when `rawLorgnetteData` is
// incorrectly formatted.
func TestMatchesLorgnetteCapabilitiesTestInvalidJSON(t *testing.T) {
	result, _, err := MatchesLorgnetteCapabilitiesTest(utils.ScannerCapabilities{}, invalidJSONString)()
	if result != utils.Error {
		t.Errorf("Result: expected %d, got %d", utils.Error, result)
	}

	if err == nil {
		t.Error("Expected error for invalid JSON data.")
	}
}
