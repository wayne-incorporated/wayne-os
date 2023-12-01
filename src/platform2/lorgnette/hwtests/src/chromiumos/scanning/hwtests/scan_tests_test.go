// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package hwtests

import (
	"chromiumos/scanning/utils"
	"testing"
)

// Output from `identify` run on a black and white image.
const identifyOutputLineart = `lorgnette/test_images/bw.png PNG 1700x2200 1700x2200+0+0 8-bit Grayscale Gray 2c 147B 0.000u 0:00.000`

// Output from `identify` run on a grayscale image.
const identifyOutputGrayscale = `/tmp/scan-airscan_escl_Canon_MF741C_743C__9e_31_7f___4___9e_31_7f___17___9e_31_7f___8__http___200_100_90_40_30_eSCL__page1.png PNG 850x1100 850x1100+0+0 8-bit Grayscale Gray 256c 899008B 0.000u 0:00.000`

// Output from `identify` run on a color image.
const identifyOutputColor = `/tmp/scan-airscan_escl_Canon_MF741C_743C__9e_31_7f___4___9e_31_7f___17___9e_31_7f___8__http___200_100_90_40_30_eSCL__page1.png PNG 2550x3300 2550x3300+0+0 8-bit sRGB 1.74592MiB 0.000u 0:00.000`

// String input that does not match any of the regexes used in scan_tests.go.
const unrecognizedInput = `Unrecognized input.`

// TestToInputColorMode tests that toInputColorMode functions correctly.
func TestToInputColorMode(t *testing.T) {
	tests := []struct {
		lorgnetteColorMode string
		inputColorMode     string
	}{
		{
			lorgnetteColorMode: "MODE_LINEART",
			inputColorMode:     "Lineart",
		},
		{
			lorgnetteColorMode: "MODE_GRAYSCALE",
			inputColorMode:     "Grayscale",
		},
		{
			lorgnetteColorMode: "MODE_COLOR",
			inputColorMode:     "Color",
		},
	}

	for _, tc := range tests {
		inputColorMode, err := toInputColorMode(tc.lorgnetteColorMode)

		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}

		if inputColorMode != tc.inputColorMode {
			t.Errorf("inputColorMode: expected %s, got %s", tc.inputColorMode, inputColorMode)
		}
	}
}

// TestToInputColorModeUnrecognizedInput tests that toInputColorMode returns an
// error when it encounters an unrecognized input.
func TestToInputColorModeUnrecognizedInput(t *testing.T) {
	_, err := toInputColorMode(unrecognizedInput)
	if err == nil {
		t.Error("Expected error from unrecognized input.")
	}
}

// TestToIdentifyColorspace tests that toIdentifyColorspace functions correctly.
func TestToIdentifyColorspace(t *testing.T) {
	tests := []struct {
		lorgnetteColorMode string
		identifyColorspace string
	}{
		{
			lorgnetteColorMode: "MODE_LINEART",
			identifyColorspace: "Grayscale Gray 2c",
		},
		{
			lorgnetteColorMode: "MODE_GRAYSCALE",
			identifyColorspace: "Grayscale Gray 256c",
		},
		{
			lorgnetteColorMode: "MODE_COLOR",
			identifyColorspace: "sRGB",
		},
	}

	for _, tc := range tests {
		identifyColorspace, err := toIdentifyColorspace(tc.lorgnetteColorMode)

		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}

		if identifyColorspace != tc.identifyColorspace {
			t.Errorf("identifyColorspace: expected %s, got %s", tc.identifyColorspace, identifyColorspace)
		}
	}
}

// TestToIdentifyColorspaceUnrecognizedInput tests that toIdentifyColorspace
// returns an error when it encounters an unrecognized input.
func TestToIdentifyColorspaceUnrecognizedInput(t *testing.T) {
	_, err := toIdentifyColorspace(unrecognizedInput)
	if err == nil {
		t.Error("Expected error from unrecognized input.")
	}
}

// TestVerifyScannedImage tests that verifyScannedImage functions correctly.
func TestVerifyScannedImage(t *testing.T) {
	tests := []struct {
		identifyOutput string
		resolution     int
		colorMode      string
		passed         bool
		failureMessage string
	}{
		{
			identifyOutput: identifyOutputLineart,
			resolution:     200,
			colorMode:      "MODE_LINEART",
			passed:         true,
			failureMessage: "",
		},
		{
			identifyOutput: identifyOutputGrayscale,
			resolution:     100,
			colorMode:      "MODE_GRAYSCALE",
			passed:         true,
			failureMessage: "",
		},
		{
			identifyOutput: identifyOutputColor,
			resolution:     300,
			colorMode:      "MODE_COLOR",
			passed:         true,
			failureMessage: "",
		},
		{
			identifyOutput: identifyOutputGrayscale,
			resolution:     100,
			colorMode:      "MODE_LINEART",
			passed:         false,
			failureMessage: "Colorspace: got Grayscale Gray 256c, expected Grayscale Gray 2c",
		},
		{
			identifyOutput: identifyOutputColor,
			resolution:     200,
			colorMode:      "MODE_COLOR",
			passed:         false,
			failureMessage: "Width: got 2550, expected 1700",
		},
	}

	for _, tc := range tests {
		passed, failureMessage, err := verifyScannedImage(tc.identifyOutput, utils.LetterSize, tc.resolution, tc.colorMode)

		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}

		if passed != tc.passed {
			t.Errorf("Passed: expected %t, got %t", tc.passed, passed)
		}

		if failureMessage != tc.failureMessage {
			t.Errorf("Failure message: expected %s, got %s", tc.failureMessage, failureMessage)
		}
	}
}

// TestVerifyScannedImageUnrecognizedInput tests that verifyScannedImage returns
// an error when it encounters an unrecognized input.
func TestVerifyScannedImageUnrecognizedInput(t *testing.T) {
	_, _, err := verifyScannedImage(unrecognizedInput, utils.LetterSize, 300, "MODE_COLOR")
	if err == nil {
		t.Error("Expected error from unrecognized input.")
	}
}
