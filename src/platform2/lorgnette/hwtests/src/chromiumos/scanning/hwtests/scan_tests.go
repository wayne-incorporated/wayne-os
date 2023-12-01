// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package hwtests

import (
	"chromiumos/scanning/utils"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

// identifyOutputRegex parses out the width, height and colorspace from the
// output of `identify someImage`.
var identifyOutputRegex = regexp.MustCompile(`^.+ PNG (?P<width>[0-9]+)x(?P<height>[0-9]+).+ 8-bit (?P<colorspace>sRGB|Grayscale Gray 256c|Grayscale Gray 2c)`)

// toInputColorMode converts from the color mode output by `lorgnette_cli
// get_json_caps --scanner=someScanner` to the color mode accepted by
// `lorgnette_cli scan --color_mode=colorMode`.
func toInputColorMode(lorgnetteColorMode string) (string, error) {
	switch lorgnetteColorMode {
	case "MODE_LINEART":
		return "Lineart", nil
	case "MODE_GRAYSCALE":
		return "Grayscale", nil
	case "MODE_COLOR":
		return "Color", nil
	default:
		return "", fmt.Errorf("Unable to convert lorgnette color mode: %s to input color mode", lorgnetteColorMode)
	}
}

// toIdentifyColorspace converts from the color mode output by `lorgnette_cli
// get_json_caps --scanner=someScanner` to the colorspace output by `identify
// someImage`.
func toIdentifyColorspace(lorgnetteColorMode string) (string, error) {
	switch lorgnetteColorMode {
	case "MODE_LINEART":
		return "Grayscale Gray 2c", nil
	case "MODE_GRAYSCALE":
		return "Grayscale Gray 256c", nil
	case "MODE_COLOR":
		return "sRGB", nil
	default:
		return "", fmt.Errorf("Unable to convert lorgnette color mode: %s to identify colorspace", lorgnetteColorMode)
	}
}

// verifyScannedImage checks that `identifyOutput` is the expected size for the
// given `resolution`, and that `identifyOutput` matches the given `colorMode`.
// If the verification fails, the returned string will contain the details of
// the failures.
func verifyScannedImage(identifyOutput string, paperSize utils.PaperSize, resolution int, colorMode string) (bool, string, error) {
	match := identifyOutputRegex.FindStringSubmatch(identifyOutput)
	if match == nil || len(match) < 4 {
		return false, "", fmt.Errorf("Unable to parse identify output: %s", identifyOutput)
	}

	for i, name := range identifyOutputRegex.SubexpNames() {
		if name == "width" {
			width, err := strconv.Atoi(match[i])

			if err != nil {
				return false, "", err
			}

			expectedWidth := paperSize.PixelWidthForResolution(resolution)
			if expectedWidth != width {
				return false, fmt.Sprintf("Width: got %d, expected %d", width, expectedWidth), nil
			}
		}

		if name == "height" {
			height, err := strconv.Atoi(match[i])

			if err != nil {
				return false, "", err
			}

			expectedHeight := paperSize.PixelHeightForResolution(resolution)
			if expectedHeight != height {
				return false, fmt.Sprintf("Height: got %d, expected %d", height, expectedHeight), nil
			}
		}

		if name == "colorspace" {
			colorSpace, err := toIdentifyColorspace(colorMode)
			if err != nil {
				return false, "", err
			}

			if colorSpace != match[i] {
				return false, fmt.Sprintf("Colorspace: got %s, expected %s", match[i], colorSpace), nil
			}
		}
	}

	return true, "", nil
}

// AllScanCombinationsTest checks that lorgnette CLI produces a scanned image
// for each combination of resolution and color mode advertised by `source`.
// Basic verification is performed on the scanned image to make sure that it is
// the correct size and color space. One critical failure will be returned for
// each combination that either produces no scanned image or produces a scanned
// image which fails the verification. Scanned images will be output to
// `outputDir`/scan-sourceName-${mode}-${res}_page%n.png` for each color mode
// `mode` and resolution `res`. `outputDir` should not contain the pattern "%n".
func AllScanCombinationsTest(source utils.LorgnetteSource, sourceName string, scannerName string, outputDir string) utils.TestFunction {
	return func() (result utils.TestResult, failures []utils.TestFailure, err error) {
		if !source.IsPopulated() {
			result = utils.Skipped
			return
		}

		result = utils.Passed
		for _, colorMode := range source.ColorModes {
			var inputColorMode string
			inputColorMode, err = toInputColorMode(colorMode)
			if err != nil {
				result = utils.Error
				return
			}

			for _, resolution := range source.Resolutions {
				numPages := 1
				if sourceName == "ADF Simplex" || sourceName == "ADF Duplex" {
					fmt.Print("Put paper in ADF and enter number of sheets of paper: ")
					var n int
					n, err = fmt.Scanln(&numPages)
					if n != 1 || err != nil {
						result = utils.Error
						return
					}
				}

				if sourceName == "ADF Duplex" {
					// A duplex scan will generate two images for every physical
					// page in the ADF.
					numPages *= 2
				}

				outputPattern := fmt.Sprintf("%s/scan-%s-%s-%d_page%%n.png", outputDir, sourceName, colorMode, resolution)
				_, err = utils.LorgnetteCLIScan(scannerName, sourceName, utils.LetterSize, resolution, inputColorMode, outputPattern)

				if err != nil {
					result = utils.Error
					return
				}

				for i := 1; i <= numPages; i++ {
					cmd := exec.Command("identify", strings.Replace(outputPattern, "%n", strconv.Itoa(i), 1))
					var identifyBytes []byte
					identifyBytes, err = cmd.Output()

					if err != nil {
						result = utils.Error
						return
					}

					var passed bool
					var failureMessage string
					passed, failureMessage, err = verifyScannedImage(string(identifyBytes), utils.LetterSize, resolution, colorMode)

					if err != nil {
						result = utils.Error
						return
					}

					if !passed {
						failures = append(failures, utils.TestFailure{Type: utils.CriticalFailure, Message: fmt.Sprintf("Image verification failed for resolution: %d and color mode: %s with message: %s", resolution, colorMode, failureMessage)})
					}
				}

			}
		}

		if len(failures) == 0 {
			result = utils.Passed
		} else {
			result = utils.Failed
		}

		return
	}
}
