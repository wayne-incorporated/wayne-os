// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package main

import (
	"flag"
	"fmt"
	"log"

	"chromiumos/scanning/hwtests"
	"chromiumos/scanning/utils"
)

// Runs various tests to verify that a scanner's reported capabilities satisfy
// the WWCB specification.
func main() {
	identifierFlag := flag.String("identifier", "", "Substring of the identifier printed by lorgnette_cli of the scanner to test.")
	flag.Parse()

	logFile, err := utils.CreateLogFile("test_scanner_capabilities")
	if err != nil {
		log.Fatal(err)
	}

	log.SetOutput(logFile)
	fmt.Printf("Created log file at: %s\n", logFile.Name())

	listOutput, err := utils.LorgnetteCLIList()
	if err != nil {
		log.Fatal(err)
	}

	scannerInfo, err := utils.GetLorgnetteScannerInfo(listOutput, *identifierFlag)
	if err != nil {
		log.Fatal(err)
	}

	log.Print("INFO: Testing scanner: ", scannerInfo.ToLorgnetteScannerName())

	caps, err := utils.GetScannerCapabilities(scannerInfo)
	if err != nil {
		log.Fatal(err)
	}

	rawLorgnetteCaps, err := utils.LorgnetteCLIGetJSONCaps(scannerInfo.ToLorgnetteScannerName())
	if err != nil {
		log.Fatal(err)
	}

	tests := map[string]utils.TestFunction{
		"HasSupportedDocumentSource":   hwtests.HasSupportedDocumentSourceTest(caps.PlatenInputCaps, caps.AdfCapabilities.AdfSimplexInputCaps, caps.AdfCapabilities.AdfDuplexInputCaps),
		"NoCameraSource":               hwtests.NoCameraSourceTest(caps.CameraInputCaps),
		"NoStoredJobSupport":           hwtests.NoStoredJobSupportTest(caps.StoredJobRequestSupport),
		"HasSupportedResolution":       hwtests.HasSupportedResolutionTest(caps.PlatenInputCaps, caps.AdfCapabilities.AdfSimplexInputCaps, caps.AdfCapabilities.AdfDuplexInputCaps),
		"HighestResolutionIsSupported": hwtests.HighestResolutionIsSupportedTest(caps.PlatenInputCaps, caps.AdfCapabilities.AdfSimplexInputCaps, caps.AdfCapabilities.AdfDuplexInputCaps),
		"LowestResolutionIsSupported":  hwtests.LowestResolutionIsSupportedTest(caps.PlatenInputCaps, caps.AdfCapabilities.AdfSimplexInputCaps, caps.AdfCapabilities.AdfDuplexInputCaps),
		"HasSupportedColorMode":        hwtests.HasSupportedColorModeTest(caps.PlatenInputCaps, caps.AdfCapabilities.AdfSimplexInputCaps, caps.AdfCapabilities.AdfDuplexInputCaps),
		"NoUnsupportedColorMode":       hwtests.NoUnsupportedColorModeTest(caps.PlatenInputCaps, caps.AdfCapabilities.AdfSimplexInputCaps, caps.AdfCapabilities.AdfDuplexInputCaps),
		"MatchesLorgnetteCapabilities": hwtests.MatchesLorgnetteCapabilitiesTest(caps, rawLorgnetteCaps)}
	failed := []string{}
	skipped := []string{}
	errors := []string{}

	for name, test := range tests {
		testResult := utils.RunTest(name, test)
		if testResult == utils.Failed {
			failed = append(failed, name)
		} else if testResult == utils.Skipped {
			skipped = append(skipped, name)
		} else if testResult == utils.Error {
			errors = append(errors, name)
		}
	}

	fmt.Printf("Ran %d tests.\n", len(tests))
	if len(failed) != 0 {
		fmt.Printf("%d tests failed:\n", len(failed))
		for _, failedTest := range failed {
			fmt.Println(failedTest)
		}
	}
	if len(skipped) != 0 {
		fmt.Printf("%d tests skipped:\n", len(skipped))
		for _, skippedTest := range skipped {
			fmt.Println(skippedTest)
		}
	}
	if len(errors) != 0 {
		fmt.Printf("%d tests had errors:\n", len(errors))
		for _, errorTest := range errors {
			fmt.Println(errorTest)
		}
	}
}
