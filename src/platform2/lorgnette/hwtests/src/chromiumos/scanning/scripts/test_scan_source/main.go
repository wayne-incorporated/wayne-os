// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package main

import (
	"flag"
	"fmt"
	"log"
	"path"

	"chromiumos/scanning/hwtests"
	"chromiumos/scanning/utils"
)

// Tests each scan source of a scanner to make sure the scanning behavior
// conforms to the WWCB specification. Each scan source should be at least
// letter-sized.
func main() {
	identifierFlag := flag.String("identifier", "", "Substring of the identifier printed by lorgnette_cli of the scanner to test.")
	flag.Parse()

	logFile, err := utils.CreateLogFile("test_scan_source")
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

	rawLorgnetteCaps, err := utils.LorgnetteCLIGetJSONCaps(scannerInfo.ToLorgnetteScannerName())
	if err != nil {
		log.Fatal(err)
	}

	lorgnetteCaps, err := utils.ParseLorgnetteCapabilities(rawLorgnetteCaps)
	if err != nil {
		log.Fatal(err)
	}

	outputDir := path.Dir(logFile.Name())
	tests := map[string]utils.TestFunction{
		"PlatenScanSource":     hwtests.AllScanCombinationsTest(lorgnetteCaps.PlatenCaps, "Platen", scannerInfo.ToLorgnetteScannerName(), outputDir),
		"AdfSimplexScanSource": hwtests.AllScanCombinationsTest(lorgnetteCaps.AdfSimplexCaps, "ADF Simplex", scannerInfo.ToLorgnetteScannerName(), outputDir),
		"AdfDuplexScanSource":  hwtests.AllScanCombinationsTest(lorgnetteCaps.AdfDuplexCaps, "ADF Duplex", scannerInfo.ToLorgnetteScannerName(), outputDir)}
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
