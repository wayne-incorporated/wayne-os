// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package utils

import "log"

// TestFunction is the type used by RunTest. All test functions should return a
// TestFunction. Returned TestFailures indicate that the test was completed
// successfully, but a condition tested was out of compliance with WWCB. Errors
// indicate that the test was unable to complete. For example, consider a test
// that retrieves a scanner's XML capabilities then parses those to check for
// unsupported resolutions on Chrome OS. If the test is unable to retrieve the
// capabilities from the scanner, it should return an error. If it retrieves and
// parses the capabilities successfully, then finds an unsupported resolution,
// it should return a TestFailure.
type TestFunction func() (TestResult, []TestFailure, error)

// TestResult indicates the result of a TestFunction.
type TestResult int

// Enumeration of different TestResults.
const (
	Passed TestResult = iota
	Failed
	Skipped
	Error
)

// FailureType differentiates between different failure types.
type FailureType int

// Enumeration of different FailureTypes.
const (
	CriticalFailure FailureType = iota // Blocks WWCB certification.
	NeedsAudit                         // Needs auditing by a human - handled on a case-by-case basis.
)

// TestFailure represents a single failure caught by a test function.
type TestFailure struct {
	Type    FailureType // Type of the failure.
	Message string      // More details about the failure.
}

// logFailures logs each failure in `failures`.
func logFailures(failures []TestFailure) {
	for _, failure := range failures {
		switch failureType := failure.Type; failureType {
		case CriticalFailure:
			log.Println("CRITICAL FAILURE:", failure.Message)
		case NeedsAudit:
			log.Println("NEEDS AUDIT:", failure.Message)
		default:
			log.Printf("Unrecognized failure type: %d", failureType)
		}
	}
}

// RunTest wraps the execution of a TestFunction. It provides a standardized way
// of logging test execution, errors, and test results.
func RunTest(testName string, testFunction TestFunction) (testResult TestResult) {
	log.Printf("===== START %s =====", testName)
	testResult, failures, err := testFunction()

	switch testResult {
	case Passed:
		if err != nil {
			log.Fatalf("Non-nil error in passed test: %v", err)
		}

		log.Println("PASSED.")
	case Failed:
		if err != nil {
			log.Fatalf("Non-nil error in failed test: %v", err)
		}

		if len(failures) == 0 {
			log.Fatal("No TestFailures in failed test.")
		}

		logFailures(failures)
	case Skipped:
		if err != nil {
			log.Fatalf("Non-nil error in skipped test: %v", err)
		}

		log.Println("SKIPPED.")
	case Error:
		if err == nil {
			log.Fatal("Nil error in error test.")
		}

		// Log any failures the test found before encountering an error.
		logFailures(failures)

		log.Printf("ERROR: %v", err)
	}

	log.Printf("===== END %s =====", testName)
	return
}
