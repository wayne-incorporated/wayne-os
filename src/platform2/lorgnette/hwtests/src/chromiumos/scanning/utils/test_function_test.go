// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package utils

import (
	"bytes"
	"fmt"
	"log"
	"strings"
	"testing"
)

const testName = "testInt"

const criticalFailureMessage = "Critical failure."
const needsAuditFailureMessage = "Needs audit failure."
const errorMessage = "Bad integer: 1"

var criticalFailure = TestFailure{Type: CriticalFailure, Message: criticalFailureMessage}
var needsAuditFailure = TestFailure{Type: NeedsAudit, Message: needsAuditFailureMessage}

// integerTest returns a TestFunction used in the TestRunTest unit test.
func integerTest(testInt int) TestFunction {
	return func() (result TestResult, failures []TestFailure, err error) {
		switch testInt {
		case 1:
			failures = append(failures, criticalFailure)
			err = fmt.Errorf(errorMessage)
			result = Error
		case 2:
			failures = append(failures, needsAuditFailure)
			result = Failed
		case 3:
			failures = append(failures, criticalFailure, needsAuditFailure)
			result = Failed
		case 4:
			result = Passed
		case 5:
			result = Skipped
		}
		return
	}
}

// TestRunTest tests that we can run a TestFunction via the RunTest wrapper.
func TestRunTest(t *testing.T) {
	tests := []struct {
		testInt    int
		testResult TestResult
		failures   []TestFailure
		errText    string
	}{
		{
			testInt:    1,
			testResult: Error,
			failures:   []TestFailure{criticalFailure},
			errText:    errorMessage,
		},
		{
			testInt:    2,
			testResult: Failed,
			failures:   []TestFailure{needsAuditFailure},
			errText:    "",
		},
		{
			testInt:    3,
			testResult: Failed,
			failures:   []TestFailure{criticalFailure, needsAuditFailure},
			errText:    "",
		},
		{
			testInt:    4,
			testResult: Passed,
			failures:   []TestFailure{},
			errText:    "",
		},
		{
			testInt:    5,
			testResult: Skipped,
			failures:   []TestFailure{},
			errText:    "",
		},
	}

	for _, tc := range tests {
		var logBuf bytes.Buffer
		log.SetOutput(&logBuf)

		got := RunTest(testName, integerTest(tc.testInt))

		if got != tc.testResult {
			t.Errorf("TestResult: got %d, want %d", got, tc.testResult)
		}

		lines := strings.Split(strings.TrimSuffix(logBuf.String(), "\n"), "\n")

		var expectedNumLines int
		// All tests should have the starting and finished lines. Additionally:
		// Tests with errors should have a single line with the error.
		// Tests with failures should have a line for each failuree.
		// Tests with no errors and no failures should have a single "PASSED" or
		// "SKIPPED" line.
		if tc.errText != "" {
			expectedNumLines = 3 + len(tc.failures)
		} else if len(tc.failures) != 0 {
			expectedNumLines = 2 + len(tc.failures)
		} else {
			expectedNumLines = 3
		}

		if len(lines) != expectedNumLines {
			t.Errorf("Number of log lines: got %d, want %d", len(lines), expectedNumLines)
		}

		for lineNum, line := range lines {
			var expectedLine string
			if lineNum == 0 {
				expectedLine = "===== START " + testName + " ====="
			} else if lineNum == expectedNumLines-1 {
				expectedLine = "===== END " + testName + " ====="
			} else if tc.testResult == Passed {
				expectedLine = "PASSED."
			} else if tc.testResult == Skipped {
				expectedLine = "SKIPPED."
			} else if len(tc.failures) >= lineNum && tc.failures[lineNum-1] == criticalFailure {
				expectedLine = "CRITICAL FAILURE: " + criticalFailureMessage
			} else if len(tc.failures) >= lineNum && tc.failures[lineNum-1] == needsAuditFailure {
				expectedLine = "NEEDS AUDIT: " + needsAuditFailureMessage
			} else if tc.testResult == Error {
				expectedLine = "ERROR: " + tc.errText
			}

			// Logged lines will also contain timestamps, so we can't check for
			// direct equality with the expected line.
			if !strings.Contains(line, expectedLine) {
				t.Errorf("Line: %s does not contain: %s", line, expectedLine)
			}
		}
	}
}
