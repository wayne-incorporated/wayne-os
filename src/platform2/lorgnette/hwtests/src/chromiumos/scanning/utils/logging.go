// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package utils

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// CreateLogFile creates a log file and its parent directory. TODO(b/191933619):
// add a parameter so that each tool from a single logical certification run
// logs to the same directory.
func CreateLogFile(scriptName string) (*os.File, error) {
	t := time.Now()
	fullPath := filepath.Join(fmt.Sprintf("/tmp/wwcb_mfp_testing/%s/results", scriptName), t.Format("20060102-150405"))
	if err := os.MkdirAll(fullPath, 0755); err != nil {
		return nil, fmt.Errorf("Failed to create log directory %v: %v", fullPath, err)
	}

	logFullPathName := filepath.Join(fullPath, "log.txt")

	logFile, err := os.Create(logFullPathName)
	if err != nil {
		return nil, fmt.Errorf("Failed to create log file %v: %v", fullPath, err)
	}

	return logFile, nil
}
