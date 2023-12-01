// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path"
	"strconv"
	"strings"
)

const numWErrorEstimate = 30

func getForceDisableWerrorDir(env env, cfg *config) string {
	return path.Join(getCompilerArtifactsDir(env), cfg.newWarningsDir)
}

func shouldForceDisableWerror(env env, cfg *config, ty compilerType) bool {
	if cfg.isAndroidWrapper {
		return cfg.useLlvmNext
	}

	// We only want this functionality for clang.
	if ty != clangType {
		return false
	}
	value, _ := env.getenv("FORCE_DISABLE_WERROR")
	return value != ""
}

func disableWerrorFlags(originalArgs []string) []string {
	extraArgs := []string{"-Wno-error"}
	newArgs := make([]string, 0, len(originalArgs)+numWErrorEstimate)
	for _, flag := range originalArgs {
		if strings.HasPrefix(flag, "-Werror=") {
			extraArgs = append(extraArgs, strings.Replace(flag, "-Werror", "-Wno-error", 1))
		}
		if !strings.Contains(flag, "-warnings-as-errors") {
			newArgs = append(newArgs, flag)
		}
	}
	return append(newArgs, extraArgs...)
}

func isLikelyAConfTest(cfg *config, cmd *command) bool {
	// Android doesn't do mid-build `configure`s, so we don't need to worry about this there.
	if cfg.isAndroidWrapper {
		return false
	}

	for _, a := range cmd.Args {
		// The kernel, for example, will do configure tests with /dev/null as a source file.
		if a == "/dev/null" || strings.HasPrefix(a, "conftest.c") {
			return true
		}
	}
	return false
}

func doubleBuildWithWNoError(env env, cfg *config, originalCmd *command) (exitCode int, err error) {
	originalStdoutBuffer := &bytes.Buffer{}
	originalStderrBuffer := &bytes.Buffer{}
	// TODO: This is a bug in the old wrapper that it drops the ccache path
	// during double build. Fix this once we don't compare to the old wrapper anymore.
	if originalCmd.Path == "/usr/bin/ccache" {
		originalCmd.Path = "ccache"
	}

	getStdin, err := prebufferStdinIfNeeded(env, originalCmd)
	if err != nil {
		return 0, wrapErrorwithSourceLocf(err, "prebuffering stdin: %v", err)
	}

	var originalExitCode int
	commitOriginalRusage, err := maybeCaptureRusage(env, originalCmd, func(willLogRusage bool) error {
		originalExitCode, err = wrapSubprocessErrorWithSourceLoc(originalCmd,
			env.run(originalCmd, getStdin(), originalStdoutBuffer, originalStderrBuffer))
		return err
	})
	if err != nil {
		return 0, err
	}

	// The only way we can do anything useful is if it looks like the failure
	// was -Werror-related.
	originalStdoutBufferBytes := originalStdoutBuffer.Bytes()
	shouldRetry := originalExitCode != 0 &&
		!isLikelyAConfTest(cfg, originalCmd) &&
		(bytes.Contains(originalStderrBuffer.Bytes(), []byte("-Werror")) ||
			bytes.Contains(originalStdoutBufferBytes, []byte("warnings-as-errors")) ||
			bytes.Contains(originalStdoutBufferBytes, []byte("clang-diagnostic-")))
	if !shouldRetry {
		if err := commitOriginalRusage(originalExitCode); err != nil {
			return 0, fmt.Errorf("commiting rusage: %v", err)
		}
		originalStdoutBuffer.WriteTo(env.stdout())
		originalStderrBuffer.WriteTo(env.stderr())
		return originalExitCode, nil
	}

	retryStdoutBuffer := &bytes.Buffer{}
	retryStderrBuffer := &bytes.Buffer{}
	retryCommand := &command{
		Path:       originalCmd.Path,
		Args:       disableWerrorFlags(originalCmd.Args),
		EnvUpdates: originalCmd.EnvUpdates,
	}

	var retryExitCode int
	commitRetryRusage, err := maybeCaptureRusage(env, retryCommand, func(willLogRusage bool) error {
		retryExitCode, err = wrapSubprocessErrorWithSourceLoc(retryCommand,
			env.run(retryCommand, getStdin(), retryStdoutBuffer, retryStderrBuffer))
		return err
	})
	if err != nil {
		return 0, err
	}

	// If -Wno-error fixed us, pretend that we never ran without -Wno-error. Otherwise, pretend
	// that we never ran the second invocation.
	if retryExitCode != 0 {
		originalStdoutBuffer.WriteTo(env.stdout())
		originalStderrBuffer.WriteTo(env.stderr())
		if err := commitOriginalRusage(originalExitCode); err != nil {
			return 0, fmt.Errorf("commiting rusage: %v", err)
		}
		return originalExitCode, nil
	}

	if err := commitRetryRusage(retryExitCode); err != nil {
		return 0, fmt.Errorf("commiting rusage: %v", err)
	}

	retryStdoutBuffer.WriteTo(env.stdout())
	retryStderrBuffer.WriteTo(env.stderr())

	lines := []string{}
	if originalStderrBuffer.Len() > 0 {
		lines = append(lines, originalStderrBuffer.String())
	}
	if originalStdoutBuffer.Len() > 0 {
		lines = append(lines, originalStdoutBuffer.String())
	}
	outputToLog := strings.Join(lines, "\n")

	// Ignore the error here; we can't do anything about it. The result is always valid (though
	// perhaps incomplete) even if this returns an error.
	parentProcesses, _ := collectAllParentProcesses()
	jsonData := warningsJSONData{
		Cwd:             env.getwd(),
		Command:         append([]string{originalCmd.Path}, originalCmd.Args...),
		Stdout:          outputToLog,
		ParentProcesses: parentProcesses,
	}

	// Write warning report to stdout for Android.  On Android,
	// double-build can be requested on remote builds as well, where there
	// is no canonical place to write the warnings report.
	if cfg.isAndroidWrapper {
		stdout := env.stdout()
		io.WriteString(stdout, "<LLVM_NEXT_ERROR_REPORT>")
		if err := json.NewEncoder(stdout).Encode(jsonData); err != nil {
			return 0, wrapErrorwithSourceLocf(err, "error in json.Marshal")
		}
		io.WriteString(stdout, "</LLVM_NEXT_ERROR_REPORT>")
		return retryExitCode, nil
	}

	// All of the below is basically logging. If we fail at any point, it's
	// reasonable for that to fail the build. This is all meant for FYI-like
	// builders in the first place.

	// Buildbots use a nonzero umask, which isn't quite what we want: these directories should
	// be world-readable and world-writable.
	oldMask := env.umask(0)
	defer env.umask(oldMask)

	warningsDir := getForceDisableWerrorDir(env, cfg)
	// Allow root and regular users to write to this without issue.
	if err := os.MkdirAll(warningsDir, 0777); err != nil {
		return 0, wrapErrorwithSourceLocf(err, "error creating warnings directory %s", warningsDir)
	}

	// Have some tag to show that files aren't fully written. It would be sad if
	// an interrupted build (or out of disk space, or similar) caused tools to
	// have to be overly-defensive.
	const incompleteSuffix = ".incomplete"

	// Coming up with a consistent name for this is difficult (compiler command's
	// SHA can clash in the case of identically named files in different
	// directories, or similar); let's use a random one.
	tmpFile, err := ioutil.TempFile(warningsDir, "warnings_report*.json"+incompleteSuffix)
	if err != nil {
		return 0, wrapErrorwithSourceLocf(err, "error creating warnings file")
	}

	if err := tmpFile.Chmod(0666); err != nil {
		return 0, wrapErrorwithSourceLocf(err, "error chmoding the file to be world-readable/writeable")
	}

	enc := json.NewEncoder(tmpFile)
	if err := enc.Encode(jsonData); err != nil {
		_ = tmpFile.Close()
		return 0, wrapErrorwithSourceLocf(err, "error writing warnings data")
	}

	if err := tmpFile.Close(); err != nil {
		return 0, wrapErrorwithSourceLocf(err, "error closing warnings file")
	}

	if err := os.Rename(tmpFile.Name(), tmpFile.Name()[:len(tmpFile.Name())-len(incompleteSuffix)]); err != nil {
		return 0, wrapErrorwithSourceLocf(err, "error removing incomplete suffix from warnings file")
	}

	return retryExitCode, nil
}

func parseParentPidFromPidStat(pidStatContents string) (parentPid int, ok bool) {
	// The parent's pid is the fourth field of /proc/[pid]/stat. Sadly, the second field can
	// have spaces in it. It ends at the last ')' in the contents of /proc/[pid]/stat.
	lastParen := strings.LastIndex(pidStatContents, ")")
	if lastParen == -1 {
		return 0, false
	}

	thirdFieldAndBeyond := strings.TrimSpace(pidStatContents[lastParen+1:])
	fields := strings.Fields(thirdFieldAndBeyond)
	if len(fields) < 2 {
		return 0, false
	}

	fourthField := fields[1]
	parentPid, err := strconv.Atoi(fourthField)
	if err != nil {
		return 0, false
	}
	return parentPid, true
}

func collectProcessData(pid int) (args, env []string, parentPid int, err error) {
	procDir := fmt.Sprintf("/proc/%d", pid)

	readFile := func(fileName string) (string, error) {
		s, err := ioutil.ReadFile(path.Join(procDir, fileName))
		if err != nil {
			return "", fmt.Errorf("reading %s: %v", fileName, err)
		}
		return string(s), nil
	}

	statStr, err := readFile("stat")
	if err != nil {
		return nil, nil, 0, err
	}

	parentPid, ok := parseParentPidFromPidStat(statStr)
	if !ok {
		return nil, nil, 0, fmt.Errorf("no parseable parent PID found in %q", statStr)
	}

	argsStr, err := readFile("cmdline")
	if err != nil {
		return nil, nil, 0, err
	}
	args = strings.Split(argsStr, "\x00")

	envStr, err := readFile("environ")
	if err != nil {
		return nil, nil, 0, err
	}
	env = strings.Split(envStr, "\x00")
	return args, env, parentPid, nil
}

// The returned []processData is valid even if this returns an error. The error is just the first we
// encountered when trying to collect parent process data.
func collectAllParentProcesses() ([]processData, error) {
	results := []processData{}
	for parent := os.Getppid(); parent != 1; {
		args, env, p, err := collectProcessData(parent)
		if err != nil {
			return results, fmt.Errorf("inspecting parent %d: %v", parent, err)
		}
		results = append(results, processData{Args: args, Env: env})
		parent = p
	}
	return results, nil
}

type processData struct {
	Args []string `json:"invocation"`
	Env  []string `json:"env"`
}

// Struct used to write JSON. Fields have to be uppercase for the json encoder to read them.
type warningsJSONData struct {
	Cwd             string        `json:"cwd"`
	Command         []string      `json:"command"`
	Stdout          string        `json:"stdout"`
	ParentProcesses []processData `json:"parent_process_data"`
}
