// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package utils

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

// Name of the lorgnette_cli executable.
const lorgnetteCLI = "lorgnette_cli"

// Regex which matches an HTTP or HTTPS scanner address.
var scannerRegex = regexp.MustCompile(`^(?P<protocol>airscan|ippusb):escl:(?P<name>[^:]+):(?P<address>.*)/eSCL/$`)

// LorgnetteScannerInfo aggregates a scanner's information as reported by
// lorgnette.
type LorgnetteScannerInfo struct {
	Protocol  string
	Name      string
	Address   string
	SocketDir string
}

// LorgnetteCLIList runs the command `lorgnette_cli list` and returns its
// stdout.
func LorgnetteCLIList() (string, error) {
	cmd := exec.Command(lorgnetteCLI, "list")
	outputBytes, err := cmd.Output()
	return string(outputBytes), err
}

// LorgnetteCLIGetJSONCaps runs the command
// `lorgnette_cli get_json_caps --scanner=`scanner`` and returns its stdout.
func LorgnetteCLIGetJSONCaps(scanner string) (string, error) {
	cmd := exec.Command(lorgnetteCLI, "get_json_caps", "--scanner="+scanner)
	outputBytes, err := cmd.Output()
	return string(outputBytes), err
}

// LorgnetteCLIScan runs the command `lorgnette_cli scan` with the specified
// scanner, source, resolution and color mode. The command's stdout is returned.
// The scanned image will be the same size as `paperSize`. Scanned images will
// be output to `output`.
func LorgnetteCLIScan(scanner string, source string, paperSize PaperSize, resolution int, colorMode string, output string) (string, error) {
	cmd := exec.Command(lorgnetteCLI, "scan", "--scanner="+scanner, "--top_left_x=0.0", "--top_left_y=0.0", "--bottom_right_x="+fmt.Sprintf("%f", paperSize.BottomRightX()), "--bottom_right_y="+fmt.Sprintf("%f", paperSize.BottomRightY()), "--scan_resolution="+strconv.Itoa(resolution), "--color_mode="+colorMode, "--scan_source="+source, "--output="+output)
	outputBytes, err := cmd.Output()
	return string(outputBytes), err
}

// GetLorgnetteScannerInfo parses `listOutput` to find the lorgnette scanner
// information for the first scanner in `listOutput` which matches `identifier`.
// `listOutput` is expected to be the output from `lorgnette_cli list`.
func GetLorgnetteScannerInfo(listOutput string, identifier string) (info LorgnetteScannerInfo, err error) {
	// All IPP over USB scanners will use the same socket directory. Network
	// scanners don't need this, but it doesn't hurt to include it.
	info.SocketDir = "/run/ippusb"

	lines := strings.Split(listOutput, "\n")
	for _, line := range lines {
		identifierMatch, _ := regexp.MatchString(identifier, line)
		if !identifierMatch && identifier != line {
			continue
		}

		match := scannerRegex.FindStringSubmatch(line)
		if match == nil || len(match) < 4 {
			continue
		}

		for i, name := range scannerRegex.SubexpNames() {
			if name == "protocol" {
				info.Protocol = match[i]
			}

			if name == "name" {
				info.Name = match[i]
			}

			if name == "address" {
				info.Address = match[i]
			}
		}

		return
	}

	err = fmt.Errorf("No scanner info found for identifier: %s", identifier)
	return
}

// GetIPPUSBSocket returns the IPP over USB socket for `info`. If `info` is
// using an protocol other than `ippusb`, an error is returned.
func (info LorgnetteScannerInfo) GetIPPUSBSocket() (socket string, err error) {
	if info.Protocol != "ippusb" {
		err = fmt.Errorf("Cannot generate IPPUSB socket for protocol: %s", info.Protocol)
		return
	}

	socket = fmt.Sprintf("%s/%s.sock", info.SocketDir, strings.ReplaceAll(info.Address, "_", "-"))
	return
}

// HTTPGet sends an HTTP GET method to the scanner represented by `info`.
func (info LorgnetteScannerInfo) HTTPGet(url string) (*http.Response, error) {
	if info.Protocol == "ippusb" {
		socket, err := info.GetIPPUSBSocket()
		if err != nil {
			return nil, err
		}

		client := http.Client{
			Transport: &http.Transport{
				DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
					return net.Dial("unix", socket)
				},
			},
		}

		return client.Get("http://localhost" + url)
	}

	// Deliberately ignore certificate errors because printers normally
	// have self-signed certificates.
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion:         tls.VersionTLS12,
				InsecureSkipVerify: true,
			},
		},
	}

	return client.Get(info.Address + url)
}

// ToLorgnetteScannerName constructs the scanner name used by Lorgnette for
// `info`.
func (info LorgnetteScannerInfo) ToLorgnetteScannerName() string {
	return fmt.Sprintf("%s:escl:%s:%s/eSCL/", info.Protocol, info.Name, info.Address)
}
