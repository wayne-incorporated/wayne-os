// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Tests for lorgnette_cli_utils.go.

package utils

import (
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// Sample output from `lorgnette_cli list` with a valid airscan scanner.
const lorgnetteCLIListOutputAirscan = `Getting scanner list.
SANE scanners:
pixma:MF741C/743C_207.648.54.70: CANON Canon i-SENSYS MF741C/743C(multi-function peripheral)
1 SANE scanners found.
Detected scanners:
pixma:MF741C/743C_207.648.54.70
airscan:escl:Canon MF741C/743C (8d_29_6f) (4):http://207.648.54.70:99/eSCL/`

// Sample output from `lorgnette_cli list` with a valid IPP USB scanner.
const lorgnetteCLIListOutputIPPUSB = `Getting scanner list.
SANE scanners:
pixma:MF741C/743C_207.648.54.70: CANON Canon i-SENSYS MF741C/743C(multi-function peripheral)
1 SANE scanners found.
Detected scanners:
pixma:MF741C/743C_207.648.54.70
ippusb:escl:Canon TR8500 series:04a9_1823/eSCL/`

// Sample output from `lorgnette_cli list` with a scanner name containing
// special regex characters.
const lorgnetteCLIListOutputRegex = `Detected scanners:
airscan:escl:HP ENVY Photo 7100 series [ABCD12]:https://201.995.21.789:343/eSCL/`

// Sample output from `lorgnette_cli list` with no valid scanner.
const lorgnetteCLIListOutputNoeSCLScanner = `Getting scanner list.
SANE scanners:
pixma:MF741C/743C_207.648.54.70: CANON Canon i-SENSYS MF741C/743C(multi-function peripheral)
1 SANE scanners found.
Detected scanners:
pixma:MF741C/743C_207.648.54.70`

// Response strings for different hosts.
const localhostResponse = "IPP over USB response."
const ipAddressResponse = "Network response."

// TestGetLorgnetteScannerInfo tests that scanner info can be parsed correctly.
func TestGetLorgnetteScannerInfo(t *testing.T) {
	tests := []struct {
		input      string
		identifier string
		protocol   string
		name       string
		address    string
	}{
		{
			input:      lorgnetteCLIListOutputAirscan,
			identifier: "MF741C",
			protocol:   "airscan",
			name:       "Canon MF741C/743C (8d_29_6f) (4)",
			address:    "http://207.648.54.70:99",
		},
		{
			input:      lorgnetteCLIListOutputIPPUSB,
			identifier: "TR8500",
			protocol:   "ippusb",
			name:       "Canon TR8500 series",
			address:    "04a9_1823",
		},
		{
			input:      lorgnetteCLIListOutputRegex,
			identifier: "airscan:escl:HP ENVY Photo 7100 series [ABCD12]:https://201.995.21.789:343/eSCL/",
			protocol:   "airscan",
			name:       "HP ENVY Photo 7100 series [ABCD12]",
			address:    "https://201.995.21.789:343",
		},
	}

	for _, tc := range tests {
		got, err := GetLorgnetteScannerInfo(tc.input, tc.identifier)

		if err != nil {
			t.Error(err)
		}

		if got.Protocol != tc.protocol {
			t.Errorf("Protocol: got %s, want %s", got.Protocol, tc.protocol)
		}

		if got.Name != tc.name {
			t.Errorf("Name: got %s, want %s", got.Name, tc.name)
		}

		if got.Address != tc.address {
			t.Errorf("Address: got %s, want %s", got.Address, tc.address)
		}

		if got.SocketDir != "/run/ippusb" {
			t.Errorf("SocketDir: got %s, expected /run/ippusb", got.SocketDir)
		}
	}
}

// TestGetLorgnetteScannerInfoNoeSCLScanner tests that an error is returned when
// no valid scanner info is found.
func TestGetLorgnetteScannerInfoNoeSCLScanner(t *testing.T) {
	tests := []struct {
		input string
		model string
	}{
		{
			input: lorgnetteCLIListOutputNoeSCLScanner,
			model: "MF741C",
		},
		{
			input: lorgnetteCLIListOutputAirscan,
			model: "Bad Model",
		},
	}

	for _, tc := range tests {
		_, err := GetLorgnetteScannerInfo(tc.input, tc.model)

		if err == nil {
			t.Errorf("Expected error for no eSCL scanner found with input: %s and model: %s", tc.input, tc.model)
		}
	}
}

// TestGetIPPUSBSocket tests that GetIPPUSBSocket functions correctly.
func TestGetIPPUSBSocket(t *testing.T) {
	tests := []struct {
		info    LorgnetteScannerInfo
		socket  string
		errText string
	}{
		{
			info:    LorgnetteScannerInfo{Protocol: "ippusb", Address: "04a9_0001", SocketDir: "/foo/bar"},
			socket:  "/foo/bar/04a9-0001.sock",
			errText: "",
		},
		{
			info:    LorgnetteScannerInfo{Protocol: "airscan", Address: "200.201.22.23:24"},
			socket:  "",
			errText: "Cannot generate IPPUSB socket for protocol: airscan",
		},
	}

	for _, tc := range tests {
		socket, err := tc.info.GetIPPUSBSocket()

		if err == nil {
			if tc.errText != "" {
				t.Errorf("Expected error with message: %s", tc.errText)
			}

			if socket != tc.socket {
				t.Errorf("Socket: expected %s, got %s", tc.socket, socket)
			}
		} else {
			if tc.errText == "" {
				t.Error(err)
			} else if !strings.Contains(err.Error(), tc.errText) {
				t.Errorf("Error text: expected %s, got %s", tc.errText, err.Error())
			}
		}
	}
}

// TestHTTPGetNetwork tests that HTTPGet functions correctly with a network
// scanner.
func TestHTTPGetNetwork(t *testing.T) {
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, ipAddressResponse)
	}))

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Error(err)
	}

	ts.Listener = listener
	ts.Start()
	defer ts.Close()

	resp, err := LorgnetteScannerInfo{Protocol: "airscan", Address: "http://" + listener.Addr().String()}.HTTPGet("/TestUrl")
	if err != nil {
		t.Error(err)
	}
	defer resp.Body.Close()

	respbytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Error(err)
	}

	if !strings.Contains(string(respbytes), ipAddressResponse) {
		t.Errorf("Response: expected %s, got %s", ipAddressResponse, string(respbytes))
	}
}

// TestHTTPGetIPPUSB tests that HTTPGet functions correctly with an IPP over USB
// scanner.
func TestHTTPGetIPPUSB(t *testing.T) {
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, localhostResponse)
	}))

	// This package name is long enough that for some builders with longer
	// names, the default temp directory produces a socket name longer than the
	// unix limit. Work around this by creating the socket under /tmp.
	dir, err := ioutil.TempDir("/tmp", "*")
	if err != nil {
		t.Error(err)
	}
	defer os.RemoveAll(dir)

	info := LorgnetteScannerInfo{Protocol: "ippusb", Address: "04a9_0001", SocketDir: dir}

	socket, err := info.GetIPPUSBSocket()
	if err != nil {
		t.Error(err)
	}

	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Error(err)
	}

	ts.Listener = listener
	ts.Start()
	defer ts.Close()

	resp, err := info.HTTPGet("/TestUrl")
	if err != nil {
		t.Error(err)
	}
	defer resp.Body.Close()

	respbytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Error(err)
	}

	if !strings.Contains(string(respbytes), localhostResponse) {
		t.Errorf("Response: expected %s, got %s", localhostResponse, string(respbytes))
	}
}

// TestToLorgnetteScannerName tests that ToLorgnetteScannerName functions
// correctly.
func TestToLorgnetteScannerName(t *testing.T) {
	scannerInfo := LorgnetteScannerInfo{
		Protocol: "airscan",
		Name:     "Test Scanner Name",
		Address:  "http://192.789.32.10:80",
	}

	expectedName := "airscan:escl:Test Scanner Name:http://192.789.32.10:80/eSCL/"
	if scannerInfo.ToLorgnetteScannerName() != expectedName {
		t.Errorf("LorgnetteScannerName: expected %s, got %s", expectedName, scannerInfo.ToLorgnetteScannerName())
	}
}
