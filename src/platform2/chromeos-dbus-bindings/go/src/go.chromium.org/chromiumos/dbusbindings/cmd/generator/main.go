// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Package main implements the generate-chromeos-dbus-bindings used to generate
// dbus bindings
package main

import (
	"flag"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"

	"go.chromium.org/chromiumos/dbusbindings/generate/adaptor"
	"go.chromium.org/chromiumos/dbusbindings/generate/methodnames"
	"go.chromium.org/chromiumos/dbusbindings/generate/proxy"
	"go.chromium.org/chromiumos/dbusbindings/introspect"
	"go.chromium.org/chromiumos/dbusbindings/serviceconfig"
)

func main() {
	serviceConfigPath := flag.String("service-config", "", "the DBus service configuration file for the generator.")
	methodNamesPath := flag.String("method-names", "", "the output header file with string constants for each method name")
	adaptorPath := flag.String("adaptor", "", "the output header file name containing the DBus adaptor class")
	proxyPath := flag.String("proxy", "", "the output header file name containing the DBus proxy class")
	mockPath := flag.String("mock", "", "the output header file name containing the DBus gmock proxy class")
	proxyPathForMocks := flag.String("proxy-path-for-mocks", "", "the path to the header file for proxy interface, relative to the mock output path")
	flag.Parse()

	var sc serviceconfig.Config
	if *serviceConfigPath != "" {
		c, err := serviceconfig.Load(*serviceConfigPath)
		if err != nil {
			log.Fatalf("Failed to read config file %s: %v", *serviceConfigPath, err)
		}
		sc = *c
	}

	var introspections []introspect.Introspection
	for _, path := range flag.Args() {
		b, err := ioutil.ReadFile(path)
		if err != nil {
			log.Fatalf("Failed to read file %s: %v\n", path, err)
		}

		introspection, err := introspect.Parse(b)
		if err != nil {
			log.Fatalf("Failed to parse interface file %s: %v\n", path, err)
		}

		introspections = append(introspections, introspection)
	}

	if *methodNamesPath != "" {
		f, err := os.Create(*methodNamesPath)
		if err != nil {
			log.Fatalf("Failed to create file %s: %v\n", *methodNamesPath, err)
		}
		defer func() {
			if err := f.Close(); err != nil {
				log.Fatalf("Failed to close file %s: %v\n", *methodNamesPath, err)
			}
		}()

		if err := methodnames.Generate(introspections, f); err != nil {
			log.Fatalf("Failed to generate methodnames: %v\n", err)
		}
	}

	if *adaptorPath != "" {
		f, err := os.Create(*adaptorPath)
		if err != nil {
			log.Fatalf("Failed to create adaptor file %s: %v\n", *adaptorPath, err)
		}
		defer func() {
			if err := f.Close(); err != nil {
				log.Fatalf("Failed to close file %s: %v\n", *adaptorPath, err)
			}
		}()

		if err := adaptor.Generate(introspections, f, *adaptorPath); err != nil {
			log.Fatalf("Failed to generate adaptor: %v\n", err)
		}
	}

	if *proxyPath != "" {
		f, err := os.Create(*proxyPath)
		if err != nil {
			log.Fatalf("Failed to create proxy file %s: %v\n", *proxyPath, err)
		}
		defer func() {
			if err := f.Close(); err != nil {
				log.Fatalf("Failed to close file %s: %v\n", *proxyPath, err)
			}
		}()

		if err := proxy.Generate(introspections, f, *proxyPath, sc); err != nil {
			log.Fatalf("Failed to generate proxy: %v\n", err)
		}
	}

	if *mockPath != "" {
		p := *proxyPathForMocks
		if p == "" && *proxyPath != "" {
			// -proxy-path-for-mock is not specified. Derive it from proxyPath.
			d := filepath.Dir(*mockPath)
			var err error
			p, err = filepath.Rel(d, *proxyPath)
			if err != nil {
				log.Fatal("Failed to compute the relpath from mock to proxy: ", err)
			}
		}

		f, err := os.Create(*mockPath)
		if err != nil {
			log.Fatalf("Failed to create proxy mock file %s: %v\n", *mockPath, err)
		}
		defer func() {
			if err := f.Close(); err != nil {
				log.Fatalf("Failed to close file %s: %v\n", *mockPath, err)
			}
		}()

		if err := proxy.GenerateMock(introspections, f, *mockPath, p, sc); err != nil {
			log.Fatalf("Failed to generate proxy mock: %v\n", err)
		}
	}
}
