// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Package serviceconfig provides a way to configure generated headers.
package serviceconfig

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
)

// ObjectManagerConfig is a way to configure the object manager class generation.
type ObjectManagerConfig struct {
	// Name is the name of the ObjectManager class to use. If empty, no object manager
	// is generated in the proxy code (this also disables property support on
	// proxy objects).
	// This is a "fake" name used to generate namespaces and the actual class
	// name for the object manager proxy. This name has no relationship to the
	// actual D-Bus properties of the actual object manager.
	Name string `json:"name"`
	// The D-Bus path to Object Manager instance.
	ObjectPath string `json:"object_path"`
}

// Config contains a way to configure header generations.
type Config struct {
	// ServiceName is a D-Bus service name to be used when constructing proxy objects.
	// If omitted (empty), the service name parameter will be added to the
	// constructor of generated proxy class(es).
	ServiceName string `json:"service_name"`
	// ObjectManger contains the settings of ObjectManager outputs.
	ObjectManager *ObjectManagerConfig `json:"object_manager"`
}

// Load reads and parses a file at path into Config.
func Load(path string) (*Config, error) {
	b, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parse(b)
}

// Parse parses the JSON byte array, and returns the config data.
func parse(b []byte) (*Config, error) {
	var c Config
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, err
	}

	// If object_manager.name is not explicitly specified,
	// derive it from service_name.
	if c.ObjectManager != nil && c.ObjectManager.Name == "" {
		if c.ServiceName == "" {
			return nil, fmt.Errorf("ObjectManager's name cannot be set")
		}
		c.ObjectManager.Name = c.ServiceName + ".ObjectManager"
	}

	return &c, nil
}
