// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package serviceconfig

import "testing"

func TestParseEmpty(t *testing.T) {
	c, err := parse([]byte("{}"))
	if err != nil {
		t.Fatal("Unexpected failure of parse: ", err)
	}
	if c.ServiceName != "" {
		t.Errorf("Unexpected service_name: got %q, want \"\"", c.ServiceName)
	}
	if c.ObjectManager != nil {
		t.Errorf("Unexpected object_manager: got %v, want nil", c.ObjectManager)
	}
}

func TestParseFull(t *testing.T) {
	c, err := parse([]byte(`{
	  "service_name": "test.ServiceName",
	  "object_manager": {
	    "name": "test.ObjectManagerName",
	    "object_path": "test.object.Path"
	  }
	}`))

	if err != nil {
		t.Fatal("Unexpected failure of parse: ", err)
	}
	if c.ServiceName != "test.ServiceName" {
		t.Errorf("Unexpected service_name: got %q, want \"\"", c.ServiceName)
	}
	if c.ObjectManager == nil {
		t.Fatal("Unexpected object_manager: got nil, want non-nil")
	}
	if c.ObjectManager.Name != "test.ObjectManagerName" {
		t.Errorf("Unexpected object_manager.name: got %q, want test.ObjectManagerName", c.ObjectManager.Name)
	}
	if c.ObjectManager.ObjectPath != "test.object.Path" {
		t.Errorf("Unexpected object_manager.object_path: got %q, want test.object.Path", c.ObjectManager.ObjectPath)
	}
}

func TestParseFallbackObjectName(t *testing.T) {
	if _, err := parse([]byte("{object_manager: {}}")); err == nil {
		t.Fatal("Unexpected success of parse")
	}

	c, err := parse([]byte(`{"service_name": "test.ServiceName", "object_manager": {}}`))
	if err != nil {
		t.Fatal("Unexpected failure of parse: ", err)
	}
	if c.ObjectManager == nil {
		t.Fatal("Unexpecte object_manager: got nil, want non-nil")
	}
	if c.ObjectManager.Name != "test.ServiceName.ObjectManager" {
		t.Fatalf("Unexpected object_manager.name: got %q, want test.ServiceName.ObjectManager", c.ObjectManager.Name)
	}
}
