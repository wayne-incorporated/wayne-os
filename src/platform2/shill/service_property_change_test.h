// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_SERVICE_PROPERTY_CHANGE_TEST_H_
#define SHILL_SERVICE_PROPERTY_CHANGE_TEST_H_

#include "shill/refptr_types.h"

namespace shill {

class MockManager;
class ServiceMockAdaptor;

// Test property change notifications that are implemented by all
// Services.
void TestCommonPropertyChanges(ServiceRefPtr service,
                               ServiceMockAdaptor* adaptor);
// Test AutoConnect property change notification. Implemented by
// all Services except EthernetService.
void TestAutoConnectPropertyChange(ServiceRefPtr service,
                                   ServiceMockAdaptor* adaptor);
// Test Name property change notification. Only VPNService allows
// changing the name property.
void TestNamePropertyChange(ServiceRefPtr service, ServiceMockAdaptor* adaptor);
// Test that the common customer setters (for all Services) return
// false if setting to the same as the current value.
void TestCommonCustomSetterNoopChange(ServiceRefPtr service,
                                      MockManager* mock_manager);
}  // namespace shill

#endif  // SHILL_SERVICE_PROPERTY_CHANGE_TEST_H_
