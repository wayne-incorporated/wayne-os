// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TYPECD_TEST_UTILS_H_
#define TYPECD_TEST_UTILS_H_

#include <base/files/file_path.h>
#include <memory>

#include "typecd/port.h"

namespace typecd {

// Helper function to create the sysfs entries for an alt mode, for testing
// purposes.
//
// Returns:
//   True on success, False otherwise.
bool CreateFakeAltMode(const base::FilePath& mode_path,
                       uint16_t svid,
                       uint32_t vdo,
                       uint32_t vdo_index);

// Helper functions for USB-C cables.
void AddUnbrandedUSB2Cable(Port& port);
void AddNekteckUSB2PassiveCable(Port& port);
void AddHongjuUSB3p1Gen1Cable(Port& port);
void AddHPUSB3p2Gen1Cable(Port& port);
void AddAnkerUSB3p2Gen2Cable(Port& port);
void AddCableMatters20GbpsCable(Port& port);
void AddUnbrandedTBT3Cable(Port& port);
void AddBelkinTBT3PassiveCable(Port& port);
void AddBelkinTBT3ActiveCable(Port& port);
void AddAppleTBT3ProCable(Port& port);
void AddCalDigitTBT4Cable(Port& port);
void AddCableMattersTBT4LRDCable(Port& port);
void AddStartech40GbpsCable(Port& port);

// Helper functions for USB-C partners.
void AddCableMattersDock(Port& port);
void AddDellWD19TBDock(Port& port);
void AddStartechDock(Port& port);
void AddStartechTB3DK2DPWDock(Port& port);
void AddThinkpadTBT3Dock(Port& port);
void AddIntelUSB4GatkexCreekDock(Port& port);
void AddOWCTBT4Dock(Port& port);
void AddWimaxitDisplay(Port& port);

}  // namespace typecd

#endif  // TYPECD_TEST_UTILS_H_
