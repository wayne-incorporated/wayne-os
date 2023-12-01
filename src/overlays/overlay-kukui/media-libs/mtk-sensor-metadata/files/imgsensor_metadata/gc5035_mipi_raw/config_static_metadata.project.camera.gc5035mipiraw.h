/*
 * Copyright (C) 2020 MediaTek Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */



STATIC_METADATA_BEGIN(DEVICE, CAMERA, SENSOR_DRVNAME_GC5035_MIPI_RAW)
//------------------------------------------------------------------------------
// android.info
//------------------------------------------------------------------------------
//==========================================================================
CONFIG_METADATA_BEGIN(MTK_INFO_SUPPORTED_HARDWARE_LEVEL)
CONFIG_ENTRY_VALUE(MTK_INFO_SUPPORTED_HARDWARE_LEVEL_FULL, MUINT8)
CONFIG_METADATA_END()
//==========================================================================
//------------------------------------------------------------------------------
// android.sync
//------------------------------------------------------------------------------
//==========================================================================
CONFIG_METADATA_BEGIN(MTK_SYNC_MAX_LATENCY)
CONFIG_ENTRY_VALUE(MTK_SYNC_MAX_LATENCY_PER_FRAME_CONTROL, MINT32)
CONFIG_METADATA_END()
//==========================================================================
//------------------------------------------------------------------------------
//  android.sensor
//------------------------------------------------------------------------------
//==========================================================================
switch (rInfo.getDeviceId()) {
case 0:
    //======================================================================
    CONFIG_METADATA_BEGIN(MTK_SENSOR_INFO_ORIENTATION)
    CONFIG_ENTRY_VALUE(270, MINT32)
    CONFIG_METADATA_END()
    //======================================================================
    CONFIG_METADATA_BEGIN(MTK_SENSOR_INFO_WANTED_ORIENTATION)
    CONFIG_ENTRY_VALUE(270, MINT32)
    CONFIG_METADATA_END()
    //======================================================================
    CONFIG_METADATA_BEGIN(MTK_SENSOR_INFO_FACING)
    CONFIG_ENTRY_VALUE(MTK_LENS_FACING_BACK, MUINT8)
    CONFIG_METADATA_END()
    //======================================================================

    break;

case 1:
    //======================================================================
    CONFIG_METADATA_BEGIN(MTK_SENSOR_INFO_ORIENTATION)
    CONFIG_ENTRY_VALUE(270, MINT32)
    CONFIG_METADATA_END()
    //======================================================================
    CONFIG_METADATA_BEGIN(MTK_SENSOR_INFO_WANTED_ORIENTATION)
    CONFIG_ENTRY_VALUE(270, MINT32)
    CONFIG_METADATA_END()
    //======================================================================
    CONFIG_METADATA_BEGIN(MTK_SENSOR_INFO_FACING)
    CONFIG_ENTRY_VALUE(MTK_LENS_FACING_FRONT, MUINT8)
    CONFIG_METADATA_END()
    //======================================================================
    break;

default:
    break;
}
//==========================================================================
//------------------------------------------------------------------------------
STATIC_METADATA_END()

