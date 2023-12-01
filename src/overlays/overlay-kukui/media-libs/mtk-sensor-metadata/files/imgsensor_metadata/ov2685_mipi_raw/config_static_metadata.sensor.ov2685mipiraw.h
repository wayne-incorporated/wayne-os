/*
 * Copyright (C) 2019 MediaTek Inc.
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



STATIC_METADATA2_BEGIN(DEVICE, SENSOR, SENSOR_DRVNAME_OV2685_MIPI_RAW)
//------------------------------------------------------------------------------
//  android.sensor
//------------------------------------------------------------------------------
//==========================================================================
CONFIG_METADATA_BEGIN(MTK_SENSOR_BLACK_LEVEL_PATTERN)
CONFIG_ENTRY_VALUE(0, MINT32)
CONFIG_ENTRY_VALUE(0, MINT32)
CONFIG_ENTRY_VALUE(0, MINT32)
CONFIG_ENTRY_VALUE(0, MINT32)
CONFIG_METADATA_END()
//==========================================================================
//------------------------------------------------------------------------------
//  android.sensor.info
//------------------------------------------------------------------------------
//==========================================================================
CONFIG_METADATA_BEGIN(MTK_SENSOR_INFO_ACTIVE_ARRAY_REGION)
CONFIG_ENTRY_VALUE(MRect(MPoint(0, 0), MSize(1600, 1200)), MRect)
CONFIG_METADATA_END()
CONFIG_METADATA_BEGIN(MTK_SENSOR_INFO_SENSITIVITY_RANGE)
CONFIG_ENTRY_VALUE(100, MINT32)
CONFIG_ENTRY_VALUE(6400, MINT32)
CONFIG_METADATA_END()
//==========================================================================
CONFIG_METADATA_BEGIN(MTK_SENSOR_INFO_EXPOSURE_TIME_RANGE)// 1 us - 30 sec
CONFIG_ENTRY_VALUE(100000L, MINT64)
CONFIG_ENTRY_VALUE(400000000L, MINT64)
CONFIG_METADATA_END()
//==========================================================================
CONFIG_METADATA_BEGIN(MTK_SENSOR_INFO_MAX_FRAME_DURATION)// 30 sec
CONFIG_ENTRY_VALUE(400000000L, MINT64)
CONFIG_METADATA_END()
//==========================================================================
CONFIG_METADATA_BEGIN(MTK_SENSOR_INFO_PHYSICAL_SIZE) // mm
CONFIG_ENTRY_VALUE(5.98f, MFLOAT)
CONFIG_ENTRY_VALUE(4.49f, MFLOAT)
CONFIG_METADATA_END()
//==========================================================================
CONFIG_METADATA_BEGIN(MTK_SENSOR_INFO_PIXEL_ARRAY_SIZE)
CONFIG_ENTRY_VALUE(MSize(1600, 1200), MSize)
CONFIG_METADATA_END()
CONFIG_METADATA_BEGIN(MTK_SENSOR_INFO_WHITE_LEVEL)
CONFIG_ENTRY_VALUE(1023, MINT32)
CONFIG_METADATA_END()
//==========================================================================
CONFIG_METADATA_BEGIN(MTK_SENSOR_INFO_TIMESTAMP_SOURCE)
CONFIG_ENTRY_VALUE(MTK_SENSOR_INFO_TIMESTAMP_SOURCE_UNKNOWN, MUINT8)
CONFIG_METADATA_END()
//==========================================================================
CONFIG_METADATA_BEGIN(MTK_SENSOR_MAX_ANALOG_SENSITIVITY)
CONFIG_ENTRY_VALUE(240, MINT32)
CONFIG_METADATA_END()
//==========================================================================
CONFIG_METADATA_BEGIN(MTK_SENSOR_BASE_GAIN_FACTOR)
CONFIG_ENTRY_VALUE(MRational(42, 256), MRational)
CONFIG_METADATA_END()
//==========================================================================
CONFIG_METADATA_BEGIN(MTK_SENSOR_INFO_ORIENTATION)
CONFIG_ENTRY_VALUE(90, MINT32)
CONFIG_METADATA_END()
//==========================================================================
CONFIG_METADATA_BEGIN(MTK_SENSOR_PROFILE_HUE_SAT_MAP_DIMENSIONS)
CONFIG_ENTRY_VALUE(1, MINT32)
CONFIG_ENTRY_VALUE(2, MINT32)
CONFIG_ENTRY_VALUE(1, MINT32)
CONFIG_METADATA_END()
//==========================================================================
CONFIG_METADATA_BEGIN(MTK_SENSOR_AVAILABLE_TEST_PATTERN_MODES)
CONFIG_ENTRY_VALUE(0, MINT32)
CONFIG_ENTRY_VALUE(2, MINT32)
CONFIG_METADATA_END()
//------------------------------------------------------------------------------
STATIC_METADATA_END()


