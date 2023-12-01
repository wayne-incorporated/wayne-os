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



STATIC_METADATA_BEGIN(DEVICE, FLASHLIGHT, COMMON)
//------------------------------------------------------------------------------
//  android.flash.info
//------------------------------------------------------------------------------
//==========================================================================
switch (rInfo.getDeviceId()) {
case 0:
    //==========================================================================
    CONFIG_METADATA_BEGIN(MTK_FLASH_INFO_AVAILABLE)
    CONFIG_ENTRY_VALUE(MTK_FLASH_INFO_AVAILABLE_TRUE, MUINT8)
    CONFIG_METADATA_END()
    //==========================================================================
    break;
case 1:
    //==========================================================================
    CONFIG_METADATA_BEGIN(MTK_FLASH_INFO_AVAILABLE)
    CONFIG_ENTRY_VALUE(MTK_FLASH_INFO_AVAILABLE_FALSE, MUINT8)
    CONFIG_METADATA_END()
    //==========================================================================
    break;
case 2:
    //==========================================================================
    CONFIG_METADATA_BEGIN(MTK_FLASH_INFO_AVAILABLE)
    CONFIG_ENTRY_VALUE(MTK_FLASH_INFO_AVAILABLE_FALSE, MUINT8)
    CONFIG_METADATA_END()
    //==========================================================================
    break;
default:
    //==========================================================================
    CONFIG_METADATA_BEGIN(MTK_FLASH_INFO_AVAILABLE)
    CONFIG_ENTRY_VALUE(MTK_FLASH_INFO_AVAILABLE_FALSE, MUINT8)
    CONFIG_METADATA_END()
    //==========================================================================
    break;
}
//==========================================================================
CONFIG_METADATA_BEGIN(MTK_FLASH_INFO_CHARGE_DURATION)
CONFIG_ENTRY_VALUE(0, MINT64)
CONFIG_METADATA_END()
//==========================================================================
//------------------------------------------------------------------------------
STATIC_METADATA_END()


#if 0
static tag_info_t android_led[ANDROID_LED_END -
                              ANDROID_LED_START] = {
    [ ANDROID_LED_TRANSMIT - ANDROID_LED_START ] =
    { "transmit",                      TYPE_BYTE   },
    [ ANDROID_LED_AVAILABLE_LEDS - ANDROID_LED_START ] =
    { "availableLeds",                 TYPE_BYTE   },
};
#endif

