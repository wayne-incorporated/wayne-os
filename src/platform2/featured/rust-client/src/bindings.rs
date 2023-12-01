// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(dead_code)]

pub const FeatureState_FEATURE_DISABLED_BY_DEFAULT: FeatureState = 0;
pub const FeatureState_FEATURE_ENABLED_BY_DEFAULT: FeatureState = 1;
pub type FeatureState = ::std::os::raw::c_uint;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct VariationsFeature {
    pub name: *const ::std::os::raw::c_char,
    pub default_state: FeatureState,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct VariationsFeatureParam {
    pub key: *mut ::std::os::raw::c_char,
    pub value: *mut ::std::os::raw::c_char,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct VariationsFeatureGetParamsResponseEntry {
    pub name: *mut ::std::os::raw::c_char,
    pub is_enabled: ::std::os::raw::c_int,
    pub params: *mut VariationsFeatureParam,
    pub num_params: usize,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct CFeatureLibraryOpaque {
    _unused: [u8; 0],
}
pub type CFeatureLibrary = *mut CFeatureLibraryOpaque;
extern "C" {
    pub fn CFeatureLibraryInitialize() -> bool;
}
extern "C" {
    pub fn CFeatureLibraryGet() -> CFeatureLibrary;
}
extern "C" {
    pub fn CFeatureLibraryIsEnabledBlocking(
        handle: CFeatureLibrary,
        feature: *const VariationsFeature,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn CFeatureLibraryGetParamsAndEnabledBlocking(
        handle: CFeatureLibrary,
        features: *const *const VariationsFeature,
        num_features: usize,
        entries: *mut VariationsFeatureGetParamsResponseEntry,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn CFeatureLibraryFreeEntries(
        entries: *mut VariationsFeatureGetParamsResponseEntry,
        num_features: usize,
    );
}
extern "C" {
    pub fn FakeCFeatureLibraryNew() -> CFeatureLibrary;
}
extern "C" {
    pub fn FakeCFeatureLibraryDelete(handle: CFeatureLibrary);
}
extern "C" {
    pub fn FakeCFeatureLibrarySetEnabled(
        handle: CFeatureLibrary,
        feature: *const ::std::os::raw::c_char,
        enabled: ::std::os::raw::c_int,
    );
}
extern "C" {
    pub fn FakeCFeatureLibraryClearEnabled(
        handle: CFeatureLibrary,
        feature: *const ::std::os::raw::c_char,
    );
}
extern "C" {
    pub fn FakeCFeatureLibrarySetParam(
        handle: CFeatureLibrary,
        feature: *const ::std::os::raw::c_char,
        key: *const ::std::os::raw::c_char,
        value: *const ::std::os::raw::c_char,
    );
}
extern "C" {
    pub fn FakeCFeatureLibraryClearParams(
        handle: CFeatureLibrary,
        feature: *const ::std::os::raw::c_char,
    );
}
