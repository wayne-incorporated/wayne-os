// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#![deny(missing_docs)]

//! ChromeOS featured client.
//!
//! This crate provides a wrapper around the C implementation of the
//! `featured` client library, which is the preferred way for interacting
//! with ChromeOS features from the platform side.
//!

mod bindings;
use crate::bindings::*;

use once_cell::sync::OnceCell;
use std::collections::HashMap;
use std::mem::ManuallyDrop;
use std::sync::Arc;
use thiserror::Error;

/// Errors which can occur during `Feature` creation and use.
#[derive(Error, Debug)]
pub enum FeatureError {
    /// C strings are null-byte terminated, but Rust strings are not.
    /// It is invalid for a Rust string to be converted into a C string
    /// when the Rust string contains a null byte.
    #[error("feature name contains a null byte: {0}")]
    InteriorNullByte(std::ffi::NulError),
}

/// Errors that can occur when interacting with the underlying C library.
#[derive(Error, Debug)]
pub enum PlatformError {
    /// When creating handles to the underlying C client, it is possible for
    /// the call to return an invalid, null handle.
    #[error("c library returned a null pointer instead of a handle")]
    NullHandle,
    /// When querying for data through the C library handle, a result value
    /// is returned. Non-zero result values indicate an error and are passed
    /// as the argument to this error.
    #[error("c library returned an error code: {0}")]
    BadResult(i32),
}

/// `CheckFeature` provides methods for requesting the feature status from
/// the underlying `featured` service. These methods are inherently blocking,
/// and should be assumed to be invalidated when Chrome restarts.
pub trait CheckFeature {
    /// Checks if a feature is currently enabled.
    ///
    /// Since Chrome may have restarted between separate calls of this function,
    /// `get_params_and_enabled` is preferred if there are multiple dependant features
    /// that need to be checked together.
    fn is_feature_enabled_blocking(&self, feature: &Feature) -> bool;

    /// Requests the status of the provided features, including both if it is enabled
    /// and the set parameters if enabled.
    ///
    /// Since Chrome may have restarted between separate calls of this function,
    /// make sure to request all co-dependent features together to prevent invalid
    /// assumptions around feature state.
    ///
    /// # Errors
    ///
    /// If the underlying C calls do not proper fetch the feature status object,
    /// an error string will be returned.
    fn get_params_and_enabled(
        &self,
        features: &[&Feature],
    ) -> Result<GetParamsAndEnabledResponse, PlatformError>;
}

/// A wrapper around the C implementation for `VariationsFeature`.
///
/// This struct contains two major elements, a `name` attribute that
/// specifies the feature name registered in Chrome, and an `enabled_by_default`
/// attribute that specifies if the feature should enabled when it is
/// not explicitly provided.
///
/// The C featured library uses referential equality checks, so it is
/// important to reuse this struct when checking against the same feature
/// multiple times.
#[derive(Debug)]
pub struct Feature {
    name: std::ffi::CString,
    c_feature: VariationsFeature,
}

impl Feature {
    /// Creates a feature to be used for checking enablement status and parameters.
    ///
    /// The `name` argument must be a valid null-terminated UTF-8 string in order to be properly
    /// serialized into a `CString`.
    ///
    /// # Errors
    ///
    /// If the provided feature name is not a valid C string, an error will be returned.
    pub fn new(name: &str, enabled_by_default: bool) -> Result<Self, FeatureError> {
        let name = std::ffi::CString::new(name).map_err(FeatureError::InteriorNullByte)?;

        let default_state = if enabled_by_default {
            FeatureState_FEATURE_ENABLED_BY_DEFAULT
        } else {
            FeatureState_FEATURE_DISABLED_BY_DEFAULT
        };
        let c_feature = VariationsFeature {
            name: name.as_ptr(),
            default_state,
        };
        Ok(Feature { name, c_feature })
    }

    /// The name assigned to this feature.
    ///
    /// This will be the name registered in `featured` and used to enable/disable the feature
    /// via Finch or flags.
    pub fn name(&self) -> &str {
        // The validation check in `Feature::new` means this is guarateed to be `Ok`.
        self.name.to_str().expect("Unreachable")
    }

    /// If the feature is enabled when not specified in `featured`.
    pub fn enabled_by_default(&self) -> bool {
        self.c_feature.default_state == FeatureState_FEATURE_ENABLED_BY_DEFAULT
    }
}

/// An enumeration for representing the state of a feature and its parameters.
///
/// Disabled features will never have associated parameters, and an enabled
/// feature will always have a map of parameter name to parameter value, even
/// if that map is empty.
#[derive(Debug)]
enum FeatureStatus {
    Disabled,
    Enabled(HashMap<String, String>),
}

impl FeatureStatus {
    fn is_enabled(&self) -> bool {
        match self {
            FeatureStatus::Disabled => false,
            FeatureStatus::Enabled(_) => true,
        }
    }

    fn get_parameters(&self) -> Option<&HashMap<String, String>> {
        match self {
            FeatureStatus::Disabled => None,
            FeatureStatus::Enabled(parameters) => Some(parameters),
        }
    }
}

/// A wrapper around the status attributes returned by calls to
/// `CheckFeature::get_params_and_enabled`.
///
/// Features that are not enabled do not have parameters.
/// Features that are enabled will have an associated parameter
/// map, which may be empty.
#[derive(Debug)]
pub struct GetParamsAndEnabledResponse {
    status_map: HashMap<String, FeatureStatus>,
}

impl GetParamsAndEnabledResponse {
    /// Checks if the provided feature is enabled.
    ///
    /// If it is not found in the original features list that created
    /// then the value provided by `Feature::enabled_by_default` is
    /// returned.
    pub fn is_enabled(&self, feature: &Feature) -> bool {
        self.status_map
            .get(feature.name())
            .map_or_else(|| feature.enabled_by_default(), FeatureStatus::is_enabled)
    }

    /// Returns the parameters associated with the provided feature.
    ///
    /// If the feature is disabled or is not present in the original
    /// feature list, `None` is returned.
    pub fn get_params(&self, feature: &Feature) -> Option<&HashMap<String, String>> {
        self.status_map
            .get(feature.name())
            .and_then(FeatureStatus::get_parameters)
    }

    /// Returns the parameter value associated with the key for the provided feature.
    ///
    /// If the feature is disabled, is not present in the original feature list,
    /// or does not contain the provided key, `None` is returned.
    pub fn get_param(&self, feature: &Feature, key: &str) -> Option<&String> {
        self.get_params(feature).and_then(|params| params.get(key))
    }
}

/// An internal wrapper around C library a handle pointer.
///
/// Wrapping the handle with this struct allows us to be certain
/// that the handle was properly created by the C library, and provides
/// us with a way to safely call FFI functions.
struct SafeHandle {
    handle: CFeatureLibrary,
    fake: bool,
}

// SAFETY: `PlatformFeatures` stores `SafeHandle` in an Arc pointer, which is thread-safe so we can
// annotate with `Send`. `CFeatureLibrary` is also safe to use in multiple threads simultaneously
// so we can annotate with `Sync`. `SafeHandle` will only get dropped after the program terminates
// and all references to the global `PlatformFeatures` instance go out of scope. This is necessary
// since `PlatformFeatures` is trying to wrap unsafe C code in a safe Rust struct.
unsafe impl Send for SafeHandle {}
unsafe impl Sync for SafeHandle {}

impl SafeHandle {
    /// Creates a new client handle for faking requests to featured.
    ///
    /// # Errors
    ///
    /// If the underlying C calls do not return a proper handle to
    /// the featured client, an error will be returned.
    fn fake() -> Result<Self, PlatformError> {
        // SAFETY: The C library can return either a valid object pointer or a null pointer.
        // A subsequent check is made to ensure that the pointer is valid.
        let handle = unsafe { FakeCFeatureLibraryNew() };
        if handle.is_null() {
            return Err(PlatformError::NullHandle);
        };
        Ok(SafeHandle { handle, fake: true })
    }

    fn is_feature_enabled_blocking(&self, feature: &Feature) -> bool {
        // SAFETY: The C call is guaranteed to return a valid value and does not modify
        // the underlying handle or feature.
        unsafe { CFeatureLibraryIsEnabledBlocking(self.handle, &feature.c_feature) != 0 }
    }

    fn get_params_and_enabled_blocking(
        &self,
        features: &[&Feature],
    ) -> Result<GetParamsAndEnabledResponse, PlatformError> {
        // Extract the `VariationsFeature`s to pass to the C library.
        let feature_ptrs: Vec<_> = features
            .iter()
            .map(|feature| &feature.c_feature as *const VariationsFeature)
            .collect();

        // Allocate an array for the C library to populate.
        let responses: Vec<VariationsFeatureGetParamsResponseEntry> =
            Vec::with_capacity(feature_ptrs.len());
        // We need to tell Rust that we are transferring ownership of this
        // memory to the C library, and will later retake ownership.
        let mut responses = ManuallyDrop::new(responses);
        let response_ptr = responses.as_mut_ptr();
        let response_len = feature_ptrs.len();

        // Populate the response array and make sure the response is valid.
        // SAFETY: The C library will not invalidate the handle pointer, but may
        // fail to write the responses. A check is made after returning ownership
        // of the response memory back to Rust, verifying that the data is valid.
        let result = unsafe {
            CFeatureLibraryGetParamsAndEnabledBlocking(
                self.handle,
                feature_ptrs.as_ptr(),
                response_len,
                response_ptr,
            )
        };

        // Rebuild the responses array by recreating a vector
        // from the C pointer and length.
        // SAFETY: The response pointer is guaranteed to be valid and the contents will
        // either be written out by the previous C library call or zeroed out from the original
        // memory allocation via `Vec::with_capacity`. All of the safety requirements specified by
        // `Vec::from_raw_parts` are met since we are rebuilding the `Vec<T>` with the same `T` and
        // capacity. Additionally, It is important that this is called immediately after the C
        // library call to prevent a memory leak.
        let responses = unsafe { Vec::from_raw_parts(response_ptr, response_len, response_len) };

        // The C library call may have failed at some point, which would result in the response
        // being incomplete or invalid.
        // Note: When the C library call fails, it will deallocate any allocated memory, which means
        // there is no need to manually call `CFeatureLibraryFreeEntries` before this early return.
        if result != 0 {
            return Err(PlatformError::BadResult(result));
        }

        // Convert the response to Rust native structures.
        let status_map = responses
            .iter()
            .filter_map(|raw_entry| {
                // SAFETY: The C library is guaranteed to either provide a valid entry or none
                // at all. If the entry is valid, then the name field is guaranteed to contain
                // a valid, non-null C string. Additionally, we know that this C string will not
                // be mutated during this call.
                let name = unsafe { parse_cstr(raw_entry.name)? };
                let value = parse_params(raw_entry);
                Some((name, value))
            })
            .collect();

        // Free the associated C structures since they have been converted to Rust types.
        // The calls to `parse_params` and `parse_cstr` create new Rust-owned values, so the
        // underlying `VariationsFeatureGetParamsResponseEntry` data are not copied or referenced
        // anywhere.
        // SAFETY: This call only frees the underlying data allocated by the C library. It
        // does not free the memory at the provided pointer, which is currently owned by Rust
        // and will be freed at the end of this function call. The response pointer is guaranteed to
        // be valid and is never used again.
        unsafe { CFeatureLibraryFreeEntries(response_ptr, response_len) }

        Ok(GetParamsAndEnabledResponse { status_map })
    }
}

impl Drop for SafeHandle {
    fn drop(&mut self) {
        // SAFETY: The C call frees the memory associated with handle, which is okay since the
        // pointer is dropped immediately afterwards.
        if self.fake {
            unsafe { FakeCFeatureLibraryDelete(self.handle) }
        }
    }
}

/// A platform specific featured client, used to communicate to featured via the
/// wrapped C library.
pub struct PlatformFeatures {
    handle: SafeHandle,
}
static FEATURE_LIBRARY: OnceCell<Arc<PlatformFeatures>> = OnceCell::new();

impl PlatformFeatures {
    /// Returns a client handle for requests to featured. Will also initialize the client handle on
    /// the first call.
    ///
    /// # Errors
    ///
    /// If the underlying C calls do not return a proper handle to
    /// the featured client, an error will be returned.
    pub fn get() -> Result<Arc<PlatformFeatures>, PlatformError> {
        FEATURE_LIBRARY
            .get_or_try_init(|| {
                // SAFETY: The C library will initialize the handle to either a valid object pointer
                // or a null pointer. A subsequent check is made to ensure the client is initialized
                // properly.
                let initialize = unsafe { CFeatureLibraryInitialize() };
                if !initialize {
                    return Err(PlatformError::NullHandle);
                }

                let cpp_handle = unsafe { CFeatureLibraryGet() };
                if cpp_handle.is_null() {
                    return Err(PlatformError::NullHandle);
                }

                let lib = Arc::new(PlatformFeatures {
                    handle: SafeHandle {
                        handle: cpp_handle,
                        fake: false,
                    },
                });

                Ok(lib)
            })
            .map(Arc::clone)
    }
}

impl CheckFeature for PlatformFeatures {
    fn is_feature_enabled_blocking(&self, feature: &Feature) -> bool {
        self.handle.is_feature_enabled_blocking(feature)
    }

    fn get_params_and_enabled(
        &self,
        features: &[&Feature],
    ) -> Result<GetParamsAndEnabledResponse, PlatformError> {
        self.handle.get_params_and_enabled_blocking(features)
    }
}

/// A fake featured client, used to mock communications to featured via the
/// wrapped fake C library.
///
/// This client never makes actual requests to featured,
/// instead it uses an in-memory store to mock out responses.
pub struct FakePlatformFeatures {
    handle: SafeHandle,
    // Since there are references to these `CString`s stored in an
    // in-memory map managed by the C library, it is important that
    // they are not dropped until the C library is cleaned up and the
    // handle to the library is released, or the feature is specifically
    // cleared. By storing them in a `Vec` in this struct, we guarantee
    // that they always live long enough. By storing those `Vec`s in a
    // `HashMap` under the feature's name as a key, we are able to properly
    // track and remove them when a feature is explicitly cleared.
    c_strings: HashMap<String, Vec<(std::ffi::CString, std::ffi::CString)>>,
}

impl FakePlatformFeatures {
    /// Creates a new client for faking requests to featured.
    ///
    /// # Errors
    ///
    /// If the underlying C calls do not return a proper handle to
    /// the fake featured client, an error string will be returned.
    pub fn new() -> Result<Self, PlatformError> {
        Ok(FakePlatformFeatures {
            handle: SafeHandle::fake()?,
            c_strings: HashMap::default(),
        })
    }

    /// Sets the specified feature's enablement status in the in-memory store
    /// managed by the underlying fake C client.
    ///
    /// The in-memory store uses referential equality to save enablement state,
    /// so it is important to use the same feature for setting and checking the state.
    pub fn set_feature_enabled<'a>(&'a mut self, feature: &'a Feature, is_enabled: bool) {
        // SAFETY: The C call will never invalidate the handle or feature pointers.
        unsafe {
            FakeCFeatureLibrarySetEnabled(
                self.handle.handle,
                feature.c_feature.name,
                is_enabled.into(),
            );
        };
    }

    /// Clears the specified feature's enablement status in the in-memory store
    /// managed by the underlying fake C client.
    pub fn clear_feature_enabled(&mut self, feature: &Feature) {
        // SAFETY: The C call will never invalidate the handle or feature pointers.
        unsafe { FakeCFeatureLibraryClearEnabled(self.handle.handle, feature.c_feature.name) };
    }

    /// Adds or updates value associated with the provided key for the specified feature.
    ///
    /// The in-memory store uses referential equality to save parameter values,
    /// so it is important to use the same feature for setting and checking the state.
    pub fn set_param(&mut self, feature: &Feature, key: &str, value: &str) {
        let c_key = std::ffi::CString::new(key).expect("Unable to convert key");
        let c_value = std::ffi::CString::new(value).expect("Unable to convert value");

        // SAFETY: The C call will never invalidate the handle or feature pointers.
        unsafe {
            FakeCFeatureLibrarySetParam(
                self.handle.handle,
                feature.c_feature.name,
                c_key.as_ptr(),
                c_value.as_ptr(),
            );
        };

        // The key/value `CString`s must be stored to prevent them from being dropped at
        // the end of this function.
        self.c_strings
            .entry(feature.name().to_string())
            .or_insert_with(Vec::default)
            .push((c_key, c_value));
    }

    /// Clears all parameters associated with the specified feature in the in-memory store
    /// managed by the underlying fake C client.
    pub fn clear_params(&mut self, feature: &Feature) {
        // SAFETY: The C call will never invalidate the handle or feature pointers.
        unsafe { FakeCFeatureLibraryClearParams(self.handle.handle, feature.c_feature.name) };
        // Clear the stored c_strings. This should be done after the call to the C library
        // since the underlying C structure contains a reference to these items.
        self.c_strings.remove(feature.name());
    }
}

impl CheckFeature for FakePlatformFeatures {
    fn is_feature_enabled_blocking(&self, feature: &Feature) -> bool {
        self.handle.is_feature_enabled_blocking(feature)
    }

    fn get_params_and_enabled(
        &self,
        features: &[&Feature],
    ) -> Result<GetParamsAndEnabledResponse, PlatformError> {
        self.handle.get_params_and_enabled_blocking(features)
    }
}

fn parse_params(entry: &VariationsFeatureGetParamsResponseEntry) -> FeatureStatus {
    // Disabled features will never have associated parameters.
    if entry.is_enabled == 0 {
        return FeatureStatus::Disabled;
    }

    // Read the underlying C array as a Rust slice.
    // SAFETY: The C library ensures that it will always return valid pointers in its responses,
    // which means we can safely read those values as a slice.
    let params = unsafe { std::slice::from_raw_parts(entry.params, entry.num_params) };
    let hash_map = params
        .iter()
        .filter_map(|param| {
            // SAFETY: The C library guarantees that it only returns valid entries, which means
            // that both the key and value for this parameter will be valid, non-null C strings.
            // Additionally, we know that this C string will not be mutated during this call.
            unsafe { Some((parse_cstr(param.key)?, parse_cstr(param.value)?)) }
        })
        .collect();

    FeatureStatus::Enabled(hash_map)
}

// SAFETY: The caller of this function must guarantee that the pointer points to valid,
// initialized data, that the memory ends with a null byte, and that it will not be
// mutated during the duration of this call.
#[inline]
unsafe fn parse_cstr(ptr: *const std::os::raw::c_char) -> Option<String> {
    if ptr.is_null() {
        return None;
    }
    std::ffi::CStr::from_ptr(ptr)
        .to_str()
        .ok()
        .map(str::to_string)
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_can_create_a_valid_feature() {
        let subject = Feature::new("some-valid-feature", true);
        assert!(subject.is_ok());
    }

    #[test]
    fn it_rejects_an_invalid_feature() {
        let subject = Feature::new("some-bad-feature\0", true);
        assert!(subject.is_err());
    }

    #[test]
    fn it_initializes_and_returns_a_valid_library() {
        let first_init = PlatformFeatures::get();
        assert!(first_init.is_ok());
        let second_init = PlatformFeatures::get();
        assert!(second_init.is_ok())
    }

    #[test]
    fn it_properly_fakes_the_feature_library_for_is_enabled() {
        let mut subject = FakePlatformFeatures::new().unwrap();
        let feature_one = Feature::new("some-valid-feature", false).unwrap();
        let feature_two = Feature::new("other-valid-feature", true).unwrap();

        assert!(!subject.is_feature_enabled_blocking(&feature_one));
        assert!(subject.is_feature_enabled_blocking(&feature_two));

        subject.set_feature_enabled(&feature_one, true);
        subject.set_feature_enabled(&feature_two, false);

        assert!(subject.is_feature_enabled_blocking(&feature_one));
        assert!(!subject.is_feature_enabled_blocking(&feature_two));

        subject.clear_feature_enabled(&feature_one);
        subject.clear_feature_enabled(&feature_two);

        assert!(!subject.is_feature_enabled_blocking(&feature_one));
        assert!(subject.is_feature_enabled_blocking(&feature_two));
    }

    #[test]
    fn it_properly_fakes_the_feature_library_for_parameters() {
        let mut subject = FakePlatformFeatures::new().unwrap();

        let feature_one = Feature::new("some-valid-feature", false).unwrap();
        let feature_two = Feature::new("other-valid-feature", false).unwrap();
        let feature_three = Feature::new("another-valid-feature", false).unwrap();

        let param_one_key = "some-param".to_string();
        let param_one_value = "some-value".to_string();
        let param_two_key = "other-param".to_string();
        let param_two_value = "other-value".to_string();

        subject.set_param(&feature_one, &param_one_key, &param_one_value);
        subject.set_param(&feature_one, &param_two_key, &param_two_value);
        subject.set_feature_enabled(&feature_one, true);
        subject.set_feature_enabled(&feature_two, true);

        let actual = subject
            .get_params_and_enabled(&[&feature_one, &feature_two])
            .unwrap();

        assert!(actual.is_enabled(&feature_one));
        assert!(actual.is_enabled(&feature_two));
        assert!(!actual.is_enabled(&feature_three));
        assert!(actual.get_params(&feature_one).is_some());
        assert!(actual.get_params(&feature_two).is_some());
        assert!(actual.get_params(&feature_three).is_none());

        let actual_params = actual.get_params(&feature_one).unwrap();
        assert_eq!(actual_params.len(), 2);
        assert_eq!(actual_params.get(&param_one_key), Some(&param_one_value));
        assert_eq!(actual_params.get(&param_two_key), Some(&param_two_value));

        assert_eq!(
            actual.get_param(&feature_one, &param_one_key),
            Some(&param_one_value)
        );
        assert_eq!(
            actual.get_param(&feature_one, &param_two_key),
            Some(&param_two_value)
        );

        let actual_params = actual.get_params(&feature_two).unwrap();
        assert_eq!(actual_params.len(), 0);
        assert_eq!(actual.get_param(&feature_two, &param_one_key), None);
        assert_eq!(actual.get_param(&feature_two, &param_two_key), None);
    }
}
