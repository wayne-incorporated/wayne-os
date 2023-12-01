// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Generates a libsirenia::rpc implementation for marked traits.

#![recursion_limit = "128"]

extern crate proc_macro;

use std::convert::TryFrom;
use std::env;
use std::result::Result as StdResult;

use proc_macro2::Span;
use proc_macro2::TokenStream;
use quote::format_ident;
use quote::quote;
use quote::ToTokens;
use syn::parse::Error;
use syn::parse::Parse;
use syn::parse::Parser;
use syn::parse::Result;
use syn::parse_macro_input;
use syn::parse_quote;
use syn::spanned::Spanned;
use syn::Attribute;
use syn::AttributeArgs;
use syn::FieldsUnnamed;
use syn::FnArg;
use syn::Ident;
use syn::ItemTrait;
use syn::Lit;
use syn::Meta;
use syn::NestedMeta;
use syn::Path;
use syn::PathArguments;
use syn::PathSegment;
use syn::ReturnType;
use syn::Signature;
use syn::TraitBound;
use syn::TraitBoundModifier;
use syn::TraitItem;
use syn::Type;
use syn::TypeParamBound;

const INNER_ERROR_MACRO_ATTRIBUTE: &str = "error";

/// Links the macro to the actual implementation.
#[proc_macro_attribute]
pub fn sirenia_rpc(
    args: proc_macro::TokenStream,
    input: proc_macro::TokenStream,
) -> proc_macro::TokenStream {
    let item_trait = parse_macro_input!(input as ItemTrait);

    let config = match SireniaRpcConfig::try_from(&parse_macro_input!(args as AttributeArgs)) {
        Ok(v) => v,
        Err(err) => return error_to_tokenstream(err, &item_trait).into(),
    };
    let expanded = sirenia_rpc_impl(item_trait.clone(), &config)
        .unwrap_or_else(|err| error_to_tokenstream(err, &item_trait));

    expanded.into()
}

#[derive(Debug, Default, Eq, PartialEq)]
struct SireniaRpcConfig {
    inner_error_type: Option<Type>,
}

fn str_to_type(value: &str, span: Span) -> Result<Option<Type>> {
    if value.is_empty() {
        return Ok(None);
    }
    let tokens: TokenStream = std::str::FromStr::from_str(value)
        .map_err(|err| Error::new(span, format!("failed to tokenize type: {}", &err)))?;
    Ok(Some(Type::without_plus.parse2(tokens).map_err(|err| {
        let mut ret = Error::new(span, format!("failed to parse type: {:?}", value));
        ret.combine(err);
        ret
    })?))
}

fn literal_to_type(lit: &Lit) -> Result<Option<Type>> {
    match lit {
        Lit::Verbatim(v) => str_to_type(v.to_string().as_str(), lit.span()),
        Lit::Str(s) => str_to_type(s.value().as_str(), lit.span()),
        _ => Err(Error::new(
            lit.span(),
            format!("Unexpected literal: '{:?}'", &lit),
        )),
    }
}

impl TryFrom<&AttributeArgs> for SireniaRpcConfig {
    type Error = Error;

    fn try_from(args: &AttributeArgs) -> StdResult<Self, Self::Error> {
        let mut config = SireniaRpcConfig::default();
        let get_default_err = |arg: &NestedMeta| {
            Err(Error::new(
                arg.span(),
                format!("unexpected macro argument: '{:?}'", &arg),
            ))
        };
        for arg in args {
            let name_value = if let NestedMeta::Meta(Meta::NameValue(v)) = arg {
                v
            } else {
                return get_default_err(arg);
            };

            let name = if let Some(v) = name_value.path.get_ident() {
                v.to_string()
            } else {
                return get_default_err(arg);
            };

            match name.as_str() {
                INNER_ERROR_MACRO_ATTRIBUTE => {
                    if config.inner_error_type.is_some() {
                        // Duplicate entry.
                        return get_default_err(arg);
                    }
                    config.inner_error_type = literal_to_type(&name_value.lit)?;
                }
                _ => {
                    // Unrecognized entry.
                    return get_default_err(arg);
                }
            }
        }
        Ok(config)
    }
}

fn get_request_name(name: &Ident) -> Ident {
    format_ident!("{}Request", name)
}

fn get_response_name(name: &Ident) -> Ident {
    format_ident!("{}Response", name)
}

fn get_rpc_trait_name(name: &Ident) -> Ident {
    format_ident!("{}Rpc", name)
}

fn get_client_struct_name(name: &Ident) -> Ident {
    format_ident!("{}Client", name)
}

fn get_server_trait_name(name: &Ident) -> Ident {
    format_ident!("{}Server", name)
}

fn replace_path_suffix(template: &Path, suffix: &Ident) -> Path {
    let segment = PathSegment::from(suffix.clone());
    let mut copy = template.clone();
    if let Some(last) = copy.segments.last_mut() {
        *last = segment;
        copy
    } else {
        Path::from(segment)
    }
}

// Allow for importing from libsirenia when the macro is used inside or outside libsirenia.
fn get_libsirenia_prefix() -> TokenStream {
    if env::var("CARGO_PKG_NAME")
        .map(|pkg| &pkg == "libsirenia")
        .unwrap_or(false)
    {
        quote! {crate}
    } else {
        quote! {::libsirenia}
    }
}

/// Converts 'snake_case' to upper camel case. Upper case letters in the input will be preserved.
fn to_upper_camel_case(snake_case: &str) -> String {
    let mut output = String::new();
    let mut next_upper = true;
    output.reserve(snake_case.len());
    for c in snake_case.chars() {
        if c == '_' {
            next_upper = true;
        } else if next_upper {
            output.push(c.to_ascii_uppercase());
            next_upper = false;
        } else {
            output.push(c);
        }
    }
    output
}

fn error_to_tokenstream<T: ToTokens>(err: Error, original: &T) -> TokenStream {
    let compile_error = err.to_compile_error();
    quote! {
        #compile_error

        // Include the original input to avoid "use of undeclared type"
        // errors elsewhere.
        #original
    }
}

/// Extract the first generic type T in Result<T, _> used for Ok(T).
fn extract_ok_type(type_value: &Type) -> StdResult<TokenStream, ()> {
    match type_value {
        Type::Path(path) => {
            let path = path.path.segments.last().ok_or(())?;
            // Aliases make it so the identifier might not be "Result".
            if let PathArguments::AngleBracketed(arg_tokens) = &path.arguments {
                let args = arg_tokens.args.first().ok_or(())?;
                Ok(quote! {#args})
            } else {
                Err(())
            }
        }
        _ => Err(()),
    }
}

struct RpcMethodHelper {
    signature: Signature,
    inner_error: Option<Type>,
    enum_name: Ident,
    request_args: Vec<FnArg>,
    request_arg_names: Vec<TokenStream>,
    response_arg: TokenStream,
}

impl RpcMethodHelper {
    fn new(signature: Signature, inner_error: Option<Type>) -> Result<Self> {
        let str_ident = signature.ident.to_string();
        let args = signature.inputs.iter();
        let response_arg = match &signature.output {
            ReturnType::Default => {
                quote! {}
            }
            ReturnType::Type(_, arg) => extract_ok_type(arg).map_err(|_| {
                Error::new(
                    signature.span(),
                    format!(
                        "unable to parse return type for '{}' expected std::result::Result",
                        &str_ident
                    ),
                )
            })?,
        };

        let mut request_args: Vec<FnArg> = Vec::new();
        let mut request_arg_names: Vec<TokenStream> = Vec::new();
        let mut has_self = false;
        for arg in args {
            match arg {
                FnArg::Receiver(_) => {
                    //TODO decide if self is ok (as opposed to &self and &mut self).
                    has_self = true;
                }
                FnArg::Typed(pat_type) => {
                    request_args.push(arg.clone());
                    let name = &pat_type.pat;
                    request_arg_names.push(quote! {#name});
                }
            }
        }
        if !has_self {
            return Err(Error::new(
                signature.inputs.span(),
                format!("'{}' needs a '&self' argument", &str_ident),
            ));
        }

        Ok(RpcMethodHelper {
            signature,
            inner_error,
            enum_name: format_ident!("{}", to_upper_camel_case(&str_ident)),
            request_args,
            request_arg_names,
            response_arg,
        })
    }

    fn get_request_enum_item(&self) -> TokenStream {
        let enum_name = &self.enum_name;
        let args: Vec<FnArg> = self.request_args.iter().map(|f|
            // Vec<u8> does not always send efficiently so label it as a byte field.
            if matches!(f, syn::FnArg::Typed(t) if t.ty == parse_quote!(Vec<u8>)) {
                parse_quote!(#[serde(with = "serde_bytes")] #f)
            } else {
                f.clone()
            }
        ).collect();
        quote! {
            #enum_name{#(#args),*}
        }
    }

    fn get_response_enum_item(&self) -> TokenStream {
        let enum_name = &self.enum_name;
        let response_arg = &self.response_arg;
        if let Some(err) = &self.inner_error {
            quote! {
                #enum_name(::std::result::Result<#response_arg, #err>)
            }
        } else {
            quote! {
                #enum_name(#response_arg)
            }
        }
    }

    fn get_client_trait_impl(
        &self,
        libsirenia_prefix: &TokenStream,
        request_name: &Ident,
        response_name: &Ident,
        rpc_trait_name: &Ident,
    ) -> TokenStream {
        let mut signature = self.signature.clone();
        let response_arg = &self.response_arg;
        signature.output =
            syn::parse2(quote!(-> ::std::result::Result<#response_arg, ::anyhow::Error>)).unwrap();
        let enum_name = &self.enum_name;
        let request_arg_names = &self.request_arg_names;
        let response = if self.inner_error.is_some() {
            quote! { response.map_err(|x| x.into()) }
        } else {
            quote! { Ok(response) }
        };
        quote! {
            #signature {
                if let #response_name::#enum_name(response) = #rpc_trait_name::rpc(
                    self,
                    #request_name::#enum_name{#(#request_arg_names),*},
                )? {
                    #response
                } else {
                    Err(#libsirenia_prefix::rpc::Error::ResponseMismatch.into())
                }
            }
        }
    }

    fn get_server_rpc_impl(&self, request_name: &Ident, response_name: &Ident) -> TokenStream {
        let function_name = &self.signature.ident;
        let enum_name = &self.enum_name;
        let request_arg_names = &self.request_arg_names;

        let function_call = quote! { self.#function_name(#(#request_arg_names),*) };

        let mapping = if let Some(inner_error_type) = &self.inner_error {
            quote! {
                match #function_call {
                    Ok(x) => Ok(#response_name::#enum_name(Ok(x))),
                    Err(err) => {
                        match err.downcast::<#inner_error_type>() {
                            Ok(err) => Ok(#response_name::#enum_name(Err(err))),
                            Err(err) => Err(err),
                        }
                    }
                }
            }
        } else {
            quote! { #function_call.map(|x| #response_name::#enum_name(x)) }
        };

        quote! {
            #request_name::#enum_name{#(#request_arg_names),*} => {
                #mapping
            }
        }
    }
}

struct SuperTraitHelper {
    super_name: Ident,
    super_request: Path,
    super_response: Path,
    super_rpc_trait: Path,
    super_server_trait: Path,
}

impl SuperTraitHelper {
    fn new(trait_bound: TraitBound) -> Result<Self> {
        if !matches!(trait_bound.modifier, TraitBoundModifier::None) {
            return Err(Error::new(
                trait_bound.modifier.span(),
                "TraitBoundModifier are not supported in supertrait position (yet)",
            ));
        }

        if trait_bound.lifetimes.is_some() {
            return Err(Error::new(
                trait_bound.lifetimes.span(),
                "lifetimes are not supported in supertrait position (yet)",
            ));
        }

        let super_trait = trait_bound.path;

        let super_name = super_trait
            .segments
            .last()
            .ok_or_else(|| Error::new(super_trait.span(), "Missing trait path"))?
            .ident
            .clone();

        let super_request = replace_path_suffix(&super_trait, &get_request_name(&super_name));
        let super_response = replace_path_suffix(&super_trait, &get_response_name(&super_name));
        let super_rpc_trait = replace_path_suffix(&super_trait, &get_rpc_trait_name(&super_name));
        let super_server_trait =
            replace_path_suffix(&super_trait, &get_server_trait_name(&super_name));

        Ok(SuperTraitHelper {
            super_name,
            super_request,
            super_response,
            super_rpc_trait,
            super_server_trait,
        })
    }

    fn get_request_enum_item(&self) -> TokenStream {
        let super_name = &self.super_name;
        let request_path = &self.super_request;
        quote! {
            #super_name(#request_path)
        }
    }

    fn get_response_enum_item(&self) -> TokenStream {
        let super_name = &self.super_name;
        let response_path = &self.super_response;
        quote! {
            #super_name(#response_path)
        }
    }

    fn get_super_rpc_impl(
        &self,
        libsirenia_prefix: &TokenStream,
        rpc_trait_name: &Ident,
        request_name: &Ident,
        response_name: &Ident,
    ) -> TokenStream {
        let super_name = &self.super_name;
        let super_request = &self.super_request;
        let super_response = &self.super_response;
        let super_rpc_trait = &self.super_rpc_trait;
        quote! {
            impl<R: #rpc_trait_name> #super_rpc_trait for R {
                fn rpc(&mut self, request: #super_request) ->
                        ::std::result::Result<#super_response, #libsirenia_prefix::rpc::Error> {
                    if let #response_name::#super_name(response) = #rpc_trait_name::rpc(
                        self,
                        #request_name::#super_name(request)
                    )? {
                        Ok(response)
                    } else {
                        Err(#libsirenia_prefix::rpc::Error::ResponseMismatch)
                    }
                }
            }
        }
    }

    fn get_server_rpc_impl(&self, request_name: &Ident, response_name: &Ident) -> TokenStream {
        let super_server_trait = &self.super_server_trait;
        let super_name = &self.super_name;
        quote! {
            #request_name::#super_name(request) => {
                #super_server_trait::rpc_impl(self, request).map(|x| #response_name::#super_name(x))
            }
        }
    }
}

fn get_inner_error(attr: &Attribute) -> Result<Option<Type>> {
    let mut fields = FieldsUnnamed::parse.parse2(attr.tokens.clone())?;
    if fields.unnamed.len() > 1 {
        return Err(Error::new(
            attr.span(),
            "More than one error type specified",
        ));
    }
    let error_type = fields.unnamed.iter_mut().map(|x| x.ty.clone()).next();
    Ok(error_type)
}

fn sirenia_rpc_impl(mut item_trait: ItemTrait, config: &SireniaRpcConfig) -> Result<TokenStream> {
    let trait_name = &item_trait.ident;

    let mut super_trait_helpers: Vec<SuperTraitHelper> = Vec::new();
    for bound in item_trait.supertraits.iter() {
        let trait_bound = if let TypeParamBound::Trait(t) = bound {
            t
        } else {
            return Err(Error::new(
                bound.span(),
                "lifetimes are not supported in supertrait position (yet)",
            ));
        };
        super_trait_helpers.push(SuperTraitHelper::new(trait_bound.clone())?);
    }

    let mut rpc_method_helpers: Vec<RpcMethodHelper> = Vec::new();

    for x in item_trait.items.iter_mut() {
        match x {
            TraitItem::Type(_) => {
                return Err(Error::new(x.span(), "trait types not supported yet"));
            }
            TraitItem::Method(trait_item_method) => {
                let mut inner_error = Ok(config.inner_error_type.clone());
                trait_item_method.attrs.retain(|a| {
                    if a.path == parse_quote!(error) {
                        inner_error = get_inner_error(a);
                        false
                    } else {
                        true
                    }
                });
                rpc_method_helpers.push(RpcMethodHelper::new(
                    trait_item_method.sig.clone(),
                    inner_error?,
                )?);
            }
            _ => {}
        }
    }

    let libsirenia_prefix = get_libsirenia_prefix();

    let request_name = get_request_name(trait_name);
    let response_name = get_response_name(trait_name);
    let rpc_trait_name = get_rpc_trait_name(trait_name);
    let client_struct_name = get_client_struct_name(trait_name);
    let server_trait_name = get_server_trait_name(trait_name);

    let request_contents: Vec<TokenStream> = super_trait_helpers
        .iter()
        .map(|x| x.get_request_enum_item())
        .chain(rpc_method_helpers.iter().map(|x| x.get_request_enum_item()))
        .collect();
    let response_contents: Vec<TokenStream> = super_trait_helpers
        .iter()
        .map(|x| x.get_response_enum_item())
        .chain(
            rpc_method_helpers
                .iter()
                .map(|x| x.get_response_enum_item()),
        )
        .collect();
    let super_rpc_contents: Vec<TokenStream> = super_trait_helpers
        .iter()
        .map(|x| {
            x.get_super_rpc_impl(
                &libsirenia_prefix,
                &rpc_trait_name,
                &request_name,
                &response_name,
            )
        })
        .collect();
    let client_trait_contents: Vec<TokenStream> = rpc_method_helpers
        .iter()
        .map(|x| {
            x.get_client_trait_impl(
                &libsirenia_prefix,
                &request_name,
                &response_name,
                &rpc_trait_name,
            )
        })
        .collect();
    let server_super_traits: Vec<Path> = super_trait_helpers
        .iter()
        .map(|x| x.super_server_trait.clone())
        .collect();
    let server_rpc_impl_contents: Vec<TokenStream> = super_trait_helpers
        .iter()
        .map(|x| x.get_server_rpc_impl(&request_name, &response_name))
        .chain(
            rpc_method_helpers
                .iter()
                .map(|x| x.get_server_rpc_impl(&request_name, &response_name)),
        )
        .collect();

    Ok(quote! {
        #item_trait

        #[derive(::std::fmt::Debug, ::serde::Deserialize, ::serde::Serialize)]
        pub enum #request_name {
            #(#request_contents,)*
        }

        #[derive(::std::fmt::Debug, ::serde::Deserialize, ::serde::Serialize)]
        pub enum #response_name {
            #(#response_contents,)*
        }

        pub struct #client_struct_name {
            transport: ::std::cell::RefCell<#libsirenia_prefix::transport::Transport>,
        }

        pub trait #rpc_trait_name {
            fn rpc(&mut self, request: #request_name) ->
                    ::std::result::Result<#response_name, #libsirenia_prefix::rpc::Error>;
        }

        impl #client_struct_name {
            pub fn new(transport: #libsirenia_prefix::transport::Transport) -> Self {
                #client_struct_name {
                    transport: ::std::cell::RefCell::new(transport),
                }
            }
        }

        impl #rpc_trait_name for #client_struct_name {
            fn rpc(&mut self, request: #request_name) ->
                    ::std::result::Result<#response_name, #libsirenia_prefix::rpc::Error> {
                #libsirenia_prefix::rpc::Invoker::<Self>::invoke(
                    ::std::ops::DerefMut::deref_mut(&mut self.transport.borrow_mut()),
                    request
                )
            }
        }

        impl<R: #rpc_trait_name> #trait_name<::anyhow::Error> for R {
            #(#client_trait_contents)*
        }

        #(#super_rpc_contents)*

        impl #libsirenia_prefix::rpc::Procedure for #client_struct_name {
            type Request = #request_name;
            type Response = #response_name;
        }

        pub trait #server_trait_name: #trait_name<::anyhow::Error> {
            fn box_clone(&self) -> Box<dyn #server_trait_name>;
            fn rpc_impl(&mut self, request: #request_name) ->
                    ::std::result::Result<#response_name, ::anyhow::Error>;
        }

        impl<T: #trait_name<::anyhow::Error> + #(#server_super_traits +)* ::std::clone::Clone + 'static>
                #server_trait_name for T {
            fn box_clone(&self) -> ::std::boxed::Box<dyn #server_trait_name> {
                ::std::boxed::Box::new(self.clone())
            }

            fn rpc_impl(&mut self, request: #request_name) ->
                    ::std::result::Result<#response_name, ::anyhow::Error> {
                match request {
                    #(#server_rpc_impl_contents)*
                }
            }
        }

        impl #libsirenia_prefix::rpc::Procedure for Box<dyn #server_trait_name> {
            type Request = #request_name;
            type Response = #response_name;
        }

        impl #libsirenia_prefix::rpc::MessageHandler for Box<dyn #server_trait_name> {
            fn handle_message(&mut self, request: #request_name) ->
                    ::std::result::Result<#response_name, ()> {
                self.rpc_impl(request).map_err(|_| ())
            }
        }

        impl ::std::clone::Clone for ::std::boxed::Box<dyn #server_trait_name> {
            fn clone(&self) -> Self {
                self.box_clone()
            }
        }
    })
}

#[cfg(test)]
mod test {
    use super::*;

    fn sirenia_rpc_config_parse(stream: TokenStream, expected: SireniaRpcConfig) {
        let args: AttributeArgs = parse_macro_input::ParseMacroInput::parse
            .parse2(stream)
            .unwrap();
        let config = SireniaRpcConfig::try_from(&args).unwrap();
        assert_eq!(config, expected);
    }

    #[test]
    fn sirenia_rpc_config_parse_empty_str() {
        sirenia_rpc_config_parse(
            quote! { error="" },
            SireniaRpcConfig {
                inner_error_type: None,
            },
        );
    }

    #[test]
    fn sirenia_rpc_config_parse_str_tuple() {
        sirenia_rpc_config_parse(
            quote! { error="()" },
            SireniaRpcConfig {
                inner_error_type: Some(parse_quote!(())),
            },
        );
    }

    #[test]
    fn sirenia_rpc_config_parse_tuple() {
        let verbatim = "()";
        sirenia_rpc_config_parse(
            quote! { error=#verbatim },
            SireniaRpcConfig {
                inner_error_type: Some(parse_quote!(())),
            },
        );
    }

    #[test]
    fn sirenia_rpc_config_parse_path() {
        let verbatim = "::std::option::Option<usize>";
        sirenia_rpc_config_parse(
            quote! { error=#verbatim },
            SireniaRpcConfig {
                inner_error_type: Some(parse_quote!(::std::option::Option<usize>)),
            },
        );
    }

    #[test]
    fn sirenia_rpc_value_check() {
        // This simulates #[error=()]
        let args: AttributeArgs = parse_macro_input::ParseMacroInput::parse
            .parse2(quote! { error="()" })
            .unwrap();
        let input: ItemTrait = parse_quote!(
            pub trait Nested<E>: other::Test<E> {
                #[error()]
                fn ping(&mut self, value: usize) -> Result<usize, E>;
                fn terminate(&mut self) -> Result<(), E>;
                fn echo(&mut self, value: Vec<u8>) -> Result<Vec<u8>, E>;
            }
        );

        let config = SireniaRpcConfig::try_from(&args).unwrap();
        let actual = sirenia_rpc_impl(input, &config).unwrap();
        let expected = quote! {
            pub trait Nested<E>: other::Test<E> {
                fn ping(&mut self, value: usize) -> Result<usize, E>;
                fn terminate(&mut self) -> Result<(), E>;
                fn echo(&mut self, value: Vec<u8>) -> Result<Vec<u8>, E>;
            }

            #[derive(::std::fmt::Debug, ::serde::Deserialize, ::serde::Serialize)]
            pub enum NestedRequest {
                Test(other::TestRequest),
                Ping { value: usize },
                Terminate {},
                Echo {
                    #[serde(with = "serde_bytes")]
                    value: Vec<u8>
                },
            }

            #[derive(::std::fmt::Debug, ::serde::Deserialize, ::serde::Serialize)]
            pub enum NestedResponse {
                Test(other::TestResponse),
                Ping(usize),
                Terminate(::std::result::Result<(), ()>),
                Echo(::std::result::Result<Vec<u8>, ()>),
            }

            pub struct NestedClient {
                transport: ::std::cell::RefCell<::libsirenia::transport::Transport>,
            }

            pub trait NestedRpc {
                fn rpc(
                    &mut self,
                    request: NestedRequest
                ) -> ::std::result::Result<NestedResponse, ::libsirenia::rpc::Error>;
            }

            impl NestedClient {
                pub fn new(transport: ::libsirenia::transport::Transport) -> Self {
                    NestedClient {
                        transport: ::std::cell::RefCell::new(transport),
                    }
                }
            }

            impl NestedRpc for NestedClient {
                fn rpc(&mut self, request: NestedRequest) ->
                        ::std::result::Result<NestedResponse, ::libsirenia::rpc::Error> {
                    ::libsirenia::rpc::Invoker::<Self>::invoke(
                        ::std::ops::DerefMut::deref_mut(&mut self.transport.borrow_mut()),
                        request
                    )
                }
            }

            impl<R: NestedRpc> Nested<::anyhow::Error> for R {
                fn ping(&mut self, value: usize) -> ::std::result::Result<usize, ::anyhow::Error> {
                    if let NestedResponse::Ping(response) =
                        NestedRpc::rpc(self, NestedRequest::Ping { value },)?
                    {
                        Ok(response)
                    } else {
                        Err(::libsirenia::rpc::Error::ResponseMismatch.into())
                    }
                }

                fn terminate(&mut self) -> ::std::result::Result<(), ::anyhow::Error> {
                    if let NestedResponse::Terminate(response) =
                        NestedRpc::rpc(self, NestedRequest::Terminate {},)?
                    {
                        response.map_err(|x| x.into())
                    } else {
                        Err(::libsirenia::rpc::Error::ResponseMismatch.into())
                    }
                }

                fn echo(&mut self, value: Vec<u8>) ->
                        ::std::result::Result<Vec<u8>, ::anyhow::Error> {
                    if let NestedResponse::Echo(response) =
                        NestedRpc::rpc(self, NestedRequest::Echo { value },)?
                    {
                        response.map_err(|x| x.into())
                    } else {
                        Err(::libsirenia::rpc::Error::ResponseMismatch.into())
                    }
                }
            }

            impl<R: NestedRpc> other::TestRpc for R {
                fn rpc(&mut self, request: other::TestRequest) ->
                        ::std::result::Result<other::TestResponse, ::libsirenia::rpc::Error> {
                    if let NestedResponse::Test(response) =
                        NestedRpc::rpc(self, NestedRequest::Test(request))?
                    {
                        Ok(response)
                    } else {
                        Err(::libsirenia::rpc::Error::ResponseMismatch)
                    }
                }
            }

            impl ::libsirenia::rpc::Procedure for NestedClient {
                type Request = NestedRequest;
                type Response = NestedResponse;
            }

            pub trait NestedServer: Nested<::anyhow::Error> {
                fn box_clone(&self) -> Box<dyn NestedServer>;
                fn rpc_impl(&mut self, request: NestedRequest) ->
                        ::std::result::Result<NestedResponse, ::anyhow::Error>;
            }

            impl<T: Nested<::anyhow::Error> + other::TestServer + ::std::clone::Clone + 'static>
                    NestedServer for T {
                fn box_clone(&self) -> ::std::boxed::Box<dyn NestedServer> {
                    ::std::boxed::Box::new(self.clone())
                }
                fn rpc_impl(
                    &mut self,
                    request: NestedRequest
                ) -> ::std::result::Result<NestedResponse, ::anyhow::Error> {
                    match request {
                        NestedRequest::Test(request) => {
                            other::TestServer::rpc_impl(self, request).map(|x| NestedResponse::Test(x))
                        }
                        NestedRequest::Ping { value } => {
                            self.ping(value).map(|x| NestedResponse::Ping(x))
                        }
                        NestedRequest::Terminate {} => {
                            match self.terminate() {
                                Ok(x) => Ok(NestedResponse::Terminate(Ok(x))),
                                Err(err) => {
                                    match err.downcast::<()>() {
                                        Ok(err) => Ok(NestedResponse::Terminate(Err(err))),
                                        Err(err) => Err(err),
                                    }
                                }
                            }
                        }
                        NestedRequest::Echo { value } => {
                            match self.echo(value) {
                                Ok(x) => Ok(NestedResponse::Echo(Ok(x))),
                                Err(err) => {
                                    match err.downcast::<()>() {
                                        Ok(err) => Ok(NestedResponse::Echo(Err(err))),
                                        Err(err) => Err(err),
                                    }
                                }
                            }
                        }
                    }
                }
            }

            impl ::libsirenia::rpc::Procedure for Box<dyn NestedServer> {
                type Request = NestedRequest;
                type Response = NestedResponse;
            }

            impl ::libsirenia::rpc::MessageHandler for Box<dyn NestedServer> {
                fn handle_message(&mut self, request: NestedRequest) ->
                        ::std::result::Result<NestedResponse, ()> {
                    self.rpc_impl(request).map_err(|_| ())
                }
            }

            impl ::std::clone::Clone for ::std::boxed::Box<dyn NestedServer> {
                fn clone(&self) -> Self {
                    self.box_clone()
                }
            }
        };

        assert_eq!(actual.to_string(), expected.to_string());
    }
}
