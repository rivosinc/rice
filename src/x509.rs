// Copyright (c) 2021 The RustCrypto Project Developers
// SPDX-FileCopyrightText: 2023 Rivos Inc.
//
// SPDX-License-Identifier: Apache-2.0

//! Standardized X.509 Certificate Extensions

/// Maximum supported length for a CSR
pub const MAX_CSR_LEN: usize = 4096;

/// Maximum number of FW ID entries in the `TcbInfo` FWID array
pub const MAX_TCBINFO_FWID: usize = 32;

pub(crate) const MAX_CSR_ATV: usize = 8;
pub(crate) const MAX_CSR_ATV_VALUE: usize = 8;
pub(crate) const MAX_CSR_ATV_VALUE_LEN: usize = 64;
pub(crate) const MAX_CSR_ATV_TYPE_LEN: usize = 64;
pub(crate) const MAX_CSR_ATV_LEN: usize =
    MAX_CSR_ATV_TYPE_LEN + (MAX_CSR_ATV_VALUE * MAX_CSR_ATV_VALUE_LEN);

pub(crate) const MAX_CSR_RDN: usize = 8;
pub(crate) const MAX_CSR_RDN_LEN: usize = MAX_CSR_ATV * MAX_CSR_ATV_LEN;
pub(crate) const MAX_CSR_RDN_SEQUENCE_LEN: usize = MAX_CSR_RDN * MAX_CSR_RDN_LEN;

pub(crate) const MAX_CERT_EXTENSIONS: usize = 8;
pub(crate) const MAX_CERT_ATV: usize = MAX_CSR_ATV;
pub(crate) const MAX_CERT_RDN: usize = MAX_CSR_RDN;

/// Implements the following traits for a newtype of a `der` decodable/encodable type:
///
/// - `From` conversions to/from the inner type
/// - `AsRef` and `AsMut`
/// - `DecodeValue` and `EncodeValue`
/// - `FixedTag` mapping to the inner value's `FixedTag::TAG`
///
/// The main case is simplifying newtypes which need an `AssociatedOid`
#[macro_export]
macro_rules! impl_newtype {
    ($newtype:ty, $inner:ty) => {
        #[allow(unused_lifetimes)]
        impl<'a> From<$inner> for $newtype {
            #[inline]
            fn from(value: $inner) -> Self {
                Self(value)
            }
        }

        #[allow(unused_lifetimes)]
        impl<'a> From<$newtype> for $inner {
            #[inline]
            fn from(value: $newtype) -> Self {
                value.0
            }
        }

        #[allow(unused_lifetimes)]
        impl<'a> AsRef<$inner> for $newtype {
            #[inline]
            fn as_ref(&self) -> &$inner {
                &self.0
            }
        }

        #[allow(unused_lifetimes)]
        impl<'a> AsMut<$inner> for $newtype {
            #[inline]
            fn as_mut(&mut self) -> &mut $inner {
                &mut self.0
            }
        }

        #[allow(unused_lifetimes)]
        impl<'a> ::der::FixedTag for $newtype {
            const TAG: ::der::Tag = <$inner as ::der::FixedTag>::TAG;
        }

        impl<'a> ::der::DecodeValue<'a> for $newtype {
            fn decode_value<R: ::der::Reader<'a>>(
                decoder: &mut R,
                header: ::der::Header,
            ) -> ::der::Result<Self> {
                Ok(Self(<$inner as ::der::DecodeValue>::decode_value(
                    decoder, header,
                )?))
            }
        }

        #[allow(unused_lifetimes)]
        impl<'a> ::der::EncodeValue for $newtype {
            fn encode_value(&self, encoder: &mut impl ::der::Writer) -> ::der::Result<()> {
                self.0.encode_value(encoder)
            }

            fn value_len(&self) -> ::der::Result<::der::Length> {
                self.0.value_len()
            }
        }
    };
}

mod attr;
/// x.509 certificate module.
pub mod certificate;
/// x.509 certificate extensions module.
pub mod extensions;
mod name;
/// Certificate Signing Resquest module.
pub mod request;
mod time;
mod verify;
