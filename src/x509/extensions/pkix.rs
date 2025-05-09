// Copyright (c) 2021 The RustCrypto Project Developers
// SPDX-FileCopyrightText: 2023 Rivos Inc.
//
// SPDX-License-Identifier: Apache-2.0

//! PKIX X.509 Certificate Extensions (RFC 5280)

pub mod name;

/// authorityKeyIdentifier extension module.
/// This extension provides a means of identifying the public key corresponding
/// to the private key used to sign a certificate.
pub mod authkeyid;

/// basiConstraints X.509 extension module.
/// This extension identifies wether the subject of a certificate is a CA.
pub mod basicconstraints;

/// keyUsage X.509 extension module.
/// This extension describes the intended usage for the subject public key
/// information (a.k.a. the public key) a certificate is bound to: Key
/// agreement, key wrapping, certificate signing authority, etc.
/// keyUsage extension module
pub mod keyusage;

use crate::x509::attr::AttributeTypeAndValue;

use const_oid::{AssociatedOid, ObjectIdentifier};

pub use const_oid::db::rfc5280::{
    ID_CE_INHIBIT_ANY_POLICY, ID_CE_ISSUER_ALT_NAME, ID_CE_SUBJECT_ALT_NAME,
    ID_CE_SUBJECT_DIRECTORY_ATTRIBUTES, ID_CE_SUBJECT_KEY_IDENTIFIER,
};

use der::asn1::{OctetStringRef, SequenceOf};

/// SubjectKeyIdentifier as defined in [RFC 5280 Section 4.2.1.2].
///
/// ```text
/// SubjectKeyIdentifier ::= KeyIdentifier
/// ```
///
/// [RFC 5280 Section 4.2.1.2]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.2
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct SubjectKeyIdentifier<'a>(pub OctetStringRef<'a>);

impl AssociatedOid for SubjectKeyIdentifier<'_> {
    const OID: ObjectIdentifier = ID_CE_SUBJECT_KEY_IDENTIFIER;
}

impl_newtype!(SubjectKeyIdentifier<'a>, OctetStringRef<'a>);

/// SubjectAltName as defined in [RFC 5280 Section 4.2.1.6].
///
/// ```text
/// SubjectAltName ::= GeneralNames
/// ```
///
/// [RFC 5280 Section 4.2.1.6]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.6
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SubjectAltName<'a>(pub name::GeneralNames<'a>);

impl AssociatedOid for SubjectAltName<'_> {
    const OID: ObjectIdentifier = ID_CE_SUBJECT_ALT_NAME;
}

impl_newtype!(SubjectAltName<'a>, name::GeneralNames<'a>);

/// IssuerAltName as defined in [RFC 5280 Section 4.2.1.7].
///
/// ```text
/// IssuerAltName ::= GeneralNames
/// ```
///
/// [RFC 5280 Section 4.2.1.7]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.7
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct IssuerAltName<'a>(pub name::GeneralNames<'a>);

impl AssociatedOid for IssuerAltName<'_> {
    const OID: ObjectIdentifier = ID_CE_ISSUER_ALT_NAME;
}

impl_newtype!(IssuerAltName<'a>, name::GeneralNames<'a>);

/// SubjectDirectoryAttributes as defined in [RFC 5280 Section 4.2.1.8].
///
/// ```text
/// SubjectDirectoryAttributes ::= SEQUENCE SIZE (1..MAX) OF AttributeSet
/// ```
///
/// [RFC 5280 Section 4.2.1.8]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.8
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SubjectDirectoryAttributes<'a>(pub SequenceOf<AttributeTypeAndValue<'a>, 8>);

impl AssociatedOid for SubjectDirectoryAttributes<'_> {
    const OID: ObjectIdentifier = ID_CE_SUBJECT_DIRECTORY_ATTRIBUTES;
}

impl_newtype!(
    SubjectDirectoryAttributes<'a>,
    SequenceOf<AttributeTypeAndValue<'a>, 8>
);
