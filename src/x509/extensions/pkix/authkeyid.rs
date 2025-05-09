// Copyright (c) 2021 The RustCrypto Project Developers
// SPDX-FileCopyrightText: 2023 Rivos Inc.
//
// SPDX-License-Identifier: Apache-2.0

use super::name::GeneralNames;

use const_oid::db::rfc5280::ID_CE_AUTHORITY_KEY_IDENTIFIER;
use const_oid::{AssociatedOid, ObjectIdentifier};
use der::asn1::{OctetStringRef, UintRef};
use der::Sequence;

pub(crate) const AUTH_KEY_ID_EXTENSION_LEN: usize = 64;

/// AuthorityKeyIdentifier as defined in [RFC 5280 Section 4.2.1.1].
///
/// ```text
/// AuthorityKeyIdentifier ::= SEQUENCE {
///     keyIdentifier             [0] KeyIdentifier           OPTIONAL,
///     authorityCertIssuer       [1] GeneralNames            OPTIONAL,
///     authorityCertSerialNumber [2] CertificateSerialNumber OPTIONAL
/// }
///
/// KeyIdentifier ::= OCTET STRING
/// ```
///
/// [RFC 5280 Section 4.2.1.1]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.1
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct AuthorityKeyIdentifier<'a> {
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT", optional = "true")]
    pub key_identifier: Option<OctetStringRef<'a>>,

    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", optional = "true")]
    pub authority_cert_issuer: Option<GeneralNames<'a>>,

    #[asn1(context_specific = "2", tag_mode = "IMPLICIT", optional = "true")]
    pub authority_cert_serial_number: Option<UintRef<'a>>,
}

impl AssociatedOid for AuthorityKeyIdentifier<'_> {
    const OID: ObjectIdentifier = ID_CE_AUTHORITY_KEY_IDENTIFIER;
}
