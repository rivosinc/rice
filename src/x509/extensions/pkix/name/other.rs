// Copyright (c) 2021 The RustCrypto Project Developers
// SPDX-FileCopyrightText: 2023 Rivos Inc.
//
// SPDX-License-Identifier: Apache-2.0

use der::{asn1::ObjectIdentifier, AnyRef, Sequence};

/// OtherName as defined in [RFC 5280 Section 4.2.1.6].
///
/// ```text
/// OtherName ::= SEQUENCE {
///     type-id    OBJECT IDENTIFIER,
///     value      [0] EXPLICIT ANY DEFINED BY type-id
/// }
/// ```
///
/// [RFC 5280 Section 4.2.1.6]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.6
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct OtherName<'a> {
    pub type_id: ObjectIdentifier,

    #[asn1(context_specific = "0", tag_mode = "EXPLICIT")]
    pub value: AnyRef<'a>,
}
