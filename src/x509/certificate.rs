// Copyright (c) 2021 The RustCrypto Project Developers
// Copyright (c) 2022 by Rivos Inc.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use const_oid::AssociatedOid;
use der::asn1::{BitStringRef, OctetStringRef, SequenceOf, SetOf, UIntRef, Utf8StringRef};
use der::{AnyRef, Decode, Encode};
use der::{Enumerated, Sequence};
use ed25519_dalek::Signer;
use generic_array::ArrayLength;
use spki::{AlgorithmIdentifier, SubjectPublicKeyInfo};

use crate::{
    cdi::{CompoundDeviceIdentifier, CDI_ID_LEN},
    x509::{
        attr::AttributeTypeAndValue,
        extensions::{
            pkix::authkeyid::{AuthorityKeyIdentifier, AUTH_KEY_ID_EXTENSION_LEN},
            pkix::basicconstraints::{BasicConstraints, BASIC_CONSTRAINTS_EXTENSION_LEN},
            pkix::keyusage::{KeyUsage, KeyUsageFlags, KEY_VALUE_EXTENSION_LEN},
            Extension, Extensions,
        },
        name::{Name, RdnSequence, RelativeDistinguishedName},
        request::CertReq,
        time::{Time, Validity},
        MAX_CERT_ATV, MAX_CERT_EXTENSIONS, MAX_CERT_RDN,
    },
    Error, Result,
};

/// Maximum supported size for the attestation certificate.
pub const MAX_CERT_SIZE: usize = 4096;

fn x509_serial_number(id: &[u8]) -> Result<RdnSequence> {
    let sn_atv = AttributeTypeAndValue {
        oid: const_oid::db::rfc4519::SN,
        value: AnyRef::from(Utf8StringRef::new(id).map_err(Error::InvalidDer)?),
    };
    let mut sn_atv_set = SetOf::<AttributeTypeAndValue, MAX_CERT_ATV>::new();
    sn_atv_set.add(sn_atv).map_err(Error::InvalidDer)?;
    let rdn = RelativeDistinguishedName(sn_atv_set);
    let mut rdn_sequence = SequenceOf::<RelativeDistinguishedName, MAX_CERT_RDN>::new();
    rdn_sequence.add(rdn).map_err(Error::InvalidDer)?;

    Ok(RdnSequence(rdn_sequence))
}

macro_rules! extension {
    ($extension_def:expr, $extension_id:expr, $extension_buffer:expr, $critical:expr) => {{
        let extension_bytes = $extension_def
            .encode_to_slice(&mut $extension_buffer)
            .map_err(Error::InvalidDer)?;
        Extension {
            extn_id: $extension_id,
            critical: $critical,
            extn_value: extension_bytes,
        }
    }};
}

macro_rules! basic_constraints_extension {
    ($extension_def:expr, $extension_buffer:expr) => {{
        extension!(
            $extension_def,
            BasicConstraints::OID,
            $extension_buffer,
            true
        )
    }};
}

macro_rules! key_usage_extension {
    ($extension_def:expr, $extension_buffer:expr) => {{
        extension!($extension_def, KeyUsage::OID, $extension_buffer, true)
    }};
}

macro_rules! auth_key_extension {
    ($extension_def:expr, $extension_buffer:expr) => {{
        extension!(
            $extension_def,
            AuthorityKeyIdentifier::OID,
            $extension_buffer,
            false
        )
    }};
}

/// Certificate `Version` as defined in [RFC 5280 Section 4.1].
///
/// ```text
/// Version  ::=  INTEGER  {  v1(0), v2(1), v3(2)  }
/// ```
///
/// [RFC 5280 Section 4.1]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.1
#[derive(Clone, Debug, Copy, PartialEq, Eq, Enumerated)]
#[asn1(type = "INTEGER")]
#[repr(u8)]
pub enum Version {
    /// Version 1 (default)
    V1 = 0,

    /// Version 2
    V2 = 1,

    /// Version 3
    V3 = 2,
}

impl Default for Version {
    fn default() -> Self {
        Self::V1
    }
}

/// X.509 `TbsCertificate` as defined in [RFC 5280 Section 4.1]
///
/// ASN.1 structure containing the names of the subject and issuer, a public
/// key associated with the subject, a validity period, and other associated
/// information.
///
/// ```text
/// TBSCertificate  ::=  SEQUENCE  {
///     version         [0]  EXPLICIT Version DEFAULT v1,
///     serialNumber         CertificateSerialNumber,
///     signature            AlgorithmIdentifier,
///     issuer               Name,
///     validity             Validity,
///     subject              Name,
///     subjectPublicKeyInfo SubjectPublicKeyInfo,
///     issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
///                          -- If present, version MUST be v2 or v3
///     subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
///                          -- If present, version MUST be v2 or v3
///     extensions      [3]  Extensions OPTIONAL
///                          -- If present, version MUST be v3 --
/// }
/// ```
///
/// [RFC 5280 Section 4.1]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.1
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct TbsCertificate<'a> {
    /// The certificate version
    ///
    /// Note that this value defaults to Version 1 per the RFC. However,
    /// fields such as `issuer_unique_id`, `subject_unique_id` and `extensions`
    /// require later versions. Care should be taken in order to ensure
    /// standards compliance.
    #[asn1(context_specific = "0", default = "Default::default")]
    pub version: Version,

    pub serial_number: UIntRef<'a>,
    pub signature: AlgorithmIdentifier<'a>,
    pub issuer: Name<'a>,
    pub validity: Validity,
    pub subject: Name<'a>,
    pub subject_public_key_info: SubjectPublicKeyInfo<'a>,

    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", optional = "true")]
    pub issuer_unique_id: Option<BitStringRef<'a>>,

    #[asn1(context_specific = "2", tag_mode = "IMPLICIT", optional = "true")]
    pub subject_unique_id: Option<BitStringRef<'a>>,

    #[asn1(context_specific = "3", tag_mode = "EXPLICIT", optional = "true")]
    pub extensions: Option<Extensions<'a>>,
}

/// X.509 certificates are defined in [RFC 5280 Section 4.1].
///
/// ```text
/// Certificate  ::=  SEQUENCE  {
///     tbsCertificate       TBSCertificate,
///     signatureAlgorithm   AlgorithmIdentifier,
///     signature            BIT STRING
/// }
/// ```
///
/// [RFC 5280 Section 4.1]: https://datatracker.ietf.org/doc/html/rfc5280#section-4.1
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct Certificate<'a> {
    pub tbs_certificate: TbsCertificate<'a>,
    pub signature_algorithm: AlgorithmIdentifier<'a>,
    pub signature: BitStringRef<'a>,
}

impl<'a> Certificate<'a> {
    /// Build a certificate from the current and next CDIs.
    ///
    /// # Parameters
    ///
    /// @current_cdi: The current layer CDI.
    /// @next_cdi: The next layer CDI.
    /// @extns: An optional slice of x.509 DER-formatted extensions slices.
    /// @certificate_buf: Buffer to hold the certificate DER.
    pub fn from_layer<N: ArrayLength<u8>, D: digest::Digest, H: hkdf::HmacImpl<D>>(
        current_cdi: &CompoundDeviceIdentifier<N, D, H>,
        next_cdi: &CompoundDeviceIdentifier<N, D, H>,
        extns: Option<&'a [&'a [u8]]>,
        certificate_buf: &'a mut [u8],
    ) -> Result<&'a [u8]> {
        // The serial number is the next layer CDI ID
        let next_cdi_id = next_cdi.id()?;

        // Subject contains one ATV for one RDN: `SN=<Next CDI_ID>`
        let subject = x509_serial_number(&next_cdi_id)?;

        // The subject public key is the next CDI derived public key.
        let subject_public_key_info = SubjectPublicKeyInfo {
            algorithm: ed25519::pkcs8::ALGORITHM_ID,
            subject_public_key: next_cdi.key_pair().public.as_bytes(),
        };

        Certificate::from_current_cdi(
            current_cdi,
            &next_cdi_id,
            subject,
            subject_public_key_info,
            extns,
            certificate_buf,
        )
    }

    /// Build a certificate from the current CDI and a Certificate Signing Request (CSR)
    ///
    /// # Parameters
    ///
    /// @current_cdi: The current layer CDI.
    /// @csr: The certificate signing request.
    /// @extns: An optional slice of x.509 DER-formatted extensions slices.
    /// @certificate_buf: Buffer to hold the certificate DER.
    pub fn from_csr<N: ArrayLength<u8>, D: digest::Digest, H: hkdf::HmacImpl<D>>(
        current_cdi: &CompoundDeviceIdentifier<N, D, H>,
        csr: &CertReq<'a>,
        extns: Option<&'a [&'a [u8]]>,
        certificate_buf: &'a mut [u8],
    ) -> Result<&'a [u8]> {
        // The serial number is derived from the CSR public key.
        let mut cdi_id = [0u8; CDI_ID_LEN * 2];
        csr.cdi_id::<D, H>(&mut cdi_id)?;

        Certificate::from_current_cdi(
            current_cdi,
            &cdi_id,
            csr.info.subject.clone(),
            csr.info.public_key,
            extns,
            certificate_buf,
        )
    }

    fn from_current_cdi<N: ArrayLength<u8>, D: digest::Digest, H: hkdf::HmacImpl<D>>(
        current_cdi: &CompoundDeviceIdentifier<N, D, H>,
        serial_number_bytes: &[u8],
        subject: RdnSequence,
        subject_public_key_info: SubjectPublicKeyInfo,
        extns: Option<&'a [&'a [u8]]>,
        certificate_buf: &'a mut [u8],
    ) -> Result<&'a [u8]> {
        Self::from_raw_parts(
            current_cdi.id()?,
            serial_number_bytes,
            subject,
            subject_public_key_info,
            extns,
            current_cdi.key_pair(),
            certificate_buf,
        )
    }

    /// Build a certificate from raw parts.
    ///
    /// # Parameters
    ///
    /// @cdi_id: The CDI ID.
    /// @serial_number_bytes: Certificate Serial Number.
    /// @subject: Certificate Subject.
    /// @subject_public_key_info: Subject Pulbic Key Info.
    /// @extns: An optional slice of x.509 DER-formatted extensions slices.
    /// @signer: A `Signer` trait for signing the certificate.
    /// @certificate_buf: Buffer to hold the certificate DER.
    pub fn from_raw_parts<S: Signer<ed25519_dalek::Signature>>(
        cdi_id: [u8; CDI_ID_LEN],
        serial_number_bytes: &[u8],
        subject: RdnSequence,
        subject_public_key_info: SubjectPublicKeyInfo,
        extns: Option<&'a [&'a [u8]]>,
        signer: &S,
        certificate_buf: &'a mut [u8],
    ) -> Result<&'a [u8]> {
        let mut hex_cdi_id = [0u8; 2 * CDI_ID_LEN];
        hex::encode_to_slice(cdi_id, &mut hex_cdi_id).map_err(Error::InvalidCdiId)?;
        let serial_number = UIntRef::new(serial_number_bytes).map_err(Error::InvalidDer)?;

        // Issuer contains one ATV for one RDN: `SN=<Current CDI_ID>`
        let issuer = x509_serial_number(&hex_cdi_id)?;

        let validity = Validity {
            not_before: Time::past().map_err(Error::InvalidDer)?,
            not_after: Time::never().map_err(Error::InvalidDer)?,
        };

        // Certficate extensions
        let mut extensions = SequenceOf::<_, MAX_CERT_EXTENSIONS>::new();

        // Add the keyUsage extension.
        // The SubjecPublicKeyInfo passed through the CSR should be used for key
        // agreement or wrapping.
        let key_usage = KeyUsage::new(KeyUsageFlags::KeyEncipherment | KeyUsageFlags::KeyAgreement);
        let mut key_usage_buffer = [0u8; KEY_VALUE_EXTENSION_LEN];
        let key_usage_extension = key_usage_extension!(key_usage, key_usage_buffer);

        extensions
            .add(key_usage_extension)
            .map_err(Error::InvalidDer)?;

        // Add the basicConstraints extension.
        // We are not a CA.
        let basic_constraints = BasicConstraints {
            ca: false,
            path_len_constraint: None,
        };
        let mut basic_constraints_buffer = [0u8; BASIC_CONSTRAINTS_EXTENSION_LEN];
        let basic_constraints_extension =
            basic_constraints_extension!(basic_constraints, basic_constraints_buffer);

        extensions
            .add(basic_constraints_extension)
            .map_err(Error::InvalidDer)?;

        // Add the authorityKeyIdentifier extension.
        // We only set the keyIndentifier field to the current CDI_ID.
        let auth_key_id = AuthorityKeyIdentifier {
            key_identifier: Some(OctetStringRef::new(&hex_cdi_id).map_err(Error::InvalidDer)?),
            authority_cert_issuer: None,
            authority_cert_serial_number: None,
        };
        let mut auth_key_id_buffer = [0u8; AUTH_KEY_ID_EXTENSION_LEN];
        let auth_key_id_extension = auth_key_extension!(auth_key_id, auth_key_id_buffer);

        extensions
            .add(auth_key_id_extension)
            .map_err(Error::InvalidDer)?;

        // Add all additional extensions.
        if let Some(extns) = extns {
            for extn in extns.iter() {
                extensions
                    .add(Extension::from_der(extn).map_err(Error::InvalidDer)?)
                    .map_err(Error::InvalidDer)?;
            }
        }

        let tbs_certificate = TbsCertificate {
            version: Version::V3,
            serial_number,
            issuer,
            validity,
            signature: ed25519::pkcs8::ALGORITHM_ID,
            subject,
            subject_public_key_info,
            issuer_unique_id: None,
            subject_unique_id: None,
            extensions: Some(extensions),
        };

        // We can now sign the TBS with the current CDI private key
        // and generate the actual certificate.
        let mut tbs_bytes_buffer = [0u8; MAX_CERT_SIZE];
        let tbs_bytes = tbs_certificate
            .encode_to_slice(&mut tbs_bytes_buffer)
            .map_err(Error::InvalidDer)?;
        let signature = signer.sign(tbs_bytes).to_bytes();

        let certificate = Certificate {
            tbs_certificate,
            signature: BitStringRef::from_bytes(&signature).map_err(Error::InvalidDer)?,
            signature_algorithm: ed25519::pkcs8::ALGORITHM_ID,
        };

        certificate
            .encode_to_slice(certificate_buf)
            .map_err(Error::InvalidDer)
    }
}
