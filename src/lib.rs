// Copyright (c) 2022 by Rivos Inc.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! Pure Rust, heapless attestation crate.
#![no_std]

/// Rice errors
#[derive(Debug)]
pub enum Error {
    /// Failed to expand the extracted key
    InvalidExpansion(hkdf::InvalidLength),

    /// Invalid Key bytes
    InvalidKey(ed25519_dalek::SignatureError),

    /// Next CDI is not generated
    MissingNextCdi,
}

/// Custom DICE result.
pub type Result<T> = core::result::Result<T, Error>;

/// The DICE Compound Device Identifier (CDI) module
pub mod cdi;

/// The DICE layer module
pub mod layer;

// Key Derivation Function module
mod kdf;
