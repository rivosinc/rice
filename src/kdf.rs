// Copyright (c) 2022 by Rivos Inc.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use digest::Digest;
use hkdf::{Hkdf, HmacImpl};

use crate::{cdi::ID_SALT, Error, Result};

// Generic HKDF-based derivation function
pub(crate) fn kdf<D: Digest, H: HmacImpl<D>>(
    input_key_material: &[u8],
    salt: &[u8],
    info: &[&[u8]],
    output_key_material: &mut [u8],
) -> Result<()> {
    // First extract a pseudorandom key from the IKM.
    let kdf = Hkdf::<D, H>::new(Some(salt), input_key_material);

    // Now expand the pseudorandom key into the OKM.
    kdf.expand_multi_info(info, output_key_material)
        .map_err(Error::InvalidExpansion)
}

// Extract and expand an authority ID from a public key.
// The public key should be created from a private key bound to the CDI this ID
// relates to, e.g. a private key created with `derive_secret_key()`.
pub(crate) fn derive_cdi_id<D: Digest, H: HmacImpl<D>>(
    public_key: &[u8],
    cdi_id: &mut [u8],
) -> Result<()> {
    kdf::<D, H>(public_key, &ID_SALT, &[b"CDI_ID"], cdi_id)
}

#[cfg(test)]
mod tests {
    use crate::cdi::ID_SALT;
    use crate::kdf::kdf;

    type Hmac384 = hmac::Hmac<sha2::Sha384>;

    #[test]
    fn test_kdf_invalid_okm() {
        let ikm = [0u8; 64];
        let mut okm = [0u8; 16384];

        assert!(kdf::<sha2::Sha384, Hmac384>(&ikm, &ID_SALT, &[], &mut okm).is_err());
    }
}
