# SPDX-FileCopyrightText: 2023 Rivos Inc.
#
# SPDX-License-Identifier: Apache-2.0

load("@rules_rust//crate_universe:defs.bzl", "crate", "crates_repository")

# on changes to crate dependencies, run the following command from the
# salus build directory:
# scripts/repin.sh

def rice_dependencies():
    crates_repository(
        name = "rice-index",
        isolated = False,
        cargo_lockfile = "@salus//rice/bazel-locks:Rice.Cargo.Bazel.lock",
        lockfile = "@salus//rice/bazel-locks:rice-cargo-bazel-lock.json",
        packages = {
            "arrayvec": crate.spec(
                version = "0.7.6",
                default_features = False,
            ),
            "const-oid": crate.spec(
                version = "0.9.1",
                features = ["db"],
            ),
            "der": crate.spec(
                version = "0.7.9",
                features = ["derive", "flagset", "oid"],
            ),
            "digest": crate.spec(
                version = "0.10.7",
                default_features = False,
            ),
            "ed25519": crate.spec(
                version = "2.2.3",
                default_features = False,
                features = ["pkcs8"],
            ),
            "ed25519-dalek": crate.spec(
                version = "2.1.1",
                default_features = False,
            ),
            "flagset": crate.spec(
                version = "0.4.6",
            ),
            "generic-array": crate.spec(version = "0.14.7"),
            "hex": crate.spec(
                version = "0.4.3",
                default_features = False,
            ),
            "hkdf": crate.spec(version = "0.12.4"),
            "hmac": crate.spec(version = "0.12.1"),
            "sha2": crate.spec(version = "0.10.8", default_features = False),
            "signature": crate.spec(version = "2.2.0", default_features = False),
            "spin": crate.spec(
                version = "0.10.0",
                default_features = False,
                features = ["rwlock"],
            ),
            "spki": crate.spec(version = "0.7.3"),
            "zeroize": crate.spec(version = "1.8.1"),
        },
    )
