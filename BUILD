package(default_visibility = ["//visibility:public"])

load("@rules_rust//rust:defs.bzl", "rust_clippy", "rust_library", "rust_test", "rustfmt_test")

rust_library(
    name = "rice",
    srcs = glob(["src/**/*.rs"]),
    deps = [
        "@rice-index//:arrayvec",
        "@rice-index//:const-oid",
        "@rice-index//:der",
        "@rice-index//:digest",
        "@rice-index//:ed25519",
        "@rice-index//:ed25519-dalek",
        "@rice-index//:flagset",
        "@rice-index//:generic-array",
        "@rice-index//:hex",
        "@rice-index//:hkdf",
        "@rice-index//:hmac",
        "@rice-index//:sha2",
        "@rice-index//:spin",
        "@rice-index//:spki",
        "@rice-index//:zeroize",
    ],
)

rust_clippy(
    name = "clippy",
    deps = ["rice"],
)

rustfmt_test(
    name = "rustfmt",
    targets = ["rice"],
)

rust_test(
    name = "rice-test",
    testonly = True,
    crate = ":rice",
)
