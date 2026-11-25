# Android key attestation samples

A real attestation certificate chain for an EC key in a TEE,
from Google's reference verifier,
[google/android-key-attestation](https://github.com/google/android-key-attestation)
(`src/test/resources/der/algorithm_EC_SecurityLevel_TEE`), licensed under the
Apache License 2.0. The chain runs leaf first (`cert0.der`) to Google's
RSA attestation root (`cert3.der`).
