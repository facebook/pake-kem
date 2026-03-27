# Changelog

## 0.1.0-pre.6 (March 26, 2026)

* Upgrade `ml-kem` to v0.3.0-rc.0
* Upgrade `rand_core` to v0.10, `curve25519-dalek` to v5.0.0-pre.6, `hkdf` to v0.13.0-rc.5, `sha2` to v0.11.0-pre.4
* Replace `OsRng` with `UnwrapErr(getrandom::SysRng)` for `rand_core` 0.10 compatibility
* Make `EncodedSizeUser::from_bytes` fallible (returns `Result<Self, PakeKemError>`)
* Remove dummy-key fallback on deserialization failure in `MessageTwo` and `Responder`
* Define local `EncodedSizeUser` trait (no longer re-exported from `ml-kem`)
* Fix pre-existing clippy `doc_markdown` warning

## 0.1.0-pre.1 (October 10, 2024)

* Initial release
