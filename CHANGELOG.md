# Changelog

All notable changes to this project will be documented in this file.

This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## \[[0.2.0](https://github.com/holochain/hc-auth-server/compare/v0.1.7...v0.2.0)\] - 2026-10-28

### Features

- Add POST /api/confirm-email, a rate-limited yes/no email check by @zippy
  - Gated by CONFIRM_TOKENS so the caller never holds an admin token. True only when the key is authorized and data.verified.email matches after trim and ASCII lower-casing; the caller-supplied payload is never read and the stored email is never returned. Per-token and per-key limits reply 429. Unknown keys are false, not 404.
- Add the rate-limit primitives, Storage::count_in_window and sha256_hex by @zippy
  - Count_in_window is one Lua step (INCR, then EXPIRE on the first hit in a window), so it is atomic and does not need EXPIRE NX from Redis 7. sha256_hex will key the per-token counter without storing the token.
- Add CONFIRM_RATE_PER_TOKEN and CONFIRM_RATE_PER_KEY by @zippy
  - Per-minute limits for /api/confirm-email, defaults 600 and 30. Nothing enforces them yet.
- Add PUT /api/verified/{key}, the only route that writes verified claims by @zippy
  - Admin-only, gated by API_TOKENS like the rest of /api. The body must be a JSON object; it replaces data.verified atomically in any state. The payload written by the public PUT /request-auth is never trusted.
- Add Storage::set_verified, an atomic write of a record's verified object by @zippy
  - Verified lives in its own hash field beside json. Only the admin API writes it, while authenticate_key rewrites json on every login outside a script, so keeping the two apart means a login can never lose a verified write and the caller-supplied payload is never re-encoded. Readers merge the two with record_data, which also drops any verified key found inside json. The Lua script works in any state.
- Add CONFIRM_TOKENS, a token list scoped to /api/confirm-email by @zippy
  - Parsed the same way as API_TOKENS. Nothing reads it yet.

### Bug Fixes

- Distinguish cookie purpose inside body to prevent a cookie from unauthenticated oauth from being used for authenticated user actions by @mattyg in [#38](https://github.com/holochain/hc-auth-server/pull/38)
- Compare API tokens in constant time, against any token set by @zippy
  - Check_token takes the set to compare against so a second token list can reuse it. Behavior for API_TOKENS is unchanged apart from timing.
- \[**BREAKING**\] Verify the challenge signature over a prefixed payload by @zippy
  - `/authenticate` now verifies the signature over `hc-auth-challenge-v1:` followed by the decoded `/now` payload, so the signature is valid for this purpose only. A signature over the bare payload is refused, so clients must sign the prefixed form.

### Miscellaneous Tasks

- Update the AI_POLICY.md with shared content in [#35](https://github.com/holochain/hc-auth-server/pull/35)

### Refactor

- Move the challenge prefix to an hc-auth-types crate by @zippy in [#34](https://github.com/holochain/hc-auth-server/pull/34)
  - A client can now depend on hc-auth-types, which has no dependencies, and does not need its own copy of the prefix.
  - Challenge_signing_bytes takes a 32 byte array, so the type refuses a challenge of any other length.

### Documentation

- Split a CHANGELOG line in two by @zippy
- Exercise PUT /api/verified and POST /api/confirm-email in the example client by @zippy in [#36](https://github.com/holochain/hc-auth-server/pull/36)
  - It now takes an API token and a confirm token, writes a verified email, and prints the confirm answer for a matching and a wrong address: true, then false.

### Automated Changes

- *(deps)* Bump the cargo-minor-patch group with 4 updates by @dependabot[bot] in [#33](https://github.com/holochain/hc-auth-server/pull/33)
- *(deps)* Bump the cargo-minor-patch group across 1 directory with 4 updates by @dependabot[bot] in [#32](https://github.com/holochain/hc-auth-server/pull/32)
- Update dependabot.yml with shared content in [#31](https://github.com/holochain/hc-auth-server/pull/31)
- *(deps)* Bump rust-toolchain from 1.98.0 to 1.98.1 by @dependabot[bot] in [#28](https://github.com/holochain/hc-auth-server/pull/28)
- *(deps)* Bump the updates group with 2 updates by @dependabot[bot] in [#29](https://github.com/holochain/hc-auth-server/pull/29)

### Other Changes

- Undo the hand edit to the generated CHANGELOG by @zippy in [#41](https://github.com/holochain/hc-auth-server/pull/41)
  - This reverts commit 03a4109.
- Verify the challenge signature over a prefixed payload by @zippy
  - This reverts commit 536df91. Upstream clients do not sign the prefixed challenge yet, so /authenticate goes back to the bare payload.
- Move the challenge prefix to an hc-auth-types crate by @zippy
  - This reverts commit dfd4045. Upstream clients do not sign the prefixed challenge yet.

### First-time Contributors

- @zippy made their first contribution in [#41](https://github.com/holochain/hc-auth-server/pull/41)
- @mattyg made their first contribution in [#38](https://github.com/holochain/hc-auth-server/pull/38)

## \[Unreleased\]

### Features

- Add `PUT /api/verified/{key}`, an admin route that replaces a record's `verified` object in any state, and `CONFIRM_TOKENS`, a token list scoped to `/api/confirm-email`
- Add `POST /api/confirm-email`, a rate-limited yes/no check that an authorized key's `verified.email` matches, gated by `CONFIRM_TOKENS`; limits are `CONFIRM_RATE_PER_TOKEN` and `CONFIRM_RATE_PER_KEY`
- API tokens are compared in constant time

## \[[0.1.6](https://github.com/holochain/hc-auth-server/compare/v0.1.5...v0.1.6)\] - 2026-08-04

### Bug Fixes

- Update `axum-server` API usage after version bump by @ThetaSinner in [#15](https://github.com/holochain/hc-auth-server/pull/15)
- Update `rand` API usage after version bump by @ThetaSinner in [#14](https://github.com/holochain/hc-auth-server/pull/14)

### Miscellaneous Tasks

- Update the CONTRIBUTING.md with shared content in [#8](https://github.com/holochain/hc-auth-server/pull/8)

### CI

- Add release integration workflows by @ThetaSinner

### Automated Changes

- *(deps)* Bump axum-server from 0.7.3 to 0.8.0 by @dependabot[bot]
- *(deps)* Bump rand from 0.9.2 to 0.10.2 by @dependabot[bot]
- *(deps)* Bump ed25519-dalek from 2.2.0 to 3.0.0 by @dependabot[bot] in [#17](https://github.com/holochain/hc-auth-server/pull/17)
- *(deps)* Bump base64 from 0.22.1 to 0.23.0 by @dependabot[bot] in [#16](https://github.com/holochain/hc-auth-server/pull/16)
- *(deps)* Bump the cargo-minor-patch group across 1 directory with 9 updates by @dependabot[bot] in [#13](https://github.com/holochain/hc-auth-server/pull/13)
- *(deps)* Bump the updates group across 1 directory with 4 updates by @dependabot[bot] in [#12](https://github.com/holochain/hc-auth-server/pull/12)
- *(deps)* Bump rust-toolchain from 1.93.1 to 1.97.1 by @dependabot[bot] in [#11](https://github.com/holochain/hc-auth-server/pull/11)
- Update dependabot.yml with shared content in [#10](https://github.com/holochain/hc-auth-server/pull/10)
- Update CODEOWNERS with shared content in [#9](https://github.com/holochain/hc-auth-server/pull/9)

### First-time Contributors

- @dependabot[bot] made their first contribution
- @ made their first contribution in [#10](https://github.com/holochain/hc-auth-server/pull/10)

<!-- generated by git-cliff -->
