# Kaleidoswap RGB HTLC golden vectors (vendored)

`htlc-golden-vectors.json` is a subset of the SDK/maker RGB HTLC fixtures. It is
read by the service-free tests in the `sdk_golden_vectors` module of
`src/wallet/test/htlc_swap_tree.rs`. These tests tie rgb-lib's swap tree,
MuSig2 key order and recipient-id encoder to the trees and recipient ids the
maker actually returns.

Source:

- repository: `kaleidoswap/kaleidoswap-sdk`, branch `trunk`
- files: `tests/fixtures/rgb-v1/wire-contract.json` and
  `tests/fixtures/rgb-v1/rgb-golden-vectors.json`
- last commit touching both files:
  `3b034ac7fefe7a3388ba5fefb1d52fe33b1dce0a` (2026-10-06)
- `trunk` head when fetched: `660779a3c1ec9f0bb7c32c9d9cdb276b7cbaff86`
- fetched: 2026-10-14

The upstream git blob ids and SHA-256 hashes are recorded under `_source` in the
JSON. The captured values come from maker revision
`49c6ce2e9554eea0d819fd3bbd267af6db45b1c0` using rgb-lib revision
`96f039d975cf2a83712c3c0a90e703621d445425`, as recorded under `provenance`.

What was kept:

- `provenance`: copied unchanged. It is identical in both upstream files.
- `wireContract`: from `wire-contract.json`. Contains the preimage, the swap
  keys (`claimPublicKey` and `refundPublicKey`, from the request or response,
  depending on which side supplies each key), `swapTree`, `timeoutBlockHeight`,
  the lockup address, and `rgb.{recipientId,scriptPubkey}` from both create
  responses. The JSON paths match upstream.
- `goldenVectors.recipients`: all 12 recipient vectors from
  `rgb-golden-vectors.json`, unchanged. That is both HTLC scripts on all six RGB
  networks.

What was dropped, because rgb-lib has no counterpart for it: pair responses,
invoices, swap ids and auth tokens, blinding values, amounts, the reference
taker claim PSBT and the fee model. The claim PSBT and fee model are built by
the maker and the SDK. rgb-lib only colors and signs an HTLC spend.

Do not edit values by hand. To update, re-fetch both upstream files at a newer
commit, regenerate the subset with the same paths, and update `_source` and
this README.
