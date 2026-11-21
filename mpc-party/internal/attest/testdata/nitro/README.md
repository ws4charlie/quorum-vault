# Real AWS Nitro attestation documents (test data)

Two files, base64 of the CBOR bytes, both public:

| File | What | Source |
|---|---|---|
| `aws-real-document-2022.b64` | A document a real enclave produced (module `i-04fd167167daacf3b-enc01845e97d0b3eb4e`, eu-west-1, 2022-11-09; PCR0 `22f9e1c9...`). It carries `user_data` (32 bytes) and no nonce or public key. | `test/aws_nitro_document.cbor` in https://github.com/veracruz-project/go-nitro-enclave-attestation-document |
| `aws-real-document-2022-badsig.b64` | The same document with a damaged signature. | `test/aws_nitro_document_bad_sig.cbor`, same repository |

Licence: the repository states the MIT licence for its code and tests (`LICENSE_MIT.md`, header of `lib.go`); the files are used here as test
vectors with that attribution (Copyright 2022 Veracruz, a series of LF Projects, LLC). The documents hold only public certificates, PCR hashes
and the enclave's own identifiers: no secret. Read 2026-11-20.

Other open-source samples exist (Anchorage `awsnitroverifier` testdata, Apache-2.0, which redistributes this same document and two Turnkey
documents). The Turnkey ones are not used: their licence is not stated by their origin.

The certificates in a real document are valid for a few hours, so tests verify them at the document's own time (2022-11-09 22:52 UTC), never at the
current time. `TestRealDocument*` in `nitro_real_test.go`.
