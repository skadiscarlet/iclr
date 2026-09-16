# Round 14 — Native Python startup-code closure and fresh offline trust root

## Scope and terminal semantics

This checkpoint closes the native launcher trust gap for the complete Python startup-code closure. It is an offline preflight trust-root refresh, not a provider recovery epoch. No provider/model call, live kind-4 provider run, remaining P0/P1 case, GPU job, training, trajectory compilation, or write under `data/` was performed.

The historical `.work/real-p0-codex-v2` tree remains a byte-identical Round 12 STOP epoch. It was neither modified nor back-signed. Its terminal fact remains `STOPPED_ON_REMAINING_P0_CASE_ghsa-3wfj-vh84-732p_BEFORE_P1_GPU`.

## Root cause and correction

The first Round 14 first-case failures were caused by copying the complete 1,878-file startup manifest into a bounded report. That exceeded the unchanged 4,096-node strict-JSON traversal limit. The fix does not raise or bypass that limit: the full startup manifest remains in `configs/native-signer-build-record.json` and embedded native trust material, while runner/report contracts carry a recomputed compact `python_runtime_summary`.

`fail_fast_batch._test_receipt_evidence()` was also updated to recompute that compact projection from the full build record rather than requiring the obsolete full `python_runtime` field in the launcher contract.

## Current trust bindings

- Canonical contract: `sha256:f4302893a0c20eab075a24baf3d3f015292836090c964596a37a3272f4a80c82`; file `sha256:da69775897a0d1e6969e86fad39b0dc505b67ec507a5ed97f6fbe19b3089a5b9`.
- Focused suite: `551` nodes; `sha256:c259fb4a6598373282f68db678b5ec48f28856d45c2e90c8fe5dfecfa8f3eae3`.
- Full suite: `1048` nodes; `sha256:47cb4c99bd964cfca4413d24c83c0f3fc20fad585a58fbfc216e9c7052c04a64`.
- Runner lock schema/commitment/file: `8.0` / `sha256:14caa206bb87506b7fb33bceaa6a6a9d16d8ecc5e7f36f81d40fd1c054fba05d` / `sha256:9c744d7619da996d10783536f16bfae73ef3e26ca6f5b67173005bdfa3a34a0b`.
- Native build schema/build/record/file: `3.0` / `sha256:4bb399816b1d01ce04715ef7f50044a8070b8e65e9f36d60437101b85d074c22` / `sha256:4915c5d736a3019e1079a1bd2797d3cbe5859c34648b8a555b5adb4027db6ace` / `sha256:3b7dd8348ec4f525bd1a88cf2a3c95ff30ae11a2d9205a0a130aa3f1031b6c4f`.
- Native launcher schema/contract/binary: `8.0` / `sha256:b23cf611b8868fe0aa991b3f9e16ac4a42fc5006bd35c8c6404a22525a6438ae` / `sha256:e97057f4ddedcd23c886d6c030df0f684290cdbcf5071ae83704837e1cc91558`.
- Full runtime manifest: `sha256:b50e4896b27b3ce1f18676c02f74e4e813be6b1d605387d9e3c91feeaa2d423f`.
- Startup-code manifest: `sha256:295e61bc27612786947417d79c027a7336809b4ef2c887c6d62081a88719879a`; files/directories/absent/bytes = `1878` / `199` / `3` / `52117097`.
- Compact runtime/startup summary commitments: `sha256:1121690fc97c9761f325031be58f8139a3728c13cbe59a7952e76d5421bacf7d` / `sha256:773f931d6002310e506d5f6f1e0e8b0a0ee292555cc91188ae1015ade5213783`.

## Fresh native receipts and validation

- focused: `551` passed, `0` failed; nodeids `sha256:c259fb4a6598373282f68db678b5ec48f28856d45c2e90c8fe5dfecfa8f3eae3`; receipt `sha256:2975181f5ba3a04dba5869c029c1d3ae6959fce17795d301a032ee8c690fe66c`; RSA sidecar `sha256:3e145cb9232c47336bf24b9c5ab79599956d25a25817111caa79dcf7538905ba`; receipt commitment `sha256:35b94830f8217c626d2cef2db045f69f81fbf15464efa4a9bef84a8cc9f1fe57`.
- full: `1048` passed, `0` failed; nodeids `sha256:47cb4c99bd964cfca4413d24c83c0f3fc20fad585a58fbfc216e9c7052c04a64`; receipt `sha256:44d1e496e2d60aab015ab13ae0d037942b9840a50f4b1149c040a4225b6f877f`; RSA sidecar `sha256:164ae3159a95c5f400989d7091d76eb529dbda33b674e47852de391bb75970ac`; receipt commitment `sha256:5fbe3ca77eead4942e722d29e27e3dccf2771252c9eec6b81312c762abe3b96c`.

Fresh validation ran inside `locked_runtime_bootstrap` and called both `validate_test_receipt(..., require_success=True)` and `fail_fast_batch._test_receipt_evidence(...)`. The latter independently verifies the RSA-2048 PKCS#1 v1.5/SHA-256 sidecars, current build/lock/source bindings, and the compact runtime projection recomputed from the complete build manifest.

Runtime attack coverage binds `13` canonical focused tests. Because collection and execution counts are both 551, both order digests equal `sha256:c259fb4a6598373282f68db678b5ec48f28856d45c2e90c8fe5dfecfa8f3eae3`, and all 551 tests passed, the covered malicious-encoding, lib-dynload modification/shadowing, startup same-inode mutate/restore, stdlib file/directory ABA, kind-4/kind-5 lib-dynload ABA, and loader/libpython ABA cases all passed.

## Verification state

- External compile check: `PASS`, `72` project bytecode files, zero project-tree bytecode residue.
- Historical STOP-tree audit: `PASS`, `218` entries, snapshot `sha256:a0be8a617e465b09ed6606c042436616ea561dd215ae84488e5088077c481dc8`.
- Historical focused/full receipt hashes remain `sha256:fa6eff1d9b186d3b6584c4a5d1bfd55e08afca795efe71cece1e4cbf11141051` and `sha256:60f84546ab416fdb43185a4d4e44a7b04746930a7c3f04e70d0fa3e110eb5889`.

Persistent evidence is rooted at `.work/future-live-native-trust-v7/`. Any future recovery epoch still requires an explicit decision and a fresh output root; it must not relabel or back-sign the historical STOP epoch.
