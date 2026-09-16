# Trust v11 Forward Re-anchor Design

## Status and authority

Approved by the operator on 2026-09-09 with `继续 r23`, following the explicit proposal to replace the impossible historical-provider-continuity requirement with a forward-only trust re-anchor.

Threat-model amendment approved by the operator on 2026-09-10 with `按 A 修改规格并继续 r28`: v11 uses pinned-snapshot semantics under cooperative quiescence. It does not claim an impossible user-space global atomic snapshot against non-cooperative writers.

This design amends Task 1 of `docs/superpowers/plans/2026-09-08-trust-v11-reanchor-and-p1-closure.md`. It does not weaken P0 byte conservation, provider-content confidentiality, no-clobber publication, review gates, the first-case hard gate, or the prohibition on GPU/training before the 30-case package is complete.

## Problem statement

The preserved v9/v10 evidence does not contain a complete metadata identity for `configs/providers.local.toml`:

- the v9 byte-preservation index contains no provider entry;
- the v10 snapshot/native validation records only `mode_only` evidence;
- no preserved evidence binds historical `dev`, `inode`, `uid`, `gid`, `nlink`, or `ctime_ns`;
- the earlier r22 constants were sourced from an unverified chat summary rather than a bound artifact.

Consequently, v11 cannot honestly prove continuity from a historical provider inode. Treating current pathname metadata as if it were historically authenticated would manufacture evidence and leave standalone verification vulnerable to canonical-path replacement.

## Chosen architecture: operator-authorized forward anchor

Trust v11 begins a new forward-only metadata epoch for the provider configuration.

1. The operator's explicit trust-root refresh authorization is the authority to establish a new current-state anchor.
2. Two independent metadata-only collectors observe the exact canonical provider path. Each records `dev`, `inode`, file type, mode, `uid`, `gid`, `nlink`, `size`, `mtime_ns`, `ctime_ns`, canonical path spelling, collector identity, argv, timestamp, and ancestor directory identities.
3. Neither collector may open or read provider bytes. Allowed operations are `lstat` and directory-FD `stat(..., follow_symlinks=False)` only.
4. The two observations must agree on every identity field. A disagreement, missing field, non-regular type, mode other than `0600`, unexpected link count, or path alias fails closed.
5. The resulting current identity becomes the v11 forward anchor. Historical provider identity and historical metadata delta are recorded as `UNKNOWN_UNRECOVERABLE`, not inferred.
6. All later v11 publisher/verifier transactions derive the provider deny-set from the committed forward-anchor artifact, never from the current pathname alone.

The two witnesses establish current-state consistency and reduce collection mistakes. They do not prove historical continuity or rule out a replacement that occurred before the authorized ceremony. The v11 documents must state this limitation verbatim.

## Transaction and race semantics

The provider configuration remains metadata-only throughout the transaction.

- A provider guard owns the canonical parent directory descriptor and the expected forward-anchor identity for the entire standalone publish/verify transaction.
- Before every content-bearing `os.open` or `os.read` elsewhere in the transaction, the guard re-stats the canonical provider entry and fails before the content operation if identity changed.
- The guard rechecks the provider identity and all ancestor identities at transaction close.
- The committed provider identity is always included in the pre-open deny-set so an orphaned hardlink, generation leaf, reviewer cache entry, or shadow path pointing to the provider inode is rejected before `os.open`/`os.read`.
- Fixture-only dependency injection may replace the expected anchor under `/tmp`; production code cannot accept an uncommitted or caller-supplied identity.

Deterministic `/tmp` race tests must prove that canonical-decoy replacement in standalone publish and verify causes failure and that no later content read occurs after the replacement hook fires.

### Pinned-snapshot and concurrency boundary (r28 amendment)

The authoritative object is the snapshot observed through the transaction's registered, descriptor-pinned inputs. A successful generation means that its documents are an exact commitment to those observed bytes, identities, directory memberships, metadata-only bindings, and negative-state observations. It does **not** mean that every mutable canonical pathname remained globally unchanged after the last validating syscall.

Supported concurrency model:

- All EGSİ publishers, checkers, refresh commands, first-case gates, and packaging commands are cooperative participants and must use their declared locks.
- The transaction prevents mixed reads inside its snapshot: semantic values come only from registered pinned bytes or registered metadata observations, exact inventories are committed, and each supported command checks the committed state before use.
- Mutations detected while a protected object is being observed fail closed. Provider-inode aliases remain denied before content reads, including post-open/pre-read identity checks for stat/open races.
- A non-cooperative process that replaces a canonical path after its final observation, or immediately after the verifier's last syscall, is outside the guarantee. Pure user-space code cannot exclude that race without filesystem freeze or an OS-level immutable snapshot.
- Direct mutation of module-private Python state, reuse of private helpers/seals, monkeypatching, or arbitrary code execution inside the verifier process is outside the threat model. The supported production security boundary is the CLI and documented production entrypoints; test-only public helpers must still reject the current production root.

Accordingly, r28 must not claim `live_root_globally_atomic_at_commit=true`. It records:

```json
{
  "authority_semantics": "FD_PINNED_SNAPSHOT_AS_OBSERVED",
  "concurrency_model": "COOPERATIVE_LOCKED_QUIESCENCE",
  "non_cooperative_post_observation_mutation": "OUT_OF_SCOPE_REQUIRES_OS_SNAPSHOT",
  "same_process_private_state_tampering": "OUT_OF_SCOPE"
}
```

The first-case gate performs a fresh verification immediately before the allowed provider action. A successful earlier generation is never treated as a permanent assertion that the live root is still current.

## Evidence semantics

The v11 incident/revocation documents distinguish verified facts from unavailable history:

- P0 byte inventory, counts, commitments, and the allowlisted `.egsi-batch.lock` `ctime_ns` delta remain exact requirements.
- `src/egsi/__init__.py` and `configs/canonical-test-contract.v1.json` retain exact old/current metadata deltas from preserved evidence.
- Provider history is represented as `old_identity: UNKNOWN_UNRECOVERABLE`, with the precise missing fields and evidence gap listed; the new forward anchor supplies `current_identity`.
- The v10 status is `REVOKED_BEFORE_PROVIDER_USE` when bound local generation-attempt evidence proves `provider_called:false`.
- Historical live/GPU execution state is `UNKNOWN_UNVERIFIED` unless a bound local artifact proves otherwise. Current P1-root absence is a current filesystem fact, not retroactive proof.
- Available rejected reviews and recovery audits are bound individually. Missing historical review artifacts are enumerated as unavailable; a fixed count is forbidden.

No `UNVERIFIED_CHAT_SUMMARY` value may be used as a verified input or trust anchor.

## Read-only checker

`--check` is a strict read-only operation:

- it must never use `O_CREAT`, `O_RDWR`, truncate, chmod, rename, unlink, or publish;
- it may acquire an existing lock read-only, but a missing lock is checked without creating it;
- a before/after exact tree and metadata inventory must be byte-identical and identity-identical;
- all checker semantic tests run below `TemporaryDirectory(dir="/tmp")`.

The checker compares the current observed snapshot to the committed generation and reports drift found during that supported operation. It does not promise to prevent or detect a non-cooperative mutation that occurs after the final observation. This limitation must be present in its public result semantics.

## Testing and release gates

The r23 implementation follows TDD:

1. RED tests reproduce witness disagreement, production fixture-injection rejection, canonical replacement after binding, orphan hardlink, reviewer-cache/shadow aliases, checker lock creation, and real-root test access.
2. GREEN implementation adds forward-anchor witnesses, a transaction-lifetime provider guard, strict read-only checking, and `/tmp`-only semantic fixtures.
3. The entire Task 1 suite passes with `PYTHONDONTWRITEBYTECODE=1` and `python3 -B`; no cache files remain.
4. r23 publishes to a fresh no-clobber generation, then returns `ALREADY_COMMITTED` on an identical retry.
5. Independent review must return `SPEC_APPROVED`, followed by `APPROVED(C0/I0)`. Until both pass, Tasks 2-9 remain blocked and no provider/GPU action occurs.

Race tests may inject mutations before or during a named observation and require fail-closed behavior at that boundary. A test that injects a mutation only after the last observation of an otherwise valid pinned snapshot is a limitation demonstration, not a conformance failure; it must be preserved as an expected out-of-scope result rather than used to add unbounded verification rounds.

## Rejected alternatives

### Preserve the r22 hard-coded historical identity

Rejected because no bound v9/v10 artifact proves the constants or their ctime allowlist.

### Wait for nonexistent historical evidence

Rejected because it cannot make progress and does not improve the training dataset. The evidence gap is permanent and must be disclosed rather than reconstructed.

### Remove provider identity checks entirely

Rejected because generation/reviewer aliases could expose provider bytes through ordinary evidence readers. Forward anchoring preserves the required confidentiality boundary without inventing historical continuity.
