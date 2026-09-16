# Native Python Runtime Closure Pinning Design

## Objective

Close the native launcher's pre-Python trust gap. Every Python child must run
the build-recorded interpreter through the build-recorded dynamic loader and
the recursively resolved `DT_NEEDED` closure, using inherited held file
descriptors rather than mutable runtime path lookups.

## Build contract

`scripts/build_native_rsa_material.py` reads the fixed runner interpreter with
`O_NOFOLLOW`, rejects non-regular files, hardlinks, group/other-writable modes,
unstable metadata, oversize files, and unsupported ELF formats, then hashes the
stable bytes. A bounded stdlib-only ELF64 parser extracts `PT_INTERP`,
`DT_NEEDED`, and `DT_RUNPATH`/`DT_RPATH`. Dependency resolution is recursive,
deterministic, rejects missing or ambiguous libraries, repeated names,
dependency cycles, special files, final-component symlinks, hardlinks,
group/other-writable files, `$ORIGIN` escapes, excessive depth/count/bytes,
and non-canonical results.

The resulting `python_runtime` value records:

- invocation strategy (`glibc-loader-fd-preload-v1`);
- interpreter path, ELF contract, SHA-256, mode, size, device, inode, and full
  stable identity;
- exact canonical loader entry;
- recursively ordered runtime files with role, SONAME/needed name, parent,
  SHA-256, mode, size, device, inode, and stable identity;
- a canonical closure commitment.

The closure is committed into the native build ID and binary contract, emitted
in generated private/public headers, copied into public material and the native
build record, exposed by every launcher's public contract, and checked by the
offline runner's native-launcher contract.

## Native execution

The static launcher opens every runtime entry once with `O_NOFOLLOW`, verifies
the compiled identity and bytes, and keeps the descriptors for the launcher's
entire operation. It captures a directory chain for each unique runtime parent.
Project-owned chains use exact metadata anchors. System shared ancestors use
identity plus safe-owner/non-writable permissions, avoiding unrelated ctime
noise above the dependency's direct trusted parent.

Each child is executed as:

```text
/proc/self/fd/<loader-fd>
  --argv0 <canonical-interpreter-path>
  --preload /proc/self/fd/<dependency-fd>:...
  /proc/self/fd/<interpreter-fd>
  -I -B -S /proc/self/fd/<bootstrap-fd> ...
```

This prevents the kernel or glibc loader from selecting replacement pathname
bytes. The locked environment is an allowlist and contains no inherited
`LD_PRELOAD`, `LD_LIBRARY_PATH`, `PYTHONHOME`, `PYTHONPATH`, or related startup
injection variables.

Before and after every Python child, the launcher verifies held bytes and
identity, pathname bytes and identity, descriptor paths, and directory chains.
Kind 4 repeats the check after semantic verification and immediately before
and after RSA sidecar publication. Kind 5 repeats it before returning success.
Any mismatch is fail-closed; kind 4 removes candidate/sidecar/transient files.

## Bootstrap ordering and rollback

The offline runner bootstrap becomes a transaction:

1. build and swap the new runner;
2. move current launchers/build record into an inode-preserving backup;
3. rebuild native launchers against the new interpreter closure;
4. build the final runner lock against those launchers;
5. run the locked probe;
6. commit by removing backups.

On any failure it removes partial native outputs, restores the old launchers
and build record, and restores the old runner.

## Verification

Tests cover unsafe build inputs, closure schema and commitments, interpreter
and dependency replacement before start, same-inode mutation, file and parent
ABA, ancestor swaps, kind-4 cleanup, kind-5 rejection, and the historical
malicious-shebang forgery. Focused native tests run first, followed by the
broader generation suites and the production rebuild/replay chain without any
provider, GPU, training, or data-generation action.

