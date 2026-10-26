---
title: Kubescape fork upgrade to v0.57.0
description: Fork preservation and downstream migration requirements
---

# Kubescape fork upgrade to v0.57.0

This merge integrates upstream commit
`29d60de9f7924607784915533dd5f3cc0052ee1a` into the Kubescape fork. The
node-agent dependency and bundled gadget images must be upgraded together in a
subsequent change.

## Build and dependency baseline

The module requires Go 1.26. CI and the builder use Go 1.26.6, with
golangci-lint 2.12.2. Gadget builds use the upstream Go build pipeline and this
release builder:

```text
ghcr.io/inspektor-gadget/gadget-builder@sha256:1586c58ae4731fb8fb12546c031a352db34c0ce334709b9b54e6c648edae76ad
```

The fork retains its AWS ECS dependencies. Docker integration uses the upstream
split Moby API and client modules. The overlayfs helper uses the same kernel
version helper as upstream instead of retaining the monolithic Moby module.
Container-hook and file-field embedded eBPF objects are regenerated for amd64
and arm64.

Go module replacements do not propagate to consumers. Downstream modules must
carry the fork's replacements for `github.com/notaryproject/notation-go` and
`go.opentelemetry.io/ebpf-profiler` from this repository's `go.mod`.

## Preserved fork behavior

- Uprobe reattachment after exec, bounded symbol caches, streaming symbol
  lookup, resolver interfaces, mapped-library discovery, retries, cancellation,
  and startup budgets. The upstream stripped-Go-symbol fallback also works with
  the fork's ordinary-symbol cache; Go return probes retain their restrictions.
- Context-aware container file opening, including deadlines and file ownership.
- ECS enrichment, non-Kubernetes namespace filtering, pause-container handling,
  and manual map-fetch triggers.
- Bounded datasource buffers and overlayfs inode identity corrections.

Initialization failure now stops readers, map iterators, and retry workers
before releasing their maps. Shutdown tolerates a prior `PreStop` or `Stop`.
The public `ReleaseOrasTarget` method remains available. The gadget context
releases its OCI store reference after all data operators initialize, before
attachment and execution; it does not close a caller-owned read-only store.

## Exec event contract

`args` preserves the actual argument vector, including a spoofed `argv[0]`.
Successful execution reads the committed arguments from the new process address
space, including the interpreter and script arguments installed by the kernel.
Do not replace the first argument with an executable path.

For successful execs, the capture bound is 5,120 bytes including NUL separators.
It is a byte bound rather than a limit of 20 arguments. `args_count` is an upper
bound for decoding, not an exact argument count. The WASM formatter emits only
NUL-terminated captured arguments, omitting a final incomplete argument. Failed
execs use the caller's argument vector and retain their separate bounded read
path. `ignore-failed` defaults to true.

The path and identity fields have distinct meanings:

| Field | Meaning |
| --- | --- |
| `args[0]` | Caller-supplied command name, or the committed interpreter argument for a successful script exec |
| `file` | Resolved file initially executed; the script for a shebang exec, with `paths` enabled |
| `exepath` | Executable mapped into the process; the interpreter for a successful script exec, with `paths` enabled |
| `dev_major`, `dev_minor`, `inode` | Identity of `file`, with `paths` enabled |
| `ctime`, `fctime`, `pctime` | Inode change timestamps in nanoseconds for the executable, initially executed file, and parent executable, respectively |
| `tty_major`, `tty_minor` | Controlling terminal device number; `0:0` means no controlling terminal |

The legacy `tty` index is ambiguous: `/dev/pts/0` also has index zero. Use the
device number to distinguish it from a process without a controlling terminal.
Executable and parent timestamps are initialized for successful execution;
failed execs require interpreting the available fields together with `error`.
The gadget does not expose the originally requested pathname as a separate
`requestedpath` field.

## Node-agent integration requirements

Update the fork revision only after the merge commit is available. Reconcile
the consumer module graph, including removal of obsolete monolithic Moby
requirements. A preliminary compile with this fork also requires aligning
`k8s.io/kubectl` with the v0.37 Kubernetes dependencies.

Rebuild the custom `trace_open` image and the full bundled gadget archive using
the new runtime and pinned builder. Update exec decoding, security rules, and
process-tree consumers to respect the argument and path distinctions above.
An old bundled image can compile while exposing fields incompatible with the
consumer; compilation alone does not validate that integration.

Run native kernel tests on both amd64 and arm64, including the supported kernel
matrix. The fork workflow includes glibc/musl cold-page, warm-page, invalid
pointer, script, argument-bound, isolated devpts, and bundled-image load/unload
regressions. Cross-compilation and root-only skips do not substitute for those
native checks.
