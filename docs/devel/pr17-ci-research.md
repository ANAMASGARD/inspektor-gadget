# PR #17 CI investigation and repair

The failures below were investigated at PR head
`003819050d26773d649fc7de99542188efa342b8`. This is the fork prerequisite for
[node-agent #1050](https://github.com/kubescape/node-agent/issues/1050), not the
downstream node-agent integration. The upstream merge and original authorship
are preserved.

## Findings and changes

| Check | Evidence and repair |
| --- | --- |
| ARM64 fork tests | The [maintainer's requested change](https://github.com/kubescape/inspektor-gadget/pull/17#discussion_r4385779833) identifies three stale fixtures. Both `accept` expectations are now 202, and an unknown name expects `(0, false)`. Production syscall tables are unchanged and native ARM64 coverage is retained. |
| Benchmarks | The [original job](https://github.com/kubescape/inspektor-gadget/actions/runs/40375996962/job/121759100985) exhausted disk space during compilation but succeeded because `tee` masked the error. Explicit Bash enables `pipefail`; running the same package list sequentially with `-p 2` bounds temporary build storage. Disk diagnostics make future capacity failures visible. |
| Benchmark and DNS helper images | [Benchmark](https://github.com/kubescape/inspektor-gadget/actions/runs/40375996962/job/121759149077) and [DNS](https://github.com/kubescape/inspektor-gadget/actions/runs/40375996962/job/121759149228) builds succeeded, then Trivy rejected Go 1.26.6 and `golang.org/x/net` 0.59.0. Builders use Go 1.26.10; the module graphs use x/net 0.60.0. |
| Gadget-builder image | The [scan](https://github.com/kubescape/inspektor-gadget/actions/runs/40375996962/job/121759149212) reported the same Go vulnerabilities in installed tools, with no qualifying Debian findings. Its source toolchain is updated to Go 1.26.10. |
| Gadget image | The [scan](https://github.com/kubescape/inspektor-gadget/actions/runs/40375996962/job/121773715865) found the same Go and x/net versions in the manager and hook binaries. Updating the root graph and Docker builder addresses these inputs. |
| GPU bridge image | The [scan](https://github.com/kubescape/inspektor-gadget/actions/runs/40375996962/job/121760340183) also found vulnerable OpenSSL. The existing distroless runtime is retained and overlaid with Debian's complete, checksum-verified `libssl3=3.0.22-1~deb12u2` package, including modules, licenses, and package metadata. |

[Go 1.26.10](https://go.dev/doc/devel/release#go1.26.10) covers the reported Go
security fixes. The official records are
[GO-2026-6809](https://vuln.go.dev/ID/GO-2026-6809.json),
[GO-2026-6607](https://vuln.go.dev/ID/GO-2026-6607.json),
[GO-2026-6609](https://vuln.go.dev/ID/GO-2026-6609.json), and
[GO-2026-6611](https://vuln.go.dev/ID/GO-2026-6611.json).
[x/net 0.60.0](https://proxy.golang.org/golang.org/x/net/@v/v0.60.0.mod) retains
the Go 1.26.0 minimum. The six affected module graphs are the root, examples,
benchmark tool, DNS tool, test-report tool, and trace-DNS WASM module. Fork
dependency replacements are retained.

The patched OpenSSL version is recorded by
[Debian's advisory](https://security-tracker.debian.org/tracker/CVE-2026-84782)
and authenticated bookworm-security package metadata. Merely refreshing the
distroless `latest` tag did not fix it: the inspected image still contained
`3.0.20-1~deb12u2`. Retaining OpenSSL also avoids changing the dependency set
available to host-provided NVML libraries.

## Explicit architecture scans

[Trivy 0.70's OCI reader](https://github.com/aquasecurity/trivy/blob/v0.70.0/pkg/fanal/image/oci.go)
selects the first descriptor when given an unqualified local OCI layout;
setting a platform variable does not select ARM64 for this archive path.
The helper scan preparation verifies manifest/config digests, requires exactly
one matching Linux image for each architecture, and exposes those descriptors
at the scan index root without changing content blobs. The two scans then use
explicit digest-qualified inputs. The ARM64 scan still runs if AMD64 scanning
fails. Gadget-image scanning also covers both existing architecture archives;
GPU remains AMD64-only. Eleven fixture controls cover nested indexes,
attestations, missing/duplicate platforms, config mismatches, corrupt blobs,
and unsafe digest inputs; all passed, as did workflow lint.

## Builder artifact verification

Once the repaired helper scans passed, later jobs exposed two additional
failures in [run 40470229460](https://github.com/kubescape/inspektor-gadget/actions/runs/40470229460).
The eBPF object check stopped on three formatting differences in the native
exec C fixture; these now match the builder's formatter without changing C
tokens. The ARM64 CLI job stopped before building because Ubuntu 26.04 exposes
[`qemu-user-static` as a virtual package with two providers](https://packages.ubuntu.com/resolute/qemu-user-static).
It now uses the same pinned Docker QEMU setup action already used by the other
cross-architecture jobs, restricted to ARM64. This preserves emulated build
support without relying on an ambiguous distro package name.

The next complete run exposed Ubuntu 26.04 runner differences after those
jobs became reachable. Its sudo-rs ignores `sudo -E`; the gadget unit and
kernel-matrix jobs therefore lost the prepared registry, tag and signature
settings and fetched unrelated upstream `latest` images. The unit-test
Makefile invocations now preserve those named settings explicitly. Four real
Makefile dispatch controls failed before this change and passed afterward,
with eight additional `SUDO` override controls passing.

The later integration jobs exposed the same sudo boundary: their green
results contained 37 skipped gadget tests each because `IG_PATH` was missing.
Both integration recipes now preserve the named CLI/runtime/image/signature
inputs and export the default `IG_RUNTIME` explicitly. Six negative controls
reproduced the missing-input skips; 36 positive dispatch/override controls
passed, including real GNU sudo and multiline key/flag values. Hosted workload
execution must still confirm these tests actually run.

The host's missing container-hook, exec/open and WASM events now have a
primary-source explanation: the affected runner image uses Azure kernel
7.0.0-1017 with the syscall-enter tracepoint regression confirmed in
[runner-images #15003](https://github.com/actions/runner-images/issues/15003).
Identical signed gadgets and userspace pass the exec/open tests under all seven
VM kernels, while the ordinary host drops events. The successful Ubuntu 24.04
unit run used the older 6.17 image; newer 24.04 images also carry the bad kernel.
Following [upstream's merged workaround](https://github.com/inspektor-gadget/inspektor-gadget/pull/5891),
the main workflow and both native runners use Ubuntu 22.04 temporarily. The
supported native `ubuntu-22.04-arm` image uses kernel 6.8. All seven guest-kernel
versions and all tests remain enabled. Revisit this pin when the runner kernel
is fixed; Ubuntu 22.04 runner retirement is scheduled for April 2027.

The broader suite also exposed an inherited fork panic in kernel-stack
formatting: fork commit `3c163e75e` disabled `NewKAllSyms` initialization while
retaining a method bound to the nil resolver. The repair loads one shared,
concurrency-safe symbol snapshot per formatter instance only after a nonempty
stack is fetched. Disabled, empty and missing stacks retain the fork's avoidance
of that work. Initialization failures are cached and handled through the
existing formatter error path; no global cache or extra file lifetime is added.
A native test reproduced the old panic and passed after repair. The full
affected-package race suite passed 75 tests/subtests with two skips; the new
native case passed separately as root. Tests cover concurrent initialization,
instance isolation, unused stacks, and cached initialization failures.

The preserved CI regeneration artifact identified the four object differences
as BTF forward-declaration ordering only. Every instruction, relocation,
`.BTF.ext` record, other ELF section, and generated Go binding is identical.
Complete BTF comparison also matches after remapping only forward-declaration
IDs; all names, layouts, references, and non-forward type IDs are unchanged.
[LLVM 18's BTF emitter](https://github.com/llvm/llvm-project/blob/llvmorg-18.1.8/llvm/lib/Target/BPF/BTFDebug.cpp)
assigns these IDs while iterating a pointer-keyed fixup map, explaining why
identical source/header/compiler controls can differ across allocation
environments. The four files now use the digest-verified bytes from the
original pinned builder in CI. The strict regeneration check remains enabled,
and failed artifacts remain available for future diagnosis.
The adopted objects passed native AMD64 inode-identity checks and three
notifier load/close cycles, including exec-event collection, with no descriptor
growth. Thirty focused package race tests also passed without skips.
[Strict hosted regeneration](https://github.com/kubescape/inspektor-gadget/actions/runs/40475221222/job/122093417445)
subsequently reproduced both architectures byte-for-byte at `db99105088`;
both native architecture workflows passed on that head too.

Ubuntu 26.04's uutils `echo` also rejects some spoofed argv and empty-path
execveat invocations. The exec regression suite now compiles a no-op target
with the selected libc, preserving all argument/path, cold-page, EFAULT and
execveat cases without depending on distro utility dispatch. Offline-bundle
setup acquires the configured image before export, then retains the three
read-only-store load/unload cycles. The complete updated native AMD64 exec
suite passed 54 tests/subtests with no skips, including 780 traced glibc/musl
attempts; all 26 direct fixture modes, strict C compilation and vet passed.

The helper workflow scans a freshly built image but uses its default published
builder when helper publication is disabled. Updating the Dockerfile alone
therefore does not update downstream gadget builds.

Candidate `ghcr.io/inspektor-gadget/gadget-builder@sha256:2f38528a06842570eaa56f8a745f4630701c2f1ca0fee88ed33a1904771c5c1f`
was inspected for both architectures. The OCI index, manifests, configurations,
and downloaded header layers passed digest verification. Of the 20 actual
bundled gadget headers, 19 match v0.57.0 byte-for-byte, including both architecture
`vmlinux.h` files. Only `gadget/kernel_stack_map.h` has the reviewed additive
include, unused sentinel, and comments; its existing function is unchanged.
Both architectures' actual libbpf headers match and declare version 1.3.

Both platforms' build provenance records Go 1.26.10, LLVM 18, Rust 1.87.0,
libbpf 1.3.0, and bpftool 7.3.0. However, both full image pulls reached their
300-second limits, so the final filesystem, executable versions, and builds
with this candidate remain unverified. The existing published builder defaults
are therefore retained. The source Dockerfile's Go update applies to newly
built helpers; it does not claim that downstream default builder replacement
is complete. Workspace headers remain the input to in-tree regeneration.

## External requirements

- **DCO:** the [check](https://github.com/kubescape/inspektor-gadget/pull/17/checks?check_run_id=121759136244)
  cannot evaluate the complete commit set. Independent GraphQL pagination
  returned 100, 100, and 50 commits despite `totalCount: 994`, with no next page.
  The integration merge has the correct author-matching sign-off. A local
  trailer audit also identified two imported human-authored non-merge commits,
  `2241184f2179af5f926370c30cf92a30e4020024` and
  `fee0b62beed74738d26253f9266067f80b1a289e`, without trailers. This audit is not
  a replacement for the [DCO app's policy evaluation](https://github.com/dcoapp/app).
  Complete evaluation and any historical remediation require maintainer/app
  operator handling; no third-party sign-offs are fabricated.
- **Dependency review:** the [job](https://github.com/kubescape/inspektor-gadget/actions/runs/40375996962/job/121759100247)
  fails before evaluating dependencies. A repository administrator must
  [enable Dependency Graph](https://docs.github.com/en/code-security/how-tos/secure-your-supply-chain/secure-your-dependencies/enable-dependency-graph)
  and rerun the check after graph population. The workflow remains enabled.
- **CodeQL:** the [open TLS finding](https://github.com/kubescape/inspektor-gadget/security/code-scanning/1)
  concerns upstream's kubelet connection. The maintainer reviewed it, and the
  [upstream discussion](https://github.com/inspektor-gadget/inspektor-gadget/pull/5343#issuecomment-5128360990)
  records the trust tradeoff. This repair preserves that behavior and leaves
  formal security disposition to maintainers. It does not suppress or dismiss
  the alert, or restore the broader `nodes/proxy` permission.

## Validation

Local validation used Go `1.26.10-X:nodwarf5` on Linux AMD64, read-only module
flags, bounded Go parallelism, and disk-backed temporary storage. A short
`TMPDIR` alias is required for Unix socket tests: the longer evidence-directory
path exceeded the kernel pathname limit; the affected test passed with the
short path without a source change.

- All six module graphs passed `go mod verify` and `go mod tidy -diff`.
- The CLI, all six examples, benchmark/DNS/report tools, and trace-DNS WASI
  reactor built successfully. Embedded tool metadata confirms x/net 0.60.0.
- The production packages cross-built successfully for ARM64. This is not
  native ARM64 or kernel execution evidence.
- Unit results across the corrected temporary-path rerun and the completed
  signature-puller run cover all 159 test-bearing packages: 1,768 passing
  tests/subtests and 145 skips. The original full invocation failed only on
  the long Unix socket fixture path; it is not described as a successful run.
- The nine-package fork race suite passed: 457 test/subtest passes, 17 skips,
  and no failures. The AMD64 syscall test suite passed; ARM64 fixtures require
  the native hosted job.
- Workflow lint, targeted Go lint, formatting, and diff whitespace checks passed.
  Controlled runs of the exact benchmark script returned 0 for success and
  propagated package-list, first-package, and later-package failures (23, 41,
  and 42), without continuing to later packages.
- The complete benchmark step passed all 259 package invocations and emitted
  18 result rows covering all 11 existing benchmark families. This local run
  used a warmed cache; hosted cold-cache capacity still requires CI evidence.
- Initial native AMD64 exec tests passed 40 tests/subtests and 390 glibc fixture
  executions, with one missing-musl skip. The updated 54-pass glibc/musl run
  described above supersedes that limited exec result.
  This reused the verified existing exec image, not a newly built artifact.
  Native uprobe tests passed 301 tests/subtests with two skips; three further
  fork packages passed 45 tests/subtests with one overlayfs-environment skip.
- The complete downloaded Debian package matches the pinned SHA256. Its
  version/architecture, all nine payload files, package MD5 manifest, ELF
  dependencies, and license material were checked successfully. Final image
  comparison, GPU startup, and the vulnerability scan require completed builds.

Local container builds encountered stalled base-image or dependency downloads;
no successful rebuilt-image scan is claimed. The signed and unsigned GHCR
signing-image cases eventually passed; native container-hook tests were
blocked while obtaining their Docker fixture. Native tests using the
existing local exec image are distinct from rebuilding that image with a new
builder. Complete hosted unit, image, native ARM64, and kernel results must be
checked on the pushed revision. Real GPU/NVML execution remains a separate
hardware validation requirement. Image scans retain their existing
HIGH/CRITICAL failure policy; no suppression or bypass was added.

Hosted run `40470229460` at `3d145e19b1177bd4720d9f17e11a4a1bd8533fab`
subsequently rebuilt all five image families and passed nine architecture
scans: AMD64 and ARM64 for the three helpers and gadget image, and AMD64 for
the GPU bridge. The companion native fork run `40470229543` passed unit/race,
vet, and kernel symbol tests on both native architectures. These results
precede the formatting/QEMU follow-up; the PR description records the latest
revision's status and any remaining runtime requirements.

Hosted run [40475221222](https://github.com/kubescape/inspektor-gadget/actions/runs/40475221222)
at `db99105088cac2a47c6406c8d3985cf32ee0855c` passed strict object regeneration,
all nine architecture-specific image scans, all 259 benchmark package invocations
and 11 benchmark families (84 GiB free afterward), and standard unit tests
(1,929 passing tests/subtests, 17 skips). Its native companion
[40475221227](https://github.com/kubescape/inspektor-gadget/actions/runs/40475221227)
passed both architectures, including 54 exec test/subtest events and 780
glibc/musl attempts per architecture, with no exec skips. Three other native
cases skipped for self-map_files access, a Go-version-specific oracle, and
unavailable real overlayfs fixtures.

All seven VM kernels passed 40 exec tests/subtests each, with one missing-musl
skip. Their workflows nevertheless failed on the nil-resolver panic, while
host runtime jobs also exposed the kernel regression and silent integration
skips described above. Thus this run is not an overall CI pass. Fresh hosted
validation remains required for the subsequent formatter, integration-environment
and runner repairs.

The final GPU artifact from that run has the exact config and all 16 layers of
the previously inspected image. Its nine OpenSSL payload files, matching package
metadata/licenses, Go 1.26.10 binary and restricted startup controls are verified.
All scans retain `HIGH/CRITICAL`, `ignore-unfixed=true` and `exit-code=1`;
zero qualifying findings does not imply absence of unfixed vulnerabilities.
The unchanged DNS/benchmark Alpine 3.18 runtime bases still produce EOL warnings.
The PR description records the newest pushed head and its exact check results.

### Subsequent full-run audit

Run [40481918417](https://github.com/kubescape/inspektor-gadget/actions/runs/40481918417)
at `851d8f2632bb795c54e4df30edf7f20668bcaf44` completed the runner, formatter,
native operator-fixture and sudo-environment repairs. Standard unit tests,
ordinary gadget unit tests and all seven VM kernels passed: 3,137 test/subtest
passes and 59 explicit skips in those nine jobs. Every ordinary/guest gadget
job verified the same signed local image and exercised all 40 exec cases,
profile_cpu, capability, offline-reuse and TTY tests without panics.
The [native companion](https://github.com/kubescape/inspektor-gadget/actions/runs/40481918454)
passed on AMD64 (483 passes, three skips) and ARM64 (482 passes, three skips),
including all seven privileged packages, the empty/operator kernel-stack
fixtures, and 54 exec test/subtest passes with 780 glibc/musl attempts per
architecture and no exec skips.

Strict eBPF regeneration and all nine image scan steps passed again. Benchmarks
executed all 259 packages, 11 families and 18 timing rows, with 83 GiB free
afterward. All five separate CLI lifecycle/enrichment jobs passed. The five
gadget integration jobs executed real tests with no missing-IG_PATH skips:
local containerd and all three Kubernetes runtimes passed, while local Docker
had 34 passes, two skips and the duration-assertion failure described below.
Dependency review still failed on repository configuration; this is not an
overall green CI run. The signed Kubernetes claim also requires the helper
repair below: a passing job alone did not establish that policy was retained.

Two further inherited test-harness issues were isolated from these logs:

- **FSSlower duration:** all five expected `cat`/`foo`/`F_OPEN` records were
  present, but their `delta_us` was zero. The BPF program divides nanoseconds by
  1,000, so sub-microsecond operations validly round to zero with `--min=0`.
  The test now distinguishes missing/null duration from a present zero using
  a pointer, while retaining all identity, path and operation assertions.
  Replaying the actual source callback against those five records reproduces
  the old failure and passes after the fix; positive, absent, null, wrong-file
  and wrong-operation controls give all 20 expected outcomes. Package
  compilation and vet pass. Production tracing is unchanged.
- **Multitenancy configuration:** both redeployment and restoration supplied
  `operator.oci.verify-image=false` even when `GADGET_DAEMON_CONFIG` specified
  verification and a public key. The deploy command applies explicit settings
  after the file, so that fallback disabled the intended policy. The shared
  test helper now adds it only when no file is supplied. Four shell-argument
  regression cases cover both paths with/without configuration, including a
  path containing spaces: both configured cases fail before the repair, and
  all four pass with the race detector afterward. Full Kubernetes integration
  package compilation and vet pass. No production verification or TLS policy
  changes. Hosted signed Kubernetes execution must validate this repair.

The PR description and external validation handoff record the pushed revision
and subsequent hosted outcomes for these final test-harness changes.
