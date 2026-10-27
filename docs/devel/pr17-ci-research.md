# PR #17 CI investigation and repair

The failures below were investigated at PR head
`003819050d26773d649fc7de99542188efa342b8`. This is the fork prerequisite for
[node-agent #1050](https://github.com/kubescape/node-agent/issues/1050), not the
downstream node-agent integration. The upstream merge and original authorship
are preserved.

## Findings and changes

| Check | Evidence and repair |
| --- | --- |
| ARM64 fork tests | The [maintainer's requested change](https://github.com/kubescape/inspektor-gadget/pull/17#discussion_r4385779833) identifies three stale fixtures. Both `accept` expectations are now 202, and an unknown name expects `(0, false)`. Production syscall tables and the native ARM64 job remain unchanged. |
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

## Builder artifact verification

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
- The nine-package fork race suite passed: 457 test/subtest passes, 17 skips,
  and no failures. The AMD64 syscall test suite passed; ARM64 fixtures require
  the native hosted job.
- Workflow lint, targeted Go lint, formatting, and diff whitespace checks passed.
  Controlled runs of the exact benchmark script returned 0 for success and
  propagated package-list, first-package, and later-package failures (23, 41,
  and 42), without continuing to later packages.
- The complete downloaded Debian package matches the pinned SHA256. Its
  version/architecture, all nine payload files, package MD5 manifest, ELF
  dependencies, and license material were checked successfully. Final image
  comparison, GPU startup, and the vulnerability scan require completed builds.

Local container builds encountered stalled base-image or dependency downloads;
no successful rebuilt-image scan is claimed. The full unit-suite attempt also
encountered remote signing-image retrieval, and native container-hook tests
were blocked while obtaining their Docker fixture. Native tests using the
existing local exec image are distinct from rebuilding that image with a new
builder. Complete hosted unit, image, native ARM64, and kernel results must be
checked on the pushed revision. Real GPU/NVML execution remains a separate
hardware validation requirement. Image scans retain their existing
HIGH/CRITICAL failure policy; no suppression or bypass was added.
