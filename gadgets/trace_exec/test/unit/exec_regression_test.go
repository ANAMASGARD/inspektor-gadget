// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package tests

import (
	"context"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
	"oras.land/oras-go/v2"
	orasoci "oras.land/oras-go/v2/content/oci"

	gadgettesting "github.com/inspektor-gadget/inspektor-gadget/gadgets/testing"
	traceexec "github.com/inspektor-gadget/inspektor-gadget/gadgets/trace_exec/consts"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/oci"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/simple"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/gadgetrunner"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/utils"
)

type execPathEvent struct {
	ExpectedTraceExecEvent
	ExePath string `json:"exepath"`
	File    string `json:"file"`
}

// captureExec runs the actual image, including its WASM argument formatter.
// Each invocation also exercises loading and unloading after the OCI target
// has been released, rather than testing a standalone argument decoder.
func captureExec(t *testing.T, action func() error) []execPathEvent {
	t.Helper()
	return captureExecFrom(t, action, nil)
}

func captureExecFrom(t *testing.T, action func() error, target oras.ReadOnlyTarget) []execPathEvent {
	t.Helper()
	runner := utils.NewRunnerWithTest(t, &utils.RunnerConfig{})
	gr := gadgetrunner.NewGadgetRunner(t, gadgetrunner.GadgetRunnerOpts[execPathEvent]{
		Image:              "trace_exec",
		Timeout:            5 * time.Second,
		MntnsFilterMap:     utils.CreateMntNsFilterMap(t, runner.Info.MountNsID),
		OrasReadonlyTarget: target,
		GlobalParamsValues: api.ParamValues{
			"operator.oci.verify-image": "false", // Locally built regression image.
		},
		ParamValues: api.ParamValues{
			"operator.oci.ebpf.paths":         "true",
			"operator.oci.ebpf.ignore-failed": "false",
		},
		OnGadgetRun: func(ctx operators.GadgetContext) error {
			require.Nil(t, ctx.OrasTarget(), "image operators must release the OCI target after loading")
			utils.RunWithRunner(t, runner, action)
			return nil
		},
	})
	if target != nil {
		gr.DataOperator = append(gr.DataOperator, simple.New("readonly-store-lifetime",
			simple.WithPriority(math.MaxInt-1),
			simple.OnInit(func(ctx operators.GadgetContext) error {
				require.NotNil(t, ctx.OrasTarget(), "later data operators must still be able to read the caller's store during initialization")
				return nil
			}),
		))
	}
	gr.RunGadget()
	return gr.CapturedEvents
}

func TestTraceExecOfflineBundle(t *testing.T) {
	gadgettesting.InitUnitTest(t)
	// CI serves the configured image from a registry; populate the local store
	// through the normal loading path before exporting the offline bundle.
	captureExec(t, func() error { return nil })
	bundle := filepath.Join(t.TempDir(), "exec.tar")
	image := gadgetrunner.GetGadgetImageName("trace_exec")
	require.NoError(t, oci.ExportGadgetImages(context.Background(), bundle, image))
	store, err := orasoci.NewFromTar(context.Background(), bundle)
	require.NoError(t, err)
	// Reuse the caller-owned, read-only store across independent load/unload
	// cycles. The gadget context releases its reference, not the shared store.
	for range 3 {
		events := captureExecFrom(t, func() error {
			return exec.Command("/bin/true", "offline-bundle").Run()
		}, store)
		require.Len(t, events, 1)
		require.Equal(t, "/bin/true"+traceexec.ArgsSeparator+"offline-bundle", events[0].Args)
	}
}

func compileExecFixture(t *testing.T, compiler, source string) string {
	t.Helper()
	fixture := filepath.Join(t.TempDir(), strings.TrimSuffix(source, ".c"))
	args := []string{"-Wall", "-Wextra", "-Werror", "-O2", "-o", fixture, filepath.Join("testdata", source)}
	if compiler == "musl-gcc" {
		args = append(args, "-static")
	}
	output, err := exec.Command(compiler, args...).CombinedOutput()
	require.NoError(t, err, "%s", output)
	resolved, err := filepath.EvalSymlinks(fixture)
	require.NoError(t, err)
	return resolved
}

func TestTraceExecCommittedArguments(t *testing.T) {
	gadgettesting.InitUnitTest(t)
	// A dedicated executable accepts every argv shape, independent of the
	// host distribution's command dispatch or argument validation.
	target := compileExecFixture(t, "cc", "exec_target.c")
	dir := t.TempDir()
	alias := filepath.Join(dir, "target-link")
	require.NoError(t, os.Symlink(target, alias))
	script := filepath.Join(dir, "script")
	require.NoError(t, os.WriteFile(script, []byte("#!/bin/sh\nexit 0\n"), 0o700))
	shellPath, err := filepath.EvalSymlinks("/bin/sh")
	require.NoError(t, err)
	sink, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	require.NoError(t, err)
	defer sink.Close()
	many := append([]string{"spoofed"}, slices.Repeat([]string{"arg"}, 100)...)
	for _, tc := range []struct {
		name, path, cwd, exe, file string
		argv, want                 []string
	}{
		{"argv0", target, "", target, target, []string{"spoofed", "value"}, []string{"spoofed", "value"}},
		{"symlink", alias, "", target, target, []string{"alias-name", "value"}, []string{"alias-name", "value"}},
		{"relative", "./target-link", dir, target, target, []string{"relative-name", "value"}, []string{"relative-name", "value"}},
		{"shebang", script, "", shellPath, script, []string{"spoofed-script", "value", ""}, []string{"/bin/sh", script, "value", ""}},
		{"missing-argv", target, "", target, target, nil, []string{""}},
		{"empty-argv0", target, "", target, target, []string{"", "value"}, []string{"", "value"}},
		{"empty", target, "", target, target, []string{"echo", "", "", "tail", ""}, []string{"echo", "", "", "tail", ""}},
		{"many", target, "", target, target, many, many},
		{"long", target, "", target, target, []string{"echo", strings.Repeat("x", 1024)}, []string{"echo", strings.Repeat("x", 1024)}},
		{"exact-buffer", target, "", target, target, []string{"echo", strings.Repeat("x", 5114)}, []string{"echo", strings.Repeat("x", 5114)}},
		// An argument whose terminating NUL lies outside the capture block is
		// omitted by the formatter. It must not turn into a fabricated argv.
		{"truncated", target, "", target, target, []string{"echo", "prefix", strings.Repeat("x", 6000)}, []string{"echo", "prefix"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			events := captureExec(t, func() error {
				p, err := os.StartProcess(tc.path, tc.argv, &os.ProcAttr{Dir: tc.cwd, Files: []*os.File{sink, sink, sink}})
				if err != nil {
					return err
				}
				state, err := p.Wait()
				if err == nil && !state.Success() {
					return fmt.Errorf("fixture exited: %s", state)
				}
				return err
			})
			require.Len(t, events, 1)
			require.Equal(t, strings.Join(tc.want, traceexec.ArgsSeparator), events[0].Args)
			require.Equal(t, tc.exe, events[0].ExePath)
			require.Equal(t, tc.file, events[0].File)
		})
	}
}

func TestTraceExecLibcColdPages(t *testing.T) {
	gadgettesting.InitUnitTest(t)
	for _, compiler := range []string{"cc", "musl-gcc"} {
		t.Run(compiler, func(t *testing.T) {
			if _, err := exec.LookPath(compiler); err != nil {
				t.Skipf("%s is required for this libc's kernel regression tests", compiler)
			}
			fixture := compileExecFixture(t, compiler, "exec.c")
			target := compileExecFixture(t, compiler, "exec_target.c")
			for _, mode := range []string{"warm", "cold-path", "cold-argument", "cold-vector", "cold-all", "unmapped-path", "unmapped-argument", "unmapped-vector", "system", "popen", "wordexp", "execveat", "execveat-empty"} {
				t.Run(mode, func(t *testing.T) {
					const attempts = 30
					events := captureExec(t, func() error {
						for range attempts {
							if output, err := exec.Command(fixture, mode, target).CombinedOutput(); err != nil {
								return fmt.Errorf("%s: %w: %s", mode, err, output)
							}
						}
						return nil
					})
					matched := 0
					for _, event := range events {
						if strings.HasPrefix(mode, "unmapped-") {
							if event.Error == "EFAULT" {
								matched++
							}
							continue
						}
						argv := strings.Split(event.Args, traceexec.ArgsSeparator)
						if mode == "system" || mode == "popen" || mode == "wordexp" {
							if filepath.Base(argv[0]) != "sh" {
								continue
							}
							command := "printf :"
							if mode == "system" {
								command = ":"
							}
							require.Contains(t, argv, "-c")
							if mode == "wordexp" && compiler == "musl-gcc" {
								// musl passes the expression and redirection as
								// arguments to its shell's eval wrapper.
								require.Equal(t, []string{"sh", "-c", `eval "printf %s\\\\0 x $1 $2"`, "sh", "$(printf :)", "2>/dev/null"}, argv)
							} else {
								require.Equal(t, command, argv[len(argv)-1])
							}
						} else {
							if argv[0] != "probe-argv0" {
								continue
							}
							require.Equal(t, []string{"probe-argv0", "cold-argument"}, argv)
						}
						require.Empty(t, event.Error)
						require.NotEmpty(t, event.ExePath)
						matched++
					}
					require.Equal(t, attempts, matched, "every attempt must produce the expected real eBPF event")
				})
			}
		})
	}
}

// A fresh devpts instance guarantees index zero even on hosts with active PTYs.
func TestTraceExecPtsZero(t *testing.T) {
	gadgettesting.InitUnitTest(t)
	dir := t.TempDir()
	events := captureExec(t, func() error {
		if err := unix.Mount("devpts", dir, "devpts", 0, "newinstance,ptmxmode=0666,mode=0620"); err != nil {
			return err
		}
		defer unix.Unmount(dir, unix.MNT_DETACH)
		master, err := os.OpenFile(filepath.Join(dir, "ptmx"), os.O_RDWR, 0)
		if err != nil {
			return err
		}
		defer master.Close()
		if err := unix.IoctlSetPointerInt(int(master.Fd()), unix.TIOCSPTLCK, 0); err != nil {
			return err
		}
		number, err := unix.IoctlGetInt(int(master.Fd()), unix.TIOCGPTN)
		if err != nil {
			return err
		}
		require.Zero(t, number)
		slave, err := os.OpenFile(filepath.Join(dir, "0"), os.O_RDWR, 0)
		if err != nil {
			return err
		}
		defer slave.Close()
		for _, withTTY := range []bool{true, false} {
			attr := &os.ProcAttr{Sys: &syscall.SysProcAttr{Setsid: true}}
			if withTTY {
				attr.Files = []*os.File{slave, slave, slave}
				attr.Sys.Setctty = true
			}
			p, err := os.StartProcess("/bin/echo", []string{"echo", "tty-control"}, attr)
			if err != nil {
				return err
			}
			if _, err := p.Wait(); err != nil {
				return err
			}
		}
		return nil
	})
	require.Len(t, events, 2)
	require.Zero(t, events[0].Tty)
	require.Equal(t, uint32(136), events[0].TtyMajor)
	require.Zero(t, events[0].TtyMinor)
	require.Zero(t, events[1].Tty)
	require.Zero(t, events[1].TtyMajor)
	require.Zero(t, events[1].TtyMinor)
}
