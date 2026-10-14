package uprobetracer

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf"
)

func fakeStartupProcess(t *testing.T, proc string, pid uint32, ns, exe string, children ...uint32) {
	t.Helper()
	base := filepath.Join(proc, fmt.Sprint(pid))
	task := filepath.Join(base, "task", fmt.Sprint(pid))
	if err := os.MkdirAll(task, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(base, "ns"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(ns, filepath.Join(base, "ns/mnt")); err != nil {
		t.Fatal(err)
	}
	fakeExeProc(t, proc, pid, exe)
	var ids []string
	for _, child := range children {
		ids = append(ids, fmt.Sprint(child))
	}
	if err := os.WriteFile(filepath.Join(task, "children"), []byte(strings.Join(ids, " ")), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestExistingProcessPids(t *testing.T) {
	proc := withFakeProcRoot(t)
	fakeStartupProcess(t, proc, 100, "mnt:[1]", "/init", 200, 300, 400)
	fakeStartupProcess(t, proc, 200, "mnt:[1]", "/client", 100) // dedup/cycle
	fakeStartupProcess(t, proc, 300, "mnt:[2]", "/outside")
	// 400 exited; child of another thread must still be discovered.
	task := filepath.Join(proc, "100/task/101")
	if err := os.MkdirAll(task, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(task, "children"), []byte("500"), 0o644); err != nil {
		t.Fatal(err)
	}
	fakeStartupProcess(t, proc, 500, "mnt:[1]", "/thread-client")
	got := existingProcessPids(100, time.Now().Add(time.Minute))
	slices.Sort(got)
	if want := []uint32{100, 200, 500}; !slices.Equal(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestExistingProcessPidsCapped(t *testing.T) {
	proc := withFakeProcRoot(t)
	var children []uint32
	for pid := uint32(200); pid < 250; pid++ {
		children = append(children, pid)
		fakeStartupProcess(t, proc, pid, "mnt:[1]", "/client")
	}
	fakeStartupProcess(t, proc, 100, "mnt:[1]", "/init", children...)
	if got := len(existingProcessPids(100, time.Now().Add(time.Minute))); got != startupMaxProcesses {
		t.Fatalf("got %d want %d", got, startupMaxProcesses)
	}
}

func TestStartupAttachesExistingChildWithoutExecEvent(t *testing.T) {
	for _, pending := range []bool{false, true} {
		t.Run(fmt.Sprint("pending=", pending), func(t *testing.T) {
			proc := withFakeProcRoot(t)
			fakeStartupProcess(t, proc, 100, "mnt:[1]", "/init", 200)
			fakeStartupProcess(t, proc, 200, "mnt:[1]", "/tls-client")
			tr, st := newTestTracer(t)
			if pending {
				tr.prog = nil
			}
			if err := tr.AttachContainer(settledTestContainer(100)); err != nil {
				t.Fatal(err)
			}
			if pending {
				if err := tr.AttachProg(tr.progName, tr.progType, tr.attachFilePath+":"+tr.attachSymbol, &ebpf.Program{}); err != nil {
					t.Fatal(err)
				}
			}
			found := false
			for _, path := range st.openedPaths {
				if path == "/tls-client" {
					found = true
				}
			}
			if !found {
				t.Fatalf("existing child never attached; opened %v", st.openedPaths)
			}
			// The child is credited to its container, never tracked independently.
			if _, exists := tr.containerPid2Inodes[200]; exists {
				t.Fatal("child tracked as separate container")
			}
		})
	}
}

func TestStartupDoesNotScanUnsettledContainer(t *testing.T) {
	proc := withFakeProcRoot(t)
	fakeStartupProcess(t, proc, 100, "mnt:[1]", "/runc", 200)
	fakeStartupProcess(t, proc, 200, "mnt:[1]", "/host-client")
	tr, st := newTestTracer(t)
	tr.SetStartupMappedLibPattern(regexp.MustCompile(`.*`))
	if err := tr.AttachContainer(testContainer(100)); err != nil {
		t.Fatal(err)
	}
	if len(st.openedPaths) != 1 || st.openedPaths[0] != tr.attachFilePath {
		t.Fatalf("unsettled scan: %v", st.openedPaths)
	}
}

func TestStartupAttachesMappedLibrariesWithoutExecEvent(t *testing.T) {
	for _, pending := range []bool{false, true} {
		t.Run(fmt.Sprint("pending=", pending), func(t *testing.T) {
			proc := withFakeProcRoot(t)
			selfExe, err := os.Readlink("/proc/self/exe")
			if err != nil {
				t.Fatal(err)
			}
			fakeStartupProcess(t, proc, 100, "mnt:[1]", selfExe, 200)
			fakeStartupProcess(t, proc, 200, "mnt:[1]", selfExe)
			tr, st := newTestTracer(t)
			// Fail ordinary path attachment: only the mapped inode can attach.
			st.openErr = os.ErrNotExist
			tr.SetStartupMappedLibPattern(regexp.MustCompile(`^libssl\.so\.3$`))
			var scanned []uint32
			tr.openMapFileFunc = func(pid uint32, _ string, _ uint64) (*os.File, error) {
				scanned = append(scanned, pid)
				st.currentInode = uint64(pid)
				f, err := os.Open("/proc/self/exe")
				if err == nil {
					st.openFiles = append(st.openFiles, f)
				}
				return f, err
			}
			for _, pid := range []uint32{100, 200} {
				line := buildMapsLine("7e8714023000-7e87141a3000", "r-xp", uint64(pid), "/custom/libssl.so.3 (deleted)")
				if err := os.WriteFile(filepath.Join(proc, fmt.Sprint(pid), "maps"), []byte(line+"\n"), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			if pending {
				tr.prog = nil
			}
			container := settledTestContainer(100)
			if err := tr.AttachContainer(container); err != nil {
				t.Fatal(err)
			}
			if pending {
				if err := tr.AttachProg(tr.progName, tr.progType, tr.attachFilePath+":"+tr.attachSymbol, &ebpf.Program{}); err != nil {
					t.Fatal(err)
				}
			}
			if !slices.Equal(scanned, []uint32{100, 200}) {
				t.Fatalf("scanned %v", scanned)
			}
			if st.attachCount != 2 || !tr.HasMappedLibForPid(100) {
				t.Fatalf("attaches=%d mapped=%v", st.attachCount, tr.HasMappedLibForPid(100))
			}
			if err := tr.DetachContainer(container); err != nil {
				t.Fatal(err)
			}
			if len(tr.inodeRefCount) != 0 {
				t.Fatalf("leaked inodes %v", tr.inodeRefCount)
			}
			tr.attachExistingProcesses(100)
			if st.attachCount != 2 {
				t.Fatal("reattached detached container")
			}
		})
	}
}

func TestExistingProcessPidsExpiredDeadline(t *testing.T) {
	proc := withFakeProcRoot(t)
	fakeStartupProcess(t, proc, 100, "mnt:[1]", "/init", 200)
	fakeStartupProcess(t, proc, 200, "mnt:[1]", "/client")
	if got := existingProcessPids(100, time.Now().Add(-time.Second)); !slices.Equal(got, []uint32{100}) {
		t.Fatalf("expired discovery walked children: %v", got)
	}
}

func TestStartupMappedLibraryRejectsChangedNamespace(t *testing.T) {
	proc := withFakeProcRoot(t)
	fakeStartupProcess(t, proc, 100, "mnt:[1]", "/init", 200)
	fakeStartupProcess(t, proc, 200, "mnt:[1]", "/client")
	pids := existingProcessPids(100, time.Now().Add(time.Minute))
	if !slices.Contains(pids, uint32(200)) {
		t.Fatal("child missing from original snapshot")
	}
	nsLink := filepath.Join(proc, "200/ns/mnt")
	if err := os.Remove(nsLink); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("mnt:[2]", nsLink); err != nil {
		t.Fatal(err)
	}
	tr, _ := newTestTracer(t)
	tr.containerPid2Inodes[100] = nil
	tr.openMapFileFunc = func(uint32, string, uint64) (*os.File, error) {
		t.Fatal("opened mapped file in changed namespace")
		return nil, nil
	}
	if err := tr.ReattachContainerMappedLibsPid(100, 200, regexp.MustCompile(`.*`)); err != nil {
		t.Fatal(err)
	}
	if tr.HasMappedLibForPid(100) {
		t.Fatal("wrong namespace credited to container")
	}
}

func TestStartupCloseJoinsAttachWorker(t *testing.T) {
	proc := withFakeProcRoot(t)
	fakeStartupProcess(t, proc, 100, "mnt:[1]", "/init", 200)
	fakeStartupProcess(t, proc, 200, "mnt:[1]", "/client")
	tr, st := newTestTracer(t)
	tr.syncAttach = false
	started, release := make(chan struct{}), make(chan struct{})
	tr.openInContainer = func(ctx context.Context, pid uint32, path string) (*os.File, error) {
		if path == "/client" {
			close(started)
			<-release
		}
		return st.open(ctx, pid, path)
	}
	if err := tr.AttachContainer(settledTestContainer(100)); err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("startup child attach not reached")
	}
	closed := make(chan struct{})
	go func() { tr.Close(); close(closed) }()
	select {
	case <-closed:
		t.Fatal("Close did not join worker")
	case <-time.After(10 * time.Millisecond):
	}
	close(release)
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("Close did not finish")
	}
	if len(tr.inodeRefCount) != 0 {
		t.Fatal("startup worker installed an inode after Close")
	}
}
