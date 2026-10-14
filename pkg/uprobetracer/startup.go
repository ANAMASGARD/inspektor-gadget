package uprobetracer

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/host"
)

const (
	startupMaxProcesses = 32
	startupMaxTasks     = 256
)

// SetStartupMappedLibPattern supplies the embedder's library matcher for the
// one-shot scan of already-running containers. Call before attaching containers.
// A nil pattern disables library discovery; executable discovery still runs.
func (t *Tracer[Event]) SetStartupMappedLibPattern(pattern *regexp.Regexp) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.startupMappedLibPattern = pattern
}

// attachExistingProcesses runs inside the settled attach worker, sharing its
// process-wide semaphore and WaitGroup. The deadline bounds scheduling between
// operations, not an in-flight resolver/attach (which is not preemptible). New containers must never enter this
// path: their PID can still name the host's runc shim. Reattachment retains the
// tracked-container guards, resolver gates, inode deduplication and teardown.
func (t *Tracer[Event]) attachExistingProcesses(containerPid uint32) {
	t.mu.Lock()
	pattern := t.startupMappedLibPattern
	t.mu.Unlock()
	expectedMntns, err := readProcMntns(containerPid)
	if err != nil {
		return
	}
	deadline := time.Now().Add(attachIOTimeout)
	pids := existingProcessPids(containerPid, deadline)
	if len(pids) == startupMaxProcesses {
		t.logger.Infof("uprobetracer: startup discovery containerPid=%d reached process cap %d", containerPid, startupMaxProcesses)
	}
	for _, pid := range pids {
		if time.Now().After(deadline) {
			t.logger.Infof("uprobetracer: startup discovery containerPid=%d reached time budget", containerPid)
			break
		}
		// The entrypoint executable was handled by attachContainerWork already.
		if pid != containerPid {
			if err := t.reattachContainerExecPid(containerPid, pid, expectedMntns); err != nil {
				t.logger.Debugf("startup executable attach containerPid=%d pid=%d: %v", containerPid, pid, err)
			}
		}
		if time.Now().After(deadline) {
			t.logger.Infof("uprobetracer: startup discovery containerPid=%d reached time budget", containerPid)
			break
		}
		if err := t.ReattachContainerMappedLibsPid(containerPid, pid, pattern); err != nil {
			t.logger.Debugf("startup mapped-library attach containerPid=%d pid=%d: %v", containerPid, pid, err)
		}
	}
}

// existingProcessPids walks a bounded snapshot of descendants, including children
// forked by non-leader threads. Only descendants sharing the entrypoint's mount
// namespace qualify: executable paths are opened through the container root.
// Processes that exit during discovery are harmless; attach revalidates tracking.
func existingProcessPids(root uint32, deadline time.Time) []uint32 {
	pids := []uint32{root}
	ns, err := os.Readlink(filepath.Join(host.HostProcFs, fmt.Sprint(root), "ns/mnt"))
	if err != nil {
		return pids
	}
	seen := map[uint32]bool{root: true}
	for idx := 0; idx < len(pids) && len(pids) < startupMaxProcesses; idx++ {
		if time.Now().After(deadline) {
			return pids
		}
		taskDir := filepath.Join(host.HostProcFs, fmt.Sprint(pids[idx]), "task")
		dir, err := os.Open(taskDir)
		if err != nil {
			continue
		}
		tasks, _ := dir.Readdirnames(startupMaxTasks)
		dir.Close()
		for _, tid := range tasks {
			if time.Now().After(deadline) {
				return pids
			}
			f, err := os.Open(filepath.Join(taskDir, tid, "children"))
			if err != nil {
				continue
			}
			data, _ := io.ReadAll(io.LimitReader(f, 4097))
			f.Close()
			// Discard a truncated final PID rather than treating its prefix as a PID.
			if len(data) > 4096 {
				data = data[:4096]
				if end := strings.LastIndexAny(string(data), " \t\n"); end >= 0 {
					data = data[:end]
				} else {
					continue
				}
			}
			for _, child := range strings.Fields(string(data)) {
				n, err := strconv.ParseUint(child, 10, 32)
				if err != nil || n == 0 {
					continue
				}
				pid := uint32(n)
				if seen[pid] {
					continue
				}
				seen[pid] = true
				childNS, err := os.Readlink(filepath.Join(host.HostProcFs, child, "ns/mnt"))
				if err != nil || childNS != ns {
					continue
				}
				pids = append(pids, pid)
				if len(pids) == startupMaxProcesses {
					return pids
				}
			}
		}
	}
	return pids
}

// Recheck both identities before executable resolution and before committing
// opened files; a namespace change invalidates the startup snapshot.
func startupNamespaceMatches(containerPid, pid uint32, expected uint64) bool {
	containerNS, err := readProcMntns(containerPid)
	if err != nil || containerNS != expected {
		return false
	}
	processNS, err := readProcMntns(pid)
	return err == nil && processNS == expected
}
