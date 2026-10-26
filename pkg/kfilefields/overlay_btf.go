// Copyright 2026 The Inspektor Gadget authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package kfilefields

import (
	"errors"
	"fmt"
	"io/fs"
	"strings"

	"github.com/inspektor-gadget/inspektor-gadget/internal/testing/kernel"
)

// checkOverlayModuleBTF diagnoses missing BTF for a loaded overlay module.
// Built-in overlayfs has its BTF in vmlinux and is absent from /proc/modules.
func checkOverlayModuleBTF(root fs.FS) error {
	version, err := kernel.GetKernelVersion()
	if err != nil {
		return fmt.Errorf("checking overlay module BTF: getting kernel version: %w", err)
	}
	return checkOverlayModuleBTFForKernel(root, *version)
}

func checkOverlayModuleBTFForKernel(root fs.FS, version kernel.VersionInfo) error {
	// Older kernels use the legacy private_data layout, which does not
	// require overlay module BTF for real-inode resolution.
	if kernel.CompareKernelVersion(version, kernel.VersionInfo{Kernel: 6, Major: 13}) < 0 {
		return nil
	}

	modules, err := fs.ReadFile(root, "proc/modules")
	if errors.Is(err, fs.ErrNotExist) {
		return nil // Kernels without CONFIG_MODULES do not expose /proc/modules.
	}
	if err != nil {
		return fmt.Errorf("checking overlay module BTF: reading /proc/modules: %w", err)
	}
	for line := range strings.SplitSeq(string(modules), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || fields[0] != "overlay" {
			continue
		}
		if _, err := fs.ReadFile(root, "sys/kernel/btf/overlay"); err != nil {
			return fmt.Errorf("overlay module BTF is unavailable at /sys/kernel/btf/overlay: %w; overlayfs real-inode resolution may be incorrect on Linux 6.13 and newer; ensure CONFIG_DEBUG_INFO_BTF_MODULES is enabled and module BTF is accessible", err)
		}
		return nil
	}
	return nil
}
