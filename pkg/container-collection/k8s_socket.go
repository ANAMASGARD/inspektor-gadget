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

package containercollection

import (
	"fmt"
	"os"
	"path/filepath"

	securejoin "github.com/cyphar/filepath-securejoin"
	log "github.com/sirupsen/logrus"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/config"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/config/gadgettracermanagerconfig"
	runtimeclient "github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils/runtime-client"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/host"
)

// resolveK8sRuntimeSocketPath selects a host socket before applying HostRoot.
// Leaving an empty path to the runtime constructors would select a default in
// the daemon's filesystem rather than the mounted host filesystem.
func resolveK8sRuntimeSocketPath(runtime types.RuntimeName, detectedPath string) (string, error) {
	var configKey, envKey, defaultPath string
	switch runtime {
	case types.RuntimeNameContainerd:
		configKey = gadgettracermanagerconfig.ContainerdSocketPath
		envKey = "INSPEKTOR_GADGET_CONTAINERD_SOCKETPATH"
		defaultPath = runtimeclient.ContainerdDefaultSocketPath
	case types.RuntimeNameCrio:
		configKey = gadgettracermanagerconfig.CrioSocketPath
		envKey = "INSPEKTOR_GADGET_CRIO_SOCKETPATH"
		defaultPath = runtimeclient.CrioDefaultSocketPath
	case types.RuntimeNamePodman:
		configKey = gadgettracermanagerconfig.PodmanSocketPath
		envKey = "INSPEKTOR_GADGET_PODMAN_SOCKETPATH"
		defaultPath = runtimeclient.PodmanDefaultSocketPath
	case types.RuntimeNameDocker:
		// Docker's CRI constructor uses this fixed endpoint. docker-socketpath
		// and its environment override configure the separate Engine API.
		return hostRuntimeSocketPath(runtimeclient.CriDockerDefaultSocketPath)
	default:
		return "", fmt.Errorf("unsupported runtime: %s", runtime)
	}

	if detectedPath != "" {
		resolved, err := hostRuntimeSocketPath(detectedPath)
		if err == nil {
			return resolved, nil
		}
		log.Warnf("Invalid detected runtime socket path: %v. Falling back to configured container runtime", err)
	}

	path := config.Config.GetString(configKey)
	if path == "" {
		path = os.Getenv(envKey)
	}
	if path == "" {
		path = defaultPath
	}
	return hostRuntimeSocketPath(path)
}

func hostRuntimeSocketPath(path string) (string, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) == "/" {
		return "", fmt.Errorf("runtime socket must be an absolute host path, got %q", path)
	}
	resolved, err := securejoin.SecureJoin(host.HostRoot, path)
	if err != nil {
		return "", fmt.Errorf("resolving runtime socket %q beneath %q: %w", path, host.HostRoot, err)
	}
	if resolved == filepath.Clean(host.HostRoot) {
		return "", fmt.Errorf("runtime socket %q resolves to host root", path)
	}
	return resolved, nil
}
