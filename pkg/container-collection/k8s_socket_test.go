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
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/config"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/config/gadgettracermanagerconfig"
	runtimeclient "github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils/runtime-client"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/host"
)

func configureSocketTest(t *testing.T, root string) {
	t.Helper()
	previousConfig, previousRoot := config.Config, host.HostRoot
	t.Cleanup(func() {
		config.Config, host.HostRoot = previousConfig, previousRoot
	})
	config.Config, host.HostRoot = viper.New(), root
}

func TestK8sSocketConfigHostRoot(t *testing.T) {
	configureSocketTest(t, "/host")
	config.Config.Set(gadgettracermanagerconfig.ContainerdSocketPath, "/run/containerd/containerd.sock")
	got, err := resolveK8sRuntimeSocketPath(types.RuntimeNameContainerd, "")
	require.NoError(t, err)
	require.Equal(t, "/host/run/containerd/containerd.sock", got)
}

func TestK8sSocketPrecedence(t *testing.T) {
	for _, runtime := range []struct {
		name        types.RuntimeName
		configKey   string
		envKey      string
		defaultPath string
	}{
		{types.RuntimeNameContainerd, gadgettracermanagerconfig.ContainerdSocketPath, "INSPEKTOR_GADGET_CONTAINERD_SOCKETPATH", runtimeclient.ContainerdDefaultSocketPath},
		{types.RuntimeNameCrio, gadgettracermanagerconfig.CrioSocketPath, "INSPEKTOR_GADGET_CRIO_SOCKETPATH", runtimeclient.CrioDefaultSocketPath},
		{types.RuntimeNamePodman, gadgettracermanagerconfig.PodmanSocketPath, "INSPEKTOR_GADGET_PODMAN_SOCKETPATH", runtimeclient.PodmanDefaultSocketPath},
	} {
		// Use a fixture root for real host paths: /run/podman can be
		// inaccessible to an unprivileged unit-test process on the host.
		for _, root := range []string{t.TempDir(), "/host"} {
			t.Run(runtime.name.String()+root, func(t *testing.T) {
				configureSocketTest(t, root)
				for _, tc := range []struct {
					name, detected, configured, env, want string
					wantError                             bool
				}{
					{name: "discovery", detected: "/custom/detected.sock", configured: "invalid-config", env: "invalid-env", want: "/custom/detected.sock"},
					{name: "config", configured: "/custom/config.sock", env: "/custom/environment.sock", want: "/custom/config.sock"},
					{name: "environment", env: "/custom/environment.sock", want: "/custom/environment.sock"},
					{name: "default", want: runtime.defaultPath},
					{name: "invalid discovery", detected: "relative/detected.sock", configured: "/custom/config.sock", want: "/custom/config.sock"},
					{name: "invalid config", configured: "relative/config.sock", env: "/custom/environment.sock", wantError: true},
					{name: "invalid environment", env: "relative/environment.sock", wantError: true},
				} {
					t.Run(tc.name, func(t *testing.T) {
						config.Config.Set(runtime.configKey, tc.configured)
						t.Setenv(runtime.envKey, tc.env)
						got, err := resolveK8sRuntimeSocketPath(runtime.name, tc.detected)
						if tc.wantError {
							require.Error(t, err)
							require.Empty(t, got)
							return
						}
						require.NoError(t, err)
						require.Equal(t, filepath.Join(root, tc.want), got)
					})
				}
			})
		}
	}
}

func TestK8sSocketNativeHostRoot(t *testing.T) {
	configureSocketTest(t, "/")
	root, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	socket := filepath.Join(root, "runtime.sock")
	config.Config.Set(gadgettracermanagerconfig.ContainerdSocketPath, socket)
	got, err := resolveK8sRuntimeSocketPath(types.RuntimeNameContainerd, "")
	require.NoError(t, err)
	require.Equal(t, socket, got)
}

func TestK8sDockerSocketUsesCRI(t *testing.T) {
	for _, root := range []string{"/", "/host"} {
		t.Run(root, func(t *testing.T) {
			configureSocketTest(t, root)
			config.Config.Set(gadgettracermanagerconfig.DockerSocketPath, "/run/docker-engine.sock")
			t.Setenv("INSPEKTOR_GADGET_DOCKER_SOCKETPATH", "/run/environment-engine.sock")
			got, err := resolveK8sRuntimeSocketPath(types.RuntimeNameDocker, "/run/custom-cri.sock")
			require.NoError(t, err)
			require.Equal(t, filepath.Join(root, "/run/cri-dockerd.sock"), got)
		})
	}
}

func TestK8sSocketUnknownRuntime(t *testing.T) {
	configureSocketTest(t, "/host")
	got, err := resolveK8sRuntimeSocketPath(types.String2RuntimeName("unknown"), "/run/unknown.sock")
	require.ErrorContains(t, err, "unsupported runtime")
	require.Empty(t, got)
}

func TestK8sSocketHostPaths(t *testing.T) {
	root := t.TempDir()
	configureSocketTest(t, root)
	require.NoError(t, os.MkdirAll(filepath.Join(root, "run"), 0o755))
	require.NoError(t, os.Symlink("/run", filepath.Join(root, "runtime")))
	got, err := hostRuntimeSocketPath("/runtime/containerd.sock")
	require.NoError(t, err)
	require.Equal(t, filepath.Join(root, "run/containerd.sock"), got)

	require.NoError(t, os.Symlink("/", filepath.Join(root, "root-link")))
	for _, path := range []string{"", "/", "/run/..", "relative.sock", "/root-link", "/bad\x00path"} {
		t.Run(path, func(t *testing.T) {
			got, err := hostRuntimeSocketPath(path)
			require.Error(t, err)
			require.Empty(t, got)
		})
	}

	// A detected path resolving to the host root cannot bypass the fallback.
	config.Config.Set(gadgettracermanagerconfig.ContainerdSocketPath, "/run/fallback.sock")
	got, err = resolveK8sRuntimeSocketPath(types.RuntimeNameContainerd, "/root-link")
	require.NoError(t, err)
	require.Equal(t, filepath.Join(root, "run/fallback.sock"), got)
}
