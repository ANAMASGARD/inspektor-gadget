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

package main

import (
	"os/exec"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMultiTenancyDeployCommand(t *testing.T) {
	for _, tc := range []struct {
		name         string
		configFile   string
		multiTenancy bool
	}{
		{name: "initial without config", multiTenancy: true},
		{name: "restore without config"},
		{name: "initial with config", configFile: "/tmp/signed daemon config.yaml", multiTenancy: true},
		{name: "restore with config", configFile: "/tmp/signed daemon config.yaml"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Inspect the actual shell arguments without deploying anything.
			command := `kubectl() { printf '%s' 'test/image:latest'; }
test_gadget() { printf '%s\n' "$@"; }
` + multiTenancyDeployCommand("test_gadget", tc.configFile, tc.multiTenancy)
			output, err := exec.Command("sh", "-c", command).CombinedOutput()
			require.NoError(t, err, string(output))

			want := []string{"undeploy", "deploy", "--experimental", "--debug", "--image=test/image:latest", "--image-pull-policy=IfNotPresent"}
			if tc.configFile == "" {
				want = append(want, "--set-daemon-config=operator.oci.verify-image=false")
			} else {
				want = append(want, "--daemon-config="+tc.configFile)
			}
			if tc.multiTenancy {
				want = append(want, "--set-daemon-config=multi-tenancy=true")
			}
			require.Equal(t, want, strings.Split(strings.TrimSuffix(string(output), "\n"), "\n"))
		})
	}
}
