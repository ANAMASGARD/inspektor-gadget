// Copyright 2019-2021 The Inspektor Gadget authors
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
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/pflag"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/core/v1"
	"sigs.k8s.io/yaml"

	"github.com/inspektor-gadget/inspektor-gadget/cmd/common"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/config/gadgettracermanagerconfig"
	grpcruntime "github.com/inspektor-gadget/inspektor-gadget/pkg/runtime/grpc"
)

func TestPrintOnly(t *testing.T) {
	grpcRuntime = grpcruntime.New(grpcruntime.WithConnectUsingK8SProxy)
	runtimeGlobalParams = grpcRuntime.GlobalParamDescs().ToParams()

	cmd := rootCmd
	common.AddFlags(cmd, runtimeGlobalParams, nil, grpcRuntime)
	cmd.SetArgs([]string{"deploy", "--print-only"})

	var stdErr bytes.Buffer
	cmd.SetErr(&stdErr)
	cmd.Execute()
	require.Empty(t, stdErr.String(), "Error while running command")
}

func TestApplyConfigToConfgMap(t *testing.T) {
	// Helper to create a ConfigMap with config.yaml data
	makeCM := func(yaml string) *v1.ConfigMap {
		return &v1.ConfigMap{
			Data: map[string]string{
				"config.yaml": yaml,
			},
		}
	}

	tmpFileWith := func(content string) (string, func()) {
		f, err := os.CreateTemp("", "ig-config-*.yaml")
		require.NoError(t, err, "failed to create temp file")
		_, err = f.WriteString(content)
		require.NoError(t, err, "failed to write temp file")
		return f.Name(), func() { os.Remove(f.Name()) }
	}

	tests := []struct {
		name          string
		cm            *v1.ConfigMap
		configContent string
		setConfig     []string
		flagSetup     func(*pflag.FlagSet)
		wantContains  []string
		wantErr       bool
	}{
		{
			name:         "default configmap only",
			cm:           makeCM("operator:\n  oci:\n    disallow-pulling: false\n"),
			flagSetup:    func(fs *pflag.FlagSet) {},
			wantContains: []string{"disallow-pulling: false"},
		},
		{
			name:         "set-config overrides configmap",
			cm:           makeCM("operator:\n  oci:\n    disallow-pulling: false\n"),
			setConfig:    []string{"operator.oci.disallow-pulling=true"},
			flagSetup:    func(fs *pflag.FlagSet) {},
			wantContains: []string{"disallow-pulling: true"},
		},
		{
			name:          "config file overrides configmap",
			cm:            makeCM("operator:\n  oci:\n    disallow-pulling: false\n"),
			configContent: "operator:\n  oci:\n    disallow-pulling: true\n",
			flagSetup:     func(fs *pflag.FlagSet) {},
			wantContains:  []string{"disallow-pulling: true"},
		},
		{
			name: "flag overrides configmap",
			cm:   makeCM("operator:\n  oci:\n    disallow-pulling: false\n"),
			flagSetup: func(fs *pflag.FlagSet) {
				fs.Set("disallow-gadgets-pulling", "true")
			},
			wantContains: []string{"disallow-pulling: true"},
		},
		{
			name:          "set-config overrides config file",
			cm:            makeCM("operator:\n  oci:\n    disallow-pulling: false\n"),
			setConfig:     []string{"operator.oci.disallow-pulling=true"},
			configContent: "operator:\n  oci:\n    disallow-pulling: false\n",
			flagSetup:     func(fs *pflag.FlagSet) {},
			wantContains:  []string{"disallow-pulling: true"},
		},
		{
			name:      "flag overrides set-config",
			cm:        makeCM("operator:\n  oci:\n    disallow-pulling: false\n"),
			setConfig: []string{"operator.oci.disallow-pulling=false"},
			flagSetup: func(fs *pflag.FlagSet) {
				fs.Set("disallow-gadgets-pulling", "true")
			},
			wantContains: []string{"disallow-pulling: true"},
		},
		{
			name:          "Merge configmap, set-config, and config file",
			cm:            makeCM("operator:\n  oci:\n    disallow-pulling: false\n"),
			setConfig:     []string{"operator.oci.verify-image=true"},
			configContent: "operator:\n  oci:\n    insecure-registries: registry.example.com\n",
			wantContains:  []string{"disallow-pulling: false", "verify-image: \"true\"", "insecure-registries: registry.example.com"},
		},
		{
			name:      "invalid set-config format",
			cm:        makeCM("operator:\n  oci:\n    disallow-pulling: false\n"),
			setConfig: []string{"badformat"},
			flagSetup: func(fs *pflag.FlagSet) {},
			wantErr:   true,
		},
		{
			name:      "missing config.yaml",
			cm:        &v1.ConfigMap{Data: map[string]string{}},
			flagSetup: func(fs *pflag.FlagSet) {},
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
			fs.Bool("disallow-gadgets-pulling", false, "")

			if tt.flagSetup != nil {
				tt.flagSetup(fs)
			}

			// Patch global setDaemonConfig for this test
			oldSetConfig := setDaemonConfig
			setDaemonConfig = tt.setConfig
			defer func() { setDaemonConfig = oldSetConfig }()

			// if configContent is provided, create a temp file
			var configPath string
			if tt.configContent != "" {
				var cleanup func()
				configPath, cleanup = tmpFileWith(tt.configContent)
				defer cleanup()
				fs.String("config", configPath, "Path to the configuration file")
			} else {
				fs.String("config", "", "Path to the configuration file")
			}

			err := applyConfigToConfigMap(tt.cm, configPath, fs)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			got := tt.cm.Data["config.yaml"]
			for _, want := range tt.wantContains {
				require.Contains(t, got, want, "config.yaml should contain %q", want)
			}
		})
	}
}

func TestApplyKubeletTLSConfigFile(t *testing.T) {
	const caCertificate = `-----BEGIN CERTIFICATE-----
MIIBpTCCAUugAwIBAgIUIK9uqLti5fpvkA5yRX1HmP/EXTcwCgYIKoZIzj0EAwIw
KDEmMCQGA1UEAwwdS3ViZWxldCBjb25maWd1cmF0aW9uIHRlc3QgQ0EwHhcNMjYx
MDI3MTExOTI3WhcNMzYxMDI0MTExOTI3WjAoMSYwJAYDVQQDDB1LdWJlbGV0IGNv
bmZpZ3VyYXRpb24gdGVzdCBDQTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABEMc
9qukwrp4jvjUgQv08k6+uSK3qvR4iQOmyIzmcVNBxmenPaKc5RY8ZcoBP5io5rNK
cgEfwaYtH39rIk5ivaajUzBRMB0GA1UdDgQWBBSzItxMCafL6lkKo/l7dTcW2yNU
8DAfBgNVHSMEGDAWgBSzItxMCafL6lkKo/l7dTcW2yNU8DAPBgNVHRMBAf8EBTAD
AQH/MAoGCCqGSM49BAMCA0gAMEUCIQDmRABS0sX02Dyl/ZOprIbF9k9B7fLPofce
VkTocSzsRwIgMFv4MAMRtIiyk/V1lqUAp/5BEmVfGINtZoh9yxIOwHY=
-----END CERTIFICATE-----
`
	oldSetConfig := setDaemonConfig
	setDaemonConfig = nil
	t.Cleanup(func() { setDaemonConfig = oldSetConfig })

	for _, tc := range []struct {
		name           string
		caBundle       string
		serverName     string
		setConfig      []string
		wantCABundle   string
		wantServerName string
	}{
		{name: "discovery disabled by empty settings"},
		{
			name: "PEM bundle and DNS override", caBundle: caCertificate + caCertificate, serverName: "kubelet.internal.example",
			wantCABundle: caCertificate + caCertificate, wantServerName: "kubelet.internal.example",
		},
		{
			name: "literal YAML boolean name", caBundle: caCertificate, serverName: "true",
			wantCABundle: caCertificate, wantServerName: "true",
		},
		{
			name: "scalar flags override file and clear bundle", caBundle: caCertificate, serverName: "old.internal.example",
			setConfig: []string{
				"--set-daemon-config=kubelet-server-name=new.internal.example",
				"--set-daemon-config=kubelet-ca-bundle=",
			},
			wantServerName: "new.internal.example",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			configYAML, err := yaml.Marshal(map[string]string{
				gadgettracermanagerconfig.KubeletCABundle:   tc.caBundle,
				gadgettracermanagerconfig.KubeletServerName: tc.serverName,
			})
			require.NoError(t, err)
			if tc.caBundle != "" {
				require.Contains(t, string(configYAML), "kubelet-ca-bundle: |")
			}
			configPath := filepath.Join(t.TempDir(), "daemon config.yaml")
			require.NoError(t, os.WriteFile(configPath, configYAML, 0o600))
			cm := &v1.ConfigMap{Data: map[string]string{
				"config.yaml": "kubelet-ca-bundle: \"\"\nkubelet-server-name: \"\"\noperator:\n  oci:\n    verify-image: true\n",
			}}
			flags := pflag.NewFlagSet("test", pflag.ContinueOnError)
			flags.StringSliceVar(&setDaemonConfig, "set-daemon-config", nil, "")
			require.NoError(t, flags.Parse(tc.setConfig))
			require.NoError(t, applyConfigToConfigMap(cm, configPath, flags))

			// Exercise both YAML layers: the ConfigMap manifest and config.yaml.
			manifest, err := yaml.Marshal(cm)
			require.NoError(t, err)
			var decoded v1.ConfigMap
			require.NoError(t, yaml.UnmarshalStrict(manifest, &decoded))
			var config map[string]interface{}
			require.NoError(t, yaml.UnmarshalStrict([]byte(decoded.Data["config.yaml"]), &config))
			require.Equal(t, tc.wantCABundle, config[gadgettracermanagerconfig.KubeletCABundle])
			require.Equal(t, tc.wantServerName, config[gadgettracermanagerconfig.KubeletServerName])
			require.Equal(t, map[string]interface{}{"oci": map[string]interface{}{"verify-image": true}}, config["operator"])
		})
	}
}
