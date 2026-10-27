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
	"fmt"
	"strconv"
)

func multiTenancyDeployCommand(kubectlGadget, configFile string, multiTenancy bool) string {
	// Local unsigned images need the fallback, but --set-daemon-config would
	// override verification and public-key policy from a supplied CI config.
	daemonConfigFlag := "--set-daemon-config=operator.oci.verify-image=false"
	if configFile != "" {
		daemonConfigFlag = "--daemon-config=" + q(configFile)
	}
	if multiTenancy {
		daemonConfigFlag += " --set-daemon-config=multi-tenancy=true"
	}

	return fmt.Sprintf(`ig_image="$(kubectl -n gadget get daemonset gadget -o jsonpath='{.spec.template.spec.containers[0].image}')"
%[1]s undeploy || true
%[1]s deploy --experimental --debug \
  --image="$ig_image" \
  --image-pull-policy=IfNotPresent \
  %[2]s`, q(kubectlGadget), daemonConfigFlag)
}

func q(s string) string {
	return strconv.Quote(s)
}
