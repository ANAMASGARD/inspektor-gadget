// Copyright 2019-2022 The Inspektor Gadget authors
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
	"context"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"

	log "github.com/sirupsen/logrus"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/kubernetes"

	containerutils "github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils"
	runtimeclient "github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils/runtime-client"
	containerutilsTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/k8sutil"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/host"
)

type K8sClient struct {
	clientset     *kubernetes.Clientset
	nodeName      string
	fieldSelector string
	runtimeClient runtimeclient.ContainerRuntimeClient
	RuntimeConfig *containerutilsTypes.RuntimeConfig
}

func NewK8sClient(nodeName string, kubeconfigPath string, userAgentComment string) (*K8sClient, error) {
	clientset, err := k8sutil.NewClientset(kubeconfigPath, userAgentComment)
	if err != nil {
		return nil, err
	}

	fieldSelector := fields.OneTermEqualSelector("spec.nodeName", nodeName).String()

	socketPath, err := getContainerRuntimeSocketPath(clientset, nodeName)
	if err != nil {
		socketPath = ""
		if !errors.Is(err, errKubeletDiscoveryDisabled) {
			log.Warnf("Failed to retrieve socket path for runtime client from kubelet: %v. Falling back to configured container runtime", err)
		}
	}

	node, err := clientset.CoreV1().Nodes().Get(context.TODO(), nodeName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("getting node %w", err)
	}

	// Get a runtime client to talk to the container runtime handling pods in
	// this node.
	list := strings.SplitN(node.Status.NodeInfo.ContainerRuntimeVersion, "://", 2)
	socketPath, err = resolveK8sRuntimeSocketPath(types.String2RuntimeName(list[0]), socketPath)
	if err != nil {
		return nil, fmt.Errorf("resolving container runtime socket path: %w", err)
	}
	runtimeConfig := &containerutilsTypes.RuntimeConfig{
		Name:            types.String2RuntimeName(list[0]),
		SocketPath:      socketPath,
		RuntimeProtocol: containerutilsTypes.RuntimeProtocolCRI,
	}
	runtimeClient, err := containerutils.NewContainerRuntimeClient(runtimeConfig)
	if err != nil {
		return nil, err
	}

	return &K8sClient{
		clientset:     clientset,
		nodeName:      nodeName,
		fieldSelector: fieldSelector,
		runtimeClient: runtimeClient,
		RuntimeConfig: runtimeConfig,
	}, nil
}

func (k *K8sClient) Close() {
	k.runtimeClient.Close()
}

// trimRuntimePrefix removes the runtime prefix from a container ID.
func trimRuntimePrefix(id string) string {
	parts := strings.SplitN(id, "//", 2)
	if len(parts) != 2 {
		return ""
	}

	return parts[1]
}

// GetNonRunningContainers returns the list of containers IDs that are not running.
func (k *K8sClient) GetNonRunningContainers(pod *v1.Pod) []string {
	ret := []string{}

	containerStatuses := append([]v1.ContainerStatus{}, pod.Status.InitContainerStatuses...)
	containerStatuses = append(containerStatuses, pod.Status.ContainerStatuses...)
	containerStatuses = append(containerStatuses, pod.Status.EphemeralContainerStatuses...)

	for _, s := range containerStatuses {
		if s.ContainerID != "" && s.State.Running == nil {
			id := trimRuntimePrefix(s.ContainerID)
			if id == "" {
				continue
			}

			ret = append(ret, id)
		}
	}

	return ret
}

// GetRunningContainers returns a list of the containers of a given Pod that are running.
func (k *K8sClient) GetRunningContainers(pod *v1.Pod) []Container {
	containers := []Container{}

	labels := map[string]string{}
	for k, v := range pod.Labels {
		labels[k] = v
	}

	containerStatuses := append([]v1.ContainerStatus{}, pod.Status.InitContainerStatuses...)
	containerStatuses = append(containerStatuses, pod.Status.ContainerStatuses...)
	containerStatuses = append(containerStatuses, pod.Status.EphemeralContainerStatuses...)

	for _, s := range containerStatuses {
		if s.ContainerID == "" || s.State.Running == nil {
			continue
		}

		containerData, err := k.runtimeClient.GetContainerDetails(s.ContainerID)
		if err != nil {
			log.Warnf("Skip pod %s/%s: cannot find container (ID: %s): %v",
				pod.GetNamespace(), pod.GetName(), s.ContainerID, err)
			continue
		}

		pid := containerData.Pid
		if pid > math.MaxUint32 {
			log.Errorf("Container PID (%d) exceeds math.MaxUint32 (%d), skipping this container", pid, math.MaxUint32)
			continue
		}

		// Check if process exists. Better check now rather than fail later in the enrichment pipeline.
		containerPidPath := filepath.Join(host.HostProcFs, fmt.Sprint(pid))
		_, err = os.Stat(containerPidPath)
		if os.IsNotExist(err) {
			log.Warnf("Skip pod %s/%s container %q (ID: %s, image: %s): PID %d doesn't exist",
				pod.GetNamespace(), pod.GetName(),
				containerData.Runtime.RuntimeName,
				containerData.Runtime.ContainerID,
				containerData.Runtime.ContainerImageName,
				pid)
			continue
		}

		containerDef := Container{
			Runtime: RuntimeMetadata{
				BasicRuntimeMetadata: types.BasicRuntimeMetadata{
					RuntimeName:          containerData.Runtime.RuntimeName,
					ContainerID:          containerData.Runtime.ContainerID,
					ContainerName:        containerData.Runtime.ContainerName,
					ContainerPID:         uint32(pid),
					ContainerImageName:   containerData.Runtime.ContainerImageName,
					ContainerImageDigest: containerData.Runtime.ContainerImageDigest,
					ContainerStartedAt:   containerData.Runtime.ContainerStartedAt,
				},
			},
			K8s: K8sMetadata{
				BasicK8sMetadata: types.BasicK8sMetadata{
					Namespace:     pod.GetNamespace(),
					PodName:       pod.GetName(),
					ContainerName: s.Name,
				},
			},
		}

		// PodLabels must be set through the SetPodLabels method
		containerDef.SetPodLabels(pod.Labels)
		containers = append(containers, containerDef)
	}

	return containers
}

// ListContainers return a list of the current containers that are
// running in the node.
func (k *K8sClient) ListContainers() (arr []Container, err error) {
	// List pods
	pods, err := k.clientset.CoreV1().Pods("").List(context.TODO(), metav1.ListOptions{
		FieldSelector: k.fieldSelector,
	})
	if err != nil {
		return nil, err
	}

	for _, pod := range pods.Items {
		containers := k.GetRunningContainers(&pod)
		arr = append(arr, containers...)
	}
	return arr, nil
}

func getContainerRuntimeSocketPath(clientset *kubernetes.Clientset, nodeName string) (string, error) {
	kubeletConfig, err := getCurrentKubeletConfig(clientset, nodeName)
	if err != nil {
		return "", fmt.Errorf("getting /configz: %w", err)
	}

	socketPath := strings.TrimPrefix(kubeletConfig.ContainerRuntimeEndpoint, "unix://")
	if socketPath == "" {
		return "", fmt.Errorf("container runtime socket path is empty")
	}

	log.Infof("using the detected container runtime socket path from Kubelet's config: %s", socketPath)
	return socketPath, nil
}
