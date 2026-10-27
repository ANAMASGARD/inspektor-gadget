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
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	kubeletconfigv1beta1 "k8s.io/kubelet/config/v1beta1"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/config"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/config/gadgettracermanagerconfig"
)

const (
	kubeletPort           = "10250"
	kubeletRequestTimeout = 5 * time.Second
	kubeletConfigzLimit   = 5 << 20 // 5 MiB
	kubeletTokenFile      = "/var/run/secrets/kubernetes.io/serviceaccount/token"
)

var errKubeletDiscoveryDisabled = errors.New("kubelet discovery disabled: no trusted CA bundle configured")

type kubeletConfigzOptions struct {
	caBundle   string
	serverName string
	tokenFile  string
	timeout    time.Duration
}

type kubeletConfigzClient struct {
	httpClient *http.Client
	tokenFile  string
}

func newKubeletConfigzClient(options kubeletConfigzOptions) (*kubeletConfigzClient, error) {
	if strings.TrimSpace(options.caBundle) == "" {
		return nil, errKubeletDiscoveryDisabled
	}

	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(options.caBundle)) {
		return nil, fmt.Errorf("kubelet CA bundle contains no usable PEM certificates")
	}
	if options.timeout <= 0 {
		options.timeout = kubeletRequestTimeout
	}

	return &kubeletConfigzClient{
		httpClient: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					MinVersion: tls.VersionTLS12,
					RootCAs:    roots,
					// Use this identity literally; an empty value verifies the URL's IP.
					ServerName: options.serverName,
				},
				Proxy: nil,
			},
			// A kubelet response must not redirect the bearer credential.
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
			Timeout: options.timeout,
		},
		tokenFile: options.tokenFile,
	}, nil
}

func (c *kubeletConfigzClient) get(ctx context.Context, endpoint string) ([]byte, error) {
	// Discovery is a one-shot operation; do not retain its idle connection.
	defer c.httpClient.CloseIdleConnections()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("building kubelet request: %w", err)
	}
	if req.URL.Scheme != "https" || req.URL.Host == "" {
		return nil, fmt.Errorf("kubelet endpoint must use HTTPS")
	}

	// Read the projected token for every discovery, including after rotation.
	token, err := os.ReadFile(c.tokenFile)
	if err != nil {
		return nil, fmt.Errorf("reading service account token: %w", err)
	}
	if strings.TrimSpace(string(token)) == "" {
		return nil, fmt.Errorf("service account token is empty")
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(token)))

	response, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("getting kubelet /configz: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("kubelet /configz status is %d, expected: %d", response.StatusCode, http.StatusOK)
	}

	body, err := io.ReadAll(io.LimitReader(response.Body, kubeletConfigzLimit+1))
	if err != nil {
		return nil, fmt.Errorf("reading kubelet /configz: %w", err)
	}
	if len(body) > kubeletConfigzLimit {
		return nil, fmt.Errorf("kubelet /configz exceeds the %d-byte response limit", kubeletConfigzLimit)
	}
	return body, nil
}

func getNodeInternalIP(node *v1.Node) (string, error) {
	for _, address := range node.Status.Addresses {
		if address.Type == v1.NodeInternalIP && net.ParseIP(address.Address) != nil {
			return address.Address, nil
		}
	}
	return "", fmt.Errorf("no valid internal IP found for node %q", node.Name)
}

func getCurrentKubeletConfigThroughNodesConfigz(ctx context.Context, clientset *kubernetes.Clientset, nodeName string) ([]byte, error) {
	client, err := newKubeletConfigzClient(kubeletConfigzOptions{
		caBundle:   config.Config.GetString(gadgettracermanagerconfig.KubeletCABundle),
		serverName: config.Config.GetString(gadgettracermanagerconfig.KubeletServerName),
		tokenFile:  kubeletTokenFile,
	})
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(ctx, kubeletRequestTimeout)
	defer cancel()
	node, err := clientset.CoreV1().Nodes().Get(ctx, nodeName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("getting node %q: %w", nodeName, err)
	}
	nodeIP, err := getNodeInternalIP(node)
	if err != nil {
		return nil, err
	}
	endpoint := "https://" + net.JoinHostPort(nodeIP, kubeletPort) + "/configz"
	return client.get(ctx, endpoint)
}

func getCurrentKubeletConfig(clientset *kubernetes.Clientset, nodeName string) (*kubeletconfigv1beta1.KubeletConfiguration, error) {
	response, err := getCurrentKubeletConfigThroughNodesConfigz(context.TODO(), clientset, nodeName)
	if err != nil {
		return nil, fmt.Errorf("fetching /configz from %q: %w", nodeName, err)
	}
	return decodeConfigz(response)
}

func decodeConfigz(body []byte) (*kubeletconfigv1beta1.KubeletConfiguration, error) {
	var wrapper struct {
		ComponentConfig kubeletconfigv1beta1.KubeletConfiguration `json:"kubeletconfig"`
	}
	if err := json.Unmarshal(body, &wrapper); err != nil {
		return nil, err
	}
	return &wrapper.ComponentConfig, nil
}
