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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/spf13/viper"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/config"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/config/gadgettracermanagerconfig"
)

type kubeletTestCA struct {
	certificate *x509.Certificate
	key         *ecdsa.PrivateKey
	pem         string
}

func newKubeletTestCA(t *testing.T) kubeletTestCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test kubelet CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return kubeletTestCA{certificate: certificate, key: key, pem: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))}
}

func (ca kubeletTestCA) serverCertificate(t *testing.T, ips []net.IP, names []string, expired bool) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(2), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IPAddresses: ips, DNSNames: names,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if expired {
		template.NotAfter = time.Now().Add(-time.Minute)
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.certificate, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func newKubeletTestServer(t *testing.T, certificate tls.Certificate, handler http.Handler) *httptest.Server {
	t.Helper()
	server := httptest.NewUnstartedServer(handler)
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.TLS = &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12}
	server.StartTLS()
	t.Cleanup(server.Close)
	return server
}

func kubeletTestToken(t *testing.T, value string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func kubeletTestClient(t *testing.T, ca, serverName, tokenFile string) *kubeletConfigzClient {
	t.Helper()
	client, err := newKubeletConfigzClient(kubeletConfigzOptions{caBundle: ca, serverName: serverName, tokenFile: tokenFile})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func TestKubeletTLSVerification(t *testing.T) {
	ca, otherCA := newKubeletTestCA(t), newKubeletTestCA(t)
	for _, tc := range []struct {
		name, bundle, serverName string
		ips                      []net.IP
		names                    []string
		expired, wantSuccess     bool
	}{
		{name: "trusted IP SAN", bundle: ca.pem, ips: []net.IP{net.ParseIP("127.0.0.1")}, wantSuccess: true},
		{name: "bundle with multiple roots", bundle: otherCA.pem + ca.pem, ips: []net.IP{net.ParseIP("127.0.0.1")}, wantSuccess: true},
		{name: "untrusted CA withholds bearer", bundle: otherCA.pem, ips: []net.IP{net.ParseIP("127.0.0.1")}},
		{name: "wrong IP SAN withholds bearer", bundle: ca.pem, ips: []net.IP{net.ParseIP("192.0.2.1")}},
		{name: "DNS certificate requires override", bundle: ca.pem, names: []string{"kubelet.example.test"}},
		{name: "literal DNS override", bundle: ca.pem, serverName: "kubelet.example.test", names: []string{"kubelet.example.test"}, wantSuccess: true},
		{name: "wrong DNS override withholds bearer", bundle: ca.pem, serverName: "wrong.example.test", names: []string{"kubelet.example.test"}},
		{name: "expired certificate withholds bearer", bundle: ca.pem, ips: []net.IP{net.ParseIP("127.0.0.1")}, expired: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var requests atomic.Int32
			server := newKubeletTestServer(t, ca.serverCertificate(t, tc.ips, tc.names, tc.expired), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				if got := r.Header.Get("Authorization"); got != "Bearer dummy-test-token" {
					t.Errorf("Authorization = %q", got)
				}
				if r.URL.Path != "/configz" {
					t.Errorf("path = %q", r.URL.Path)
				}
				_, _ = io.WriteString(w, `{"kubeletconfig":{"containerRuntimeEndpoint":"unix:///run/containerd/containerd.sock"}}`)
			}))
			client := kubeletTestClient(t, tc.bundle, tc.serverName, kubeletTestToken(t, "dummy-test-token\n"))
			body, err := client.get(context.Background(), server.URL+"/configz")
			if !tc.wantSuccess {
				if err == nil {
					t.Fatal("unverified server was accepted")
				}
				if requests.Load() != 0 {
					t.Fatal("unverified server received the bearer credential")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			configuration, err := decodeConfigz(body)
			if err != nil || configuration.ContainerRuntimeEndpoint != "unix:///run/containerd/containerd.sock" || requests.Load() != 1 {
				t.Fatalf("configuration = %v, requests = %d, err = %v", configuration, requests.Load(), err)
			}
		})
	}
}

func TestKubeletDiscoveryDisabledBeforeNodeOrTokenAccess(t *testing.T) {
	previous := config.Config
	t.Cleanup(func() { config.Config = previous })
	config.Config = viper.New()
	for _, bundle := range []string{"", " \n\t"} {
		config.Config.Set(gadgettracermanagerconfig.KubeletCABundle, bundle)
		// A nil client deliberately detects any Node API access while disabled.
		_, err := getCurrentKubeletConfigThroughNodesConfigz(context.Background(), nil, "test-node")
		if !errors.Is(err, errKubeletDiscoveryDisabled) {
			t.Fatalf("bundle %q: err = %v", bundle, err)
		}
	}
}

func TestKubeletRejectsUnusableCABundle(t *testing.T) {
	for _, bundle := range []string{"not PEM", "-----BEGIN CERTIFICATE-----\ninvalid\n-----END CERTIFICATE-----", "-----BEGIN PRIVATE KEY-----\nAA==\n-----END PRIVATE KEY-----"} {
		_, err := newKubeletConfigzClient(kubeletConfigzOptions{caBundle: bundle, tokenFile: "/missing-test-token"})
		if err == nil || !strings.Contains(err.Error(), "no usable PEM certificates") {
			t.Fatalf("bundle %q: err = %v", bundle, err)
		}
	}
}

func TestKubeletNodeLookupCancellationAndDeadline(t *testing.T) {
	previous := config.Config
	t.Cleanup(func() { config.Config = previous })
	config.Config = viper.New()
	config.Config.Set(gadgettracermanagerconfig.KubeletCABundle, newKubeletTestCA(t).pem)
	for _, cancelEarly := range []bool{true, false} {
		name := "five second discovery budget"
		if cancelEarly {
			name = "caller cancellation"
		}
		t.Run(name, func(t *testing.T) {
			started, ended := make(chan struct{}, 1), make(chan struct{}, 1)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/api/v1/nodes/test-node" {
					t.Errorf("unexpected Node API path %q", r.URL.Path)
				}
				started <- struct{}{}
				<-r.Context().Done()
				ended <- struct{}{}
			}))
			t.Cleanup(server.Close)
			clientset, err := kubernetes.NewForConfig(&rest.Config{Host: server.URL})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			result := make(chan error, 1)
			go func() {
				_, err := getCurrentKubeletConfigThroughNodesConfigz(ctx, clientset, "test-node")
				result <- err
			}()
			select {
			case <-started:
			case <-time.After(10 * time.Second):
				t.Fatal("Node lookup never started")
			}
			want := context.DeadlineExceeded
			if cancelEarly {
				want = context.Canceled
				cancel()
			}
			select {
			case err := <-result:
				if !errors.Is(err, want) {
					t.Fatalf("error = %v, want %v", err, want)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("Node lookup exceeded the discovery budget")
			}
			select {
			case <-ended:
			case <-time.After(5 * time.Second):
				t.Fatal("Node API connection was not canceled")
			}
		})
	}
}

func TestKubeletTokenRotationAndFailures(t *testing.T) {
	ca := newKubeletTestCA(t)
	tokens := make(chan string, 2)
	server := newKubeletTestServer(t, ca.serverCertificate(t, []net.IP{net.ParseIP("127.0.0.1")}, nil, false), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokens <- r.Header.Get("Authorization")
		_, _ = io.WriteString(w, "{}")
	}))
	tokenFile := kubeletTestToken(t, "first-dummy-token")
	client := kubeletTestClient(t, ca.pem, "", tokenFile)
	for _, token := range []string{"first-dummy-token", "rotated-dummy-token"} {
		// Atomic replacement models the projected service-account volume update.
		if err := os.WriteFile(tokenFile+".new", []byte(token), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(tokenFile+".new", tokenFile); err != nil {
			t.Fatal(err)
		}
		if _, err := client.get(context.Background(), server.URL); err != nil {
			t.Fatal(err)
		}
		if got := <-tokens; got != "Bearer "+token {
			t.Fatalf("Authorization = %q", got)
		}
	}
	for _, token := range []string{"", " \n\t"} {
		if err := os.WriteFile(tokenFile, []byte(token), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := client.get(context.Background(), server.URL); err == nil || !strings.Contains(err.Error(), "token is empty") {
			t.Fatalf("empty token: err = %v", err)
		}
	}
	if err := os.Remove(tokenFile); err != nil {
		t.Fatal(err)
	}
	if _, err := client.get(context.Background(), server.URL); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing token: err = %v", err)
	}
	if len(tokens) != 0 {
		t.Fatal("invalid token caused an HTTP request")
	}
}

func TestKubeletRejectsRedirects(t *testing.T) {
	ca := newKubeletTestCA(t)
	var redirected atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirected.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(target.Close)
	for _, status := range []int{http.StatusMovedPermanently, http.StatusFound, http.StatusTemporaryRedirect, http.StatusPermanentRedirect} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			server := newKubeletTestServer(t, ca.serverCertificate(t, []net.IP{net.ParseIP("127.0.0.1")}, nil, false), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, target.URL, status)
			}))
			client := kubeletTestClient(t, ca.pem, "", kubeletTestToken(t, "dummy-test-token"))
			if _, err := client.get(context.Background(), server.URL); err == nil || !strings.Contains(err.Error(), fmt.Sprint(status)) {
				t.Fatalf("redirect error = %v", err)
			}
			if redirected.Load() != 0 {
				t.Fatal("redirect destination received a request")
			}
		})
	}
}

func TestKubeletIgnoresEnvironmentProxy(t *testing.T) {
	ca := newKubeletTestCA(t)
	server := newKubeletTestServer(t, ca.serverCertificate(t, nil, []string{"kubelet.example.test"}, false), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "{}")
	}))
	for _, key := range []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"} {
		t.Setenv(key, "http://proxy.example.test:8888")
	}
	t.Setenv("NO_PROXY", "")
	t.Setenv("no_proxy", "")
	client := kubeletTestClient(t, ca.pem, "", kubeletTestToken(t, "dummy-test-token"))
	endpoint, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	endpoint.Host = net.JoinHostPort("kubelet.example.test", endpoint.Port())
	// Use a non-loopback URL so Go's automatic proxy bypass cannot mask a
	// regression. Only route that exact address to the local test listener.
	client.httpClient.Transport.(*http.Transport).DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		if address != endpoint.Host {
			return nil, fmt.Errorf("request routed through proxy %q", address)
		}
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	}
	if _, err := client.get(context.Background(), endpoint.String()); err != nil {
		t.Fatal(err)
	}
}

func TestKubeletIPv6(t *testing.T) {
	listener, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("IPv6 loopback unavailable: %v", err)
	}
	ca := newKubeletTestCA(t)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "{}")
	}))
	_ = server.Listener.Close()
	server.Listener = listener
	server.TLS = &tls.Config{Certificates: []tls.Certificate{ca.serverCertificate(t, []net.IP{net.ParseIP("::1")}, nil, false)}, MinVersion: tls.VersionTLS12}
	server.StartTLS()
	t.Cleanup(server.Close)
	client := kubeletTestClient(t, ca.pem, "", kubeletTestToken(t, "dummy-test-token"))
	if _, err := client.get(context.Background(), server.URL+"/configz"); err != nil {
		t.Fatal(err)
	}
}

func TestKubeletCancellationAndTimeout(t *testing.T) {
	ca := newKubeletTestCA(t)
	for _, tc := range []struct {
		name    string
		timeout time.Duration
		cancel  bool
	}{
		{name: "context cancellation", timeout: time.Second, cancel: true},
		{name: "client timeout", timeout: 500 * time.Millisecond},
	} {
		t.Run(tc.name, func(t *testing.T) {
			started, ended := make(chan struct{}), make(chan struct{})
			server := newKubeletTestServer(t, ca.serverCertificate(t, []net.IP{net.ParseIP("127.0.0.1")}, nil, false), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				close(started)
				<-r.Context().Done()
				close(ended)
			}))
			client, err := newKubeletConfigzClient(kubeletConfigzOptions{caBundle: ca.pem, tokenFile: kubeletTestToken(t, "dummy-test-token"), timeout: tc.timeout})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			result := make(chan error, 1)
			go func() {
				_, err := client.get(ctx, server.URL)
				result <- err
			}()
			select {
			case <-started:
			case <-time.After(5 * time.Second):
				t.Fatal("request did not reach server")
			}
			want := context.DeadlineExceeded
			if tc.cancel {
				want = context.Canceled
				cancel()
			}
			select {
			case err := <-result:
				if !errors.Is(err, want) {
					t.Fatalf("error = %v, want %v", err, want)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("request exceeded its bound")
			}
			select {
			case <-ended:
			case <-time.After(5 * time.Second):
				t.Fatal("server connection was not canceled")
			}
		})
	}
}

func TestKubeletResponseBoundsAndConnectionCleanup(t *testing.T) {
	ca := newKubeletTestCA(t)
	for _, tc := range []struct {
		name     string
		status   int
		size     int
		wantErr  string
		truncate bool
	}{
		{name: "success", status: http.StatusOK, size: 2},
		{name: "exact limit", status: http.StatusOK, size: kubeletConfigzLimit},
		{name: "oversized", status: http.StatusOK, size: kubeletConfigzLimit + 1, wantErr: "response limit"},
		{name: "unauthorized", status: http.StatusUnauthorized, size: 2, wantErr: "status is 401"},
		{name: "forbidden", status: http.StatusForbidden, size: 2, wantErr: "status is 403"},
		{name: "server error", status: http.StatusInternalServerError, size: 2, wantErr: "status is 500"},
		{name: "truncated response", status: http.StatusOK, size: 2, truncate: true, wantErr: "unexpected EOF"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			closed := make(chan struct{}, 1)
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tc.truncate {
					w.Header().Set("Content-Length", "10")
				}
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, strings.Repeat(" ", tc.size))
			}))
			server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
				if state == http.StateClosed {
					select {
					case closed <- struct{}{}:
					default:
					}
				}
			}
			server.TLS = &tls.Config{Certificates: []tls.Certificate{ca.serverCertificate(t, []net.IP{net.ParseIP("127.0.0.1")}, nil, false)}, MinVersion: tls.VersionTLS12}
			server.StartTLS()
			t.Cleanup(server.Close)
			client := kubeletTestClient(t, ca.pem, "", kubeletTestToken(t, "dummy-test-token"))
			body, err := client.get(context.Background(), server.URL)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("error = %v, want %q", err, tc.wantErr)
				}
			} else if err != nil || len(body) != tc.size {
				t.Fatalf("response length = %d, err = %v", len(body), err)
			}
			// Observe cleanup before httptest.Server.Close can mask a leak.
			select {
			case <-closed:
			case <-time.After(5 * time.Second):
				t.Fatal("discovery retained an idle or unread connection")
			}
		})
	}
}

func TestKubeletRejectsPlainHTTP(t *testing.T) {
	ca := newKubeletTestCA(t)
	client := kubeletTestClient(t, ca.pem, "", "/missing-test-token")
	if _, err := client.get(context.Background(), "http://127.0.0.1/configz"); err == nil || !strings.Contains(err.Error(), "must use HTTPS") {
		t.Fatalf("error = %v", err)
	}
}

func TestKubeletRejectsLegacyTLS(t *testing.T) {
	ca := newKubeletTestCA(t)
	var requests atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1) }))
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.TLS = &tls.Config{Certificates: []tls.Certificate{ca.serverCertificate(t, []net.IP{net.ParseIP("127.0.0.1")}, nil, false)}, MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS11}
	server.StartTLS()
	t.Cleanup(server.Close)
	client := kubeletTestClient(t, ca.pem, "", kubeletTestToken(t, "dummy-test-token"))
	if _, err := client.get(context.Background(), server.URL); err == nil || requests.Load() != 0 {
		t.Fatalf("legacy TLS error = %v, requests = %d", err, requests.Load())
	}
}

func TestKubeletNodeInternalIP(t *testing.T) {
	for _, tc := range []struct {
		name      string
		addresses []v1.NodeAddress
		want      string
	}{
		{name: "IPv4", addresses: []v1.NodeAddress{{Type: v1.NodeInternalIP, Address: "192.0.2.1"}}, want: "192.0.2.1"},
		{name: "IPv6", addresses: []v1.NodeAddress{{Type: v1.NodeInternalIP, Address: "2001:db8::1"}}, want: "2001:db8::1"},
		{name: "skip invalid", addresses: []v1.NodeAddress{{Type: v1.NodeInternalIP, Address: "invalid"}, {Type: v1.NodeInternalIP, Address: "192.0.2.1"}}, want: "192.0.2.1"},
		{name: "external only", addresses: []v1.NodeAddress{{Type: v1.NodeExternalIP, Address: "192.0.2.1"}}},
		{name: "missing"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := getNodeInternalIP(&v1.Node{ObjectMeta: metav1.ObjectMeta{Name: "test-node"}, Status: v1.NodeStatus{Addresses: tc.addresses}})
			if got != tc.want || (err != nil) != (tc.want == "") {
				t.Fatalf("IP = %q, err = %v", got, err)
			}
		})
	}
}

func TestKubeletDecodeMalformedConfigz(t *testing.T) {
	if _, err := decodeConfigz([]byte(`{"kubeletconfig":`)); err == nil {
		t.Fatal("malformed JSON accepted")
	}
}
