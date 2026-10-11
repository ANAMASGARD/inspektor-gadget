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

package containerhook

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/metrics"
)

func TestCallbackBudgetValidation(t *testing.T) {
	previous := configuredCallbackHardBound.Load()
	t.Cleanup(func() { configuredCallbackHardBound.Store(previous) })
	configuredCallbackHardBound.Store(0)
	require.Equal(t, time.Second, AddContainerCallbackHardBound())
	require.NoError(t, SetAddContainerCallbackHardBound(5*time.Second))
	for _, invalid := range []time.Duration{0, -time.Second, 5*time.Second + 1} {
		require.Error(t, SetAddContainerCallbackHardBound(invalid))
		require.Equal(t, 5*time.Second, AddContainerCallbackHardBound())
	}
}

func TestCallbackWaitsBeyondOriginalBudget(t *testing.T) {
	previous := configuredCallbackHardBound.Load()
	t.Cleanup(func() { configuredCallbackHardBound.Store(previous) })
	require.NoError(t, SetAddContainerCallbackHardBound(5*time.Second))
	finished := make(chan struct{})
	n := &ContainerNotifier{callback: func(ContainerEvent) {
		time.Sleep(1200 * time.Millisecond)
		close(finished)
	}}
	n.callbackAddContainerBounded(ContainerEvent{Type: EventTypeAddContainer})
	select {
	case <-finished:
	default:
		t.Fatal("container released before slow startup callback completed")
	}
	require.Zero(t, n.CallbackStats().Breaches)
}

func TestCallbackFailOpenMetrics(t *testing.T) {
	previous := configuredCallbackHardBound.Load()
	t.Cleanup(func() { configuredCallbackHardBound.Store(previous) })
	require.NoError(t, SetAddContainerCallbackHardBound(20*time.Millisecond))
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	require.NoError(t, metrics.RegisterProvider(provider))
	t.Cleanup(func() {
		metrics.UnregisterProvider(provider)
		require.NoError(t, provider.Shutdown(context.Background()))
	})
	fast := &ContainerNotifier{callback: func(ContainerEvent) {}}
	fast.callbackAddContainerBounded(ContainerEvent{Type: EventTypeAddContainer})
	require.Zero(t, fast.CallbackStats().Breaches)
	for _, reason := range []string{"timeout", "in_flight"} {
		release := make(chan struct{})
		finished := make(chan struct{})
		n := &ContainerNotifier{callback: func(ContainerEvent) { <-release; close(finished) }}
		if reason == "in_flight" {
			n.cbInFlight.Store(addContainerCallbackTripThreshold)
		}
		start := time.Now()
		n.callbackAddContainerBounded(ContainerEvent{Type: EventTypeAddContainer})
		elapsed := time.Since(start)
		if reason == "timeout" {
			require.GreaterOrEqual(t, elapsed, 20*time.Millisecond)
		} else {
			require.Less(t, elapsed, 100*time.Millisecond)
		}
		require.Equal(t, uint64(1), n.CallbackStats().Breaches)
		close(release)
		<-finished
	}
	var data metricdata.ResourceMetrics
	require.NoError(t, reader.Collect(context.Background(), &data))
	counts := map[string]int64{}
	for _, scope := range data.ScopeMetrics {
		for _, m := range scope.Metrics {
			if m.Name == "ig_container_hook_fail_open_total" {
				for _, point := range m.Data.(metricdata.Sum[int64]).DataPoints {
					reason, ok := point.Attributes.Value("reason")
					require.True(t, ok)
					counts[reason.AsString()] = point.Value
				}
			}
		}
	}
	require.Equal(t, map[string]int64{"timeout": 1, "in_flight": 1}, counts)
}
