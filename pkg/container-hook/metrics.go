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

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/metrics"
)

var callbackFailOpenCounter, _ = metrics.Int64Counter("ig_container_hook_fail_open_total",
	metric.WithDescription("Container starts allowed before AddContainer completed"))

func recordCallbackFailOpen(reason string) {
	callbackFailOpenCounter.Add(context.Background(), 1,
		metric.WithAttributes(attribute.String("reason", reason)))
}
