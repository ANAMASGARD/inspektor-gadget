// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package ebpfoperator

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestStopAfterFailedStartSignalsIterators(t *testing.T) {
	instance := &ebpfInstance{done: make(chan struct{})}
	ctx := newResolverGadgetCtx(t, nil)
	t.Cleanup(func() { instance.PreStop(ctx) })
	instance.wg.Add(1)
	go func() {
		defer instance.wg.Done()
		<-instance.done
	}()
	stopped := make(chan struct{})
	go func() {
		instance.Stop(ctx)
		close(stopped)
	}()
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("startup-error cleanup must work without a prior PreStop")
	}
}

func TestCloseStopsPartiallyStartedTracers(t *testing.T) {
	tracer := &Tracer{done: make(chan struct{})}
	t.Cleanup(tracer.close)
	instance := &ebpfInstance{
		bpfOperator: &ebpfOperator{},
		done:        make(chan struct{}),
		tracers:     map[string]*Tracer{"exec": tracer},
	}
	var stopped atomic.Bool
	instance.wg.Add(1)
	go func() {
		defer instance.wg.Done()
		<-tracer.done
		stopped.Store(true)
	}()

	ctx := newResolverGadgetCtx(t, nil)
	require.NoError(t, instance.Close(ctx))
	select {
	case <-tracer.done:
	default:
		t.Fatal("Close must stop readers even when startup failed before Stop")
	}
	select {
	case <-instance.done:
	default:
		t.Fatal("Close must stop map iterators after partial initialization")
	}
	require.True(t, stopped.Load(), "Close must join readers before releasing their collection")
	// The normal shutdown hooks can also have run before Close.
	require.NoError(t, instance.PreStop(ctx))
	require.NoError(t, instance.Stop(ctx))
}
