// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package ebpfoperator

import (
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/stretchr/testify/require"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/kallsyms"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/logger"
	ebpftypes "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/ebpf/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/utils"
)

func TestKernelSymbolLookupLazyAndConcurrent(t *testing.T) {
	var loads atomic.Int32
	load := func() (*kallsyms.KAllSyms, error) {
		loads.Add(1)
		return kallsyms.NewKAllSymsFromReader(strings.NewReader("1000 T first\n2000 T second\n"))
	}
	lookup := newKernelSymbolLookup(load)
	require.Zero(t, loads.Load(), "constructing formatters must not load symbols")

	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			name, err := lookup(0x1001)
			if err != nil || name != "first" {
				t.Errorf("lookup = %q, %v; want first", name, err)
			}
		})
	}
	wg.Wait()
	require.Equal(t, int32(1), loads.Load(), "fields and concurrent events share one snapshot")
	name, err := lookup(0x2001)
	require.NoError(t, err)
	require.Equal(t, "second", name)
	require.Equal(t, int32(1), loads.Load())

	// A subsequent gadget instance owns a fresh snapshot, not process-global
	// symbol state that can outlive its formatter lifecycle.
	next := newKernelSymbolLookup(load)
	_, err = next(0x1001)
	require.NoError(t, err)
	require.Equal(t, int32(2), loads.Load())
}

func TestStackConverterSkipsUnusedSymbols(t *testing.T) {
	loads := 0
	lookup := newKernelSymbolLookup(func() (*kallsyms.KAllSyms, error) {
		loads++
		return nil, errors.New("symbols must not be loaded")
	})
	emptyStack := func(_, out interface{}) error {
		*out.(*[ebpftypes.KernelPerfMaxStackDepth]uint64) = [ebpftypes.KernelPerfMaxStackDepth]uint64{}
		return nil
	}
	trace, err := fetchAndFormatStackTrace(0, emptyStack, lookup)
	require.NoError(t, err)
	require.Empty(t, trace)

	missing := errors.New("stack no longer exists")
	trace, err = fetchAndFormatStackTrace(42, func(_, _ interface{}) error { return missing }, lookup)
	require.ErrorIs(t, err, missing)
	require.Empty(t, trace)
	require.Zero(t, loads)
}

func TestKernelSymbolLookupInitializationFailure(t *testing.T) {
	readError := errors.New("reading kallsyms failed")
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"read error", readError},
		{"nil resolver", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			loads := 0
			lookup := newKernelSymbolLookup(func() (*kallsyms.KAllSyms, error) {
				loads++
				return nil, tc.err
			})
			stackLookup := func(_, out interface{}) error {
				*out.(*[ebpftypes.KernelPerfMaxStackDepth]uint64) = [ebpftypes.KernelPerfMaxStackDepth]uint64{0x1000}
				return nil
			}
			for range 2 {
				trace, err := fetchAndFormatStackTrace(42, stackLookup, lookup)
				require.ErrorContains(t, err, "loading kernel symbols")
				if tc.err != nil {
					require.ErrorIs(t, err, tc.err)
				}
				require.Empty(t, trace)
			}
			require.Equal(t, 1, loads, "failed initialization must not retry for every event")
		})
	}
}

func TestStackConverterResolvesKernelSymbols(t *testing.T) {
	utils.RequireRoot(t)
	require.NoError(t, rlimit.RemoveMemlock())
	address, _, err := kallsyms.KernelSymbolAddress("vfs_read")
	require.NoError(t, err)
	require.NotZero(t, address, "kernel symbol addresses must be available")
	symbols, err := kallsyms.NewKAllSyms()
	require.NoError(t, err)
	expected := symbols.LookupByInstructionPointer(address) + "; "

	mapSpec := &ebpf.MapSpec{
		Type:       ebpf.Hash,
		KeySize:    4,
		ValueSize:  8 * ebpftypes.KernelPerfMaxStackDepth,
		MaxEntries: 1,
	}
	stackMap, err := ebpf.NewMap(mapSpec)
	require.NoError(t, err)
	t.Cleanup(func() { stackMap.Close() })
	stack := [ebpftypes.KernelPerfMaxStackDepth]uint64{address}
	require.NoError(t, stackMap.Put(uint32(42), stack))

	ctx := newResolverGadgetCtx(t, nil)
	t.Cleanup(ctx.Cancel)
	ds, err := ctx.RegisterDataSource(datasource.TypeSingle, "stacks")
	require.NoError(t, err)
	in, err := ds.AddField("stack_raw", api.Kind_Uint32,
		datasource.WithTags("type:"+ebpftypes.KernelStackTypeName))
	require.NoError(t, err)
	instance := &ebpfInstance{
		logger: logger.DefaultLogger(),
		collectionSpec: &ebpf.CollectionSpec{
			Maps: map[string]*ebpf.MapSpec{ebpftypes.KernelStackMapName: mapSpec},
		},
		kernelStackMap: stackMap,
		formatters:     make(map[datasource.DataSource][]func(datasource.DataSource, datasource.Data) error),
	}
	require.NoError(t, instance.initStackConverter(ctx))
	require.Len(t, instance.formatters[ds], 1)
	data, err := ds.NewPacketSingle()
	require.NoError(t, err)
	require.NoError(t, in.PutUint32(data, 42))
	require.NoError(t, instance.formatters[ds][0](ds, data))
	actual, err := ds.GetField("stack").String(data)
	require.NoError(t, err)
	require.Equal(t, expected, actual)
}
