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

package ebpfoperator

import (
	"bytes"
	"reflect"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/content/memory"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

func TestMappedLibContextPatternPreservesLegacyStartup(t *testing.T) {
	SetMappedLibPattern(regexp.MustCompile(`^libnetty.*\.so$`))
	t.Cleanup(func() { SetMappedLibPattern(nil) })
	legacy := mappedLibPatternGlobal.Load()
	sslCtx := newResolverGadgetCtx(t, nil)
	sslCtx.SetVar(MappedLibRetryPatternVar, regexp.MustCompile(`^libssl\.so\.3$`))
	otherCtx := newResolverGadgetCtx(t, nil)

	ssl, other := &ebpfInstance{}, &ebpfInstance{}
	if err := ssl.configureMappedLibPatterns(sslCtx); err != nil {
		t.Fatal(err)
	}
	if err := other.configureMappedLibPatterns(otherCtx); err != nil {
		t.Fatal(err)
	}
	if !ssl.mappedLibPattern.MatchString("libssl.so.3") || !ssl.mappedLibPattern.MatchString("libnetty.so") {
		t.Fatalf("retry matcher lost context or legacy pattern: %s", ssl.mappedLibPattern)
	}
	if other.mappedLibPattern != legacy || other.mappedLibPattern.MatchString("libssl.so.3") {
		t.Fatal("context matcher leaked into unrelated instance")
	}
	if mappedLibPatternGlobal.Load() != legacy {
		t.Fatal("context registration changed the global matcher")
	}
	for _, instance := range []*ebpfInstance{ssl, other} {
		if instance.startupMappedLibPattern != legacy {
			t.Fatal("startup scan did not retain only the legacy matcher")
		}
		tracer, err := instance.newUprobeTracer(sslCtx)
		if err != nil {
			t.Fatal(err)
		}
		// Check the actual tracer wiring without exporting a production getter
		// just for tests. Pointer inspection needs no unsafe access.
		got := reflect.ValueOf(tracer).Elem().FieldByName("startupMappedLibPattern").Pointer()
		if got != reflect.ValueOf(legacy).Pointer() {
			t.Fatal("uprobe tracer received the retry union instead of the legacy startup matcher")
		}
	}
	SetMappedLibPattern(nil)
	if !ssl.mappedLibPattern.MatchString("libnetty.so") || other.mappedLibPattern != legacy {
		t.Fatal("later global mutation changed an existing instance's snapshot")
	}
}

func TestMappedLibContextDispatchIsScoped(t *testing.T) {
	SetMappedLibPattern(nil)
	t.Cleanup(func() { SetMappedLibPattern(nil) })
	shrinkBackoff(t)
	var sslCalls, otherCalls atomic.Int32
	ssl := newTimerInstance(func(_ uint32, _ []uint32, pattern *regexp.Regexp, _ time.Time) (bool, []uint32) {
		if pattern.MatchString("libssl.so.3") {
			sslCalls.Add(1)
		}
		return true, nil
	})
	other := newTimerInstance(func(_ uint32, _ []uint32, _ *regexp.Regexp, _ time.Time) (bool, []uint32) {
		otherCalls.Add(1)
		return false, nil
	})
	sslCtx := newResolverGadgetCtx(t, nil)
	sslCtx.SetVar(MappedLibRetryPatternVar, regexp.MustCompile(`^libssl\.so\.3$`))
	if err := ssl.configureMappedLibPatterns(sslCtx); err != nil {
		t.Fatal(err)
	}
	if err := other.configureMappedLibPatterns(newResolverGadgetCtx(t, nil)); err != nil {
		t.Fatal(err)
	}
	container := &containercollection.Container{Runtime: containercollection.RuntimeMetadata{
		BasicRuntimeMetadata: types.BasicRuntimeMetadata{ContainerPID: 100},
	}}
	for _, instance := range []*ebpfInstance{ssl, other} {
		if instance.startupMappedLibPattern != nil {
			t.Fatal("context matcher enabled startup discovery")
		}
		if err := instance.ReattachContainer(container, 200); err != nil {
			t.Fatal(err)
		}
		instance.mappedLibTimers.wg.Wait()
	}
	if sslCalls.Load() != mappedLibRetryAttempts || otherCalls.Load() != 0 {
		t.Fatalf("retry passes: SSL=%d, unrelated=%d", sslCalls.Load(), otherCalls.Load())
	}
	if mappedLibPatternGlobal.Load() != nil {
		t.Fatal("context matcher enabled global discovery")
	}
}

func TestMappedLibContextPatternValues(t *testing.T) {
	for _, legacy := range []*regexp.Regexp{nil, regexp.MustCompile(`^libnetty.*\.so$`)} {
		SetMappedLibPattern(legacy)
		t.Cleanup(func() { SetMappedLibPattern(nil) })
		for _, tc := range []struct {
			name    string
			value   any
			invalid bool
		}{
			{name: "nil", value: nil},
			{name: "typed nil", value: (*regexp.Regexp)(nil)},
			{name: "string", value: "libssl", invalid: true},
			{name: "regexp value", value: *regexp.MustCompile("libssl"), invalid: true},
		} {
			t.Run(tc.name, func(t *testing.T) {
				ctx := newResolverGadgetCtx(t, nil)
				ctx.SetVar(MappedLibRetryPatternVar, tc.value)
				instance := &ebpfInstance{}
				err := instance.configureMappedLibPatterns(ctx)
				if tc.invalid {
					if err == nil || !strings.Contains(err.Error(), MappedLibRetryPatternVar) || !strings.Contains(err.Error(), "expected *regexp.Regexp") {
						t.Fatalf("expected clear invalid-context error, got %v", err)
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				if instance.mappedLibPattern != mappedLibPatternGlobal.Load() || instance.startupMappedLibPattern != mappedLibPatternGlobal.Load() {
					t.Fatal("nil context value changed legacy behavior")
				}
			})
		}
	}
}

// Exercise the real construction entry point: context validation must not be
// accidentally skipped when the helper changes.
func TestMappedLibContextInvalidValueFailsConstruction(t *testing.T) {
	ctx := newResolverGadgetCtx(t, nil)
	ctx.SetVar(MappedLibRetryPatternVar, "not a regexp")
	program := []byte("validation precedes ELF loading")
	desc := content.NewDescriptorFromBytes("application/octet-stream", program)
	store := memory.New()
	if err := store.Push(ctx.Context(), desc, bytes.NewReader(program)); err != nil {
		t.Fatal(err)
	}
	op := &ebpfOperator{}
	instance, err := op.InstantiateImageOperator(ctx, store, desc, nil)
	if instance != nil || err == nil || !strings.Contains(err.Error(), MappedLibRetryPatternVar) {
		t.Fatalf("construction accepted invalid context matcher: instance=%v, err=%v", instance, err)
	}
}

// A compiled regexp may quote to end-of-input. Appending a grouping suffix
// changes its parse, so valid individual regexps need not form a valid union.
func TestMappedLibContextUncombinablePatternReturnsError(t *testing.T) {
	SetMappedLibPattern(regexp.MustCompile(`^libnetty.*\.so$`))
	t.Cleanup(func() { SetMappedLibPattern(nil) })
	legacy := mappedLibPatternGlobal.Load()
	pattern := regexp.MustCompile(`\Qlibssl.so.3`)
	if !pattern.MatchString("libssl.so.3") {
		t.Fatal("regression requires a valid standalone context matcher")
	}
	ctx := newResolverGadgetCtx(t, nil)
	ctx.SetVar(MappedLibRetryPatternVar, pattern)
	instance := &ebpfInstance{}
	err := instance.configureMappedLibPatterns(ctx)
	if err == nil || !strings.Contains(err.Error(), MappedLibRetryPatternVar) {
		t.Fatalf("expected a contextual combination error, got %v", err)
	}
	if instance.mappedLibPattern != legacy || instance.startupMappedLibPattern != legacy || mappedLibPatternGlobal.Load() != legacy {
		t.Fatal("failed combination changed legacy or startup registration")
	}

	program := []byte("combination validation precedes ELF loading")
	desc := content.NewDescriptorFromBytes("application/octet-stream", program)
	store := memory.New()
	if err := store.Push(ctx.Context(), desc, bytes.NewReader(program)); err != nil {
		t.Fatal(err)
	}
	op := &ebpfOperator{}
	constructed, err := op.InstantiateImageOperator(ctx, store, desc, nil)
	if constructed != nil || err == nil || !strings.Contains(err.Error(), MappedLibRetryPatternVar) {
		t.Fatalf("construction accepted an invalid matcher union: instance=%v, err=%v", constructed, err)
	}
}
