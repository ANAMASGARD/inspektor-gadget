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

package uprobetracer

import (
	"container/list"
	"debug/elf"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"syscall"

	"github.com/cilium/ebpf/link"
)

// Keep only individual answers, never ELF symbol tables, executable objects or
// descriptors. The bound covers successes and stable negative answers alike.
var ordinarySymbols = newSymbolCache(2048)

type symbolVersion struct {
	device, inode     uint64
	size              int64
	modified, changed syscall.Timespec
}

type symbolKey struct {
	version symbolVersion
	name    string
}
type symbolResult struct {
	address, size uint64
	found         bool
}
type symbolEntry struct {
	key    symbolKey
	result symbolResult
}
type symbolFlight struct {
	done   chan struct{}
	result symbolResult
	err    error
}
type symbolCache struct {
	mu       sync.Mutex
	capacity int
	entries  map[symbolKey]*list.Element
	recent   list.List
	pending  map[symbolKey]*symbolFlight
	parse    func(*os.File, string) (symbolResult, error)
}

func newSymbolCache(capacity int) *symbolCache {
	return &symbolCache{capacity: capacity, entries: make(map[symbolKey]*list.Element), pending: make(map[symbolKey]*symbolFlight), parse: parseOrdinarySymbol}
}

func fileSymbolVersion(file *os.File) (symbolVersion, error) {
	info, err := file.Stat()
	if err != nil {
		return symbolVersion{}, err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return symbolVersion{}, fmt.Errorf("unsupported file stat for symbol lookup")
	}
	return symbolVersion{device: uint64(st.Dev), inode: st.Ino, size: st.Size, modified: st.Mtim, changed: st.Ctim}, nil
}

func (r symbolResult) offset(name string) (uint64, error) {
	if !r.found {
		return 0, fmt.Errorf("symbol %s: %w", name, link.ErrNoSymbol)
	}
	if r.address == 0 {
		return 0, fmt.Errorf("resolving library call %q: %w", name, link.ErrNotSupported)
	}
	if r.size == 0 {
		return 0, fmt.Errorf("offset 0 is out of range of symbol %s", name)
	}
	return r.address, nil
}

func (c *symbolCache) resolve(file *os.File, name string) (uint64, error) {
	version, err := fileSymbolVersion(file)
	if err != nil {
		return 0, err
	}
	// Symbol names normally come from gadget configuration. Do not let an
	// unbounded name turn the entry limit into an unbounded memory limit.
	if len(name) > 1024 {
		result, err := c.parse(file, name)
		if err != nil {
			return 0, err
		}
		current, err := fileSymbolVersion(file)
		if err != nil {
			return 0, err
		}
		if current != version {
			return 0, fmt.Errorf("file changed during symbol lookup")
		}
		return result.offset(name)
	}
	key := symbolKey{version: version, name: name}
	c.mu.Lock()
	if entry := c.entries[key]; entry != nil {
		c.recent.MoveToFront(entry)
		result := entry.Value.(symbolEntry).result
		c.mu.Unlock()
		return result.offset(name)
	}
	if flight := c.pending[key]; flight != nil {
		c.mu.Unlock()
		<-flight.done
		if flight.err != nil {
			return 0, flight.err
		}
		current, err := fileSymbolVersion(file)
		if err != nil {
			return 0, err
		}
		if current != version {
			return 0, fmt.Errorf("file changed during symbol lookup")
		}
		return flight.result.offset(name)
	}
	// Copy only on a miss: a short name may otherwise retain a large backing string.
	key.name = strings.Clone(name)
	flight := &symbolFlight{done: make(chan struct{})}
	c.pending[key] = flight
	c.mu.Unlock()
	result, err := c.parse(file, name)
	if err == nil {
		current, statErr := fileSymbolVersion(file)
		if statErr != nil {
			err = statErr
		} else if current != version {
			err = fmt.Errorf("file changed during symbol lookup")
		}
	}
	c.mu.Lock()
	if err == nil {
		c.entries[key] = c.recent.PushFront(symbolEntry{key: key, result: result})
		if c.recent.Len() > c.capacity {
			oldest := c.recent.Back()
			delete(c.entries, oldest.Value.(symbolEntry).key)
			c.recent.Remove(oldest)
		}
	}
	flight.result, flight.err = result, err
	delete(c.pending, key)
	close(flight.done)
	c.mu.Unlock()
	if err != nil {
		return 0, err
	}
	return result.offset(name)
}

// parseOrdinarySymbol matches cilium/ebpf v0.22's ordinary-symbol lookup,
// including dynamic table precedence, zero-address rejection and executable
// segment translation. It streams the tables instead of materializing them
// (see symbol_stream.go): memory use is a few fixed-size buffers plus one
// offset per occurrence of the wanted name in the string table, and does not
// depend on the binary's symbol count.
func parseOrdinarySymbol(file *os.File, name string) (result symbolResult, err error) {
	// debug/elf may panic on malformed input; cilium's SafeELFFile likewise
	// converts such panics to errors. They must never populate the negative cache.
	defer func() {
		if value := recover(); value != nil {
			result = symbolResult{}
			err = fmt.Errorf("reading ELF symbols: %v", value)
		}
	}()
	f, err := elf.NewFile(file)
	if err != nil {
		return result, err
	}
	if f.Type != elf.ET_EXEC && f.Type != elf.ET_DYN {
		return result, fmt.Errorf("the given file is not an executable or a shared object")
	}
	scanner := newSymbolScanner(f, name)
	defer scanner.release()
	for _, typ := range []elf.SectionType{elf.SHT_SYMTAB, elf.SHT_DYNSYM} {
		if err := scanner.scan(typ); err != nil && !errors.Is(err, elf.ErrNoSymbols) {
			return symbolResult{}, err
		}
	}
	return scanner.result, nil
}

// bindOrdinarySites keeps custom offsets intact and resolves ordinary names
// before binding, so cilium receives a nonzero explicit address and never
// materializes its full symbol map on this path. USDT bypasses this helper.
func (t *Tracer[Event]) bindOrdinarySites(file *os.File, offsets []uint64, bind func(*uint64) (link.Link, error)) ([]link.Link, error) {
	if len(offsets) == 0 {
		offset, err := ordinarySymbols.resolve(file, t.attachSymbol)
		if err != nil {
			return nil, err
		}
		offsets = []uint64{offset}
	}
	return t.bindSites(offsets, bind)
}
