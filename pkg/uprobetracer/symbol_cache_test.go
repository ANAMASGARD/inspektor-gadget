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
	"bytes"
	"debug/elf"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/cilium/ebpf/link"
	"github.com/stretchr/testify/require"
)

func cacheTestFile(t *testing.T) *os.File {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "elf")
	require.NoError(t, err)
	_, err = f.WriteString("fixture")
	require.NoError(t, err)
	t.Cleanup(func() { f.Close() })
	return f
}

func TestSymbolCacheReuseEvictionAndErrors(t *testing.T) {
	f := cacheTestFile(t)
	c := newSymbolCache(2)
	calls := 0
	c.parse = func(*os.File, string) (symbolResult, error) { calls++; return symbolResult{}, nil }
	for range 2 {
		_, err := c.resolve(f, "absent")
		require.ErrorIs(t, err, link.ErrNoSymbol)
	}
	require.Equal(t, 1, calls)
	_, _ = c.resolve(f, "two")
	_, _ = c.resolve(f, "absent")
	_, _ = c.resolve(f, "three")
	_, _ = c.resolve(f, "two")
	require.Equal(t, 4, calls)
	c.parse = func(*os.File, string) (symbolResult, error) { calls++; return symbolResult{}, os.ErrPermission }
	for range 2 {
		_, err := c.resolve(f, "error")
		require.ErrorIs(t, err, os.ErrPermission)
	}
	require.Equal(t, 6, calls)
}

func TestSymbolCacheConcurrentMiss(t *testing.T) {
	f := cacheTestFile(t)
	c := newSymbolCache(2)
	var calls atomic.Int32
	started, release := make(chan struct{}), make(chan struct{})
	c.parse = func(*os.File, string) (symbolResult, error) {
		calls.Add(1)
		close(started)
		<-release
		return symbolResult{found: true, address: 123, size: 1}, nil
	}
	var wg sync.WaitGroup
	for range 20 {
		wg.Go(func() {
			got, err := c.resolve(f, "target")
			require.NoError(t, err)
			require.Equal(t, uint64(123), got)
		})
	}
	<-started
	close(release)
	wg.Wait()
	require.Equal(t, int32(1), calls.Load())
}

func TestSymbolCacheFileChanges(t *testing.T) {
	f := cacheTestFile(t)
	c := newSymbolCache(2)
	calls := 0
	c.parse = func(*os.File, string) (symbolResult, error) { calls++; return symbolResult{}, nil }
	_, _ = c.resolve(f, "target")
	before, err := fileSymbolVersion(f)
	require.NoError(t, err)
	info, err := f.Stat()
	require.NoError(t, err)
	require.Eventually(t, func() bool {
		_, err = f.WriteAt([]byte("changed"), 0)
		require.NoError(t, err)
		require.NoError(t, os.Chtimes(f.Name(), info.ModTime(), info.ModTime()))
		after, err := fileSymbolVersion(f)
		require.NoError(t, err)
		return after != before
	}, time.Second, time.Millisecond)
	_, _ = c.resolve(f, "target")
	require.Equal(t, 2, calls)
	replacement := cacheTestFile(t)
	_, _ = c.resolve(replacement, "target")
	require.Equal(t, 3, calls)
	require.NoError(t, f.Close())
	_, err = c.resolve(f, "target")
	require.Error(t, err)
}

func TestSymbolCacheDoesNotCacheConcurrentRewrite(t *testing.T) {
	f := cacheTestFile(t)
	c := newSymbolCache(2)
	c.parse = func(*os.File, string) (symbolResult, error) {
		require.NoError(t, f.Truncate(100))
		return symbolResult{found: true, address: 1, size: 1}, nil
	}
	_, err := c.resolve(f, "target")
	require.Error(t, err)
	require.Empty(t, c.entries)
}

func TestSymbolResultErrors(t *testing.T) {
	for _, tc := range []struct {
		result symbolResult
		want   error
	}{
		{symbolResult{}, link.ErrNoSymbol},
		{symbolResult{found: true, size: 1}, link.ErrNotSupported},
	} {
		_, err := tc.result.offset("target")
		require.True(t, errors.Is(err, tc.want))
	}
	_, err := (symbolResult{found: true, address: 1}).offset("target")
	require.ErrorContains(t, err, "out of range")
}

func TestSymbolCacheLongNames(t *testing.T) {
	f := cacheTestFile(t)
	c := newSymbolCache(2)
	c.parse = func(*os.File, string) (symbolResult, error) { return symbolResult{}, nil }
	_, err := c.resolve(f, strings.Repeat("x", 1025))
	require.ErrorIs(t, err, link.ErrNoSymbol)
	require.Empty(t, c.entries)
}

func TestSymbolCacheSymlinkAndDescriptorReuse(t *testing.T) {
	first, second := cacheTestFile(t), cacheTestFile(t)
	symlink := filepath.Join(t.TempDir(), "link")
	require.NoError(t, os.Symlink(first.Name(), symlink))
	c := newSymbolCache(4)
	calls := 0
	c.parse = func(*os.File, string) (symbolResult, error) { calls++; return symbolResult{}, nil }
	opened, err := os.Open(symlink)
	require.NoError(t, err)
	_, _ = c.resolve(opened, "target")
	fd := int(opened.Fd())
	require.NoError(t, os.Remove(symlink))
	require.NoError(t, os.Symlink(second.Name(), symlink))
	retargeted, err := os.Open(symlink)
	require.NoError(t, err)
	defer retargeted.Close()
	_, _ = c.resolve(retargeted, "target")
	require.Equal(t, 2, calls)
	_, _ = c.resolve(opened, "target")
	require.Equal(t, 2, calls) // old fd still identifies old inode
	// Replace the descriptor itself, rather than hoping the allocator reuses it.
	require.NoError(t, unix.Dup3(int(retargeted.Fd()), fd, unix.O_CLOEXEC))
	_, _ = c.resolve(opened, "different")
	require.Equal(t, 3, calls)
	_, _ = c.resolve(opened, "target")
	require.Equal(t, 3, calls)
	require.NoError(t, opened.Close())
}

func TestBindOrdinarySites(t *testing.T) {
	file := symbolFixture(t, elf.ELFCLASS64, elf.ET_DYN, []elf.Symbol{{Name: "target", Info: byte(elf.STT_FUNC), Value: 0x1020, Size: 10}}, nil)
	tr := &Tracer[struct{}]{attachSymbol: "target"}
	binds := 0
	bind := func(offset *uint64) (link.Link, error) {
		binds++
		require.NotNil(t, offset)
		require.Equal(t, uint64(0x220), *offset)
		require.Equal(t, *offset, uprobeOffsetOptions(offset).Address)
		return nil, nil
	}
	links, err := tr.bindOrdinarySites(file, nil, bind)
	require.NoError(t, err)
	require.Len(t, links, 1)
	tr.attachSymbol = "absent"
	for range 2 {
		_, err = tr.bindOrdinarySites(file, nil, bind)
		require.ErrorIs(t, err, link.ErrNoSymbol)
	}
	require.Equal(t, 1, binds)
	// The custom-offset path must not even stat or parse the file.
	links, err = tr.bindOrdinarySites(nil, []uint64{0x220}, bind)
	require.NoError(t, err)
	require.Len(t, links, 1)
}

// symbolFixture writes only the ELF structures needed by debug/elf. Using both
// classes exercises table decoding without a cross compiler or host binaries.
func symbolFixture(t testing.TB, class elf.Class, kind elf.Type, static, dynamic []elf.Symbol) *os.File {
	t.Helper()
	return symbolFixtureOrder(t, binary.LittleEndian, class, kind, static, dynamic)
}

func symbolFixtureOrder(t testing.TB, order binary.ByteOrder, class elf.Class, kind elf.Type, static, dynamic []elf.Symbol) *os.File {
	t.Helper()
	data := make([]byte, 4096)
	put := func(offset int, value any) {
		var out bytes.Buffer
		require.NoError(t, binary.Write(&out, order, value))
		copy(data[offset:], out.Bytes())
	}
	encoding := elf.ELFDATA2LSB
	if order == binary.BigEndian {
		encoding = elf.ELFDATA2MSB
	}
	ident := [16]byte{0x7f, 'E', 'L', 'F', byte(class), byte(encoding), byte(elf.EV_CURRENT)}
	const sections = 128
	const stringsAt = 512
	const staticAt = 1024
	const dynamicAt = 2048
	stringsTable := []byte{0}
	encode := func(symbols []elf.Symbol, at int) int {
		size := 24
		if class == elf.ELFCLASS32 {
			size = 16
		}
		for i, s := range symbols {
			name := len(stringsTable)
			stringsTable = append(stringsTable, []byte(s.Name)...)
			stringsTable = append(stringsTable, 0)
			if class == elf.ELFCLASS64 {
				put(at+(i+1)*size, elf.Sym64{Name: uint32(name), Info: s.Info, Value: s.Value, Size: s.Size, Shndx: uint16(s.Section)})
			} else {
				put(at+(i+1)*size, elf.Sym32{Name: uint32(name), Info: s.Info, Value: uint32(s.Value), Size: uint32(s.Size), Shndx: uint16(s.Section)})
			}
		}
		return (len(symbols) + 1) * size
	}
	staticSize, dynamicSize := encode(static, staticAt), encode(dynamic, dynamicAt)
	copy(data[stringsAt:], stringsTable)
	if class == elf.ELFCLASS64 {
		put(0, elf.Header64{Ident: ident, Type: uint16(kind), Machine: uint16(elf.EM_X86_64), Version: 1, Phoff: 64, Shoff: sections, Ehsize: 64, Phentsize: 56, Phnum: 1, Shentsize: 64, Shnum: 4})
		put(64, elf.Prog64{Type: uint32(elf.PT_LOAD), Flags: uint32(elf.PF_X), Off: 0x200, Vaddr: 0x1000, Memsz: 0x100})
		put(sections+64, elf.Section64{Type: uint32(elf.SHT_STRTAB), Off: stringsAt, Size: uint64(len(stringsTable))})
		put(sections+128, elf.Section64{Type: uint32(elf.SHT_SYMTAB), Off: staticAt, Size: uint64(staticSize), Link: 1, Entsize: 24})
		put(sections+192, elf.Section64{Type: uint32(elf.SHT_DYNSYM), Off: dynamicAt, Size: uint64(dynamicSize), Link: 1, Entsize: 24})
	} else {
		put(0, elf.Header32{Ident: ident, Type: uint16(kind), Machine: uint16(elf.EM_386), Version: 1, Phoff: 52, Shoff: sections, Ehsize: 52, Phentsize: 32, Phnum: 1, Shentsize: 40, Shnum: 4})
		put(52, elf.Prog32{Type: uint32(elf.PT_LOAD), Flags: uint32(elf.PF_X), Off: 0x200, Vaddr: 0x1000, Memsz: 0x100})
		put(sections+40, elf.Section32{Type: uint32(elf.SHT_STRTAB), Off: stringsAt, Size: uint32(len(stringsTable))})
		put(sections+80, elf.Section32{Type: uint32(elf.SHT_SYMTAB), Off: staticAt, Size: uint32(staticSize), Link: 1, Entsize: 16})
		put(sections+120, elf.Section32{Type: uint32(elf.SHT_DYNSYM), Off: dynamicAt, Size: uint32(dynamicSize), Link: 1, Entsize: 16})
	}
	f, err := os.CreateTemp(t.TempDir(), "symbols")
	require.NoError(t, err)
	_, err = f.Write(data)
	require.NoError(t, err)
	t.Cleanup(func() { f.Close() })
	return f
}

func TestParseOrdinarySymbolParity(t *testing.T) {
	fn := func(value, size uint64) elf.Symbol {
		return elf.Symbol{Name: "target", Info: byte(elf.STT_FUNC), Value: value, Size: size}
	}
	for _, class := range []elf.Class{elf.ELFCLASS32, elf.ELFCLASS64} {
		for _, tc := range []struct {
			name            string
			static, dynamic []elf.Symbol
			want            symbolResult
		}{
			{"static", []elf.Symbol{fn(0x1020, 10)}, nil, symbolResult{found: true, address: 0x220, size: 10}},
			{"dynamic override", []elf.Symbol{fn(0x1020, 10)}, []elf.Symbol{fn(0x1030, 20)}, symbolResult{found: true, address: 0x230, size: 20}},
			{"last wins", []elf.Symbol{fn(0x1020, 10), fn(0x1040, 30)}, nil, symbolResult{found: true, address: 0x240, size: 30}},
			{"undefined", []elf.Symbol{fn(0, 10)}, nil, symbolResult{found: true, size: 10}},
			{"zero size", []elf.Symbol{fn(0x1020, 0)}, nil, symbolResult{found: true, address: 0x220}},
			{"outside executable", []elf.Symbol{fn(0x2000, 10)}, nil, symbolResult{found: true, address: 0x2000, size: 10}},
			{"non function", []elf.Symbol{{Name: "target", Info: byte(elf.STT_OBJECT), Value: 0x1020, Size: 10}}, nil, symbolResult{}},
			{"absent", nil, nil, symbolResult{}},
		} {
			t.Run(class.String()+"/"+tc.name, func(t *testing.T) {
				f := symbolFixture(t, class, elf.ET_DYN, tc.static, tc.dynamic)
				got, err := parseOrdinarySymbol(f, "target")
				require.NoError(t, err)
				require.Equal(t, tc.want, got)
			})
		}
	}
	f := symbolFixture(t, elf.ELFCLASS64, elf.ET_REL, nil, nil)
	_, err := parseOrdinarySymbol(f, "target")
	require.Error(t, err)
	f = cacheTestFile(t)
	_, err = parseOrdinarySymbol(f, "target")
	require.Error(t, err)
}

func BenchmarkOrdinarySymbolAbsent(b *testing.B) {
	executable, err := os.Executable()
	require.NoError(b, err)
	f, err := os.Open(executable)
	require.NoError(b, err)
	defer f.Close()
	for _, warm := range []bool{false, true} {
		name := "parse"
		if warm {
			name = "cache"
		}
		b.Run(name, func(b *testing.B) {
			c := newSymbolCache(2048)
			_, _ = c.resolve(f, "absent_uprobe_symbol")
			b.ReportAllocs()
			for b.Loop() {
				if warm {
					_, err = c.resolve(f, "absent_uprobe_symbol")
					if !errors.Is(err, link.ErrNoSymbol) {
						b.Fatal(err)
					}
				} else {
					_, err = parseOrdinarySymbol(f, "absent_uprobe_symbol")
					if err != nil {
						b.Fatal(err)
					}
				}
			}
		})
	}
}

func TestParseOrdinarySymbolReadsDynamicErrors(t *testing.T) {
	f := symbolFixture(t, elf.ELFCLASS64, elf.ET_EXEC, []elf.Symbol{{Name: "target", Info: byte(elf.STT_FUNC), Value: 0x1020, Size: 10}}, nil)
	result, err := parseOrdinarySymbol(f, "target")
	require.NoError(t, err)
	require.Equal(t, uint64(0x220), result.address)
	// Corrupt the dynamic table's string-table link, after a valid static hit.
	_, err = f.WriteAt([]byte{99, 0, 0, 0}, 128+3*64+40)
	require.NoError(t, err)
	_, err = parseOrdinarySymbol(f, "target")
	require.Error(t, err)
	c := newSymbolCache(2)
	_, err = c.resolve(f, "target")
	require.Error(t, err)
	require.Empty(t, c.entries)
}

func TestParseOrdinarySymbolNonExecutableSegment(t *testing.T) {
	f := symbolFixture(t, elf.ELFCLASS64, elf.ET_EXEC, []elf.Symbol{{Name: "target", Info: byte(elf.STT_FUNC), Value: 0x1020, Size: 10}}, nil)
	_, err := f.WriteAt([]byte{byte(elf.PF_R), 0, 0, 0}, 64+4)
	require.NoError(t, err)
	result, err := parseOrdinarySymbol(f, "target")
	require.NoError(t, err)
	require.Equal(t, uint64(0x1020), result.address)
}
