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
	"fmt"
	"io"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

// parseOrdinarySymbolMaterialized is the lookup that parseOrdinarySymbol
// replaced, kept verbatim as the oracle: it materializes every symbol through
// debug/elf and so allocates in proportion to the symbol count. The streaming
// lookup must return exactly what this returns.
func parseOrdinarySymbolMaterialized(file *os.File, name string) (result symbolResult, err error) {
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
	for _, read := range []func() ([]elf.Symbol, error){f.Symbols, f.DynamicSymbols} {
		symbols, readErr := read()
		if readErr != nil && !errors.Is(readErr, elf.ErrNoSymbols) {
			return symbolResult{}, readErr
		}
		for _, s := range symbols {
			if s.Name != name || elf.ST_TYPE(s.Info) != elf.STT_FUNC {
				continue
			}
			address := s.Value
			for _, p := range f.Progs {
				if p.Type == elf.PT_LOAD && p.Flags&elf.PF_X != 0 && p.Vaddr <= s.Value && s.Value < p.Vaddr+p.Memsz {
					address = s.Value - p.Vaddr + p.Off
					break
				}
			}
			result = symbolResult{found: true, address: address, size: s.Size}
		}
	}
	return result, nil
}

// requireSameLookup fails unless the oracle and the streaming lookup agree on
// the result, or both fail. Error text is not compared: only error versus
// success decides whether a probe attaches and whether the answer is cached.
func requireSameLookup(t testing.TB, f *os.File, name string) {
	t.Helper()
	want, wantErr := parseOrdinarySymbolMaterialized(f, name)
	got, gotErr := parseOrdinarySymbol(f, name)
	if (wantErr != nil) != (gotErr != nil) {
		t.Fatalf("%s: name %q: error mismatch: oracle=%v streaming=%v", f.Name(), name, wantErr, gotErr)
	}
	if wantErr == nil && want != got {
		t.Fatalf("%s: name %q: oracle=%+v streaming=%+v", f.Name(), name, want, got)
	}
}

// corpusFiles lists real binaries for the differential test: the test binary
// itself (a Go executable), the system C library when present, the Go
// toolchain's own binary, and whatever SYMSTREAM_CORPUS (a path list) adds.
// A fuller corpus is built with, for example:
//
//	go build -buildmode=pie -o pie ./some/main
//	go build -ldflags='-s -w' -o stripped ./some/main
//	GOARCH=386 go build -o elf32 ./some/main      # 32-bit little endian
//	GOARCH=mips go build -o elf32be ./some/main   # 32-bit big endian
//	GOARCH=s390x go build -o elf64be ./some/main  # 64-bit big endian
//	cc -shared -fPIC -o libx.so x.c               # C shared object
func corpusFiles(t testing.TB) []string {
	t.Helper()
	var files []string
	if exe, err := os.Executable(); err == nil {
		files = append(files, exe)
	}
	for _, pattern := range []string{"/lib/*/libc.so.6", "/usr/lib/*/libc.so.6", "/lib64/libc.so.6", "/usr/lib64/libc.so.6", "/lib/*/libssl.so*", "/usr/lib/*/libssl.so*"} {
		matches, _ := filepath.Glob(pattern)
		files = append(files, matches...)
	}
	if goBin, err := exec.LookPath("go"); err == nil {
		files = append(files, goBin)
	}
	for _, p := range filepath.SplitList(os.Getenv("SYMSTREAM_CORPUS")) {
		if p != "" {
			files = append(files, p)
		}
	}
	// Symlinks (libssl.so -> libssl.so.3) would repeat a file.
	var unique []string
	seen := map[string]bool{}
	for _, p := range files {
		real, err := filepath.EvalSymlinks(p)
		if err != nil || seen[real] {
			continue
		}
		seen[real] = true
		unique = append(unique, real)
	}
	return unique
}

// symbolNamesOf returns every distinct symbol name of both tables, split into
// function and non-function names, by reading them the way the oracle does.
func symbolNamesOf(f *elf.File) (funcs, others []string) {
	seenFunc, seenOther := map[string]bool{}, map[string]bool{}
	for _, read := range []func() ([]elf.Symbol, error){f.Symbols, f.DynamicSymbols} {
		symbols, _ := read()
		for _, s := range symbols {
			switch {
			case elf.ST_TYPE(s.Info) == elf.STT_FUNC && !seenFunc[s.Name]:
				seenFunc[s.Name] = true
				funcs = append(funcs, s.Name)
			case elf.ST_TYPE(s.Info) != elf.STT_FUNC && !seenOther[s.Name]:
				seenOther[s.Name] = true
				others = append(others, s.Name)
			}
		}
	}
	slices.Sort(funcs)
	slices.Sort(others)
	return funcs, others
}

// Every function symbol of a binary, up to a bound, must resolve identically.
func TestParseOrdinarySymbolMatchesMaterializedOnRealBinaries(t *testing.T) {
	files := corpusFiles(t)
	require.NotEmpty(t, files)
	for _, path := range files {
		t.Run(filepath.Base(path), func(t *testing.T) {
			file, err := os.Open(path)
			require.NoError(t, err)
			defer file.Close()
			ef, err := elf.NewFile(file)
			if err != nil {
				t.Skipf("not an ELF file: %v", err)
			}
			funcs, others := symbolNamesOf(ef)
			t.Logf("%s: class=%v order=%v type=%v function names=%d other names=%d", path, ef.Class, ef.ByteOrder, ef.Type, len(funcs), len(others))

			// The oracle is slow on a big binary (it re-materializes all symbols
			// per call), so large inputs are sampled: a deterministic stride that
			// always includes the first and last names of the sorted list. Setting
			// SYMSTREAM_FULL=1 checks every name.
			limit := 400
			if os.Getenv("SYMSTREAM_FULL") != "" {
				limit = len(funcs)
			}
			var sample []string
			if len(funcs) <= limit {
				sample = funcs
			} else {
				for i := range limit {
					sample = append(sample, funcs[i*(len(funcs)-1)/(limit-1)])
				}
			}
			for _, name := range sample {
				requireSameLookup(t, file, name)
				// Prefixes, suffixes and near misses of real names: each must match
				// the oracle (almost always "absent"), never a longer or shorter name.
				if len(name) > 1 {
					requireSameLookup(t, file, name[:len(name)-1])
					requireSameLookup(t, file, name[1:])
				}
				requireSameLookup(t, file, name+"x")
				requireSameLookup(t, file, name+"\x00")
				requireSameLookup(t, file, "x"+name)
			}
			for i := 0; i < len(others) && i < 40; i++ {
				requireSameLookup(t, file, others[i*max(1, len(others)/40)%len(others)])
			}
			for _, name := range []string{"", "\x00", "absent_uprobe_symbol", strings.Repeat("a", 5000), "SSL_read", "SSL_write", "malloc", "main.main", "runtime.main"} {
				requireSameLookup(t, file, name)
			}

			// Independent expectation for every function name: a single pass over
			// the materialized tables with the oracle's own rules (last match wins,
			// dynamic table last). This is the "all names" check without paying one
			// oracle call per name; it is itself validated by the sampled calls above.
			if len(funcs) <= 3000 || os.Getenv("SYMSTREAM_FULL") != "" {
				want := map[string]symbolResult{}
				for _, read := range []func() ([]elf.Symbol, error){ef.Symbols, ef.DynamicSymbols} {
					symbols, _ := read()
					for _, s := range symbols {
						if elf.ST_TYPE(s.Info) != elf.STT_FUNC {
							continue
						}
						address := s.Value
						for _, p := range ef.Progs {
							if p.Type == elf.PT_LOAD && p.Flags&elf.PF_X != 0 && p.Vaddr <= s.Value && s.Value < p.Vaddr+p.Memsz {
								address = s.Value - p.Vaddr + p.Off
								break
							}
						}
						want[s.Name] = symbolResult{found: true, address: address, size: s.Size}
					}
				}
				for _, name := range funcs {
					got, err := parseOrdinarySymbol(file, name)
					require.NoError(t, err, name)
					require.Equal(t, want[name], got, name)
				}
			}
		})
	}
}

// fixtureSymbols exercises: duplicates inside and across tables, names that are
// prefixes or suffixes of each other, a non-function with a function's name, an
// undefined function (value 0) and a name that only lives in the dynamic table.
func fixtureSymbols() (static, dynamic []elf.Symbol) {
	fn := func(name string, value, size uint64) elf.Symbol {
		return elf.Symbol{Name: name, Info: byte(elf.STT_FUNC), Value: value, Size: size}
	}
	static = []elf.Symbol{
		fn("target", 0x1020, 10),
		fn("target_longer", 0x1030, 11),
		fn("targe", 0x1040, 12),
		fn("arget", 0x1050, 13),
		{Name: "object_only", Info: byte(elf.STT_OBJECT), Value: 0x1060, Size: 14},
		fn("undef", 0, 15),
		fn("target", 0x1070, 16),
		fn("arget", 0x2000, 17),
	}
	dynamic = []elf.Symbol{
		fn("target", 0x1080, 18),
		fn("dyn_only", 0x1090, 19),
		{Name: "object_only", Info: byte(elf.STT_OBJECT), Value: 0x10a0, Size: 20},
	}
	return static, dynamic
}

var fixtureNames = []string{"target", "target_longer", "targe", "arget", "get", "t", "targ", "target_", "target_longerx", "object_only", "undef", "dyn_only", "dyn_onl", "yn_only", "absent", "", "ta\x00rget"}

func readAll(t testing.TB, f *os.File) []byte {
	t.Helper()
	data, err := os.ReadFile(f.Name())
	require.NoError(t, err)
	return data
}

// Section header field offsets inside the fixture, whose section table starts
// at byte 128 (1 = strings, 2 = symtab, 3 = dynsym).
func fixtureSection(class elf.Class, index int) (header int, off, size, link, entsize int) {
	if class == elf.ELFCLASS64 {
		return 128 + 64*index, 24, 32, 40, 56
	}
	return 128 + 40*index, 16, 20, 24, 36
}

func putUint(t testing.TB, data []byte, class elf.Class, at int, wide bool, value uint64) {
	t.Helper()
	if wide && class == elf.ELFCLASS64 {
		binary.LittleEndian.PutUint64(data[at:], value)
		return
	}
	binary.LittleEndian.PutUint32(data[at:], uint32(value))
}

// stringTableModes runs a test once per way of reaching the string table. The
// fixtures are small, so by default they take the whole-table path; "window"
// forces the sliding window that large Go binaries use.
var stringTableModes = []struct {
	name  string
	limit uint64
}{
	{"whole", wholeStringTableMax},
	{"window", 0},
}

func forEachStringTableMode(t *testing.T, test func(t *testing.T)) {
	for _, mode := range stringTableModes {
		t.Run(mode.name, func(t *testing.T) {
			saved := wholeStringTableLimit
			wholeStringTableLimit = mode.limit
			t.Cleanup(func() { wholeStringTableLimit = saved })
			test(t)
		})
	}
}

// Crafted and corrupted files: the streaming lookup must agree with the oracle
// on both the answer and on whether the file is rejected, through both string
// table paths.
func TestParseOrdinarySymbolMatchesMaterializedOnMalformedFiles(t *testing.T) {
	forEachStringTableMode(t, checkMalformedFiles)
}

func checkMalformedFiles(t *testing.T) {
	static, dynamic := fixtureSymbols()
	for _, class := range []elf.Class{elf.ELFCLASS32, elf.ELFCLASS64} {
		base := readAll(t, symbolFixture(t, class, elf.ET_DYN, static, dynamic))
		sec := func(index int) (h, off, size, link, entsize int) { return fixtureSection(class, index) }
		set := func(data []byte, index, field int, value uint64) {
			h, off, size, link, entsize := sec(index)
			at := h + map[int]int{0: off, 1: size, 2: link, 3: entsize}[field]
			putUint(t, data, class, at, field != 2, value)
		}
		const offF, sizeF, linkF, entF = 0, 1, 2, 3
		get := func(data []byte, index, field int) uint64 {
			h, off, size, link, entsize := sec(index)
			at := h + map[int]int{0: off, 1: size, 2: link, 3: entsize}[field]
			if field != 2 && class == elf.ELFCLASS64 {
				return binary.LittleEndian.Uint64(data[at:])
			}
			return uint64(binary.LittleEndian.Uint32(data[at:]))
		}
		entSize := 24
		if class == elf.ELFCLASS32 {
			entSize = 16
		}
		// Byte offset of the type field of section header `index`.
		typeAt := func(index int) int { h, _, _, _, _ := sec(index); return h + 4 }
		symOff := func(table, i int) int { return int(get(base, table, offF)) + i*entSize }

		type mutation struct {
			name string
			do   func(data []byte) []byte
		}
		mutations := []mutation{
			{"unchanged", func(d []byte) []byte { return d }},
			{"truncated inside symtab", func(d []byte) []byte { return d[:symOff(2, 3)] }},
			{"truncated inside dynsym", func(d []byte) []byte { return d[:symOff(3, 1)+5] }},
			{"truncated before strings end", func(d []byte) []byte { return d[:int(get(d, 1, offF))+int(get(d, 1, sizeF))-3] }},
			{"truncated to the section headers", func(d []byte) []byte { return d[:400] }},
			{"symtab size not a multiple", func(d []byte) []byte { set(d, 2, sizeF, get(d, 2, sizeF)+1); return d }},
			{"dynsym size not a multiple", func(d []byte) []byte { set(d, 3, sizeF, get(d, 3, sizeF)-3); return d }},
			{"symtab size zero", func(d []byte) []byte { set(d, 2, sizeF, 0); return d }},
			{"dynsym size zero", func(d []byte) []byte { set(d, 3, sizeF, 0); return d }},
			{"symtab only the null entry", func(d []byte) []byte { set(d, 2, sizeF, uint64(entSize)); return d }},
			{"symtab size beyond the file", func(d []byte) []byte { set(d, 2, sizeF, uint64(entSize)*100000); return d }},
			{"symtab huge size", func(d []byte) []byte { set(d, 2, sizeF, 1<<40); return d }},
			{"entsize zero", func(d []byte) []byte { set(d, 2, entF, 0); set(d, 3, entF, 0); return d }},
			{"entsize odd", func(d []byte) []byte { set(d, 2, entF, 7); set(d, 3, entF, 1); return d }},
			{"entsize huge", func(d []byte) []byte { set(d, 2, entF, 1<<30); return d }},
			{"symtab link zero", func(d []byte) []byte { set(d, 2, linkF, 0); return d }},
			{"symtab link out of range", func(d []byte) []byte { set(d, 2, linkF, 99); return d }},
			{"dynsym link out of range", func(d []byte) []byte { set(d, 3, linkF, 99); return d }},
			{"symtab links to itself", func(d []byte) []byte { set(d, 2, linkF, 2); return d }},
			{"dynsym links to symtab", func(d []byte) []byte { set(d, 3, linkF, 2); return d }},
			{"strings size zero", func(d []byte) []byte { set(d, 1, sizeF, 0); return d }},
			{"strings size one", func(d []byte) []byte { set(d, 1, sizeF, 1); return d }},
			{"strings unterminated at the end", func(d []byte) []byte { set(d, 1, sizeF, get(d, 1, sizeF)-1); return d }},
			{"strings cut mid name", func(d []byte) []byte { set(d, 1, sizeF, get(d, 1, sizeF)-5); return d }},
			{"strings size beyond the file", func(d []byte) []byte { set(d, 1, sizeF, 1<<20); return d }},
			{"strings offset beyond the file", func(d []byte) []byte { set(d, 1, offF, 1<<20); return d }},
			{"strings is NOBITS", func(d []byte) []byte { binary.LittleEndian.PutUint32(d[typeAt(1):], uint32(elf.SHT_NOBITS)); return d }},
			{"strings is NOBITS and empty", func(d []byte) []byte {
				binary.LittleEndian.PutUint32(d[typeAt(1):], uint32(elf.SHT_NOBITS))
				set(d, 1, sizeF, 0)
				return d
			}},
			{"symtab is NOBITS", func(d []byte) []byte { binary.LittleEndian.PutUint32(d[typeAt(2):], uint32(elf.SHT_NOBITS)); return d }},
			{"dynsym is NOBITS", func(d []byte) []byte { binary.LittleEndian.PutUint32(d[typeAt(3):], uint32(elf.SHT_NOBITS)); return d }},
			{"symtab retyped as dynsym", func(d []byte) []byte { binary.LittleEndian.PutUint32(d[typeAt(2):], uint32(elf.SHT_DYNSYM)); return d }},
			{"dynsym retyped as symtab", func(d []byte) []byte { binary.LittleEndian.PutUint32(d[typeAt(3):], uint32(elf.SHT_SYMTAB)); return d }},
			{"no symbol sections", func(d []byte) []byte {
				binary.LittleEndian.PutUint32(d[typeAt(2):], uint32(elf.SHT_PROGBITS))
				binary.LittleEndian.PutUint32(d[typeAt(3):], uint32(elf.SHT_PROGBITS))
				return d
			}},
			{"st_name past the string table", func(d []byte) []byte {
				binary.LittleEndian.PutUint32(d[symOff(2, 1):], 0xfffffff0)
				binary.LittleEndian.PutUint32(d[symOff(2, 2):], uint32(get(d, 1, sizeF)))
				binary.LittleEndian.PutUint32(d[symOff(3, 1):], 0x80000000)
				return d
			}},
			{"st_name into the middle of a name", func(d []byte) []byte {
				binary.LittleEndian.PutUint32(d[symOff(2, 1):], binary.LittleEndian.Uint32(d[symOff(2, 2):])+2)
				return d
			}},
			{"st_name zero on functions", func(d []byte) []byte {
				binary.LittleEndian.PutUint32(d[symOff(2, 1):], 0)
				binary.LittleEndian.PutUint32(d[symOff(3, 2):], 0)
				return d
			}},
			{"embedded NUL in the strings", func(d []byte) []byte {
				d[int(get(d, 1, offF))+4] = 0
				return d
			}},
			{"all symbols are undefined section", func(d []byte) []byte {
				for i := 1; i <= len(static); i++ {
					at := symOff(2, i) + 6
					if class == elf.ELFCLASS32 {
						at = symOff(2, i) + 14
					}
					binary.LittleEndian.PutUint16(d[at:], 0)
				}
				return d
			}},
			{"executable type", func(d []byte) []byte { binary.LittleEndian.PutUint16(d[16:], uint16(elf.ET_EXEC)); return d }},
			{"relocatable type", func(d []byte) []byte { binary.LittleEndian.PutUint16(d[16:], uint16(elf.ET_REL)); return d }},
			{"no program headers", func(d []byte) []byte {
				binary.LittleEndian.PutUint16(d[map[elf.Class]int{elf.ELFCLASS64: 56, elf.ELFCLASS32: 44}[class]:], 0)
				return d
			}},
		}
		for _, m := range mutations {
			t.Run(class.String()+"/"+m.name, func(t *testing.T) {
				data := m.do(bytes.Clone(base))
				path := filepath.Join(t.TempDir(), "elf")
				require.NoError(t, os.WriteFile(path, data, 0o600))
				f, err := os.Open(path)
				require.NoError(t, err)
				defer f.Close()
				for _, name := range fixtureNames {
					requireSameLookup(t, f, name)
				}
			})
		}

		// Random corruption of everything the lookup reads: the ELF header,
		// program header, section headers, both symbol tables and the strings.
		t.Run(class.String()+"/random corruption", func(t *testing.T) {
			rng := rand.New(rand.NewSource(1))
			path := filepath.Join(t.TempDir(), "elf")
			f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
			require.NoError(t, err)
			defer f.Close()
			for i := range 4000 {
				data := bytes.Clone(base)
				for range 1 + rng.Intn(4) {
					at := rng.Intn(2400)
					if rng.Intn(3) == 0 {
						at = 128 + rng.Intn(260) // section headers
					}
					data[at] = byte(rng.Intn(256))
				}
				if rng.Intn(10) == 0 {
					data = data[:rng.Intn(len(data))]
				}
				require.NoError(t, f.Truncate(0))
				_, err = f.WriteAt(data, 0)
				require.NoError(t, err)
				for _, name := range []string{"target", "arget", "dyn_only", "undef", "", "targe", "object_only"} {
					want, wantErr := parseOrdinarySymbolMaterialized(f, name)
					got, gotErr := parseOrdinarySymbol(f, name)
					if (wantErr != nil) != (gotErr != nil) || (wantErr == nil && want != got) {
						t.Fatalf("iteration %d name %q: oracle=%+v/%v streaming=%+v/%v", i, name, want, wantErr, got, gotErr)
					}
				}
			}
		})
	}
}

// The known divergence from the oracle, documented: debug/elf's DynamicSymbols
// also parses the GNU symbol-version tables and fails the whole lookup if they
// are corrupt, although versions play no part in finding a name. The streaming
// lookup does not read them, so it answers where the oracle errors.
func TestParseOrdinarySymbolIgnoresCorruptVersionTables(t *testing.T) {
	var data []byte
	var f *elf.File
	var verneed *elf.Section
	for _, path := range corpusFiles(t) {
		content, err := os.ReadFile(path)
		require.NoError(t, err)
		candidate, err := elf.NewFile(bytes.NewReader(content))
		if err != nil {
			continue
		}
		if section := candidate.SectionByType(elf.SHT_GNU_VERNEED); section != nil && candidate.SectionByType(elf.SHT_DYNSYM) != nil {
			data, f, verneed = content, candidate, section
			break
		}
	}
	if verneed == nil {
		skipOffLinux(t, "no corpus file with GNU version-need tables")
	}
	// vn_version must be 1; debug/elf rejects anything else.
	corrupt := bytes.Clone(data)
	f.ByteOrder.PutUint16(corrupt[verneed.Offset:], 2)
	path := filepath.Join(t.TempDir(), "libc")
	require.NoError(t, os.WriteFile(path, corrupt, 0o600))
	file, err := os.Open(path)
	require.NoError(t, err)
	defer file.Close()
	_, oracleErr := parseOrdinarySymbolMaterialized(file, "malloc")
	got, err := parseOrdinarySymbol(file, "malloc")
	require.NoError(t, err)
	require.True(t, got.found)
	t.Logf("oracle on corrupt version table: %v", oracleErr)
	require.Error(t, oracleErr, "the oracle is expected to reject this file")
}

// skipOffLinux skips a test whose corpus is missing, except on Linux, where the
// system C library is always in the corpus and a missing file is a real failure.
func skipOffLinux(t *testing.T, reason string) {
	t.Helper()
	if runtime.GOOS == "linux" {
		t.Fatal(reason)
	}
	t.Skip(reason)
}

// Pooled buffers must never be shared between concurrent lookups.
func TestParseOrdinarySymbolConcurrent(t *testing.T) {
	var file *os.File
	var funcs []string
	for _, path := range corpusFiles(t) {
		candidate, err := os.Open(path)
		require.NoError(t, err)
		t.Cleanup(func() { candidate.Close() })
		if ef, err := elf.NewFile(candidate); err == nil {
			if names, _ := symbolNamesOf(ef); len(names) >= 24 && len(names) <= 5000 {
				file, funcs = candidate, names
				break
			}
		}
	}
	if file == nil {
		skipOffLinux(t, "no corpus file with symbols")
	}
	var err error
	names := funcs
	if len(names) > 24 {
		names = names[:24]
	}
	want := make([]symbolResult, len(names))
	for i, name := range names {
		want[i], err = parseOrdinarySymbolMaterialized(file, name)
		require.NoError(t, err)
	}
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for round := range 3 {
				for i, name := range names {
					got, err := parseOrdinarySymbol(file, name)
					if err != nil || got != want[i] {
						t.Errorf("round %d name %q: got %+v err %v want %+v", round, name, got, err, want[i])
						return
					}
				}
			}
		})
	}
	wg.Wait()
}

// A name with a very long string must work through the windowed reader: a name
// longer than the window is compared in several pieces.
func TestParseOrdinarySymbolNameLongerThanWindow(t *testing.T) {
	forEachStringTableMode(t, checkNameLongerThanWindow)
}

func checkNameLongerThanWindow(t *testing.T) {
	long := strings.Repeat("abcdefghij", nameWindowSize/10*3) // 3 windows
	static := []elf.Symbol{
		{Name: "pad", Info: byte(elf.STT_FUNC), Value: 0x1010, Size: 1},
		{Name: long, Info: byte(elf.STT_FUNC), Value: 0x1020, Size: 2},
		{Name: long + "x", Info: byte(elf.STT_FUNC), Value: 0x1030, Size: 3},
	}
	for _, class := range []elf.Class{elf.ELFCLASS32, elf.ELFCLASS64} {
		// symbolFixture reserves 512 bytes for strings; build the table here instead.
		file := bigStringsFixture(t, class, static)
		for _, name := range []string{long, long + "x", long[:len(long)-1], long + "y", "pad"} {
			requireSameLookup(t, file, name)
		}
		got, err := parseOrdinarySymbol(file, long)
		require.NoError(t, err)
		require.Equal(t, symbolResult{found: true, address: 0x220, size: 2}, got)
	}
}

// bigStringsFixture is symbolFixture with room for a large string table:
// header, one program header, sections [null, strings, symtab] at known places.
func bigStringsFixture(t testing.TB, class elf.Class, symbols []elf.Symbol) *os.File {
	t.Helper()
	entSize := map[elf.Class]int{elf.ELFCLASS32: 16, elf.ELFCLASS64: 24}[class]
	strs := []byte{0}
	var table bytes.Buffer
	table.Write(make([]byte, entSize))
	for _, s := range symbols {
		name := uint32(len(strs))
		strs = append(strs, s.Name...)
		strs = append(strs, 0)
		if class == elf.ELFCLASS64 {
			require.NoError(t, binary.Write(&table, binary.LittleEndian, elf.Sym64{Name: name, Info: s.Info, Value: s.Value, Size: s.Size}))
		} else {
			require.NoError(t, binary.Write(&table, binary.LittleEndian, elf.Sym32{Name: name, Info: s.Info, Value: uint32(s.Value), Size: uint32(s.Size)}))
		}
	}
	const headersAt = 128
	stringsAt := 1024
	symtabAt := stringsAt + len(strs)
	data := make([]byte, symtabAt+table.Len())
	copy(data[stringsAt:], strs)
	copy(data[symtabAt:], table.Bytes())
	put := func(at int, v any) {
		var out bytes.Buffer
		require.NoError(t, binary.Write(&out, binary.LittleEndian, v))
		copy(data[at:], out.Bytes())
	}
	ident := [16]byte{0x7f, 'E', 'L', 'F', byte(class), byte(elf.ELFDATA2LSB), byte(elf.EV_CURRENT)}
	if class == elf.ELFCLASS64 {
		put(0, elf.Header64{Ident: ident, Type: uint16(elf.ET_DYN), Machine: uint16(elf.EM_AARCH64), Version: 1, Phoff: 64, Shoff: headersAt, Ehsize: 64, Phentsize: 56, Phnum: 1, Shentsize: 64, Shnum: 3})
		put(64, elf.Prog64{Type: uint32(elf.PT_LOAD), Flags: uint32(elf.PF_X), Off: 0x200, Vaddr: 0x1000, Memsz: 0x100})
		put(headersAt+64, elf.Section64{Type: uint32(elf.SHT_STRTAB), Off: uint64(stringsAt), Size: uint64(len(strs))})
		put(headersAt+128, elf.Section64{Type: uint32(elf.SHT_SYMTAB), Off: uint64(symtabAt), Size: uint64(table.Len()), Link: 1, Entsize: 24})
	} else {
		put(0, elf.Header32{Ident: ident, Type: uint16(elf.ET_DYN), Machine: uint16(elf.EM_386), Version: 1, Phoff: 52, Shoff: headersAt, Ehsize: 52, Phentsize: 32, Phnum: 1, Shentsize: 40, Shnum: 3})
		put(52, elf.Prog32{Type: uint32(elf.PT_LOAD), Flags: uint32(elf.PF_X), Off: 0x200, Vaddr: 0x1000, Memsz: 0x100})
		put(headersAt+40, elf.Section32{Type: uint32(elf.SHT_STRTAB), Off: uint32(stringsAt), Size: uint32(len(strs))})
		put(headersAt+80, elf.Section32{Type: uint32(elf.SHT_SYMTAB), Off: uint32(symtabAt), Size: uint32(table.Len()), Link: 1, Entsize: 16})
	}
	f, err := os.CreateTemp(t.TempDir(), "bigstrings")
	require.NoError(t, err)
	_, err = f.Write(data)
	require.NoError(t, err)
	t.Cleanup(func() { f.Close() })
	return f
}

// A symbol table larger than one chunk, with the match in the last chunk and
// again in the first, must still honour last-match-wins and read every entry.
func TestParseOrdinarySymbolSpansChunks(t *testing.T) {
	forEachStringTableMode(t, checkSpansChunks)
}

func checkSpansChunks(t *testing.T) {
	var symbols []elf.Symbol
	count := 3 * symbolChunkSize / 16 // several chunks even for 32-bit entries
	for i := range count {
		name := fmt.Sprintf("filler_%d", i)
		if i == 5 || i == count-3 {
			name = "wanted"
		}
		symbols = append(symbols, elf.Symbol{Name: name, Info: byte(elf.STT_FUNC), Value: 0x1000 + uint64(i%0x80), Size: uint64(i + 1)})
	}
	for _, class := range []elf.Class{elf.ELFCLASS32, elf.ELFCLASS64} {
		file := bigStringsFixture(t, class, symbols)
		got, err := parseOrdinarySymbol(file, "wanted")
		require.NoError(t, err)
		require.Equal(t, uint64(count-3+1), got.size)
		for _, name := range []string{"wanted", "filler_0", "filler_6", fmt.Sprintf("filler_%d", count-1), "filler_", "absent"} {
			requireSameLookup(t, file, name)
		}
	}
}

// Allocation of the lookup must not depend on the symbol count. The oracle's
// allocation is shown beside it for reference.
func BenchmarkOrdinarySymbolLookup(b *testing.B) {
	path := os.Getenv("SYMSTREAM_BENCH_FILE")
	if path == "" {
		path, _ = exec.LookPath("go")
	}
	file, err := os.Open(path)
	if err != nil {
		b.Skipf("no benchmark binary: %v", err)
	}
	defer file.Close()
	ef, err := elf.NewFile(file)
	require.NoError(b, err)
	funcs, _ := symbolNamesOf(ef)
	b.Logf("%s: %d function names", path, len(funcs))
	present := funcs[len(funcs)/2]
	for _, lookup := range []struct {
		impl string
		fn   func(*os.File, string) (symbolResult, error)
	}{
		{"oracle", parseOrdinarySymbolMaterialized},
		{"streaming", parseOrdinarySymbol},
	} {
		for _, name := range []struct{ label, value string }{{"absent", "absent_uprobe_symbol"}, {"present", present}} {
			b.Run(lookup.impl+"/"+name.label, func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					if _, err := lookup.fn(file, name.value); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}

// shuffledStringsFixture is an ELF64 shared object with n function symbols in
// .dynsym whose names sit in .dynstr in a random order, the shape GNU ld gives
// (GNU-hash symbol order, suffix-merged strings). Names are 38 bytes, so the
// string table is about 39*n bytes.
func shuffledStringsFixture(t testing.TB, n int) *os.File {
	t.Helper()
	names := make([]string, n)
	for i := range names {
		names[i] = fmt.Sprintf("OPENSSL_some_long_function_name_%06d", i)
	}
	strs := []byte{0}
	offs := make([]uint32, n)
	for _, i := range rand.New(rand.NewSource(1)).Perm(n) {
		offs[i] = uint32(len(strs))
		strs = append(strs, names[i]...)
		strs = append(strs, 0)
	}
	var table bytes.Buffer
	table.Write(make([]byte, elf.Sym64Size))
	for i := range names {
		require.NoError(t, binary.Write(&table, binary.LittleEndian, elf.Sym64{Name: offs[i], Info: byte(elf.STT_FUNC), Value: 0x1000 + uint64(i), Size: 1, Shndx: 1}))
	}
	const headersAt = 128
	stringsAt := 1024
	symtabAt := stringsAt + len(strs)
	data := make([]byte, symtabAt+table.Len())
	copy(data[stringsAt:], strs)
	copy(data[symtabAt:], table.Bytes())
	put := func(at int, v any) {
		var out bytes.Buffer
		require.NoError(t, binary.Write(&out, binary.LittleEndian, v))
		copy(data[at:], out.Bytes())
	}
	ident := [16]byte{0x7f, 'E', 'L', 'F', byte(elf.ELFCLASS64), byte(elf.ELFDATA2LSB), byte(elf.EV_CURRENT)}
	put(0, elf.Header64{Ident: ident, Type: uint16(elf.ET_DYN), Machine: uint16(elf.EM_X86_64), Version: 1, Phoff: 64, Shoff: headersAt, Ehsize: 64, Phentsize: 56, Phnum: 1, Shentsize: 64, Shnum: 3})
	put(64, elf.Prog64{Type: uint32(elf.PT_LOAD), Flags: uint32(elf.PF_X), Memsz: 0x100000})
	put(headersAt+64, elf.Section64{Type: uint32(elf.SHT_STRTAB), Off: uint64(stringsAt), Size: uint64(len(strs))})
	put(headersAt+128, elf.Section64{Type: uint32(elf.SHT_DYNSYM), Off: uint64(symtabAt), Size: uint64(table.Len()), Link: 1, Entsize: elf.Sym64Size})
	f, err := os.CreateTemp(t.TempDir(), "shuffled")
	require.NoError(t, err)
	_, err = f.Write(data)
	require.NoError(t, err)
	t.Cleanup(func() { f.Close() })
	return f
}

// countingReader counts the reads that reach the file.
type countingReader struct {
	r     io.ReaderAt
	calls int
	bytes int
}

func (c *countingReader) ReadAt(p []byte, off int64) (int, error) {
	c.calls++
	c.bytes += len(p)
	return c.r.ReadAt(p, off)
}

// scanCounting runs the same scan as parseOrdinarySymbol over a counting reader.
func scanCounting(t testing.TB, file *os.File, name string) (symbolResult, *countingReader) {
	t.Helper()
	c := &countingReader{r: file}
	f, err := elf.NewFile(c)
	require.NoError(t, err)
	scanner := newSymbolScanner(f, name)
	defer scanner.release()
	for _, typ := range []elf.SectionType{elf.SHT_SYMTAB, elf.SHT_DYNSYM} {
		if err := scanner.scan(typ); err != nil && !errors.Is(err, elf.ErrNoSymbols) {
			require.NoError(t, err)
		}
	}
	return scanner.result, c
}

// A string table in random order must not cost one read per symbol. Below the
// whole-table cap it is read once, so the read count follows the symbol-table
// chunks, not the symbol count.
func TestParseOrdinarySymbolShuffledStringsReadCount(t *testing.T) {
	const n = 20000 // about 780 KB of strings, under the cap
	file := shuffledStringsFixture(t, n)
	for _, name := range []string{"absent_name_here_xx", "OPENSSL_some_long_function_name_000123", "OPENSSL_some_long_function_name_019999"} {
		requireSameLookup(t, file, name)
	}
	result, reads := scanCounting(t, file, "absent_name_here_xx")
	require.False(t, result.found)
	symtabChunks := (n+1)*elf.Sym64Size/symbolChunkSize + 1
	t.Logf("whole table: %d reads, %d bytes", reads.calls, reads.bytes)
	// ELF headers, the string table once, the symbol table in chunks.
	require.LessOrEqual(t, reads.calls, symtabChunks+16)

	saved := wholeStringTableLimit
	wholeStringTableLimit = 0
	defer func() { wholeStringTableLimit = saved }()
	_, windowReads := scanCounting(t, file, "absent_name_here_xx")
	t.Logf("sliding window: %d reads, %d bytes", windowReads.calls, windowReads.bytes)
}

// The cost of a lookup on a GNU-ld shaped table (see shuffledStringsFixture),
// streaming against the oracle, with the reads per lookup reported.
func BenchmarkOrdinarySymbolShuffledStrings(b *testing.B) {
	for _, n := range []int{5000, 25000} {
		file := shuffledStringsFixture(b, n)
		for _, lookup := range []struct {
			impl string
			fn   func(*os.File, string) (symbolResult, error)
		}{
			{"oracle", parseOrdinarySymbolMaterialized},
			{"streaming", parseOrdinarySymbol},
		} {
			b.Run(fmt.Sprintf("%s/n=%d", lookup.impl, n), func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					if _, err := lookup.fn(file, "absent_name_here_xx"); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
		_, reads := scanCounting(b, file, "absent_name_here_xx")
		b.Logf("n=%d: streaming reads per lookup=%d bytes=%d", n, reads.calls, reads.bytes)
	}
}
