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
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
)

// The streaming ordinary-symbol lookup.
//
// debug/elf's Symbols and DynamicSymbols build a []elf.Symbol with one Go
// string per symbol, plus a copy of the symbol table and of the string table.
// On a large Go binary that is tens of megabytes of garbage to find one name,
// and every distinct probed name repeats it. The scanner below reads the symbol
// table in fixed-size chunks and, for each function symbol, compares the
// candidate name against the string table in place. It never builds a string
// per symbol, so its allocation does not depend on the symbol count.
//
// The string table is reached in one of two ways. A table of at most
// wholeStringTableMax bytes is read whole, once per table, into a pooled buffer.
// A larger one is read through a small sliding window instead.
//
// The window only pays off when consecutive function symbols name nearby
// strings. The Go linker writes .symtab and .strtab in the same order, so on a
// Go binary (whose tables are the large ones) the window moves forward and a
// refill is rare. GNU ld output does not have that property: .dynsym is in
// GNU-hash order and .dynstr/.strtab are suffix-merged, so nearly every symbol
// lands outside the window and would cost one window-sized read. Those tables
// are small (libcrypto.so.3's .dynstr is well under the cap), so reading them
// whole avoids the problem.
//
// The result must stay identical to the debug/elf based lookup it replaces
// (kept as the oracle in symbol_stream_test.go), so the rules below are the
// ones debug/elf applies, including its oddities.
const (
	// symbolChunkSize is the largest slice of a symbol table read at once.
	symbolChunkSize = 64 << 10
	// nameWindowSize is the sliding window used for a string table larger than
	// wholeStringTableMax.
	nameWindowSize = 16 << 10
	// wholeStringTableMax is the largest string table read whole.
	wholeStringTableMax = 1 << 20
)

// wholeStringTableLimit is wholeStringTableMax, lowered only by tests so that
// small fixtures also exercise the sliding window.
var wholeStringTableLimit uint64 = wholeStringTableMax

// scanBuffers are the only per-lookup allocations that scale with anything, and
// they are fixed-size, so they are pooled.
type scanBuffers struct {
	entries [symbolChunkSize]byte
	window  [nameWindowSize]byte
}

var (
	scanBufferPool = sync.Pool{New: func() any { return new(scanBuffers) }}
	// wholeTablePool holds the buffers for string tables read whole. They are
	// taken only when a table fits, so a lookup on a large Go binary never
	// touches one.
	wholeTablePool = sync.Pool{New: func() any { return new([wholeStringTableMax]byte) }}
)

// tableView is random access to the uncompressed bytes of one ELF section.
type tableView struct {
	r    io.ReaderAt
	size uint64
}

// openTable returns the uncompressed contents of s.
//
// An ordinary section is read in place. debug/elf's Section.Data treats
// SHT_NOBITS, SHF_COMPRESSED and ".zdebug"-named sections specially, and a
// symbol or string table is never expected to be one of those, so for them the
// section is materialized exactly as the old lookup did. That keeps their
// results and errors identical at no cost to the common case.
func openTable(s *elf.Section) (tableView, error) {
	if s.Type != elf.SHT_NOBITS && s.Flags&elf.SHF_COMPRESSED == 0 && !strings.HasPrefix(s.Name, ".zdebug") && s.ReaderAt != nil {
		return tableView{r: s.ReaderAt, size: s.Size}, nil
	}
	data, err := s.Data()
	if err != nil {
		return tableView{}, err
	}
	return tableView{r: bytes.NewReader(data), size: uint64(len(data))}, nil
}

// readFull fills p from offset off and reports a short read as an error.
func (v tableView) readFull(p []byte, off uint64) error {
	n, err := v.r.ReadAt(p, int64(off))
	if n == len(p) {
		return nil
	}
	if err == nil || err == io.EOF {
		err = io.ErrUnexpectedEOF
	}
	return err
}

// stringTable answers "is the NUL-terminated string at this offset equal to
// name" without ever building the string. Its window is either the whole table
// (start 0, filled = size, so at never refills) or a fixed-size sliding window.
type stringTable struct {
	view   tableView
	window []byte // backing buffer
	start  uint64 // string-table offset of window[0]
	filled int    // valid bytes in window
}

// at returns the bytes from pos to the end of the window, refilling the window
// at pos when pos is outside it. pos must be inside the table.
func (t *stringTable) at(pos uint64) ([]byte, error) {
	if t.filled > 0 && pos >= t.start && pos-t.start < uint64(t.filled) {
		return t.window[pos-t.start : t.filled], nil
	}
	n := min(uint64(len(t.window)), t.view.size-pos)
	if err := t.view.readFull(t.window[:n], pos); err != nil {
		t.filled = 0
		return nil, err
	}
	t.start, t.filled = pos, int(n)
	return t.window[:n], nil
}

// equals reports whether the string at off is exactly name, terminated by a NUL
// inside the table. name must not contain a NUL and must not be empty.
func (t *stringTable) equals(off uint64, name string) (bool, error) {
	need := uint64(len(name)) + 1
	if off >= t.view.size || t.view.size-off < need {
		return false, nil
	}
	for done := uint64(0); done < uint64(len(name)); {
		w, err := t.at(off + done)
		if err != nil {
			return false, err
		}
		n := min(uint64(len(w)), uint64(len(name))-done)
		if string(w[:n]) != name[done:done+n] {
			return false, nil
		}
		done += n
	}
	w, err := t.at(off + uint64(len(name)))
	if err != nil {
		return false, err
	}
	return w[0] == 0, nil
}

// isEmpty reports whether debug/elf would decode the name at off as "". That is
// the case for an empty string, and also for an offset outside the table or a
// string with no terminating NUL, which its getString turns into "" as well.
func (t *stringTable) isEmpty(off uint64) (bool, error) {
	if off >= t.view.size {
		return true, nil
	}
	for pos := off; pos < t.view.size; {
		w, err := t.at(pos)
		if err != nil {
			return false, err
		}
		if i := bytes.IndexByte(w, 0); i >= 0 {
			return pos+uint64(i) == off, nil
		}
		pos += uint64(len(w))
	}
	return true, nil
}

type symbolScanner struct {
	f    *elf.File
	name string
	// matchable is false for a name that debug/elf could never produce: a
	// decoded name stops at its first NUL, so a name containing one never matches.
	matchable bool
	bufs      *scanBuffers
	whole     *[wholeStringTableMax]byte // taken on first use, nil until then
	strings   stringTable
	result    symbolResult
}

func newSymbolScanner(f *elf.File, name string) *symbolScanner {
	return &symbolScanner{f: f, name: name, matchable: strings.IndexByte(name, 0) < 0, bufs: scanBufferPool.Get().(*scanBuffers)}
}

func (s *symbolScanner) release() {
	scanBufferPool.Put(s.bufs)
	s.bufs = nil
	if s.whole != nil {
		wholeTablePool.Put(s.whole)
		s.whole = nil
	}
}

// scan folds every matching function symbol of the first section of type typ
// into s.result. Later matches replace earlier ones, as in the old lookup, and
// the whole table is always read so that a truncated table is an error whether
// or not a match came first. It returns elf.ErrNoSymbols when the section is
// missing or empty.
func (s *symbolScanner) scan(typ elf.SectionType) error {
	// The entry size is fixed by the ELF class. debug/elf ignores sh_entsize,
	// so a section header that disagrees with it changes nothing here either.
	var entSize uint64
	switch s.f.Class {
	case elf.ELFCLASS64:
		entSize = elf.Sym64Size
	case elf.ELFCLASS32:
		entSize = elf.Sym32Size
	default:
		return errors.New("not implemented")
	}
	section := s.f.SectionByType(typ)
	if section == nil {
		return elf.ErrNoSymbols
	}
	table, err := openTable(section)
	if err != nil {
		return fmt.Errorf("cannot load symbol section: %w", err)
	}
	if table.size == 0 {
		return elf.ErrNoSymbols
	}
	if table.size%entSize != 0 {
		return fmt.Errorf("length of symbol section is not a multiple of %d", entSize)
	}
	if section.Link == 0 || section.Link >= uint32(len(s.f.Sections)) {
		return fmt.Errorf("cannot load string table section: %w", errors.New("section has invalid string table link"))
	}
	strtab, err := openTable(s.f.Sections[section.Link])
	if err != nil {
		return fmt.Errorf("cannot load string table section: %w", err)
	}
	if err := s.loadStrings(strtab); err != nil {
		return fmt.Errorf("cannot load string table section: %w", err)
	}

	chunk := uint64(len(s.bufs.entries)) / entSize * entSize
	skip := true // the first entry is the all-zero null symbol
	for pos := uint64(0); pos < table.size; {
		n := min(chunk, table.size-pos)
		buf := s.bufs.entries[:n]
		if err := table.readFull(buf, pos); err != nil {
			return fmt.Errorf("cannot load symbol section: %w", err)
		}
		pos += n
		for ; len(buf) > 0; buf = buf[entSize:] {
			if skip {
				skip = false
				continue
			}
			if err := s.visit(buf[:entSize]); err != nil {
				return err
			}
		}
	}
	return nil
}

// loadStrings prepares s.strings for strtab. The old lookup read the whole
// string table up front, so a truncated one failed even when no name was ever
// looked up; both branches below fail the same way.
func (s *symbolScanner) loadStrings(strtab tableView) error {
	if strtab.size <= wholeStringTableLimit {
		if s.whole == nil {
			s.whole = wholeTablePool.Get().(*[wholeStringTableMax]byte)
		}
		data := s.whole[:strtab.size]
		if err := strtab.readFull(data, 0); err != nil {
			return err
		}
		s.strings = stringTable{view: strtab, window: data, filled: len(data)}
		return nil
	}
	// Reading the last byte proves the whole range is present, without reading
	// the rest.
	var last [1]byte
	if err := strtab.readFull(last[:], strtab.size-1); err != nil {
		return err
	}
	s.strings = stringTable{view: strtab, window: s.bufs.window[:]}
	return nil
}

// visit decodes one symbol entry and updates the result when it matches.
//
// Only STT_FUNC is tested. The section index (st_shndx) is deliberately NOT
// checked: the old lookup did not filter SHN_UNDEF either, so an undefined
// function symbol (value 0) still matches and is reported as found with address
// zero, which symbolResult.offset turns into ErrNotSupported. Changing that
// would change which probes attach, so it is preserved as is.
func (s *symbolScanner) visit(entry []byte) error {
	var nameOff, value, size uint64
	var info byte
	bo := s.f.ByteOrder
	if s.f.Class == elf.ELFCLASS64 {
		info = entry[4]
		if elf.ST_TYPE(info) != elf.STT_FUNC {
			return nil
		}
		nameOff = uint64(bo.Uint32(entry[0:4]))
		value = bo.Uint64(entry[8:16])
		size = bo.Uint64(entry[16:24])
	} else {
		info = entry[12]
		if elf.ST_TYPE(info) != elf.STT_FUNC {
			return nil
		}
		nameOff = uint64(bo.Uint32(entry[0:4]))
		value = uint64(bo.Uint32(entry[4:8]))
		size = uint64(bo.Uint32(entry[8:12]))
	}
	var match bool
	var err error
	switch {
	case !s.matchable:
	case s.name == "":
		match, err = s.strings.isEmpty(nameOff)
	default:
		match, err = s.strings.equals(nameOff, s.name)
	}
	if err != nil {
		return fmt.Errorf("cannot load string table section: %w", err)
	}
	if !match {
		return nil
	}
	address := value
	for _, p := range s.f.Progs {
		if p.Type == elf.PT_LOAD && p.Flags&elf.PF_X != 0 && p.Vaddr <= value && value < p.Vaddr+p.Memsz {
			address = value - p.Vaddr + p.Off
			break
		}
	}
	s.result = symbolResult{found: true, address: address, size: size}
	return nil
}
