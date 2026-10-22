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

//go:build go1.27

package uprobetracer

// stdlibMatchesMalformedOracle reports whether the running debug/elf is the
// one the malformed-file oracle was written against. The agent builds with
// Go 1.27; older debug/elf rejects some corrupted tables that 1.27 accepts.
const stdlibMatchesMalformedOracle = true
