// Copyright 2024 The Inspektor Gadget authors
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

package datasource

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
)

func TestReleaseBoundsPayloadRetention(t *testing.T) {
	for _, wrapped := range []bool{false, true} {
		name := "element"
		if wrapped {
			name = "packet"
		}
		t.Run(name, func(t *testing.T) {
			ds, err := newDataSource(TypeSingle, "event")
			require.NoError(t, err)
			small := []byte("metadata")
			backing := [][]byte{bytes.Repeat([]byte{0x42}, 18*1024), small, make([]byte, 0, 4096), []byte("tail")}
			elem := &dataElement{Payload: backing[:3]}
			var item interface{} = elem
			var packet *data
			if wrapped {
				packet = &data{Data: (*api.DataElement)(elem), Node: "node", Seq: 42}
				item = packet
			}
			ds.Release(item)
			// Observe retention before any pool consumer runs; do not depend on
			// sync.Pool returning a particular object (especially under -race).
			require.Len(t, elem.Payload, 0)
			require.Equal(t, 4, cap(elem.Payload))
			require.Nil(t, backing[0], "large active buffer must be dropped")
			require.Len(t, backing[1], 0)
			require.Equal(t, cap(small), cap(backing[1]))
			require.Same(t, &small[0], &backing[1][:cap(backing[1])][0])
			require.Nil(t, backing[2], "total capacity, not length, must fit the budget")
			require.Nil(t, backing[3], "inactive tail must be cleared")
			if wrapped {
				require.Nil(t, packet.Data)
				require.Empty(t, packet.Node)
				require.Zero(t, packet.Seq)
			}
		})
	}
}

func TestReleasePayloadRetentionBoundaries(t *testing.T) {
	atLimit := &dataElement{Payload: make([][]byte, maxRetainedPayloadSlots)}
	atLimit.Payload[0] = make([]byte, maxRetainedPayloadBytes)
	atLimit.Payload[1] = make([]byte, 1)
	atLimit.releasePayload()
	require.Equal(t, maxRetainedPayloadSlots, cap(atLimit.Payload))
	require.Equal(t, maxRetainedPayloadBytes, cap(atLimit.Payload[:2][0]))
	require.Nil(t, atLimit.Payload[:2][1])

	tooManySlots := &dataElement{Payload: make([][]byte, 1, maxRetainedPayloadSlots+1)}
	tooManySlots.Payload[0] = []byte("small")
	tooManySlots.releasePayload()
	require.Nil(t, tooManySlots.Payload)

	empty := &dataElement{Payload: [][]byte{[]byte("stale")}}
	backing := empty.Payload
	empty.Payload = empty.Payload[:0]
	empty.releasePayload()
	require.Nil(t, backing[0])
}

func TestDeepCopyReusesRetainedSmallBuffer(t *testing.T) {
	buffer := make([]byte, 128)
	out := &dataElement{Payload: [][]byte{buffer}}
	out.releasePayload()
	source := &dataElement{Payload: [][]byte{[]byte("new event")}}
	source.deepCopyInto(out)
	require.Equal(t, source.Payload, out.Payload)
	require.Same(t, &buffer[0], &out.Payload[0][0])
	source.Payload[0][0] = 'X'
	require.Equal(t, byte('n'), out.Payload[0][0])
}

func TestDeepCopyOwnershipAcrossRelease(t *testing.T) {
	for _, wrapped := range []bool{false, true} {
		name := "element"
		if wrapped {
			name = "packet"
		}
		t.Run(name, func(t *testing.T) {
			ds, err := newDataSource(TypeSingle, "event")
			require.NoError(t, err)
			// Vary lengths and slot counts across successive acquisitions, including
			// empty payloads, without assuming sync.Pool returns any specific object.
			for _, payload := range [][][]byte{
				{bytes.Repeat([]byte{0x42}, 18*1024), []byte("metadata")},
				{[]byte("small")},
				nil,
				{[]byte("again"), nil, []byte("last")},
			} {
				elem := &dataElement{Payload: payload}
				var source Data = elem
				if wrapped {
					source = &data{Data: (*api.DataElement)(elem), Node: "node", Seq: 42}
				}
				first := ds.DeepCopy(source)
				second := ds.DeepCopy(source)
				require.Equal(t, source.payload(), first.payload())
				require.Equal(t, source.payload(), second.payload())
				if wrapped {
					require.Equal(t, "node", first.(*data).Node)
					require.Equal(t, uint32(42), first.(*data).Seq)
				}
				for i, slot := range source.payload() {
					if len(slot) == 0 {
						continue
					}
					original := slot[0]
					slot[0] ^= 0xff
					require.Equal(t, original, first.payload()[i][0])
					require.Equal(t, original, second.payload()[i][0])
					first.payload()[i][0] ^= 0x7f
					require.Equal(t, original, second.payload()[i][0])
				}
				ds.Release(first)
				third := ds.DeepCopy(source)
				require.Equal(t, source.payload(), third.payload())
				// Releasing or reacquiring one copy must not invalidate another owner's bytes.
				for i, slot := range source.payload() {
					if len(slot) > 0 {
						require.Equal(t, slot[0]^0xff, second.payload()[i][0])
					}
				}
				ds.Release(second)
				ds.Release(third)
			}
		})
	}
}
