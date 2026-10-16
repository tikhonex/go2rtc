package cs2

import (
	"encoding/binary"
	"testing"
)

// A full media pop buffer drops the oldest packet instead of failing (PR #2377).
func TestPushDropsOldestWhenFull(t *testing.T) {
	c := newDataChannel(250, 4)
	for i := 0; i < 10; i++ {
		b := binary.BigEndian.AppendUint32(nil, 1)
		if err := c.Push(append(b, byte(i))); err != nil {
			t.Fatalf("push %d: %v", i, err)
		}
	}
	for want := byte(6); want < 10; want++ {
		got, _ := c.Pop()
		if got[0] != want {
			t.Fatalf("got %d, want %d", got[0], want)
		}
	}
}
