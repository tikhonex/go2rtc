package miss

import (
	"encoding/binary"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/AlexxIT/go2rtc/pkg/core"
	"github.com/AlexxIT/go2rtc/pkg/xiaomi/crypto"
)

type videoConn struct {
	Conn
	timestamps []uint64
	key        []byte
	codec      uint32
}

func (c *videoConn) SetDeadline(time.Time) error { return nil }
func (c *videoConn) ReadPacket() ([]byte, []byte, error) {
	if len(c.timestamps) == 0 {
		return nil, nil, io.EOF
	}
	hdr := make([]byte, hdrSize)
	binary.LittleEndian.PutUint32(hdr[4:], c.codec)
	binary.LittleEndian.PutUint64(hdr[16:], c.timestamps[0])
	c.timestamps = c.timestamps[1:]
	payload, err := crypto.Encode([]byte{0, 0, 0, 1, 0x65, 0x88}, c.key)
	return hdr, payload, err
}

func TestVideoTimelineAcrossSessions(t *testing.T) {
	for _, codec := range []uint32{codecH264, codecH265} {
		t.Run(map[uint32]string{codecH264: core.CodecH264, codecH265: core.CodecH265}[codec], func(t *testing.T) {
			// A new device session can restart its clock while RTSP consumers remain.
			var previous uint32
			for _, start := range []uint64{200000, 1000, 1792000000000, uint64(1<<32)/90 - 20} {
				key := make([]byte, 32)
				conn := &videoConn{timestamps: []uint64{start, start + 40}, key: key, codec: codec}
				recv := core.NewReceiver(nil, &core.Codec{Name: map[uint32]string{codecH264: core.CodecH264, codecH265: core.CodecH265}[codec]})
				var timestamps []uint32
				recv.Input = func(pkt *core.Packet) { timestamps = append(timestamps, pkt.Timestamp) }
				p := &Producer{client: &Client{Conn: conn, key: key}}
				p.Receivers = []*core.Receiver{recv}
				before := uint32(time.Now().UnixMilli() * 90)
				if err := p.Start(); !errors.Is(err, io.EOF) {
					t.Fatal(err)
				}
				after := uint32(time.Now().UnixMilli() * 90)
				if len(timestamps) != 2 {
					t.Fatalf("got %d frames", len(timestamps))
				}
				if int32(timestamps[0]-before) < -90 || int32(after-timestamps[0]) < -90 {
					t.Fatalf("session starts outside host timeline: %d, host %d..%d", timestamps[0], before, after)
				}
				if delta := timestamps[1] - timestamps[0]; delta != 3600 {
					t.Fatalf("frame interval changed: %d", delta)
				}
				if previous != 0 && int32(timestamps[0]-previous) < 0 {
					t.Fatal("new session timestamp went backwards")
				}
				previous = timestamps[0]
			}
		})
	}
}
