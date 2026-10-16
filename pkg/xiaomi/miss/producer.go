package miss

import (
	"fmt"
	"net/url"
	"time"

	"github.com/AlexxIT/go2rtc/pkg/core"
	"github.com/AlexxIT/go2rtc/pkg/h264"
	"github.com/AlexxIT/go2rtc/pkg/h264/annexb"
	"github.com/AlexxIT/go2rtc/pkg/h265"
	"github.com/pion/rtp"
)

type Producer struct {
	core.Connection
	client *Client
}

func Dial(rawURL string) (core.Producer, error) {
	client, err := NewClient(rawURL)
	if err != nil {
		return nil, err
	}

	u, _ := url.Parse(rawURL)
	query := u.Query()

	err = client.StartMedia(query.Get("channel"), query.Get("subtype"), query.Get("audio"))
	if err != nil {
		_ = client.Close()
		return nil, err
	}

	medias, err := probe(client, query.Get("audio") != "0")
	if err != nil {
		_ = client.Close()
		return nil, err
	}

	return &Producer{
		Connection: core.Connection{
			ID:         core.NewID(),
			FormatName: "xiaomi/miss",
			Protocol:   client.Protocol(),
			RemoteAddr: client.RemoteAddr().String(),
			UserAgent:  client.Version(),
			Medias:     medias,
			Transport:  client,
		},
		client: client,
	}, nil
}

func probe(client *Client, audio bool) ([]*core.Media, error) {
	_ = client.SetDeadline(time.Now().Add(15 * time.Second))

	var vcodec, acodec *core.Codec

	for {
		pkt, err := client.ReadPacket()
		if err != nil {
			if vcodec != nil {
				err = fmt.Errorf("no audio")
			} else if acodec != nil {
				err = fmt.Errorf("no video")
			}
			return nil, fmt.Errorf("xiaomi: probe: %w", err)
		}

		switch pkt.CodecID {
		case codecH264:
			if vcodec == nil {
				buf := annexb.EncodeToAVCC(pkt.Payload)
				if h264.NALUType(buf) == h264.NALUTypeSPS {
					vcodec = h264.AVCCToCodec(buf)
				}
			}
		case codecH265:
			if vcodec == nil {
				buf := annexb.EncodeToAVCC(pkt.Payload)
				if h265.NALUType(buf) == h265.NALUTypeVPS {
					vcodec = h265.AVCCToCodec(buf)
				}
			}
		case codecPCMA:
			if acodec == nil {
				acodec = &core.Codec{Name: core.CodecPCMA, ClockRate: 8000}
			}
		case codecOPUS:
			if acodec == nil {
				acodec = &core.Codec{Name: core.CodecOpus, ClockRate: 48000, Channels: 2}
			}
		}

		if vcodec != nil && (acodec != nil || !audio) {
			break
		}
	}

	_ = client.SetDeadline(time.Time{})

	medias := []*core.Media{
		{
			Kind:      core.KindVideo,
			Direction: core.DirectionRecvonly,
			Codecs:    []*core.Codec{vcodec},
		},
	}

	if acodec != nil {
		medias = append(medias, &core.Media{
			Kind:      core.KindAudio,
			Direction: core.DirectionRecvonly,
			Codecs:    []*core.Codec{acodec},
		})

		medias = append(medias, &core.Media{
			Kind:      core.KindAudio,
			Direction: core.DirectionSendonly,
			Codecs:    []*core.Codec{acodec.Clone()},
		})
	}

	return medias, nil
}

const timestamp40ms = 48000 * 0.040

func (p *Producer) Start() error {
	var audioTS uint32
	var videoOffset uint32
	var videoStarted bool
	var gop gopCache

	for {
		_ = p.client.SetDeadline(time.Now().Add(10 * time.Second))
		pkt, err := p.client.ReadPacket()
		if err != nil {
			return err
		}

		p.Recv += len(pkt.Payload)

		// TODO: rewrite this
		var name string
		var pkt2 *core.Packet

		switch pkt.CodecID {
		case codecH264, codecH265:
			if !videoStarted {
				// Device clocks can restart on reconnect, while consumers keep
				// their existing RTP timeline. Preserve frame intervals but
				// anchor each new session to the host clock.
				videoOffset = TimeToRTP(uint64(time.Now().UnixMilli()), 90000) - TimeToRTP(pkt.Timestamp, 90000)
				videoStarted = true
			}
			pkt2 = &core.Packet{
				Header: rtp.Header{
					SequenceNumber: uint16(pkt.Sequence),
					Timestamp:      TimeToRTP(pkt.Timestamp, 90000) + videoOffset,
				},
				Payload: annexb.EncodeToAVCC(pkt.Payload),
			}
			if pkt.CodecID == codecH264 {
				name = core.CodecH264
			} else {
				name = core.CodecH265
			}
		case codecPCMA:
			name = core.CodecPCMA
			pkt2 = &core.Packet{
				Header: rtp.Header{
					Version:        2,
					Marker:         true,
					SequenceNumber: uint16(pkt.Sequence),
					Timestamp:      audioTS,
				},
				Payload: pkt.Payload,
			}
			audioTS += uint32(len(pkt.Payload))
		case codecOPUS:
			name = core.CodecOpus
			pkt2 = &core.Packet{
				Header: rtp.Header{
					Version:        2,
					Marker:         true,
					SequenceNumber: uint16(pkt.Sequence),
					Timestamp:      audioTS,
				},
				Payload: pkt.Payload,
			}
			// known cameras sends packets with 40ms long
			audioTS += timestamp40ms
		}

		for _, recv := range p.Receivers {
			if recv.Codec.Name == name {
				switch name {
				case core.CodecH264:
					gop.write(recv, pkt2, h264.IsKeyframe(pkt2.Payload))
				case core.CodecH265:
					gop.write(recv, pkt2, h265.IsKeyframe(pkt2.Payload))
				default:
					recv.WriteRTP(pkt2)
				}
				break
			}
		}
	}
}

// gopCache gives a viewer joining a running stream the frames since the
// last keyframe at once. Without it the viewer's decoder waits for the
// camera's next keyframe (several seconds on these cameras). The replayed
// frames keep their times: the player plays them out fast to live.
// Ported from 76b3e45 (xiaomi: cs2 cloud-relay + relay-media).
type gopCache struct {
	frames   []*core.Packet
	overflow bool
	seen     map[*core.Node]bool
}

// gopMax holds 6 s of 25 fps with room; a longer interval replays nothing
// rather than an incomplete run of frames.
const gopMax = 400

func (g *gopCache) write(recv *core.Receiver, pkt *core.Packet, keyframe bool) {
	if keyframe {
		g.frames = g.frames[:0]
		g.overflow = false
	}
	if !g.overflow && (keyframe || len(g.frames) > 0) {
		if len(g.frames) < gopMax {
			g.frames = append(g.frames, pkt)
		} else {
			g.frames = g.frames[:0]
			g.overflow = true
		}
	}
	childs := recv.Node.Childs()
	seen := make(map[*core.Node]bool, len(childs))
	for _, c := range childs {
		// A new viewer, not starting on a keyframe anyway.
		if !g.seen[c] && g.seen != nil && !keyframe && len(g.frames) > 1 {
			for _, f := range g.frames[:len(g.frames)-1] {
				c.Input(f)
			}
		}
		seen[c] = true
	}
	g.seen = seen
	recv.WriteRTP(pkt)
}

func (p *Producer) Stop() error {
	_ = p.client.StopMedia()
	return p.Connection.Stop()
}

// TimeToRTP convert time in milliseconds to RTP time
func TimeToRTP(timeMS, clockRate uint64) uint32 {
	return uint32(timeMS * clockRate / 1000)
}
