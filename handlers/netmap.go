package handlers

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/klauspost/compress/zstd"
	"tailscale.com/smallzstd"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

var ErrNetmapClosed = errors.New("netmap closed")

const (
	NetMapMethod        = http.MethodPost
	NetMapPattern       = "/machine/map"
	NetMapLegacyPattern = "/machine/{mkeyhex}/map"
)

type NetMapper interface {
	// KeepAliveInterval is the keep alive interval used by the coordinator to
	// periodically send keep alive messages to the tailscale client via the
	// long poll NetMap request.
	KeepAliveInterval() time.Duration
	// NetMap handles the netmap polling request from a tailscale client. It
	// returns a channel of netmap responses and a channel of errors.
	//
	// - If the request is a streaming one, the channels are not to be closed
	// and new responses shall be sent via the channels.
	//
	// - If the request is a non-streaming one, the channels are to be closed
	// after the first response is sent.
	//
	// - If the request gets closed or cancelled by the tailscale client, the
	// context will be cancelled and the channels shall not be used anymore.
	NetMap(ctx context.Context, req tailcfg.MapRequest, peerPublicKey key.MachinePublic) (chan tailcfg.MapResponse, chan error)
}

func NetMapHandler(coordinator NetMapper, peerPublicKey key.MachinePublic) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithCancelCause(r.Context())

		var req tailcfg.MapRequest

		decoder := json.NewDecoder(r.Body)
		err := decoder.Decode(&req)
		if err != nil {
			handleAPIError(w, err, "Failed to decode request body")
			return
		}

		resChan, errChan := coordinator.NetMap(ctx, req, peerPublicKey)

		keepAliveTicker := time.NewTicker(coordinator.KeepAliveInterval())
		defer keepAliveTicker.Stop()

		var (
			res  tailcfg.MapResponse
			more bool
		)

		for {
			select {
			case _, more = <-ctx.Done():
			case err, more = <-errChan:
			case res, more = <-resChan:
			case _, more = <-keepAliveTicker.C:
				now := time.Now()
				res = tailcfg.MapResponse{
					KeepAlive:   true,
					ControlTime: &now,
				}
			}

			if !more {
				cancel(ErrNetmapClosed)
				return
			}

			if err != nil {
				handleAPIError(w, err, "Failed to poll netmap")
				cancel(err)
				return
			}

			if err := writeResponse(w, req.Compress, res); err != nil {
				handleAPIError(w, err, "Failed to write response")
				cancel(err)
				return
			}
		}
	}
}

func writeResponse(w http.ResponseWriter, compress string, res tailcfg.MapResponse) error {
	var payload []byte

	marshalled, err := json.Marshal(res)
	if err != nil {
		return fmt.Errorf("failed to marshal response: %w", err)
	}

	if compress == "zstd" {
		payload = zstdEncode(marshalled)
	} else {
		payload = marshalled
	}

	data := make([]byte, 4)
	binary.LittleEndian.PutUint32(data, uint32(len(payload)))
	data = append(data, payload...)

	_, _ = w.Write(data)

	if w, ok := w.(http.Flusher); ok {
		w.Flush()
	}

	return nil
}

func zstdEncode(in []byte) []byte {
	encoder, ok := zstdEncoderPool.Get().(*zstd.Encoder)
	if !ok {
		panic("zstdEncoderPool returned a non-encoder")
	}
	out := encoder.EncodeAll(in, nil)
	encoder.Close()
	zstdEncoderPool.Put(encoder)
	return out
}

var zstdEncoderPool = &sync.Pool{
	New: func() any {
		encoder, err := smallzstd.NewEncoder(nil, zstd.WithEncoderLevel(zstd.SpeedFastest))
		if err != nil {
			panic(err)
		}
		return encoder
	},
}
