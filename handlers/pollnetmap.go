package handlers

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/klauspost/compress/zstd"
	"github.com/loft-sh/tunnel"
	"tailscale.com/smallzstd"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

const (
	PollNetMapMethod        = http.MethodPost
	PollNetMapPattern       = "/machine/map"
	PollNetMapLegacyPattern = "/machine/{mkeyhex}/map"
)

func PollNetMapHandler(coordinator tunnel.TailscaleCoordinator, peerPublicKey key.MachinePublic) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		var req tailcfg.MapRequest

		decoder := json.NewDecoder(r.Body)
		err := decoder.Decode(&req)
		if err != nil {
			handleAPIError(w, err, "Failed to decode request body")
			return
		}

		res, err := coordinator.PollNetMap(req, peerPublicKey, false)
		if err != nil {
			handleAPIError(w, err, "Failed to poll netmap")
			return
		}

		if err := writeResponse(w, req.Compress, res); err != nil {
			handleAPIError(w, err, "Failed to write response")
			return
		}

		updateLoop(ctx, coordinator, req, peerPublicKey, w)
	}
}

func updateLoop(ctx context.Context, coordinator tunnel.TailscaleCoordinator, req tailcfg.MapRequest, peerPublicKey key.MachinePublic, w http.ResponseWriter) {
	keepAliveTicker := time.NewTicker(coordinator.KeepAliveInterval())
	defer keepAliveTicker.Stop()

	syncTicker := time.NewTicker(coordinator.SyncInterval())
	defer syncTicker.Stop()

	var (
		res tailcfg.MapResponse
		err error
	)

	for {
		select {
		case <-ctx.Done():
			return
		case <-keepAliveTicker.C:
			now := time.Now()
			res = tailcfg.MapResponse{
				KeepAlive:   true,
				ControlTime: &now,
			}
		case <-syncTicker.C:
			res, err = coordinator.PollNetMap(req, peerPublicKey, true)
		}

		if err != nil {
			handleAPIError(w, err, "Failed to poll netmap")
			return
		}

		if err := writeResponse(w, req.Compress, res); err != nil {
			handleAPIError(w, err, "Failed to write response")
			return
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
