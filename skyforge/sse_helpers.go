package skyforge

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

	"encore.app/internal/skyforgecore"
)

type sseStream struct {
	w http.ResponseWriter
	f http.Flusher
}

func newSSEStream(w http.ResponseWriter) (*sseStream, error) {
	if w == nil {
		return nil, fmt.Errorf("response writer required")
	}
	f, ok := w.(http.Flusher)
	if !ok {
		return nil, fmt.Errorf("streaming unsupported")
	}
	w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache, no-transform")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.Header().Set(skyforgecore.HeaderAPIVersion, skyforgecore.APIVersion)
	if w.Header().Get("X-Skyforge-Instance") == "" {
		if hn, err := os.Hostname(); err == nil && strings.TrimSpace(hn) != "" {
			w.Header().Set("X-Skyforge-Instance", strings.TrimSpace(hn))
		}
	}
	return &sseStream{w: w, f: f}, nil
}

func (s *sseStream) flush() {
	if s == nil || s.f == nil {
		return
	}
	s.f.Flush()
}

func (s *sseStream) comment(msg string) {
	if s == nil || s.w == nil {
		return
	}
	msg = strings.TrimSpace(msg)
	if msg == "" {
		msg = "ok"
	}
	_, _ = fmt.Fprintf(s.w, ": %s\n\n", msg)
}

func (s *sseStream) event(id int64, typ string, data []byte) {
	if s == nil || s.w == nil {
		return
	}
	typ = strings.TrimSpace(typ)
	if typ == "" {
		typ = "message"
	}
	if id > 0 {
		_, _ = fmt.Fprintf(s.w, "id: %d\n", id)
	}
	_, _ = fmt.Fprintf(s.w, "event: %s\n", typ)
	if len(data) > 0 {
		_, _ = fmt.Fprintf(s.w, "data: %s\n\n", strings.TrimSpace(string(data)))
	} else {
		_, _ = fmt.Fprintf(s.w, "data: {}\n\n")
	}
}

func (s *sseStream) eventJSON(id int64, typ string, payload any) {
	if s == nil {
		return
	}
	data, _ := json.Marshal(payload)
	s.event(id, typ, data)
}
