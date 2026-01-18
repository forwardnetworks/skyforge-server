package skyforge

import (
	"bytes"
	"embed"
	"io/fs"
	"mime"
	"net/http"
	"path"
	"strings"
	"time"
)

//go:embed frontend_dist
var frontendDist embed.FS

var frontendFS fs.FS = func() fs.FS {
	sub, err := fs.Sub(frontendDist, "frontend_dist")
	if err != nil {
		return nil
	}
	return sub
}()

func serveFrontendFile(w http.ResponseWriter, req *http.Request, filePath string) bool {
	if frontendFS == nil {
		return false
	}
	filePath = strings.TrimPrefix(filePath, "/")
	filePath = path.Clean(filePath)
	if filePath == "." || strings.HasPrefix(filePath, "..") {
		return false
	}
	b, err := fs.ReadFile(frontendFS, filePath)
	if err != nil {
		return false
	}

	ext := path.Ext(filePath)
	if ext != "" {
		if ct := mime.TypeByExtension(ext); ct != "" {
			w.Header().Set("Content-Type", ct)
		}
	}

	// If Vite outputs hashed assets, we can safely cache them for a long time.
	if strings.HasPrefix("/"+filePath, "/assets/skyforge/") {
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	} else {
		w.Header().Set("Cache-Control", "no-store")
	}

	http.ServeContent(w, req, filePath, time.Time{}, bytes.NewReader(b))
	return true
}

func (s *Service) serveFrontendIndex(w http.ResponseWriter, req *http.Request) {
	if ok := serveFrontendFile(w, req, "/index.html"); ok {
		return
	}
	http.Error(w, "frontend not built (run `cd portal-tanstack && pnpm build`)", http.StatusServiceUnavailable)
}

// FrontendAny serves the Vite-built Skyforge UI directly from the Encore backend.
// This replaces the standalone nginx-based portal container.
//
//encore:api public raw method=GET path=/*path
func (s *Service) FrontendAny(w http.ResponseWriter, req *http.Request) {
	p := strings.TrimSpace(req.URL.Path)
	if p == "" {
		p = "/"
	}

	// Known file requests: try to serve directly, otherwise fall back to SPA routing.
	if p == "/" {
		s.serveFrontendIndex(w, req)
		return
	}
	if strings.HasPrefix(p, "/assets/skyforge/") {
		if serveFrontendFile(w, req, p) {
			return
		}
		http.NotFound(w, req)
		return
	}
	if strings.HasPrefix(p, "/favicon") || strings.HasPrefix(p, "/robots") || strings.HasPrefix(p, "/manifest") {
		if serveFrontendFile(w, req, p) {
			return
		}
		http.NotFound(w, req)
		return
	}
	if strings.HasPrefix(p, "/brand/") {
		// Let the existing static handler deal with brand assets.
		http.NotFound(w, req)
		return
	}

	// Client-side route fallback.
	s.serveFrontendIndex(w, req)
}
