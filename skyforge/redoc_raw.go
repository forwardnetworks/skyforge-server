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

//go:embed redoc_dist
var redocDist embed.FS

var redocFS fs.FS = func() fs.FS {
	sub, err := fs.Sub(redocDist, "redoc_dist")
	if err != nil {
		return nil
	}
	return sub
}()

func serveRedocFile(w http.ResponseWriter, req *http.Request, filePath string) bool {
	if redocFS == nil {
		return false
	}
	filePath = strings.TrimPrefix(filePath, "/")
	filePath = path.Clean(filePath)
	if filePath == "." || strings.HasPrefix(filePath, "..") {
		return false
	}
	b, err := fs.ReadFile(redocFS, filePath)
	if err != nil {
		return false
	}

	ext := path.Ext(filePath)
	if ext != "" {
		if ct := mime.TypeByExtension(ext); ct != "" {
			w.Header().Set("Content-Type", ct)
		}
	}

	// The JS bundle is stable (not hashed) but changes rarely; cache it.
	if strings.HasSuffix(filePath, ".js") {
		w.Header().Set("Cache-Control", "public, max-age=31536000")
	} else {
		w.Header().Set("Cache-Control", "no-store")
	}

	http.ServeContent(w, req, filePath, time.Time{}, bytes.NewReader(b))
	return true
}

// Redoc serves offline API docs.
//
//encore:api public raw method=GET path=/redoc/*path
func (s *Service) Redoc(w http.ResponseWriter, req *http.Request) {
	p := strings.TrimSpace(req.URL.Path)
	if p == "" || p == "/redoc" || p == "/redoc/" {
		_ = serveRedocFile(w, req, "/index.html")
		return
	}
	if strings.HasPrefix(p, "/redoc/") {
		suffix := strings.TrimPrefix(p, "/redoc/")
		if suffix == "" || suffix == "/" {
			suffix = "index.html"
		}
		if serveRedocFile(w, req, "/"+suffix) {
			return
		}
		http.NotFound(w, req)
		return
	}
	http.NotFound(w, req)
}
