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
	http.Error(w, "frontend not built (run `cd components/portal && pnpm build`)", http.StatusServiceUnavailable)
}

func (s *Service) serveFrontendSPA(w http.ResponseWriter, req *http.Request) {
	p := strings.TrimSpace(req.URL.Path)
	if p == "" {
		p = "/"
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

// FrontendAssets serves hashed frontend assets built by Vite.
//
//encore:api public raw method=GET path=/assets/skyforge/*path
func (s *Service) FrontendAssets(w http.ResponseWriter, req *http.Request) {
	s.serveFrontendSPA(w, req)
}

// FrontendFavicon serves the SPA favicon (including alternate icon paths).
//
//encore:api public raw method=GET path=/favicon.svg
func (s *Service) FrontendFavicon(w http.ResponseWriter, req *http.Request) {
	s.serveFrontendSPA(w, req)
}

//encore:api public raw method=GET path=/favicon.ico
func (s *Service) FrontendFaviconICO(w http.ResponseWriter, req *http.Request) {
	s.serveFrontendSPA(w, req)
}

// FrontendRobots serves robots.txt.
//
//encore:api public raw method=GET path=/robots.txt
func (s *Service) FrontendRobots(w http.ResponseWriter, req *http.Request) {
	s.serveFrontendSPA(w, req)
}

// FrontendManifest serves the PWA manifest.
//
//encore:api public raw method=GET path=/manifest.webmanifest
func (s *Service) FrontendManifest(w http.ResponseWriter, req *http.Request) {
	s.serveFrontendSPA(w, req)
}

// FrontendIndex serves the SPA entrypoint.
//
//encore:api public raw method=GET path=/index.html
func (s *Service) FrontendIndex(w http.ResponseWriter, req *http.Request) {
	s.serveFrontendSPA(w, req)
}

// FrontendDashboard serves the SPA for dashboard routes.
//
//encore:api public raw method=GET path=/dashboard/*path
func (s *Service) FrontendDashboard(w http.ResponseWriter, req *http.Request) {
	s.serveFrontendSPA(w, req)
}

// FrontendAdmin serves the SPA for admin routes.
//
//encore:api public raw method=GET path=/admin/*path
func (s *Service) FrontendAdmin(w http.ResponseWriter, req *http.Request) {
	s.serveFrontendSPA(w, req)
}

// FrontendWebhooks serves the SPA for the webhook inbox UI route.
//
//encore:api public raw method=GET path=/webhooks
func (s *Service) FrontendWebhooks(w http.ResponseWriter, req *http.Request) {
	s.serveFrontendSPA(w, req)
}

// FrontendSyslog serves the SPA for syslog routes.
//
//encore:api public raw method=GET path=/syslog/*path
func (s *Service) FrontendSyslog(w http.ResponseWriter, req *http.Request) {
	s.serveFrontendSPA(w, req)
}

// FrontendSNMP serves the SPA for SNMP routes.
//
//encore:api public raw method=GET path=/snmp/*path
func (s *Service) FrontendSNMP(w http.ResponseWriter, req *http.Request) {
	s.serveFrontendSPA(w, req)
}

// FrontendDocs serves embedded UI docs pages.
//
//encore:api public raw method=GET path=/docs/*path
func (s *Service) FrontendDocs(w http.ResponseWriter, req *http.Request) {
	p := strings.TrimSpace(req.URL.Path)
	if p == "" || p == "/docs" {
		p = "/docs/"
	}
	// Serve embedded docs pages from /docs/*
	if strings.HasPrefix(p, "/docs/") {
		docSuffix := strings.TrimPrefix(p, "/docs")
		if docSuffix == "" || docSuffix == "/" {
			docSuffix = "/index.html"
		}
		docPath := "/docs" + docSuffix
		if serveFrontendFile(w, req, docPath) {
			return
		}
		// Docs are generated from the portal build output. If the static file is
		// missing (e.g. older build output), fall back to the SPA route so the
		// TanStack /docs router (including .html redirects) can still handle it.
		s.serveFrontendSPA(w, req)
		return
	}
	http.NotFound(w, req)
}

// FrontendStatus serves the SPA status page.
//
//encore:api public raw method=GET path=/status
func (s *Service) FrontendStatus(w http.ResponseWriter, req *http.Request) {
	s.serveFrontendSPA(w, req)
}

// FrontendNotifications serves the SPA notifications page.
//
//encore:api public raw method=GET path=/notifications
func (s *Service) FrontendNotifications(w http.ResponseWriter, req *http.Request) {
	s.serveFrontendSPA(w, req)
}

// FrontendDesign serves the SPA design sandbox route.
//
//encore:api public raw method=GET path=/design
func (s *Service) FrontendDesign(w http.ResponseWriter, req *http.Request) {
	s.serveFrontendSPA(w, req)
}
