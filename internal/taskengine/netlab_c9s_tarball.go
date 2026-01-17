package taskengine

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"
)

type netlabC9sTarball struct {
	ClabYAML   []byte
	NodeFiles  map[string]map[string][]byte // node -> relative path -> bytes
	RawPaths   []string
	TotalBytes int
}

func extractNetlabC9sTarball(data []byte) (*netlabC9sTarball, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("netlab tarball is empty")
	}

	rd := bytes.NewReader(data)
	var tr *tar.Reader
	if len(data) >= 2 && data[0] == 0x1f && data[1] == 0x8b {
		gz, err := gzip.NewReader(rd)
		if err != nil {
			return nil, fmt.Errorf("failed to read gzip tarball: %w", err)
		}
		defer gz.Close()
		tr = tar.NewReader(gz)
	} else {
		tr = tar.NewReader(rd)
	}

	out := &netlabC9sTarball{
		NodeFiles: map[string]map[string][]byte{},
		RawPaths:  []string{},
	}
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to read tarball: %w", err)
		}
		if hdr == nil || hdr.Typeflag != tar.TypeReg {
			continue
		}
		name := strings.TrimPrefix(strings.TrimSpace(hdr.Name), "./")
		if name == "" {
			continue
		}
		out.RawPaths = append(out.RawPaths, name)

		// Hard cap to avoid OOM on unexpected tarballs.
		if hdr.Size > 8<<20 {
			continue
		}
		payload, err := io.ReadAll(io.LimitReader(tr, 8<<20))
		if err != nil {
			return nil, fmt.Errorf("failed to read tar entry %s: %w", name, err)
		}
		out.TotalBytes += len(payload)

		if out.ClabYAML == nil && path.Base(name) == "clab.yml" {
			out.ClabYAML = payload
			continue
		}

		idx := strings.Index(name, "node_files/")
		if idx < 0 {
			continue
		}
		rel := strings.TrimPrefix(name[idx+len("node_files/"):], "/")
		parts := strings.SplitN(rel, "/", 2)
		if len(parts) != 2 {
			continue
		}
		node := strings.TrimSpace(parts[0])
		nodeRel := strings.TrimSpace(parts[1])
		if node == "" || nodeRel == "" {
			continue
		}
		m := out.NodeFiles[node]
		if m == nil {
			m = map[string][]byte{}
			out.NodeFiles[node] = m
		}
		m[nodeRel] = payload
	}

	if len(out.ClabYAML) == 0 {
		return nil, fmt.Errorf("netlab tarball missing clab.yml")
	}
	if len(out.NodeFiles) == 0 {
		return nil, fmt.Errorf("netlab tarball missing node_files/")
	}
	return out, nil
}

func c9sConfigMapName(topologyName, node string) string {
	base := strings.TrimSpace(fmt.Sprintf("c9s-%s-%s-files", topologyName, node))
	return sanitizeKubeNameFallback(base, "c9s-files")
}
