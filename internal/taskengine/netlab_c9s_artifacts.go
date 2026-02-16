package taskengine

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"path"
	"sort"
	"strings"
	"time"

	"encore.app/internal/skyforgecore"
)

type netlabC9sArtifactsSpec struct {
	TaskID       int
	OwnerID      string
	TopologyName string
	LabName      string
	Namespace    string

	ClabYAMLRaw   []byte
	TopologyYAML  []byte
	TopologyGraph *TopologyGraph

	NodeMounts map[string][]c9sFileFromConfigMap
}

func storeNetlabC9sArtifacts(ctx context.Context, cfg skyforgecore.Config, spec netlabC9sArtifactsSpec, log Logger) error {
	if log == nil {
		log = noopLogger{}
	}
	spec.OwnerID = strings.TrimSpace(spec.OwnerID)
	spec.TopologyName = strings.TrimSpace(spec.TopologyName)
	spec.LabName = strings.TrimSpace(spec.LabName)
	spec.Namespace = strings.TrimSpace(spec.Namespace)
	if spec.OwnerID == "" || spec.TopologyName == "" || spec.Namespace == "" {
		return fmt.Errorf("missing owner/topology context")
	}
	if len(spec.ClabYAMLRaw) == 0 && len(spec.TopologyYAML) == 0 && spec.NodeMounts == nil {
		return nil
	}
	if spec.LabName == "" {
		spec.LabName = spec.TopologyName
	}

	prefix := fmt.Sprintf("topology/netlab-c9s/%s/", sanitizeArtifactKeySegment(spec.LabName))

	files := map[string][]byte{}
	if len(spec.TopologyYAML) > 0 {
		files[path.Join("clabernetes", "topology.yaml")] = spec.TopologyYAML
		// Handy for browsing directly in the S3 UI.
		_, err := putUserArtifact(ctx, cfg, spec.OwnerID, prefix+path.Join("clabernetes", "topology.yaml"), spec.TopologyYAML, "application/yaml")
		if err != nil && isObjectStoreNotConfigured(err) {
			log.Infof("netlab-c9s artifacts skipped: %v", err)
			return nil
		} else if err != nil {
			return err
		}
	}
	if len(spec.ClabYAMLRaw) > 0 {
		files[path.Join("netlab", "clab.yml")] = spec.ClabYAMLRaw
		_, err := putUserArtifact(ctx, cfg, spec.OwnerID, prefix+path.Join("netlab", "clab.yml"), spec.ClabYAMLRaw, "application/yaml")
		if err != nil && isObjectStoreNotConfigured(err) {
			log.Infof("netlab-c9s artifacts skipped: %v", err)
			return nil
		} else if err != nil {
			return err
		}
	}

	// Include the generator manifest so we can correlate file keys to configmaps.
	manifestCM := sanitizeKubeNameFallback(fmt.Sprintf("c9s-%s-manifest", spec.TopologyName), "c9s-manifest")
	if data, ok, err := kubeGetConfigMap(ctx, spec.Namespace, manifestCM); err == nil && ok {
		if raw := strings.TrimSpace(data["manifest.json"]); raw != "" {
			files[path.Join("netlab", "manifest.json")] = []byte(raw)
			_, err := putUserArtifact(ctx, cfg, spec.OwnerID, prefix+path.Join("netlab", "manifest.json"), []byte(raw), "application/json")
			if err != nil && isObjectStoreNotConfigured(err) {
				log.Infof("netlab-c9s artifacts skipped: %v", err)
				return nil
			} else if err != nil {
				return err
			}
		}
	}

	if spec.TopologyGraph != nil {
		if graphBytes, err := json.Marshal(spec.TopologyGraph); err == nil && len(graphBytes) > 0 {
			files[path.Join("clabernetes", "topology.json")] = graphBytes
			_, err := putUserArtifact(ctx, cfg, spec.OwnerID, prefix+path.Join("clabernetes", "topology.json"), graphBytes, "application/json")
			if err != nil && isObjectStoreNotConfigured(err) {
				log.Infof("netlab-c9s artifacts skipped: %v", err)
				return nil
			} else if err != nil {
				return err
			}
		}
	}

	// Read all netlab-generated node files referenced by node mounts and add to the tarball.
	mountRoot := path.Join("/tmp/skyforge-c9s", spec.TopologyName) + "/"
	cmCache := map[string]map[string]string{}
	cmKeys := make([]string, 0, len(spec.NodeMounts))
	for node := range spec.NodeMounts {
		cmKeys = append(cmKeys, node)
	}
	sort.Strings(cmKeys)
	for _, node := range cmKeys {
		for _, m := range spec.NodeMounts[node] {
			cmName := strings.TrimSpace(m.ConfigMapName)
			cmKey := strings.TrimSpace(m.ConfigMapPath)
			fp := strings.TrimSpace(m.FilePath)
			if cmName == "" || cmKey == "" || fp == "" {
				continue
			}
			rel := strings.TrimPrefix(fp, mountRoot)
			rel = strings.TrimPrefix(rel, "/")
			if rel == "" || strings.HasPrefix(rel, "..") {
				continue
			}
			rel = path.Clean(rel)
			if rel == "." || strings.HasPrefix(rel, "..") {
				continue
			}

			data, ok := cmCache[cmName]
			if !ok {
				cmData, ok, err := kubeGetConfigMap(ctx, spec.Namespace, cmName)
				if err != nil {
					return err
				}
				if !ok {
					continue
				}
				data = cmData
				cmCache[cmName] = cmData
			}
			content, ok := data[cmKey]
			if !ok {
				continue
			}
			files[path.Join("netlab", rel)] = []byte(content)
		}
	}

	tarGz, err := buildTarGz(files)
	if err != nil {
		return err
	}
	ctxPut, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	if _, err := putUserArtifact(ctxPut, cfg, spec.OwnerID, prefix+"bundle.tar.gz", tarGz, "application/gzip"); err != nil {
		if isObjectStoreNotConfigured(err) {
			log.Infof("netlab-c9s artifacts skipped: %v", err)
			return nil
		}
		return err
	}
	log.Infof("netlab-c9s artifacts stored: %s", prefix+"bundle.tar.gz")
	return nil
}

func buildTarGz(files map[string][]byte) ([]byte, error) {
	if len(files) == 0 {
		return nil, fmt.Errorf("no files to archive")
	}
	paths := make([]string, 0, len(files))
	for p := range files {
		p = strings.TrimPrefix(strings.TrimSpace(p), "/")
		if p == "" {
			continue
		}
		paths = append(paths, p)
	}
	sort.Strings(paths)

	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)

	for _, p := range paths {
		data := files[p]
		hdr := &tar.Header{
			Name:    p,
			Mode:    0644,
			Size:    int64(len(data)),
			ModTime: time.Now().UTC(),
		}
		if err := tw.WriteHeader(hdr); err != nil {
			_ = tw.Close()
			_ = gz.Close()
			return nil, err
		}
		if _, err := tw.Write(data); err != nil {
			_ = tw.Close()
			_ = gz.Close()
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		_ = gz.Close()
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
