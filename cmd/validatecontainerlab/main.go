package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"encore.app/internal/containerlabvalidate"
)

type result struct {
	rel       string
	ok        bool
	errors    []string
	elapsedMS int
	yamlTail  string
}

func tailYAML(s string, n int) string {
	lines := strings.Split(s, "\n")
	if len(lines) <= n {
		return strings.TrimSpace(s)
	}
	return strings.TrimSpace(strings.Join(lines[len(lines)-n:], "\n"))
}

func shouldValidateFile(p string) bool {
	base := filepath.Base(p)
	if base == "topology.yml" || base == "topology.yaml" {
		return true
	}
	if strings.HasSuffix(base, ".clab.yml") || strings.HasSuffix(base, ".clab.yaml") {
		return true
	}
	if strings.Contains(base, ".clab.") {
		return true
	}
	return false
}

func iterTemplates(root string) ([]string, error) {
	var out []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			// Skip hidden folders.
			if strings.HasPrefix(d.Name(), ".") {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasPrefix(d.Name(), ".") {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(d.Name()))
		if ext != ".yml" && ext != ".yaml" {
			return nil
		}
		if shouldValidateFile(path) {
			out = append(out, path)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(out)
	return out, nil
}

func main() {
	var (
		root   = flag.String("root", "blueprints/containerlab", "Blueprint root")
		filter = flag.String("filter", "", "Only validate templates whose path contains this substring")
		limit  = flag.Int("limit", 0, "Limit number of templates validated (0 = no limit)")
	)
	flag.Parse()

	files, err := iterTemplates(*root)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		os.Exit(2)
	}

	if *filter != "" {
		tmp := files[:0]
		for _, f := range files {
			if strings.Contains(filepath.ToSlash(f), *filter) {
				tmp = append(tmp, f)
			}
		}
		files = tmp
	}
	if *limit > 0 && *limit < len(files) {
		files = files[:*limit]
	}

	fmt.Fprintf(os.Stderr, "Validating %d containerlab templates\n", len(files))

	results := make([]result, 0, len(files))
	for _, f := range files {
		t0 := time.Now()
		raw, _ := os.ReadFile(f)
		errs, err := containerlabvalidate.ValidateYAML(string(raw))
		if err != nil {
			errs = append(errs, err.Error())
		}
		ok := len(errs) == 0
		elapsed := int(time.Since(t0).Milliseconds())
		rel := filepath.ToSlash(f)
		if r, err := filepath.Rel(*root, f); err == nil {
			rel = filepath.ToSlash(r)
		}
		results = append(results, result{
			rel:       rel,
			ok:        ok,
			errors:    errs,
			elapsedMS: elapsed,
			yamlTail:  tailYAML(string(raw), 80),
		})
		fmt.Fprintf(os.Stderr, "%s %s (%dms)\n", map[bool]string{true: "OK", false: "FAIL"}[ok], rel, elapsed)
	}

	failed := 0
	for _, r := range results {
		if !r.ok {
			failed++
		}
	}
	okc := len(results) - failed

	fmt.Printf("\n# Containerlab template validation report\n\n")
	fmt.Printf("- Root: `%s`\n", *root)
	fmt.Printf("- Total: %d\n", len(results))
	fmt.Printf("- OK: %d\n", okc)
	fmt.Printf("- Failed: %d\n", failed)

	if failed > 0 {
		fmt.Printf("\n## Failures\n\n")
		for _, r := range results {
			if r.ok {
				continue
			}
			fmt.Printf("### `%s`\n", r.rel)
			fmt.Printf("- Elapsed: %dms\n", r.elapsedMS)
			for _, e := range r.errors {
				fmt.Printf("- Error: %s\n", e)
			}
			fmt.Printf("\n```yaml\n%s\n```\n\n", r.yamlTail)
		}
		os.Exit(1)
	}
}
