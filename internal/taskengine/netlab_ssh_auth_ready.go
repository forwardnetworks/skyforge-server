package taskengine

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"gopkg.in/yaml.v3"
)

type netlabNodeRef struct {
	Kind  string
	Image string
}

func parseClabNodeRefs(clabYAML []byte) map[string]netlabNodeRef {
	out := map[string]netlabNodeRef{}
	if len(clabYAML) == 0 {
		return out
	}
	var topo map[string]any
	if err := yaml.Unmarshal(clabYAML, &topo); err != nil {
		return out
	}
	topology, _ := topo["topology"].(map[string]any)
	nodesAny, _ := topology["nodes"].(map[string]any)
	for rawName, nodeAny := range nodesAny {
		cfg, ok := nodeAny.(map[string]any)
		if !ok || cfg == nil {
			continue
		}
		name := strings.TrimSpace(rawName)
		if name == "" {
			continue
		}
		out[name] = netlabNodeRef{
			Kind:  strings.TrimSpace(fmt.Sprintf("%v", cfg["kind"])),
			Image: strings.TrimSpace(fmt.Sprintf("%v", cfg["image"])),
		}
	}
	return out
}

func waitForNetlabInitialSSHAuthReady(ctx context.Context, taskID int, e *Engine, graph *TopologyGraph, clabYAML []byte, timeout time.Duration, log Logger) error {
	if graph == nil || timeout <= 0 {
		return nil
	}

	nodeRefs := parseClabNodeRefs(clabYAML)

	type target struct {
		Label string
		Host  string
		User  string
		Pass  string
		Kind  string
		Image string
	}

	targets := make([]target, 0, len(graph.Nodes))
	for _, n := range graph.Nodes {
		kind := strings.ToLower(strings.TrimSpace(n.Kind))
		if kind == "linux" {
			continue
		}
		host := strings.TrimSpace(n.MgmtHost)
		if host == "" {
			host = strings.TrimSpace(n.MgmtIP)
		}
		if host == "" {
			continue
		}

		ref := nodeRefs[strings.TrimSpace(n.Label)]
		deviceKey := netlabDeviceKeyForClabNode(ref.Kind, ref.Image)
		cred, ok := netlabCredentialForDevice(deviceKey, ref.Image)
		if !ok {
			// If we cannot determine credentials, don't block the whole run here.
			// Netlab initial itself will surface a clearer error.
			if log != nil {
				log.Infof("netlab auth readiness: skipping (no credentials) label=%s kind=%s image=%s", strings.TrimSpace(n.Label), ref.Kind, ref.Image)
			}
			continue
		}

		targets = append(targets, target{
			Label: strings.TrimSpace(n.Label),
			Host:  host,
			User:  strings.TrimSpace(cred.Username),
			Pass:  strings.TrimSpace(cred.Password),
			Kind:  strings.TrimSpace(ref.Kind),
			Image: strings.TrimSpace(ref.Image),
		})
	}
	if len(targets) == 0 {
		return nil
	}

	start := time.Now()
	deadline := time.Now().Add(timeout)
	if log != nil {
		log.Infof("netlab auth readiness: waiting for SSH auth on nodes=%d timeout=%s", len(targets), timeout)
	}

	readyCount := 0
	for idx, t := range targets {
		nodeStart := time.Now()
		lastProgress := time.Time{}
		for {
			if time.Now().After(deadline) {
				return fmt.Errorf("netlab auth readiness timed out waiting for ssh auth on %s (%s) (progress %d/%d ready)", t.Label, t.Host, readyCount, len(targets))
			}
			if taskID > 0 && e != nil {
				canceled, _ := e.taskCanceled(ctx, taskID)
				if canceled {
					return fmt.Errorf("netlab auth readiness canceled")
				}
			}

			if sshPasswordAuthReady(ctx, t.Host, t.User, t.Pass) {
				readyCount++
				if log != nil {
					log.Infof("netlab auth readiness: ok (%d/%d) label=%s host=%s elapsed=%s", readyCount, len(targets), t.Label, t.Host, time.Since(nodeStart).Truncate(time.Second))
				}
				break
			}

			if log != nil {
				now := time.Now()
				if lastProgress.IsZero() || now.Sub(lastProgress) >= 10*time.Second {
					remaining := time.Until(deadline).Truncate(time.Second)
					if remaining < 0 {
						remaining = 0
					}
					log.Infof(
						"netlab auth readiness: waiting (%d/%d) label=%s host=%s user=%s nodeElapsed=%s overallElapsed=%s remaining=%s",
						idx+1,
						len(targets),
						t.Label,
						t.Host,
						t.User,
						time.Since(nodeStart).Truncate(time.Second),
						time.Since(start).Truncate(time.Second),
						remaining,
					)
					lastProgress = now
				}
			}
			time.Sleep(3 * time.Second)
		}
	}

	if log != nil {
		log.Infof("netlab auth readiness ok: nodes=%d", len(targets))
	}
	return nil
}

func sshPasswordAuthReady(ctx context.Context, host, username, password string) bool {
	host = strings.TrimSpace(host)
	username = strings.TrimSpace(username)
	password = strings.TrimSpace(password)
	if host == "" || username == "" || password == "" {
		return false
	}

	// Keep attempts short; outer loops handle retries and longer timeouts.
	ctxDial, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()

	addr := net.JoinHostPort(host, "22")
	conn, err := (&net.Dialer{}).DialContext(ctxDial, "tcp", addr)
	if err != nil {
		return false
	}
	defer conn.Close()

	// Some NOS use keyboard-interactive even for simple password prompts.
	kbi := ssh.KeyboardInteractive(func(user, instruction string, questions []string, echos []bool) ([]string, error) {
		answers := make([]string, 0, len(questions))
		for range questions {
			answers = append(answers, password)
		}
		return answers, nil
	})

	cfg := &ssh.ClientConfig{
		User:            username,
		Auth:            []ssh.AuthMethod{ssh.Password(password), kbi},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         8 * time.Second,
	}

	// Complete SSH handshake + auth. No command execution needed.
	_, _, _, err = ssh.NewClientConn(conn, addr, cfg)
	return err == nil
}

