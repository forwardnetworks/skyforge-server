package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

func main() {
	var (
		baseURL       = flag.String("url", strings.TrimSpace(os.Getenv("SKYFORGE_MCP_URL")), "Skyforge MCP endpoint URL (e.g. https://host/api/mcp/rpc or /api/workspaces/<ws>/mcp/forward/<net>/rpc)")
		apiToken      = flag.String("token", strings.TrimSpace(os.Getenv("SKYFORGE_API_TOKEN")), "Skyforge API token (Authorization: Bearer ...)")
		forwardCredID = flag.String("forward-credential-id", strings.TrimSpace(os.Getenv("SKYFORGE_FORWARD_CREDENTIAL_ID")), "Optional Forward credential set id (sent as X-Forward-Credential-Id; only meaningful for Forward-scoped MCP endpoints)")
		timeout       = flag.Duration("timeout", 60*time.Second, "HTTP timeout")
	)
	flag.Parse()

	if strings.TrimSpace(*baseURL) == "" {
		fatalf("missing -url (or SKYFORGE_MCP_URL)")
	}
	if strings.TrimSpace(*apiToken) == "" {
		fatalf("missing -token (or SKYFORGE_API_TOKEN)")
	}

	client := &http.Client{Timeout: *timeout}
	in := bufio.NewReader(os.Stdin)
	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()

	for {
		msg, err := readFramedMessage(in)
		if err != nil {
			if err == io.EOF {
				return
			}
			fatalf("read: %v", err)
		}
		respBody, err := httpPostJSON(client, *baseURL, *apiToken, *forwardCredID, msg)
		if err != nil {
			// Best-effort JSON-RPC error passthrough.
			respBody = []byte(fmt.Sprintf(`{"jsonrpc":"2.0","id":null,"error":{"code":-32000,"message":%q}}`, err.Error()))
		}
		if err := writeFramedMessage(out, respBody); err != nil {
			fatalf("write: %v", err)
		}
	}
}

func httpPostJSON(c *http.Client, url, token, forwardCredID string, body []byte) ([]byte, error) {
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(token))
	if strings.TrimSpace(forwardCredID) != "" {
		req.Header.Set("X-Forward-Credential-Id", strings.TrimSpace(forwardCredID))
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("http %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	return b, nil
}

func readFramedMessage(r *bufio.Reader) ([]byte, error) {
	// MCP stdio commonly uses LSP-style framing:
	//   Content-Length: <n>\r\n
	//   \r\n
	//   <n bytes of JSON>
	//
	// We implement the minimal subset needed for Claude Desktop and similar clients.
	var contentLen int
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return nil, err
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break
		}
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(k), "Content-Length") {
			n, err := strconv.Atoi(strings.TrimSpace(v))
			if err != nil || n < 0 {
				return nil, fmt.Errorf("invalid Content-Length: %q", v)
			}
			contentLen = n
		}
	}
	if contentLen == 0 {
		return nil, io.EOF
	}
	msg := make([]byte, contentLen)
	if _, err := io.ReadFull(r, msg); err != nil {
		return nil, err
	}
	return msg, nil
}

func writeFramedMessage(w *bufio.Writer, msg []byte) error {
	if _, err := fmt.Fprintf(w, "Content-Length: %d\r\n\r\n", len(msg)); err != nil {
		return err
	}
	if _, err := w.Write(msg); err != nil {
		return err
	}
	return w.Flush()
}

func fatalf(format string, args ...any) {
	_, _ = fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
