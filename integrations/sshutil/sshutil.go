package sshutil

import (
	"fmt"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

type KeyConfig struct {
	Host           string
	User           string
	PrivateKeyFile string
	Timeout        time.Duration
}

func DialWithKeyFile(cfg KeyConfig) (*ssh.Client, error) {
	if cfg.Timeout == 0 {
		cfg.Timeout = 8 * time.Second
	}
	keyBytes, err := os.ReadFile(cfg.PrivateKeyFile)
	if err != nil {
		return nil, err
	}
	signer, err := ssh.ParsePrivateKey(keyBytes)
	if err != nil {
		return nil, err
	}

	host := cfg.Host
	if !strings.Contains(host, ":") {
		host = host + ":22"
	}

	sshCfg := &ssh.ClientConfig{
		User:            cfg.User,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         cfg.Timeout,
	}
	return ssh.Dial("tcp", host, sshCfg)
}

func RunCommand(client *ssh.Client, command string, timeout time.Duration) (string, error) {
	session, err := client.NewSession()
	if err != nil {
		return "", err
	}
	defer session.Close()

	var outBuf strings.Builder
	var errBuf strings.Builder
	session.Stdout = &outBuf
	session.Stderr = &errBuf

	done := make(chan error, 1)
	go func() {
		done <- session.Run(command)
	}()

	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	select {
	case err := <-done:
		if err != nil {
			stderr := strings.TrimSpace(errBuf.String())
			if stderr != "" {
				return "", fmt.Errorf("%w: %s", err, stderr)
			}
			return "", err
		}
		return outBuf.String(), nil
	case <-time.After(timeout):
		_ = session.Signal(ssh.SIGKILL)
		return "", fmt.Errorf("ssh command timed out after %s", timeout)
	}
}

