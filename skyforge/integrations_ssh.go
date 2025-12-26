package skyforge

import (
	"time"

	"encore.app/integrations/sshutil"
	"golang.org/x/crypto/ssh"
)

func dialSSH(cfg NetlabConfig) (*ssh.Client, error) {
	return sshutil.DialWithKeyFile(sshutil.KeyConfig{
		Host:           cfg.SSHHost,
		User:           cfg.SSHUser,
		PrivateKeyFile: cfg.SSHKeyFile,
		Timeout:        8 * time.Second,
	})
}

func runSSHCommand(client *ssh.Client, command string, timeout time.Duration) (string, error) {
	return sshutil.RunCommand(client, command, timeout)
}

