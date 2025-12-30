package skyforge

import (
	"os"
	"strings"
	"time"

	"encore.app/integrations/sshutil"
	"encore.dev/beta/errs"
	"golang.org/x/crypto/ssh"
)

func dialSSH(cfg NetlabConfig) (*ssh.Client, error) {
	keyFile := strings.TrimSpace(cfg.SSHKeyFile)
	if keyFile == "" {
		return nil, errs.B().Code(errs.FailedPrecondition).Msg("ssh: no key configured").Err()
	}
	info, err := os.Stat(keyFile)
	if err != nil {
		return nil, errs.B().Code(errs.FailedPrecondition).Msg("ssh: no key found").Err()
	}
	if info.Size() == 0 {
		return nil, errs.B().Code(errs.FailedPrecondition).Msg("ssh: key is empty").Err()
	}
	return sshutil.DialWithKeyFile(sshutil.KeyConfig{
		Host:           cfg.SSHHost,
		User:           cfg.SSHUser,
		PrivateKeyFile: keyFile,
		Timeout:        8 * time.Second,
	})
}

func runSSHCommand(client *ssh.Client, command string, timeout time.Duration) (string, error) {
	return sshutil.RunCommand(client, command, timeout)
}

func runSSHCommandWithInput(client *ssh.Client, command string, input []byte, timeout time.Duration) (string, error) {
	return sshutil.RunCommandWithInput(client, command, input, timeout)
}
