package main

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"maps"
	"strings"
	"syscall"
	"unicode"

	"github.com/anatol/luks.go"
	"github.com/gliderlabs/ssh"
	"github.com/go-crypt/crypt"
	gossh "golang.org/x/crypto/ssh"
)

var sshServer *ssh.Server

// sshRun creates a ssh server and starts it.
func sshRun(cfg *InitNetworkConfig) {
	// sanity check
	if cfg.SshPass == "" && cfg.SshAuthorizedKeys == "" {
		debug("ssh: ssh_pass and ssh_authorized_keys not specified: not starting server")
		return
	}

	// build server
	var err error
	if sshServer, err = sshServerBuild(cfg); err != nil {
		warning("ssh: unable to create server: %v", err)
		return
	}

	// start
	info("ssh: starting on %s", sshServer.Addr)
	if err := sshServer.ListenAndServe(); err != nil && !errors.Is(err, ssh.ErrServerClosed) {
		warning("ssh: unable to start server: %v", err)
	}
}

// sshShutdown closes the ssh server.
func sshShutdown() {
	if sshServer != nil {
		if err := sshServer.Close(); err != nil {
			debug("ssh: error closing server: %v", err)
		}
		sshServer = nil
	}
}

// sshServerBuild creates the ssh server based on the passed configuration.
func sshServerBuild(cfg *InitNetworkConfig) (*ssh.Server, error) {
	// server options
	var opts []ssh.Option
	if cfg.SshServerKeys == "" {
		warning("ssh: no server keys provided -- will result in non-quantum/non-forward secure key")
	} else {
		debug("ssh: adding server keys")
		opts = append(opts, ssh.HostKeyPEM([]byte(cfg.SshServerKeys)))
	}
	if cfg.SshPass != "" {
		debug("ssh: adding password auth")
		opts = append(opts, sshPass(cfg))
	}
	if cfg.SshAuthorizedKeys != "" {
		debug("ssh: adding key auth")
		opts = append(opts, sshAuthorizedKeys(cfg))
	}

	// default listen on port 22
	addr := cfg.SshAddr
	if addr == "" {
		addr = ":22"
	}

	// server
	s := &ssh.Server{
		Addr:    addr,
		Handler: sshSessionHandler,
	}

	// set server options
	for _, o := range opts {
		if o == nil {
			continue
		}
		if err := s.SetOption(o); err != nil {
			return nil, err
		}
	}
	return s, nil
}

// sshPass creates a [ssh.Option] to add a password handler to a ssh server.
func sshPass(cfg *InitNetworkConfig) ssh.Option {
	user := cfg.SshUser
	if user == "" {
		user = "root"
	}

	// create crypt decoder
	dec, err := crypt.NewDecoderAll()
	if err != nil {
		warning("ssh: unable to create crypt decoder: %v", err)
		return nil
	}

	// create crypt digest
	d, err := dec.Decode(cfg.SshPass)

	// match func
	var match func(string) bool
	if err == nil {
		match = d.Match
	} else {
		warning("ssh: unable to create crypt digest, falling back to plaintext auth: %v", err)
		match = func(pass string) bool {
			return cfg.SshPass == pass
		}
	}
	return ssh.PasswordAuth(func(ctx ssh.Context, pass string) bool {
		u, remoteAddr := ctx.User(), ctx.RemoteAddr()
		if user != u {
			warning("ssh: session %q [%s]: invalid user: user is not %q", u, remoteAddr, user)
			return false
		}
		m, s := match(pass), "invalid"
		if m {
			s = "accepted"
		}
		warning("ssh: session %q [%s]: password %s", u, remoteAddr, s)
		return m
	})
}

// sshAuthorizedKeys creates a [ssh.Option] to add a authorized key handler to
// a ssh server.
func sshAuthorizedKeys(cfg *InitNetworkConfig) ssh.Option {
	// parse authorized keys
	var authorizedKeys []ssh.PublicKey
	i := 0
	for line := range strings.SplitSeq(cfg.SshAuthorizedKeys, "\n") {
		key, _, _, _, err := ssh.ParseAuthorizedKey(bytes.TrimSpace([]byte(line)))
		if err != nil {
			warning("ssh: ssh_authorized_keys line %d is invalid, skipping: %v", i+1, err)
		}
		authorizedKeys = append(authorizedKeys, key)
		i++
	}
	user := cfg.SshUser
	if user == "" {
		user = "root"
	}
	return ssh.PublicKeyAuth(func(ctx ssh.Context, key ssh.PublicKey) bool {
		u, remoteAddr, skey := ctx.User(), ctx.RemoteAddr(), sshMarshalKey(key)
		debug("ssh: session %q [%s]: key %q auth", u, remoteAddr, skey)
		if user != u {
			warning("ssh: session %q [%s]: invalid user: user is not %q", u, remoteAddr, user)
			return false
		}
		for _, k := range authorizedKeys {
			if ssh.KeysEqual(key, k) {
				debug("ssh: session %q [%s]: key %q matched", u, remoteAddr, skey)
				return true
			}
			debug("ssh: session %q [%s]: key %q did not match", u, remoteAddr, skey)
		}
		debug("ssh: session %q [%s]: key %q not authorized", u, remoteAddr, skey)
		return false
	})
}

// sshSessionHandler handles ssh sessions.
func sshSessionHandler(sess ssh.Session) {
	warning("ssh: session %q [%s]: opened", sess.User(), sess.RemoteAddr())
	defer func() {
		warning("ssh: session %q [%s]: closed", sess.User(), sess.RemoteAddr())
	}()

	// collect passwords
	for r := bufio.NewReader(sess); ; {
		if _, err := io.WriteString(sess, "Enter passphrase: "); err != nil {
			return
		}
		pass, err := r.ReadString('\r')
		if err != nil {
			return
		}
		_, _ = io.WriteString(sess, "\n")
		pass = strings.TrimRightFunc(pass, unicode.IsSpace)
		if len(pass) == 0 {
			continue
		}
		sshWarning(sess, "Attempting unlock...")
		if sshUnlock(sess, []byte(pass)) {
			break
		}
		sshWarning(sess, "No devices unlocked by password.")
	}
}

// sshUnlock attempts to LUKS unlock all devices with the provided password.
func sshUnlock(sess ssh.Session, pass []byte) bool {
	// ensure module has been loaded
	loadModules("dm_crypt").Wait()

	devicesMutex.Lock()
	defer devicesMutex.Unlock()

	unlocked := false
	for devpath := range seenDevices {
		sshDebug(sess, "device %s attempting to open", devpath)
		// find luks block devices
		blk, err := readBlkInfo(devpath)
		switch {
		case err != nil:
			sshDebug(sess, "device %s read block info error: %v", devpath, err)
			continue
		case blk.format != "luks":
			sshDebug(sess, "device %s block info format is %q, skipping", devpath, blk.format)
			continue
		}

		// check if mapped device
		mapping := matchLuksMapping(blk)
		if mapping == nil {
			sshDebug(sess, "device %s does not match luks mapping", devpath)
			continue
		}

		// open
		d, err := luks.Open(devpath)
		if err != nil {
			sshDebug(sess, "device %s unable to luks open device: %v", mapping.name, err)
			continue
		}

		// check slots
		if len(d.Slots()) == 0 {
			sshDebug(sess, "device %s has no unlock slots", mapping.name)
			continue
		}

		// add options
		if err := d.FlagsAdd(mapping.options...); err != nil {
			sshDebug(sess, "device %s unable to add option flags %v: %v", mapping.name, mapping.options, err)
			continue
		}

		// unlock slots
		slots := make(map[int]bool)
		for _, s := range d.Slots() {
			slots[s] = true
		}

		// unlock tokens
		tokens, err := d.Tokens()
		if err != nil {
			sshDebug(sess, "device %s unable to retrieve tokens: %v", mapping.name, err)
			continue
		}

		// exclude unlock tokens from slots
		for _, t := range tokens {
			for _, s := range t.Slots {
				delete(slots, s)
			}
		}

		// iterate slots
		for s := range maps.Keys(slots) {
			// unlock
			v, err := d.UnsealVolume(s, pass)
			if err != nil {
				sshDebug(sess, "device %s slot #%d was not unlocked: %v", mapping.name, s, err)
				continue
			}

			// setup additional modules
			sshInfo(sess, "device %s slot #%d matches password", mapping.name, s)
			if err := loadRequiredCryptoModules(v.StorageEncryption); err != nil {
				sshWarning(sess, "device %s unable to load required crypto modules %q: %v", mapping.name, v.StorageEncryption, err)
				continue
			}

			// map
			if err := v.SetupMapper(mapping.name); err != nil && !errors.Is(err, syscall.EBUSY) {
				sshWarning(sess, "device %s unable to setup volume mapping: %v", mapping.name, err)
				continue
			}

			sshInfo(sess, "device %s unlocked successfully", mapping.name)
			unlocked = true
			break
		}

		// close luks device
		_ = d.Close()

		if unlocked {
			break
		}
	}
	return unlocked
}

// sshGenEcdsaKey generates a ECDSA signing key in PEM encoded format.
func sshGenEcdsaKey(r io.Reader) (string, error) {
	if r == nil {
		r = rand.Reader
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), r)
	if err != nil {
		return "", err
	}
	enc, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: enc,
	})), nil
}

// sshInfo writes a message to the ssh session as well as via [info].
func sshInfo(sess ssh.Session, format string, v ...any) {
	info("ssh: session %q [%s]: "+format, append([]any{sess.User(), sess.RemoteAddr()}, v...)...)
	fmt.Fprintf(sess, strings.TrimRightFunc(format, unicode.IsSpace)+"\n", v...)
}

// sshWarning writes a message to the ssh session as well as via [warning].
func sshWarning(sess ssh.Session, format string, v ...any) {
	warning("ssh: session %q [%s]: "+format, append([]any{sess.User(), sess.RemoteAddr()}, v...)...)
	fmt.Fprintf(sess, strings.TrimRightFunc(format, unicode.IsSpace)+"\n", v...)
}

// sshDebug writes a message to [debug].
func sshDebug(sess ssh.Session, format string, v ...any) {
	debug("ssh: session %q [%s]: "+format, append([]any{sess.User(), sess.RemoteAddr()}, v...)...)
}

// sshMarhsalKey returns a printable string for a [ssh.PublicKey].
func sshMarshalKey(k ssh.PublicKey) string {
	return string(bytes.TrimRightFunc(gossh.MarshalAuthorizedKey(k), unicode.IsSpace))
}
