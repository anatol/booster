package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestMountZfsRootImportTimeout(t *testing.T) {
	origConfig, origDataset := config, zfsDataset
	t.Cleanup(func() {
		config, zfsDataset = origConfig, origDataset
	})
	config = InitConfig{BuiltinModules: map[string]bool{"zfs": true}}
	zfsDataset = "boosterdirty/ROOT"
	binDir := t.TempDir()
	t.Setenv("PATH", binDir)
	require.NoError(t, os.WriteFile(binDir+"/zpool", []byte("#!/bin/sh\necho \"cannot import 'boosterdirty': pool was previously in use from another system\" >&2\nexit 1\n"), 0o755))

	for _, tc := range []struct {
		name         string
		mountTimeout int
		wantTimeout  time.Duration
	}{
		{"default", 0, 30 * time.Second},
		{"configured", 1, time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config.MountTimeout = tc.mountTimeout
			started := time.Now()
			err := mountZfsRoot()
			require.ErrorContains(t, err, "zpool import boosterdirty: exit status 1: cannot import 'boosterdirty': pool was previously in use from another system")
			require.GreaterOrEqual(t, time.Since(started), tc.wantTimeout)
			require.Less(t, time.Since(started), tc.wantTimeout+5*time.Second)
		})
	}
}

func resetZfsHarness(t *testing.T) {
	resetKeyboardHarness(t)
	origExec := execZfsLoadKey
	origAsk := askKeyboardPassword
	origProp := getZfsPropertyValue
	t.Cleanup(func() {
		execZfsLoadKey = origExec
		askKeyboardPassword = origAsk
		getZfsPropertyValue = origProp
	})
	getZfsPropertyValue = func(property, dataset string) (string, error) {
		if property == "keylocation" {
			return "prompt", nil
		}
		return "", nil
	}
}

func TestZfsTrySubmitPassphraseToPending(t *testing.T) {
	withPendingPrompts(t)
	resetZfsHarness(t)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	dataset := "zroot/ROOT/default"
	var unlockedPass []byte
	reg := &promptRegistration{
		ctx:         ctx,
		cancel:      cancel,
		mappingName: dataset,
		unlock: func(uCtx context.Context, password []byte) bool {
			if string(password) == "correct-horse" {
				unlockedPass = append([]byte(nil), password...)
				return true
			}
			return false
		},
	}
	registerPendingPrompt(reg)

	// Verify dataset is listed in pending devices
	require.Equal(t, []string{dataset}, pendingDeviceNames())

	// Try wrong password
	failed := trySubmitPassphraseToPending([]byte("wrong"))
	require.Empty(t, failed)
	require.NoError(t, ctx.Err(), "ctx must not be cancelled on failed attempt")
	require.Equal(t, []string{dataset}, pendingDeviceNames())

	// Try correct password
	unlocked := trySubmitPassphraseToPending([]byte("correct-horse"))
	require.Equal(t, []string{dataset}, unlocked)
	require.Equal(t, "correct-horse", string(unlockedPass))
	require.Error(t, ctx.Err(), "ctx must be cancelled on success")
	require.Empty(t, pendingDeviceNames(), "unlocked dataset must be removed from pendingDeviceNames")

	// Verify passphraseCache was seeded
	passphraseCache.Lock()
	require.Len(t, passphraseCache.passwords, 1)
	require.Equal(t, "correct-horse", string(passphraseCache.passwords[0]))
	passphraseCache.Unlock()
}

func TestLoadZfsKeyCachedPassphrase(t *testing.T) {
	withPendingPrompts(t)
	resetZfsHarness(t)

	passphraseCache.Lock()
	passphraseCache.passwords = [][]byte{[]byte("cached-pw")}
	passphraseCache.Unlock()

	var calledWith []string
	execZfsLoadKey = func(ctx context.Context, encryptionRoot string, password []byte) (bool, error) {
		calledWith = append(calledWith, string(password))
		return string(password) == "cached-pw", nil
	}

	err := loadZfsKey("zroot/ROOT")
	require.NoError(t, err)
	require.Equal(t, []string{"cached-pw"}, calledWith)
}

func TestLoadZfsKeyPromptSuccess(t *testing.T) {
	withPendingPrompts(t)
	resetZfsHarness(t)

	execZfsLoadKey = func(ctx context.Context, encryptionRoot string, password []byte) (bool, error) {
		return string(password) == "console-pw", nil
	}

	askKeyboardPassword = func(ctx context.Context, prompt, postPrompt string) ([]byte, error) {
		require.Contains(t, prompt, "Enter passphrase for 'zroot/data':")
		return []byte("console-pw"), nil
	}

	err := loadZfsKey("zroot/data")
	require.NoError(t, err)

	passphraseCache.Lock()
	require.Len(t, passphraseCache.passwords, 1)
	require.Equal(t, "console-pw", string(passphraseCache.passwords[0]))
	passphraseCache.Unlock()
}

func TestLoadZfsKeyConcurrentSshUnlock(t *testing.T) {
	withPendingPrompts(t)
	resetZfsHarness(t)

	execZfsLoadKey = func(ctx context.Context, encryptionRoot string, password []byte) (bool, error) {
		return string(password) == "remote-ssh-pw", nil
	}

	// Console blocks until context is cancelled by SSH
	askKeyboardPassword = func(ctx context.Context, prompt, postPrompt string) ([]byte, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}

	loadDone := make(chan error, 1)
	go func() {
		loadDone <- loadZfsKey("zroot/ROOT/remote")
	}()

	// Wait for registration in pendingPrompts
	require.Eventually(t, func() bool {
		names := pendingDeviceNames()
		return len(names) == 1 && names[0] == "zroot/ROOT/remote"
	}, time.Second, 10*time.Millisecond)

	// Simulate SSH client submitting the passphrase
	unlocked := trySubmitPassphraseToPending([]byte("remote-ssh-pw"))
	require.Equal(t, []string{"zroot/ROOT/remote"}, unlocked)

	select {
	case err := <-loadDone:
		require.NoError(t, err, "loadZfsKey should return nil when cancelled by SSH unlock")
	case <-time.After(time.Second):
		t.Fatal("loadZfsKey did not complete after SSH unlock")
	}
}

func TestSshPromptLoopUnlocksZfsDataset(t *testing.T) {
	withPendingPrompts(t)
	resetZfsHarness(t)

	dataset := "tank/encrypted/root"
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	execZfsLoadKey = func(ctx context.Context, encryptionRoot string, password []byte) (bool, error) {
		return encryptionRoot == dataset && string(password) == "validZfsPass", nil
	}

	reg := &promptRegistration{
		ctx:         ctx,
		cancel:      cancel,
		mappingName: dataset,
		unlock: func(uCtx context.Context, password []byte) bool {
			ok, _ := execZfsLoadKey(uCtx, dataset, password)
			return ok
		},
	}
	registerPendingPrompt(reg)

	var input bytes.Buffer
	input.WriteString("wrongPass\r")
	input.WriteString("validZfsPass\r")
	ch := &fakeChannel{in: &input}

	addr := &fakeAddr{}
	sshPromptLoop(ch, nil, addr)

	got := ch.out.String()
	require.Contains(t, got, "Enter passphrase for tank/encrypted/root: ")
	require.Contains(t, got, "Passphrase did not unlock any device. Try again or disconnect.")
	require.Contains(t, got, "Unlocked: tank/encrypted/root\r\n")
	require.Contains(t, got, "All devices unlocked.\r\n")
}

func TestLoadZfsKeyWipesFailedAttempts(t *testing.T) {
	withPendingPrompts(t)
	resetZfsHarness(t)

	var handed [][]byte
	attempts := 0
	execZfsLoadKey = func(ctx context.Context, encryptionRoot string, password []byte) (bool, error) {
		return string(password) == "rightpass", nil
	}

	askKeyboardPassword = func(ctx context.Context, prompt, postPrompt string) ([]byte, error) {
		attempts++
		if attempts == 1 {
			p := []byte("wrongpass")
			handed = append(handed, p)
			return p, nil
		}
		p := []byte("rightpass")
		handed = append(handed, p)
		return p, nil
	}

	err := loadZfsKey("zroot/data")
	require.NoError(t, err)

	require.Len(t, handed, 2)
	require.True(t, allZero(handed[0]), "failed attempt not wiped")
	require.False(t, allZero(handed[1]), "successful attempt wrongly wiped")

	wipeSecretCache()
	require.True(t, allZero(handed[1]), "cached passphrase not wiped at handoff")
}

func TestLoadZfsKeySystemicErrorFailsFast(t *testing.T) {
	withPendingPrompts(t)
	resetZfsHarness(t)

	sysErr := errors.New("zfs: executable file not found in $PATH")
	execZfsLoadKey = func(ctx context.Context, encryptionRoot string, password []byte) (bool, error) {
		return false, sysErr
	}

	askCount := 0
	var handed []byte
	askKeyboardPassword = func(ctx context.Context, prompt, postPrompt string) ([]byte, error) {
		askCount++
		handed = []byte("any-pass")
		return handed, nil
	}

	err := loadZfsKey("zroot/data")
	require.ErrorIs(t, err, sysErr)
	require.Equal(t, 1, askCount, "must not loop indefinitely on systemic command failure")
	require.True(t, allZero(handed), "passphrase must be wiped on systemic failure")
}

func TestLoadZfsKeyFileLocationUnattended(t *testing.T) {
	withPendingPrompts(t)
	resetZfsHarness(t)

	keyfile := t.TempDir() + "/root.key"
	require.NoError(t, os.WriteFile(keyfile, []byte("32bytessecretkeyforzfsrootfs!!!!"), 0o600))

	getZfsPropertyValue = func(property, dataset string) (string, error) {
		if property == "keylocation" {
			return "file://" + keyfile, nil
		}
		return "", nil
	}

	called := false
	execZfsLoadKey = func(ctx context.Context, encryptionRoot string, password []byte) (bool, error) {
		called = true
		require.Equal(t, "zroot/ROOT", encryptionRoot)
		require.Nil(t, password, "unattended key load must pass nil password")
		return true, nil
	}

	askKeyboardPassword = func(ctx context.Context, prompt, postPrompt string) ([]byte, error) {
		t.Fatal("askKeyboardPassword must not be called for file-based keylocation")
		return nil, nil
	}

	err := loadZfsKey("zroot/ROOT")
	require.NoError(t, err)
	require.True(t, called, "execZfsLoadKey must be called")
	require.Empty(t, pendingDeviceNames(), "unattended key must not register in pendingPrompts")
}

func TestLoadZfsKeyFileLocationWaitsForFile(t *testing.T) {
	withPendingPrompts(t)
	resetZfsHarness(t)

	keyfile := t.TempDir() + "/delayed.key"

	getZfsPropertyValue = func(property, dataset string) (string, error) {
		if property == "keylocation" {
			return "file://" + keyfile, nil
		}
		return "", nil
	}

	execZfsLoadKey = func(ctx context.Context, encryptionRoot string, password []byte) (bool, error) {
		_, err := os.Stat(keyfile)
		return err == nil, nil
	}

	// Create file after short delay
	go func() {
		time.Sleep(100 * time.Millisecond)
		_ = os.WriteFile(keyfile, []byte("keydata"), 0o600)
	}()

	err := loadZfsKey("zroot/ROOT")
	require.NoError(t, err)
}

func TestLoadZfsKeyFileLocationFailure(t *testing.T) {
	withPendingPrompts(t)
	resetZfsHarness(t)

	getZfsPropertyValue = func(property, dataset string) (string, error) {
		if property == "keylocation" {
			return "file:///nonexistent.key", nil
		}
		return "", nil
	}

	// Mock fast timeout
	origTimeout := defaultKeyfileDeviceTimeout
	defaultKeyfileDeviceTimeout = 100 * time.Millisecond
	t.Cleanup(func() { defaultKeyfileDeviceTimeout = origTimeout })

	execZfsLoadKey = func(ctx context.Context, encryptionRoot string, password []byte) (bool, error) {
		return false, nil
	}

	err := loadZfsKey("zroot/ROOT")
	require.Error(t, err)
	require.Contains(t, err.Error(), "loading key for zroot/ROOT from file:///nonexistent.key failed")
}
