package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
	"golang.org/x/crypto/pbkdf2"
)

var defaultSymScheme = &tpm2.SymScheme{
	Alg:     tpm2.AlgAES,
	KeyBits: 128,
	Mode:    tpm2.AlgCFB,
}

var defaultRSAParams = &tpm2.RSAParams{
	Symmetric: defaultSymScheme,
	KeyBits:   2048,
}

var defaultECCParams = &tpm2.ECCParams{
	Symmetric: defaultSymScheme,
	CurveID:   tpm2.CurveNISTP256,
}

var enableSwEmulator bool

func openTPM() (io.ReadWriteCloser, error) {
	var dev io.ReadWriteCloser
	var err error

	if enableSwEmulator {
		dev, err = net.Dial("tcp", ":2321") // swtpm emulator is listening at port 2321
	} else {
		dev, err = tpm2.OpenTPM("/dev/tpmrm0")
	}
	if err != nil {
		return nil, err
	}

	if _, err := tpm2.GetManufacturer(dev); err != nil {
		return nil, fmt.Errorf("device is not a TPM 2.0")
	}

	return dev, nil
}

// Waits until a tpm device is available for use. Times out and returns false after 3 seconds.
func tpmAwaitReady() bool {
	timedOut := waitTimeout(&tpmReadyWg, time.Second*3)
	if timedOut {
		info("no tpm devices found after 3 seconds.")
	}
	return !timedOut
}

// extractSRKHandle parses the Intel TSS2 IESYS_RESOURCE_SERIALIZE format that
// systemd uses to store the SRK reference in LUKS2 token JSON (tpm2_srk field).
// Layout: magic[4] version[2] handle[4] ... Falls back to 0x81000001, which is
// systemd's standard persistent SRK handle, on any parse failure.
func extractSRKHandle(srk []byte) tpmutil.Handle {
	const iesysMagic = 0x69657379
	if len(srk) >= 10 && binary.BigEndian.Uint32(srk[0:4]) == iesysMagic {
		if h := binary.BigEndian.Uint32(srk[6:10]); h != 0 {
			return tpmutil.Handle(h)
		}
	}
	return tpmutil.Handle(0x81000001)
}

// tpm2PINAuthValue derives the TPM2 authValue from a PIN, matching systemd's convention.
//
// systemd v255+ ("salted PIN"): authValue = SHA256_trimmed(base64(PBKDF2-HMAC-SHA256(pin, salt, 10000, 32)))
// Older tokens (no salt):       authValue = SHA256_trimmed(pin)
//
// Trailing zero bytes are trimmed per TPM2 spec Part 1 "HMAC Computation" authValue Note 2.
func tpm2PINAuthValue(pin, salt []byte) []byte {
	var input []byte
	if len(salt) > 0 {
		dk := pbkdf2.Key(pin, salt, 10000, 32, sha256.New)
		b64 := base64.StdEncoding.EncodeToString(dk)
		input = []byte(b64)
	} else {
		input = pin
	}
	h := sha256.Sum256(input)
	auth := h[:]
	// Trim trailing zero bytes
	for len(auth) > 0 && auth[len(auth)-1] == 0 {
		auth = auth[:len(auth)-1]
	}
	return auth
}

func tpm2Unseal(public, private []byte, pcrs []int, bank tpm2.Algorithm, policyHash, password []byte, srkHandle tpmutil.Handle) ([]byte, error) {
	tpmAwaitReady()

	dev, err := openTPM()
	if err != nil {
		return nil, err
	}
	defer dev.Close()

	sessHandle, _, err := policyPCRSession(dev, pcrs, bank, policyHash, password != nil)
	if err != nil {
		return nil, err
	}
	defer tpm2.FlushContext(dev, sessHandle)

	var parent tpmutil.Handle
	if srkHandle != 0 {
		// Use the persistent SRK provisioned by systemd-tpm2-setup (systemd v252+ tokens).
		// Do not FlushContext on a persistent handle — that would evict it from the TPM.
		parent = srkHandle
	} else {
		// Legacy path: derive a transient primary from the well-known ECC template.
		// Used for tokens created by systemd pre-v252 that have no tpm2_srk field.
		srkTemplate := tpm2.Public{
			Type:          tpm2.AlgECC,
			NameAlg:       tpm2.AlgSHA256,
			Attributes:    tpm2.FlagStorageDefault,
			AuthPolicy:    nil,
			ECCParameters: defaultECCParams,
			RSAParameters: defaultRSAParams,
		}
		parent, _, err = tpm2.CreatePrimary(dev, tpm2.HandleOwner, tpm2.PCRSelection{}, "", "", srkTemplate)
		if err != nil {
			return nil, fmt.Errorf("clevis.go/tpm2: can't create primary key: %v", err)
		}
		defer tpm2.FlushContext(dev, parent)
	}

	objectHandle, _, err := tpm2.Load(dev, parent, "", public, private)
	if err != nil {
		return nil, fmt.Errorf("clevis.go/tpm2: unable to load data: %v", err)
	}
	defer tpm2.FlushContext(dev, objectHandle)

	unsealed, err := tpm2.UnsealWithSession(dev, sessHandle, objectHandle, string(password))
	if err != nil {
		return nil, fmt.Errorf("unable to unseal data: %v", err)
	}

	return unsealed, nil
}

func parsePCRBank(bank string) tpm2.Algorithm {
	switch bank {
	case "sha1":
		return tpm2.AlgSHA1
	case "sha256":
		return tpm2.AlgSHA256
	}
	return tpm2.AlgSHA256
}

// Returns session handle and policy digest.
func policyPCRSession(dev io.ReadWriteCloser, pcrs []int, algo tpm2.Algorithm, expectedDigest []byte, usePassword bool) (handle tpmutil.Handle, policy []byte, retErr error) {
	// This session assumes the bus is trusted, so we:
	// - use nil for tpmkey, encrypted salt, and symmetric
	// - use and all-zeros caller nonce, and ignore the returned nonce
	// As we are creating a plain TPM session, we:
	// - setup a policy session
	// - don't bind the session to any particular key
	sessHandle, _, err := tpm2.StartAuthSession(
		dev,
		/*tpmkey=*/ tpm2.HandleNull,
		/*bindkey=*/ tpm2.HandleNull,
		/*nonceCaller=*/ make([]byte, 32),
		/*encryptedSalt=*/ nil,
		/*sessionType=*/ tpm2.SessionPolicy,
		/*symmetric=*/ tpm2.AlgNull,
		/*authHash=*/ tpm2.AlgSHA256)
	if err != nil {
		return tpm2.HandleNull, nil, fmt.Errorf("unable to start session: %v", err)
	}

	if len(pcrs) > 0 {
		pcrSelection := tpm2.PCRSelection{
			Hash: algo,
			PCRs: pcrs,
		}
		if err := tpm2.PolicyPCR(dev, sessHandle, nil, pcrSelection); err != nil {
			return tpm2.HandleNull, nil, fmt.Errorf("unable to bind PCRs to auth policy: %v", err)
		}
	}

	if usePassword {
		if err := tpm2.PolicyPassword(dev, sessHandle); err != nil {
			return tpm2.HandleNull, nil, err
		}
	}

	policy, err = tpm2.PolicyGetDigest(dev, sessHandle)
	if err != nil {
		return tpm2.HandleNull, nil, fmt.Errorf("unable to get policy digest: %v", err)
	}

	if !bytes.Equal(policy, expectedDigest) {
		return tpm2.HandleNull, nil, fmt.Errorf("current policy digest does not match stored policy digest, cancelling TPM2 authentication attempt")
	}

	return sessHandle, policy, nil
}
