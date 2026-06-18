package main

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
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

// pcrSystemIdentity is the PCR systemd reserves as "system-identity": it is
// populated (not consumed) by FDE so later objects can be bound to the unlocked
// volume. Booster extends it after unseal to close the TPM re-unseal oracle.
const pcrSystemIdentity = 15

// pcrKernelBoot is PCR 11 ("kernel-boot"): systemd-stub measures the UKI's
// sections into it at boot, and systemd-pcrphase extends boot-phase words into
// it as barriers. A signed PCR policy binds the volume key to this PCR, so its
// value at unseal must match systemd's — which, in the initrd, is the UKI
// measurement plus the "enter-initrd" phase word.
const pcrKernelBoot = 11

// Boot-phase words measured into PCR 11. enter-initrd is extended before
// unsealing a PCR11-bound volume so the live PCR matches systemd's signed
// policy; leave-initrd after, at switch_root, as a forward-lock that bars
// re-unsealing the initrd key once the host has taken over.
const (
	phaseEnterInitrd = "enter-initrd"
	phaseLeaveInitrd = "leave-initrd"
)

// xescapeColon mirrors systemd's xescape(s, ":") (src/basic/escape.c): it
// escapes ':' (the delimiter), '\\', control bytes (<0x20) and high/DEL bytes
// (>=0x7f) as lowercase \xNN, copying everything else verbatim. Used to build
// the volume-key measurement message byte-compatibly with systemd-cryptsetup.
func xescapeColon(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 || c >= 0x7f || c == '\\' || c == ':' {
			fmt.Fprintf(&b, "\\x%02x", c)
		} else {
			b.WriteByte(c)
		}
	}
	return b.String()
}

// cryptoHashForPCRBank maps a TPM PCR bank algorithm to its crypto.Hash.
// ok is false for algorithms booster cannot handle, letting the caller fail
// closed rather than silently leave that bank's PCR un-extended.
func cryptoHashForPCRBank(alg tpm2.Algorithm) (h crypto.Hash, ok bool) {
	switch alg {
	case tpm2.AlgSHA1:
		return crypto.SHA1, true
	case tpm2.AlgSHA256:
		return crypto.SHA256, true
	case tpm2.AlgSHA384:
		return crypto.SHA384, true
	case tpm2.AlgSHA512:
		return crypto.SHA512, true
	}
	return 0, false
}

// activePCRBanks returns the hash algorithms of the TPM's allocated PCR banks.
func activePCRBanks(dev io.ReadWriter) ([]tpm2.Algorithm, error) {
	caps, _, err := tpm2.GetCapability(dev, tpm2.CapabilityPCRs, 64, 0)
	if err != nil {
		return nil, err
	}
	var banks []tpm2.Algorithm
	for _, c := range caps {
		sel, ok := c.(tpm2.PCRSelection)
		if !ok || len(sel.PCRs) == 0 {
			continue
		}
		banks = append(banks, sel.Hash)
	}
	return banks, nil
}

// volumeKeyHMACer computes HMAC(volume_key, message) with a caller-named hash
// algorithm, without exposing the master key. luks.Volume implements it, so the
// volume key never leaves the LUKS library — only the resulting digest (the
// value measured into the PCR, which is not secret) crosses into booster. The
// hash is a crypto.Hash identifier, not a constructor, so the caller cannot
// supply an implementation that observes the key. This is stricter than
// libcryptsetup's crypt_volume_key_get, which hands the raw key to the caller.
type volumeKeyHMACer interface {
	HMAC(h crypto.Hash, message []byte) ([]byte, error)
}

// measureVolumeKeyToPCR15 extends PCR15 with the systemd-compatible volume-key
// measurement after a volume is unsealed, so a key sealed to an uninitialized
// PCR15 cannot be re-unsealed for the rest of the boot. It matches
// systemd-cryptsetup's tpm2-measure-pcr=yes: for every active PCR bank it
// extends HMAC-<bank>(volume_key, "cryptsetup:" + name + ":" + uuid) using that
// bank's own hash algorithm. Extending ALL active banks is required — a policy
// satisfiable via an un-extended bank would otherwise be bypassable.
func measureVolumeKeyToPCR15(k volumeKeyHMACer, volumeName, luksUUID string) error {
	dev, err := openTPM()
	if err != nil {
		return err
	}
	defer dev.Close()

	banks, err := activePCRBanks(dev)
	if err != nil {
		return fmt.Errorf("reading active PCR banks: %v", err)
	}
	if len(banks) == 0 {
		return fmt.Errorf("no active PCR banks to extend")
	}

	msg := []byte("cryptsetup:" + xescapeColon(volumeName) + ":" + luksUUID)

	for _, bank := range banks {
		h, ok := cryptoHashForPCRBank(bank)
		if !ok {
			return fmt.Errorf("unsupported active PCR bank %v; refusing to leave PCR%d un-extended", bank, pcrSystemIdentity)
		}
		digest, err := k.HMAC(h, msg)
		if err != nil {
			return fmt.Errorf("computing PCR%d measurement for bank %v: %v", pcrSystemIdentity, bank, err)
		}
		if err := tpm2.PCRExtend(dev, tpmutil.Handle(pcrSystemIdentity), bank, digest, ""); err != nil {
			return fmt.Errorf("extending PCR%d in bank %v: %v", pcrSystemIdentity, bank, err)
		}
	}
	debug("PCR%d: extended across %d active bank(s) %v for %s", pcrSystemIdentity, len(banks), banks, volumeName)
	return nil
}

// measurePhaseToPCR11 extends PCR11 with a boot-phase word, byte-compatible with
// systemd-pcrextend (src/shared/tpm2-util.c tpm2_pcr_extend_bytes, secret=NULL):
// for every active bank it extends bankHash(word) — the raw ASCII word, no NUL
// terminator and a plain digest rather than the HMAC the PCR15 latch uses. All
// active banks are extended so a policy can't be satisfied via an un-extended
// bank. Fails closed: any extend error aborts the caller.
func measurePhaseToPCR11(word string) error {
	dev, err := openTPM()
	if err != nil {
		return err
	}
	defer dev.Close()

	banks, err := activePCRBanks(dev)
	if err != nil {
		return fmt.Errorf("reading active PCR banks: %v", err)
	}
	if len(banks) == 0 {
		return fmt.Errorf("no active PCR banks to extend")
	}

	for _, bank := range banks {
		h, ok := cryptoHashForPCRBank(bank)
		if !ok {
			return fmt.Errorf("unsupported active PCR bank %v; refusing to leave PCR%d un-extended", bank, pcrKernelBoot)
		}
		hh := h.New()
		hh.Write([]byte(word))
		if err := tpm2.PCRExtend(dev, tpmutil.Handle(pcrKernelBoot), bank, hh.Sum(nil), ""); err != nil {
			return fmt.Errorf("extending PCR%d in bank %v: %v", pcrKernelBoot, bank, err)
		}
	}
	debug("PCR%d: extended phase %q across %d active bank(s) %v", pcrKernelBoot, word, len(banks), banks)
	return nil
}

var (
	enterInitrdOnce    sync.Once
	enterInitrdErr     error
	enterInitrdApplied bool // true once "enter-initrd" was extended, so switch_root can apply the "leave-initrd" forward-lock
)

// ensureEnterInitrdBarrier extends PCR11 with "enter-initrd" exactly once for the
// boot, before the first PCR11-bound unseal, so the live PCR11 equals the value a
// systemd signed policy (signed for the enter-initrd phase) is bound to.
// systemd-pcrphase-initrd.service does this Before=cryptsetup.target; booster
// runs no pcrphase, so it does it here. Idempotent across volumes and PIN
// retries — PCR extension is monotonic, so extending twice would be the wrong
// value. Fails closed: the error propagates so the caller aborts the unseal.
func ensureEnterInitrdBarrier() error {
	enterInitrdOnce.Do(func() {
		if enterInitrdErr = measurePhaseToPCR11(phaseEnterInitrd); enterInitrdErr == nil {
			enterInitrdApplied = true
		}
	})
	return enterInitrdErr
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
