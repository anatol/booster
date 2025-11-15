package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

const pbkdf2Iters = 10000 // PBKDF2_HMAC_SHA256_ITERATIONS as in systemd

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

func hasCmdlineFlag(flag string) bool {
	data, _ := os.ReadFile("/proc/cmdline")
	return bytes.Contains(data, []byte(flag))
}

// --- BEGIN: helpers for UnsealWithSessionEx ---

// ccUnseal — TPM_CC_Unseal per SPEC.
const ccUnseal uint32 = 0x0000015e

// tpmStSessions — TPM_ST_SESSIONS for commands with an auth area.
const tpmStSessions uint16 = 0x8002

// getHashCtor returns the hash constructor and digest size for the given algorithm.
func getHashCtor(alg tpm2.Algorithm) (func() hash.Hash, int, error) {
	switch alg {
	case tpm2.AlgSHA1:
		return sha1.New, sha1.Size, nil
	case tpm2.AlgSHA256:
		return sha256.New, sha256.Size, nil
	case tpm2.AlgSHA384:
		// SHA384 is implemented via sha512.New384
		return sha512.New384, 48, nil
	case tpm2.AlgSHA512:
		return sha512.New, sha512.Size, nil
	default:
		return nil, 0, fmt.Errorf("unsupported authHash: 0x%x", uint32(alg))
	}
}

// Policy session + PolicyAuthValue:
// HMAC = HMAC_sessionAlg( key=authValue, cpHash || nonceCaller || nonceTPM || sessionAttributes )
func computeCpHashUnseal(dev io.ReadWriteCloser, objectHandle tpmutil.Handle, alg tpm2.Algorithm) ([]byte, error) {
	hf, _, err := getHashCtor(alg)
	if err != nil {
		return nil, err
	}

	// Get the object's Name (TPM2B_NAME) to include in cpHashA
	_, name, _, err := tpm2.ReadPublic(dev, objectHandle)
	if err != nil {
		return nil, fmt.Errorf("ReadPublic(%#x): %w", uint32(objectHandle), err)
	}

	h := hf()
	var cc [4]byte
	binary.BigEndian.PutUint32(cc[:], ccUnseal) // TPM_CC_Unseal
	h.Write(cc[:])                              // commandCode
	h.Write(name)                               // Name1 (sealed object)
	return h.Sum(nil), nil
}

// Policy session + PolicyAuthValue:
// HMAC = HMAC_sessionAlg( (sessionKey||authValue), cpHash || nonceCaller || nonceTPM || sessionAttributes )
func computeAuthHMAC(alg tpm2.Algorithm, authValue, cpHash, nonceCaller, nonceTPM []byte, attrs tpm2.SessionAttributes) ([]byte, error) {
	hf, _, err := getHashCtor(alg)
	if err != nil {
		return nil, err
	}
	m := hmac.New(hf, authValue) // sessionKey is empty (unbound+unsalted)
	m.Write(cpHash)              // pHash
	m.Write(nonceCaller)         // newer
	m.Write(nonceTPM)            // older
	m.Write([]byte{byte(attrs)}) // 1 byte of flags
	return m.Sum(nil), nil
}

// packAuthCommand serializes one TPMS_AUTH_COMMAND and returns authArea []byte (without the size prefix).
func packAuthCommand(sess tpmutil.Handle, nonceCaller []byte, attrs tpm2.SessionAttributes, hmac []byte) ([]byte, error) {
	// TPMS_AUTH_COMMAND := sessionHandle | TPM2B_NONCE | sessionAttributes | TPM2B_AUTH
	nb := tpmutil.U16Bytes(nonceCaller)
	hb := tpmutil.U16Bytes(hmac)
	b, err := tpmutil.Pack(sess, nb, attrs, hb)
	if err != nil {
		return nil, err
	}
	return b, nil
}

// runRawCommand sends a raw buffer to the TPM and returns a raw response.
func runRawCommand(dev io.ReadWriteCloser, cmd []byte) ([]byte, error) {
	if _, err := dev.Write(cmd); err != nil {
		return nil, err
	}
	// Response: read the header (10 bytes) to know the total size.
	hdr := make([]byte, 10)
	if _, err := io.ReadFull(dev, hdr); err != nil {
		return nil, err
	}
	total := binary.BigEndian.Uint32(hdr[2:6])
	resp := make([]byte, total)
	copy(resp[:10], hdr)
	if _, err := io.ReadFull(dev, resp[10:]); err != nil {
		return nil, err
	}
	return resp, nil
}

// parseUnsealResponse parses the Unseal response and returns the data.
func parseUnsealResponse(resp []byte) ([]byte, error) {
	if len(resp) < 10 {
		return nil, fmt.Errorf("short TPM response")
	}
	rc := binary.BigEndian.Uint32(resp[6:10])
	if rc != 0 {
		return nil, fmt.Errorf("TPM RC=0x%08x", rc)
	}
	tag := binary.BigEndian.Uint16(resp[0:2])
	off := 10
	if tag == tpmStSessions {
		if len(resp) < off+4 {
			return nil, fmt.Errorf("short response (no paramSize)")
		}
		paramSize := int(binary.BigEndian.Uint32(resp[off : off+4]))
		off += 4
		if len(resp) < off+paramSize {
			return nil, fmt.Errorf("short response (param buf)")
		}
		// Inside the parameters for Unseal: TPM2B_SENSITIVE_DATA
		if len(resp) < off+2 {
			return nil, fmt.Errorf("short TPM2B size")
		}
		n := int(binary.BigEndian.Uint16(resp[off : off+2]))
		off += 2
		if len(resp) < off+n {
			return nil, fmt.Errorf("short TPM2B data")
		}
		return resp[off : off+n], nil
	}
	// Without sessions (theoretically we won't have this), then directly TPM2B.
	if len(resp) < off+2 {
		return nil, fmt.Errorf("short TPM2B size (no sessions)")
	}
	n := int(binary.BigEndian.Uint16(resp[off : off+2]))
	off += 2
	if len(resp) < off+n {
		return nil, fmt.Errorf("short TPM2B data (no sessions)")
	}
	return resp[off : off+n], nil
}

// UnsealWithSessionEx — Unseal with a policy session: we compute HMAC ourselves and explicitly place nonceCaller/attrs/HMAC.
// Parameters:
//   - objectHandle: loaded object (sealed item)
//   - sessHandle: policy session (after PolicyPCR/PolicyAuthValue)
//   - authValue: key for HMAC (for PIN+salt this is the RAW dk, 32 bytes)
//   - authHash: session algorithm (SHA256 in your case)
//   - nonceCaller/nonceTPM: those used by the current policy session
//   - attrs: typically tpm2.AttrContinueSession
func UnsealWithSessionEx(dev io.ReadWriteCloser, objectHandle tpmutil.Handle, sessHandle tpmutil.Handle,
	authValue []byte, authHash tpm2.Algorithm, nonceCaller, nonceTPM []byte, attrs tpm2.SessionAttributes) ([]byte, error) {

	// 1) cpHash = H(TPM_CC_Unseal || Name(object))
	cpHash, err := computeCpHashUnseal(dev, objectHandle, authHash)
	if err != nil {
		return nil, err
	}
	info("cpHash(Unseal)=%x", cpHash)
	// 2) Generate a FRESH nonceCaller for this command (best practice)
	nc := make([]byte, digestSizeOfAlg(authHash))
	if _, err := rand.Read(nc); err != nil {
		return nil, fmt.Errorf("nonceCaller(rand): %w", err)
	}
	// 3) Authorization HMAC (order: cpHash → nonceCaller(new) → nonceTPM → attrs)
	hmacBytes, err := computeAuthHMAC(authHash, authValue, cpHash, nc, nonceTPM, attrs)
	if err != nil {
		return nil, err
	}
	// 4) Build the authArea (one TPMS_AUTH_COMMAND)
	authArea, err := packAuthCommand(sessHandle, nc, attrs, hmacBytes)
	if err != nil {
		return nil, fmt.Errorf("pack auth: %w", err)
	}
	// 5) Build the command: tag=SESSIONS | size | ccUnseal | handle | authSize | authArea
	var body bytes.Buffer
	// handle
	if err := binary.Write(&body, binary.BigEndian, uint32(objectHandle)); err != nil {
		return nil, err
	}
	// authorizationSize (uint32)
	if err := binary.Write(&body, binary.BigEndian, uint32(len(authArea))); err != nil {
		return nil, err
	}
	body.Write(authArea)
	// header
	total := 10 + body.Len() // 10 = header
	var hdr bytes.Buffer
	_ = binary.Write(&hdr, binary.BigEndian, tpmStSessions)
	_ = binary.Write(&hdr, binary.BigEndian, uint32(total))
	_ = binary.Write(&hdr, binary.BigEndian, ccUnseal)
	cmd := append(hdr.Bytes(), body.Bytes()...)

	// 5) Send and parse
	resp, err := runRawCommand(dev, cmd)
	if err != nil {
		return nil, err
	}
	return parseUnsealResponse(resp)
}

// --- END: helpers for UnsealWithSessionEx ---

// ---- raw TPM commands (legacy) ----
func policyORLegacy(rw io.ReadWriter, session tpmutil.Handle, digests [][]byte, hashAlg tpm2.Algorithm) error {
	const (
		tagNoSessions = tpmutil.Tag(0x8001)    // TPM_ST_NO_SESSIONS
		ccPolicyOR    = tpmutil.Command(0x171) // TPM_CC_PolicyOR
	)
	if len(digests) < 2 {
		// By the spec there must be at least 2 branches; if 0/1 — OR is not needed.
		return nil
	}
	want := digestSizeOfAlg(hashAlg)
	var params bytes.Buffer
	// TPML_DIGEST: count (u32) + array of TPM2B_DIGEST (size(u16)+bytes)
	if err := binary.Write(&params, binary.BigEndian, uint32(len(digests))); err != nil {
		return err
	}
	for i, d := range digests {
		if len(d) != want {
			return fmt.Errorf("PolicyOR: digest[%d] len=%d, want=%d (hashAlg=%v)", i, len(d), want, hashAlg)
		}
		if err := binary.Write(&params, binary.BigEndian, uint16(len(d))); err != nil {
			return err
		}
		if _, err := params.Write(d); err != nil {
			return err
		}
	}
	// header: tag(2)|size(4)|code(4) + handle(4) + params
	size := uint32(10 + 4 + params.Len())
	var pkt bytes.Buffer
	_ = binary.Write(&pkt, binary.BigEndian, tagNoSessions)
	_ = binary.Write(&pkt, binary.BigEndian, size)
	_ = binary.Write(&pkt, binary.BigEndian, ccPolicyOR)
	_ = binary.Write(&pkt, binary.BigEndian, session.HandleValue())
	_, _ = pkt.Write(params.Bytes())
	resp, err := tpmutil.RunCommandRaw(rw, pkt.Bytes())
	if err != nil {
		return err
	}
	if len(resp) < 10 {
		return fmt.Errorf("PolicyOR: short TPM response")
	}
	rc := binary.BigEndian.Uint32(resp[6:10])
	if rc != 0 {
		return fmt.Errorf("PolicyOR: TPM RC=0x%X", rc)
	}
	return nil
}

func policyTrace(dev io.ReadWriter, sess tpmutil.Handle, tag string) {
	d, err := tpm2.PolicyGetDigest(dev, sess)
	if err != nil {
		info("TPM policy trace: %s -> (error: %v)", tag, err)
		return
	}
	info("TPM policy trace: %s -> %x", tag, d)
}

func policyTraceExpect(dev io.ReadWriter, sess tpmutil.Handle, tag string, expect []byte) {
	d, err := tpm2.PolicyGetDigest(dev, sess)
	if err != nil {
		info("TPM policy trace: %s -> (error: %v)", tag, err)
		return
	}
	if len(expect) > 0 && !bytes.Equal(d, expect) {
		info("TPM policy trace: %s -> %x (≠ expect %x)", tag, d, expect)
	} else {
		info("TPM policy trace: %s -> %x", tag, d)
	}
}

func digestSizeOfAlg(a tpm2.Algorithm) int {
	switch a {
	case tpm2.AlgSHA1:
		return 20
	case tpm2.AlgSHA256:
		return 32
	case tpm2.AlgSHA384:
		return 48
	case tpm2.AlgSHA512:
		return 64
	default:
		return 32
	}
}

// deriveAuthFromPIN: authValue = HASH_alg(PIN) with trimming of trailing zeros
// (systemd does exactly this; different PINs can yield a hash ending with 0x00).
func deriveAuthFromPIN(pin []byte, alg tpm2.Algorithm) []byte {
	var sum []byte
	switch alg {
	case tpm2.AlgSHA1:
		h := sha1.Sum(pin)
		sum = h[:]
	case tpm2.AlgSHA256:
		h := sha256.Sum256(pin)
		sum = h[:]
	case tpm2.AlgSHA384:
		h := sha512.Sum384(pin)
		sum = h[:]
	case tpm2.AlgSHA512:
		h := sha512.Sum512(pin)
		sum = h[:]
	default:
		h := sha256.Sum256(pin)
		sum = h[:]
	}
	// trim trailing 0x00 to match systemd behavior
	for len(sum) > 0 && sum[len(sum)-1] == 0x00 {
		sum = sum[:len(sum)-1]
	}
	return sum
}

// pbkdf2HMACSHA256: standard PBKDF2-HMAC-SHA256 (dkLen=32) with iterations.
// Compatible with systemd: iterations = 10000, block #1 (salt || 0x00000001).

func pbkdf2HMACSHA256(pass, salt []byte, iters int) []byte {
	// U1 = HMAC(pass, salt||1)
	blk := make([]byte, len(salt)+4)
	copy(blk, salt)
	blk[len(salt)+0] = 0
	blk[len(salt)+1] = 0
	blk[len(salt)+2] = 0
	blk[len(salt)+3] = 1
	mac := hmac.New(sha256.New, pass)
	mac.Write(blk)
	u := mac.Sum(nil) // 32 bytes
	dk := make([]byte, 32)
	copy(dk, u)
	for i := 1; i < iters; i++ { // another 9999 iterations
		mac = hmac.New(sha256.New, pass)
		mac.Write(u)
		u = mac.Sum(nil)
		for j := 0; j < 32; j++ {
			dk[j] ^= u[j]
		}
	}
	return dk
}

// if the token requires a PIN and there is salt — RETURNS Base64(PBKDF2-HMAC-SHA256(pin, salt, pbkdf2Iters, 32)).
// (this is exactly what systemd does and what is stored in the tpm2-pin field / is the object's authValue).
// otherwise — returns HASH_alg(PIN) (compatibility for cases without salt).
func derivePINForTPM(pin []byte, salt []byte, usePIN bool, alg tpm2.Algorithm) (auth []byte, usedPBKDF2 bool) {
	if usePIN && len(pin) > 0 && len(salt) > 0 {
		dk := pbkdf2HMACSHA256(pin, salt, pbkdf2Iters) // 32 bytes
		return dk, true
	}
	if usePIN && len(pin) > 0 {
		return deriveAuthFromPIN(pin, alg), false
	}
	// objects without a PIN (UserWithAuth=false) — empty auth
	return nil, false
}

// TPM constants we need.
const (
	tagNoSessions     = tpmutil.Tag(0x8001)    // TPM_ST_NO_SESSIONS
	ccPolicyAuthValue = tpmutil.Command(0x16B) // TPM_CC_PolicyAuthValue
	tpmHeaderSize     = 10                     // tag(2)+size(4)+code(4)
	handleSize        = 4
)

// PolicyAuthValueLegacy sends TPM2_PolicyAuthValue for a policy session.
func PolicyAuthValueLegacy(rw io.ReadWriter, session tpmutil.Handle) error {
	// Build raw command: [tag | size | ordinal | handle]
	var pkt bytes.Buffer
	cmdSize := uint32(tpmHeaderSize + handleSize)
	_ = binary.Write(&pkt, binary.BigEndian, tagNoSessions)
	_ = binary.Write(&pkt, binary.BigEndian, cmdSize)
	_ = binary.Write(&pkt, binary.BigEndian, ccPolicyAuthValue)
	_ = binary.Write(&pkt, binary.BigEndian, session.HandleValue())

	// Send it as-is; check RC in the response header.
	resp, err := tpmutil.RunCommandRaw(rw, pkt.Bytes())
	if err != nil {
		return err
	}
	if len(resp) < tpmHeaderSize {
		return fmt.Errorf("short TPM response")
	}
	rc := binary.BigEndian.Uint32(resp[6:10]) // tag(2)+size(4)=6
	if rc != 0 {
		return fmt.Errorf("TPM returned RC=0x%X", rc)
	}
	return nil
}

// ----- Low-level PolicyAuthorizeNV (raw) ------------------------------------
// TPM2_CC for PolicyAuthorizeNV
const ccPolicyAuthorizeNV = tpmutil.Command(0x192)

// PolicyAuthorizeNVLegacy sends TPM2_PolicyAuthorizeNV(authHandle, nvIndex, policySession)
// without parameters; this is sufficient like in systemd-pcrlock.
func PolicyAuthorizeNVLegacy(rw io.ReadWriter, authHandle, nvIndex, policySession tpmutil.Handle) error {
	var pkt bytes.Buffer
	cmdSize := uint32(tpmHeaderSize + 3*handleSize)
	_ = binary.Write(&pkt, binary.BigEndian, tagNoSessions)
	_ = binary.Write(&pkt, binary.BigEndian, cmdSize)
	_ = binary.Write(&pkt, binary.BigEndian, ccPolicyAuthorizeNV)
	_ = binary.Write(&pkt, binary.BigEndian, authHandle.HandleValue())
	_ = binary.Write(&pkt, binary.BigEndian, nvIndex.HandleValue())
	_ = binary.Write(&pkt, binary.BigEndian, policySession.HandleValue())
	resp, err := tpmutil.RunCommandRaw(rw, pkt.Bytes())
	if err != nil {
		return err
	}
	if len(resp) < 10 {
		return fmt.Errorf("PolicyAuthorizeNV: short response")
	}
	rc := binary.BigEndian.Uint32(resp[6:10])
	if rc != 0 {
		return fmt.Errorf("PolicyAuthorizeNV: TPM rc=0x%x", rc)
	}
	return nil
}

// ----- NV scan + autodetect pcrlock NV by matching final policy digest -------
// Enumerate all NV indices via GetCapability(CapabilityHandles, HR_NV_INDEX).
func listAllNVIndices(rw io.ReadWriter) ([]tpmutil.Handle, error) {
	// 0x01000000 — base NV Index range (TPM2_HR_NV_INDEX)
	const nvBase = 0x01000000
	const max = 4096
	var out []tpmutil.Handle
	capData, _, err := tpm2.GetCapability(rw, tpm2.CapabilityHandles, nvBase, max)
	if err != nil {
		return nil, err
	}
	// In legacy it returns []interface{}; but on some builds it may be a different type.
	switch v := any(capData).(type) {
	case []tpmutil.Handle:
		out = append(out, v...)
	case []uint32:
		for _, u := range v {
			out = append(out, tpmutil.Handle(u))
		}
	case []interface{}:
		for _, it := range v {
			switch h := it.(type) {
			case tpmutil.Handle:
				out = append(out, h)
			case uint32:
				out = append(out, tpmutil.Handle(h))
			}
		}
	}
	return out, nil
}

// Compute the final policy digest in a TRIAL session for: PolicyAuthorizeNV -> (opt.) PolicyAuthValue -> PolicyCommandCode(Unseal)
func trialDigestForNV(rw io.ReadWriter, policyAlg tpm2.Algorithm, usePIN bool, nv tpmutil.Handle) ([]byte, error) {
	nonce, _ := tpm2.GetRandom(rw, 16)
	sess, _, err := tpm2.StartAuthSession(rw, tpm2.HandleNull, tpm2.HandleNull, nonce, nil, tpm2.SessionTrial, tpm2.AlgNull, policyAlg)
	if err != nil {
		return nil, fmt.Errorf("trial start: %w", err)
	}
	defer tpm2.FlushContext(rw, sess)
	// like in systemd-pcrlock: authorize the policy via NV (usually authHandle == nv)
	if err := PolicyAuthorizeNVLegacy(rw, nv, nv, sess); err != nil {
		return nil, err
	}
	if usePIN {
		if err := PolicyAuthValueLegacy(rw, sess); err != nil {
			return nil, err
		}
	}
	if err := tpm2.PolicyCommandCode(rw, sess, tpm2.CmdUnseal); err != nil {
		return nil, err
	}
	return tpm2.PolicyGetDigest(rw, sess)
}

// Find the pcrlock NV index for which the trial digest == policyHash from the token.
func autodetectPcrlockNVByPolicy(rw io.ReadWriter, policyAlg tpm2.Algorithm, usePIN bool, expectedPolicy []byte) (tpmutil.Handle, bool) {
	nvs, err := listAllNVIndices(rw)
	if err != nil || len(nvs) == 0 {
		return 0, false
	}
	for _, nv := range nvs {
		// You could filter by NVReadPublic (optional), but the check is cheap — just compute the trial.
		got, err := trialDigestForNV(rw, policyAlg, usePIN, nv)
		if err != nil {
			continue
		}
		if bytes.Equal(got, expectedPolicy) {
			info("pcrlock: matched NV=0x%08x by policy digest", uint32(nv))
			return nv, true
		}
	}
	return 0, false
}

// tpm2bToPublicArea: if srkData looks like TPM2B_PUBLIC, returns the inner TPMT_PUBLIC.
func tpm2bToPublicArea(b []byte) ([]byte, bool) {
	if len(b) < 2 {
		return nil, false
	}
	sz := int(binary.BigEndian.Uint16(b[:2]))
	if sz <= 0 || 2+sz > len(b) {
		return nil, false
	}
	return b[2 : 2+sz], true
}

// listPersistentHandles: returns a list of persistent handles (0x81xxxxxx).
func listPersistentHandles(rw io.ReadWriter) ([]tpmutil.Handle, error) {
	const prop = 0x81000000
	const max = 4096
	capData, _, err := tpm2.GetCapability(rw, tpm2.CapabilityHandles, prop, max)
	if err != nil {
		return nil, err
	}
	var out []tpmutil.Handle
	switch v := any(capData).(type) {
	case []tpmutil.Handle:
		out = append(out, v...)
	case []uint32:
		for _, u := range v {
			out = append(out, tpmutil.Handle(u))
		}
	case []interface{}:
		for _, it := range v {
			switch h := it.(type) {
			case tpmutil.Handle:
				out = append(out, h)
			case uint32:
				out = append(out, tpmutil.Handle(h))
			}
		}
	}
	return out, nil
}

// findStorageParentByPublic: finds a storage parent whose TPMT_PUBLIC matches the token's TPMT_PUBLIC.
func findStorageParentByPublic(rw io.ReadWriter, wantTPMT []byte) (tpmutil.Handle, bool) {
	hs, err := listPersistentHandles(rw)
	if err != nil || len(hs) == 0 {
		return 0, false
	}
	for _, h := range hs {
		pub, _, _, err := tpm2.ReadPublic(rw, h)
		if err != nil {
			continue
		}
		// Must be restricted+decrypt, otherwise it's not a storage parent.
		if (pub.Attributes&tpm2.FlagRestricted) == 0 || (pub.Attributes&tpm2.FlagDecrypt) == 0 {
			continue
		}
		gotTPMT, err := tpmutil.Pack(pub)
		if err != nil {
			continue
		}
		if bytes.Equal(gotTPMT, wantTPMT) {
			return h, true
		}
	}
	return 0, false
}

func openTPM() (io.ReadWriteCloser, error) {
	var dev io.ReadWriteCloser
	var err error

	if enableSwEmulator {
		dev, err = net.Dial("tcp", ":2321") // swtpm emulator is listening at port 2321
	} else {
		dev, err = tpm2.OpenTPM("/dev/tpmrm0")
		if err != nil {
			// Fallback for systems without resource manager
			dev, err = tpm2.OpenTPM("/dev/tpm0")
		}
	}
	if err != nil {
		return nil, err
	}

	if _, err := tpm2.GetManufacturer(dev); err != nil {
		return nil, fmt.Errorf("device is not a TPM 2.0")
	}

	return dev, nil
}

// Waits until a tpm device is available for use. Times out and returns false after 5 seconds.
func tpmAwaitReady() bool {
	timedOut := waitTimeout(&tpmReadyWg, time.Second*5)
	if timedOut {
		info("no tpm devices found after 5 seconds.")
	}
	return !timedOut
}

// Simple detector: 4 bytes as a BE persistent handle (0x81xxxxxx)
func looksLikeTPMHandleBE(b []byte) bool {
	if len(b) < 4 {
		return false
	}
	h := binary.BigEndian.Uint32(b[:4])
	return (h & 0xFF000000) == 0x81000000
}

// Also allow a JSON string with "handle": ... in srkData
func parseSRKHandle(srkData []byte) (tpmutil.Handle, bool) {
	if looksLikeTPMHandleBE(srkData) {
		return tpmutil.Handle(binary.BigEndian.Uint32(srkData[:4])), true
	}
	var node struct {
		Handle any `json:"handle"`
	}
	if json.Unmarshal(srkData, &node) == nil {
		switch v := node.Handle.(type) {
		case float64:
			return tpmutil.Handle(uint32(v)), true
		case string:
			if len(v) == 10 && (v[0:2] == "0x" || v[0:2] == "0X") {
				if x, err := strconv.ParseUint(v[2:], 16, 32); err == nil {
					return tpmutil.Handle(uint32(x)), true
				}
			}
		}
	}
	return 0, false
}

// Returns the hash algorithm by digest length in bytes.
func algFromDigestLen(n int) tpm2.Algorithm {
	switch n {
	case 20:
		return tpm2.AlgSHA1
	case 32:
		return tpm2.AlgSHA256
	case 48:
		return tpm2.AlgSHA384
	case 64:
		return tpm2.AlgSHA512
	default:
		return tpm2.AlgSHA256
	}
}

func tpm2Unseal(public, private []byte, pcrs []int, pcrBank tpm2.Algorithm, policyHash, password []byte, usePolicyAuth bool, srk []byte, preferECC bool, pcrDigests ...[][]byte) ([]byte, error) {

	tpmAwaitReady()
	dev, err := openTPM()
	if err != nil {
		return nil, err
	}
	defer dev.Close()

	var digests [][]byte
	if len(pcrDigests) > 0 {
		digests = pcrDigests[0]
	}
	// Choose the policy algorithm from the child's NameAlg (default SHA256)
	// 1) If the token has an expected policyDigest — use its length as a guide.
	policyAlg := algFromDigestLen(len(policyHash))
	// 2) Extract the CHILD object's NameAlg and simultaneously check the policyDigest length
	var childNameAlg tpm2.Algorithm
	if pub, err := tpm2.DecodePublic(public); err == nil && pub.NameAlg != 0 {
		childNameAlg = pub.NameAlg
		if digestSizeOfAlg(pub.NameAlg) != len(policyHash) {
			info("TPM policy note: child.NameAlg=%v (%d bytes) != expected policy len=%d bytes; proceeding with policyAlg=%v",
				pub.NameAlg, digestSizeOfAlg(pub.NameAlg), len(policyHash), policyAlg)
		}
	}
	// ADD PolicyAuthValue according to the token's policy (tpm2-pin=true)
	sessHandle, _, nonceCaller, nonceTPM, err := policyPCRSession(
		dev, pcrs, policyAlg, policyHash, usePolicyAuth, pcrBank, digests)
	if err != nil {
		return nil, err
	}
	defer tpm2.FlushContext(dev, sessHandle)

	// 1) Determine the parent: either from SRK in the token, or create a transient Primary
	var (
		parent    tpmutil.Handle
		needFlush bool
	)
	if len(srk) > 0 {
		if h, ok := parseSRKHandle(srk); ok && h != 0 {
			// Check that the handle is valid and that it's a storage parent
			if pub, _, _, e := tpm2.ReadPublic(dev, h); e == nil {
				attrs := pub.Attributes
				if (attrs&tpm2.FlagRestricted) != 0 && (attrs&tpm2.FlagDecrypt) != 0 {
					info("Using SRK handle from token: 0x%08x", uint32(h))
					parent = h
				} else {
					info("Provided SRK handle 0x%08x is not a storage parent (attrs=%#x), will create transient", uint32(h), attrs)
				}

			} else {
				info("Provided SRK handle 0x%08x not readable: %v (will create transient)", uint32(h), e)
			}

		} else if tpmt, ok := tpm2bToPublicArea(srk); ok {
			// If the token contains a TPM2B_PUBLIC — select the parent by the public area
			if h2, ok2 := findStorageParentByPublic(dev, tpmt); ok2 {
				info("Using SRK handle matched by public: 0x%08x", uint32(h2))
				parent = h2
			}
		}
	}

	if parent == 0 {
		// Create a transient storage primary (ECC or RSA as desired)
		tmpl := tpm2.Public{
			Type:       tpm2.AlgECC,
			NameAlg:    tpm2.AlgSHA256,
			Attributes: tpm2.FlagStorageDefault,
			ECCParameters: &tpm2.ECCParams{
				Symmetric: defaultSymScheme,
				CurveID:   tpm2.CurveNISTP256,
			},
		}
		if !preferECC {
			tmpl = tpm2.Public{
				Type:       tpm2.AlgRSA,
				NameAlg:    tpm2.AlgSHA256,
				Attributes: tpm2.FlagStorageDefault,
				RSAParameters: &tpm2.RSAParams{
					Symmetric: defaultSymScheme,
					KeyBits:   2048,
				},
			}
		}
		h, _, e := tpm2.CreatePrimary(dev, tpm2.HandleOwner, tpm2.PCRSelection{}, "", "", tmpl)
		if e != nil {
			return nil, fmt.Errorf("clevis.go/tpm2: can't create primary key: %v", e)
		}
		parent = h
		needFlush = true
	}
	if needFlush {
		defer tpm2.FlushContext(dev, parent)
	}

	// 2) Load the child. If you get "parameter 2", try swapping.
	tryLoad := func(p tpmutil.Handle, pub, priv []byte) (tpmutil.Handle, error) {
		h, _, e1 := tpm2.Load(dev, p, "", pub, priv)
		if e1 == nil {
			return h, nil
		}
		// if PUBLIC/PRIVATE are swapped in the blob — try the other way around
		info("Load failed (%v); retry with swapped PRIV/PUB", e1)
		if h2, _, e2 := tpm2.Load(dev, p, "", priv, pub); e2 == nil {
			return h2, nil
		} else {
			return tpm2.HandleNull, fmt.Errorf("clevis.go/tpm2: unable to load data: %v; swap failed: %v", e1, e2)
		}
	}

	objectHandle, err := tryLoad(parent, public, private)
	if err != nil {
		return nil, err
	}
	defer tpm2.FlushContext(dev, objectHandle)

	// IMPORTANT: HMAC key for Unseal = (sessionKey||authValue).
	// In our configuration sessionKey is empty, so this is exactly the object's RAW authValue.
	// Here `password` is the authValue passed by the call tpm2Unseal(..., password=authValue, ...).
	authAlg := childNameAlg
	if authAlg == 0 {
		authAlg = policyAlg
	}
	authValueHMAC := password // expected: 32-byte DK with tpm2-pin+tpm2-salt; may be nil if there's no PIN
	if l := len(authValueHMAC); l > 0 {
		h := sha256.Sum256(authValueHMAC)
		info("Unseal authValue: len=%d sha256=%x", l, h)
	} else {
		info("Unseal authValue: EMPTY (object may be without PIN)")
	}

	// Helper: check for RC=BAD_AUTH (0x98e)
	isBadAuth := func(err error) bool {
		if err == nil {
			return false
		}
		// parseUnsealResponse returns "TPM RC=0x0000098e"
		return strings.Contains(err.Error(), "TPM RC=0x0000098e")
	}

	// Unseal with explicit attributes: only ContinueSession, without Decrypt/Encrypt.
	unsealWithAuth := func(auth []byte) ([]byte, error) {
		// auth = RAW dk (32 bytes) for PIN+salt; otherwise — depends on the no-salt case.
		return UnsealWithSessionEx(
			dev,
			objectHandle,
			sessHandle,
			auth,
			policyAlg, // SHA256 in your case
			nonceCaller,
			nonceTPM,
			tpm2.AttrContinueSession,
		)
	}
	// 1) First attempt — with what we have (RAW 32 in our configuration)
	unsealed, err := unsealWithAuth(authValueHMAC)

	if err == nil {
		return unsealed, nil
	}
	// 2) If it's BAD_AUTH — try compatible alternatives (for "non-standard" enrolled objects):
	if isBadAuth(err) {
		// 🔁 Fallback #1 (compatibility): some "non-standard" enroll tools store as authValue not the DK, but SHA256(Base64(DK)) trimmed.
		if len(password) == 32 && !isAllBase64ASCII(password) {
			b64 := []byte(base64.StdEncoding.EncodeToString(password))
			alt := deriveAuthFromPIN(b64, tpm2.AlgSHA256) // SHA256(b64) with trimming of trailing zeros
			info("Retry Unseal with compat authValue = SHA256(Base64(dk)) trimmed")
			if altData, err2 := unsealWithAuth(alt); err2 == nil {
				return altData, nil
			} else if !isBadAuth(err2) {
				return nil, err2
			}
		}
		// 🔁 Fallback #2: if we were given Base64(DK) as text — decode to RAW DK and try that.
		if len(password) == 44 && isAllBase64ASCII(password) {
			if raw, decErr := base64.StdEncoding.DecodeString(string(password)); decErr == nil && len(raw) == 32 {
				info("Retry Unseal with authValue = decoded RAW DK from Base64")
				if altData, err2 := unsealWithAuth(raw); err2 == nil {
					return altData, nil
				} else if !isBadAuth(err2) {
					return nil, err2
				}
			}
		}
		// 🔁 Fallback #3: the object might be without a PIN → try with empty auth
		info("Retry Unseal with EMPTY auth (object may have no PIN)")
		if alt, err3 := unsealWithAuth(nil); err3 == nil {
			return alt, nil
		} else if !isBadAuth(err3) {
			// If the error is not BAD_AUTH — return it (so we don't mask it)
			return nil, err3
		}
	}
	// If we've reached here — return the original error
	return nil, err
}

// isAllBase64ASCII — small helper to check that the bytes are printable Base64.
func isAllBase64ASCII(b []byte) bool {
	for _, c := range b {
		if !(c == '+' || c == '/' || c == '=' || (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')) {
			return false
		}
	}
	return true
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
func policyPCRSession(dev io.ReadWriteCloser, pcrs []int, policyAlg tpm2.Algorithm, expectedDigest []byte, usePassword bool, pcrBank tpm2.Algorithm, pcrDigests [][]byte) (handle tpmutil.Handle, policy []byte, nonceCaller []byte, nonceTPM []byte, retErr error) {

	// This session assumes the bus is trusted, so we:
	// - use nil for tpmkey, encrypted salt, and symmetric
	// - use and all-zeros caller nonce, and ignore the returned nonce
	// As we are creating a plain TPM session, we:
	// - setup a policy session
	// - don't bind the session to any particular key
	// Most stable on this TPM: nonce = digestSize(authHash), symmetric = ALG_NULL.
	nlen := digestSizeOfAlg(policyAlg) // 32 for SHA256
	nonce := make([]byte, nlen)
	if _, err := rand.Read(nonce); err != nil {
		return tpm2.HandleNull, nil, nil, nil, fmt.Errorf("rand nonce: %w", err)
	}
	sessHandle, nonceTPM, err := tpm2.StartAuthSession(
		dev,
		/*tpmkey=*/ tpm2.HandleNull,
		/*bindkey=*/ tpm2.HandleNull,
		/*nonceCaller=*/ nonce,
		/*encryptedSalt=*/ nil,
		/*sessionType=*/ tpm2.SessionPolicy,
		/*symmetric=*/ tpm2.AlgNull,
		/*authHash=*/ policyAlg,
	)
	if err != nil {
		return tpm2.HandleNull, nil, nil, nil, fmt.Errorf("unable to start session: %v", err)
	}
	info("StartAuthSession ok: nonce=digestSize, symmetric=NULL (TPM nonce len=%d)", len(nonceTPM))

	pcrSelection := tpm2.PCRSelection{Hash: pcrBank, PCRs: pcrs}

	policyTrace(dev, sessHandle, "start")

	// (A) FILELESS pcrlock: try to find an NV in the TPM by matching the final digest
	if nv, ok := autodetectPcrlockNVByPolicy(dev, policyAlg, usePassword, expectedDigest); ok {
		if err := PolicyAuthorizeNVLegacy(dev, nv, nv, sessHandle); err != nil {
			return tpm2.HandleNull, nil, nil, nil, fmt.Errorf("PolicyAuthorizeNV(%#x) failed: %w", uint32(nv), err)
		}
		policyTrace(dev, sessHandle, "after PolicyAuthorizeNV(auto)")
		goto AUTH_AND_CC
	}
	// If systemd stored ready-made PCR digests — reproduce them (and OR them if there are several)
	switch len(pcrDigests) {
	case 0:
		if err := tpm2.PolicyPCR(dev, sessHandle, nil, pcrSelection); err != nil {
			return tpm2.HandleNull, nil, nil, nil, fmt.Errorf("policy PCR (live) failed: %v", err)
		}
	case 1:
		if err := tpm2.PolicyPCR(dev, sessHandle, pcrDigests[0], pcrSelection); err != nil {
			return tpm2.HandleNull, nil, nil, nil, fmt.Errorf("policy PCR (precomputed) failed: %v", err)
		}
	default:
		// Build branches in TRIAL sessions and join with PolicyOR
		branch := make([][]byte, 0, len(pcrDigests))
		for _, d := range pcrDigests {
			th, _, err := tpm2.StartAuthSession(dev, tpm2.HandleNull, tpm2.HandleNull, nonceTPM, nil, tpm2.SessionTrial, tpm2.AlgNull, policyAlg)
			if err != nil {
				return tpm2.HandleNull, nil, nil, nil, fmt.Errorf("trial start: %v", err)
			}
			if err := tpm2.PolicyPCR(dev, th, d, pcrSelection); err != nil {
				_ = tpm2.FlushContext(dev, th)
				return tpm2.HandleNull, nil, nil, nil, fmt.Errorf("trial PolicyPCR: %v", err)
			}
			dg, err := tpm2.PolicyGetDigest(dev, th)
			if err != nil {
				_ = tpm2.FlushContext(dev, th)
				return tpm2.HandleNull, nil, nil, nil, fmt.Errorf("trial get digest: %v", err)
			}
			_ = tpm2.FlushContext(dev, th)
			branch = append(branch, dg)
		}
		if err := policyORLegacy(dev, sessHandle, branch, policyAlg); err != nil {
			return tpm2.HandleNull, nil, nil, nil, fmt.Errorf("PolicyOR failed: %v", err)
		}
	}
	// Trace and early check after PolicyPCR
	policyTrace(dev, sessHandle, "after PolicyPCR")
	policyTraceExpect(dev, sessHandle, "checkpoint after PolicyPCR", expectedDigest)
	if len(expectedDigest) > 0 {
		if d, _ := tpm2.PolicyGetDigest(dev, sessHandle); bytes.Equal(d, expectedDigest) {
			return sessHandle, d, nonce, nonceTPM, nil
		}
	}

AUTH_AND_CC:
	if usePassword {
		if err := PolicyAuthValueLegacy(dev, sessHandle); err != nil {
			return tpm2.HandleNull, nil, nil, nil, err
		}
		policyTrace(dev, sessHandle, "after PolicyAuthValue")
	}
	// If at this stage the digest already matches the expected — do NOT add CommandCode
	if len(expectedDigest) > 0 {
		policyTraceExpect(dev, sessHandle, "checkpoint after PolicyAuthValue", expectedDigest)
		if d, _ := tpm2.PolicyGetDigest(dev, sessHandle); bytes.Equal(d, expectedDigest) {
			return sessHandle, d, nonce, nonceTPM, nil
		}
	}
	if hasCmdlineFlag("rd.tpm2.policy-unseal=1") {
		if err := tpm2.PolicyCommandCode(dev, sessHandle, tpm2.CmdUnseal); err != nil {
			return handle, nil, nil, nil, fmt.Errorf("PolicyCommandCode: %w", err)
		}
		// (optional log)
		info("TPM policy trace: after PolicyCommandCode (enabled by flag)")
	} else {
		info("TPM policy trace: skipping PolicyCommandCode (enable with rd.tpm2.policy-unseal=1)")
	}
	policyTrace(dev, sessHandle, "after PolicyCommandCode")
	policy, _ = tpm2.PolicyGetDigest(dev, sessHandle)
	policyTraceExpect(dev, sessHandle, "final", expectedDigest)
	if len(expectedDigest) > 0 && !bytes.Equal(policy, expectedDigest) {
		return tpm2.HandleNull, nil, nil, nil, fmt.Errorf("current policy digest does not match stored policy digest")
	}
	return sessHandle, policy, nonce, nonceTPM, nil
}
