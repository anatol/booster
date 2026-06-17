package main

import (
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

// parseSignedToken extracts the signed (authorized) PCR policy fields from a
// systemd-tpm2 token payload. A token is "signed" when it carries tpm2_pubkey
// (written by `systemd-cryptenroll --tpm2-public-key`); such a token's sealed
// blob is bound to the key via TPM2_PolicyAuthorize rather than to literal PCR
// values, so the same blob keeps unsealing across kernel updates as long as a
// valid signature for the current PCRs is available.
//
// ok is false with a nil error when the token has no tpm2_pubkey — i.e. it is a
// literal-PCR token that the existing unseal path handles.
func parseSignedToken(payload []byte) (pub *rsa.PublicKey, pubkeyPCRs []int, ok bool, err error) {
	var node struct {
		Pubkey     string `json:"tpm2_pubkey"`
		PubkeyPCRs []int  `json:"tpm2_pubkey_pcrs"`
	}
	if err := json.Unmarshal(payload, &node); err != nil {
		return nil, nil, false, err
	}
	if node.Pubkey == "" {
		return nil, nil, false, nil
	}
	der, err := base64.StdEncoding.DecodeString(node.Pubkey)
	if err != nil {
		return nil, nil, false, fmt.Errorf("tpm2_pubkey: %v", err)
	}
	key, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, nil, false, fmt.Errorf("tpm2_pubkey: %v", err)
	}
	rsaKey, isRSA := key.(*rsa.PublicKey)
	if !isRSA {
		// systemd's signed-policy verify path is RSA-only.
		return nil, nil, false, fmt.Errorf("tpm2_pubkey: unsupported key type %T (only RSA)", key)
	}
	return rsaKey, node.PubkeyPCRs, true, nil
}

// pcrSignature is one entry of systemd's PCR signature JSON (produced by
// systemd-measure). The top-level document maps a bank name ("sha256", …) to a
// list of these. Sig is standard base64 in the JSON and decodes into []byte
// automatically via encoding/json.
type pcrSignature struct {
	PCRs []int  `json:"pcrs"`
	Pkfp string `json:"pkfp"` // hex SHA256 of the PKCS#1 DER public key
	Pol  string `json:"pol"`  // hex of the signed PolicyPCR digest
	Sig  []byte `json:"sig"`  // RSA (RSASSA, SHA256) signature over Pol
}

// parseSignatureJSON parses systemd's {bank: [pcrSignature, …]} signature file.
func parseSignatureJSON(data []byte) (map[string][]pcrSignature, error) {
	var m map[string][]pcrSignature
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("PCR signature JSON: %v", err)
	}
	return m, nil
}

// rsaPublicKeyFingerprint returns systemd's "pkfp": the lowercase hex SHA256 of
// the PKCS#1 DER ("i2d_PublicKey") encoding of the RSA public key — NOT the SPKI
// form. This is what the signature entries are keyed by.
func rsaPublicKeyFingerprint(pub *rsa.PublicKey) string {
	sum := sha256.Sum256(x509.MarshalPKCS1PublicKey(pub))
	return hex.EncodeToString(sum[:])
}

// selectSignature returns the signature entry for bank whose public-key
// fingerprint matches pub and whose signed policy digest equals polDigest (the
// PolicyPCR digest computed for the current PCR values).
func selectSignature(sigs map[string][]pcrSignature, bank string, pub *rsa.PublicKey, polDigest []byte) (pcrSignature, error) {
	fp := rsaPublicKeyFingerprint(pub)
	want := hex.EncodeToString(polDigest)
	for _, e := range sigs[bank] {
		if strings.EqualFold(e.Pkfp, fp) && strings.EqualFold(e.Pol, want) {
			return e, nil
		}
	}
	return pcrSignature{}, fmt.Errorf("no PCR signature for bank %q matching key %s and policy %s", bank, fp, want)
}
