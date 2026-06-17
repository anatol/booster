package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
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
