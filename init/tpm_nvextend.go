package main

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// nvExtend runs TPM2_NV_Extend. go-tpm v0.9.8 has the command code but no
// typed wrapper; this builds the same wire format Execute would for NVWrite,
// with one policy/HMAC authorization session and no parameter encryption.
func nvExtend(t transport.TPM, auth tpm2.AuthHandle, nv tpm2.NamedHandle, digest []byte) error {
	if auth.Auth == nil {
		return fmt.Errorf("NV_Extend: missing auth session")
	}
	if len(digest) == 0 {
		return fmt.Errorf("NV_Extend: empty digest")
	}

	cc := tpm2.TPMCCNVExtend
	parms := tpm2.Marshal(&tpm2.TPM2BMaxNVBuffer{Buffer: digest})

	names := make([]tpm2.TPM2BName, 0, 2)
	if n := auth.KnownName(); n != nil {
		names = append(names, *n)
	} else {
		names = append(names, tpm2.TPM2BName{})
	}
	if n := nv.KnownName(); n != nil {
		names = append(names, *n)
	} else {
		names = append(names, tpm2.TPM2BName{})
	}

	sess := auth.Auth
	if err := sess.Init(t); err != nil {
		return fmt.Errorf("NV_Extend: session init: %w", err)
	}
	if err := sess.NewNonceCaller(); err != nil {
		return fmt.Errorf("NV_Extend: nonce: %w", err)
	}

	authCmd, err := sess.Authorize(cc, parms, nil, names, 0)
	if err != nil {
		_ = sess.CleanupFailure(t)
		return fmt.Errorf("NV_Extend: authorize: %w", err)
	}

	var sessArea bytes.Buffer
	_ = binary.Write(&sessArea, binary.BigEndian, uint32(0)) // size placeholder
	sessArea.Write(tpm2.Marshal(authCmd))
	sessBytes := sessArea.Bytes()
	binary.BigEndian.PutUint32(sessBytes[0:4], uint32(len(sessBytes)-4))

	var handles bytes.Buffer
	_ = binary.Write(&handles, binary.BigEndian, auth.HandleValue())
	_ = binary.Write(&handles, binary.BigEndian, nv.HandleValue())

	bodyLen := 10 + handles.Len() + len(sessBytes) + len(parms)
	hdr := tpm2.TPMCmdHeader{
		Tag:         tpm2.TPMSTSessions,
		Length:      uint32(bodyLen),
		CommandCode: cc,
	}
	cmd := append(tpm2.Marshal(&hdr), handles.Bytes()...)
	cmd = append(cmd, sessBytes...)
	cmd = append(cmd, parms...)

	rsp, err := t.Send(cmd)
	if err != nil {
		_ = sess.CleanupFailure(t)
		return fmt.Errorf("NV_Extend: send: %w", err)
	}
	if err := decodeTPMResponseHeader(rsp); err != nil {
		_ = sess.CleanupFailure(t)
		return fmt.Errorf("NV_Extend: %w", err)
	}
	return nil
}

func decodeTPMResponseHeader(rsp []byte) error {
	if len(rsp) < 10 {
		return fmt.Errorf("TPM response too short (%d)", len(rsp))
	}
	var hdr tpm2.TPMCmdHeader
	if _, err := tpm2.Unmarshal[tpm2.TPMCmdHeader](rsp[:10]); err != nil {
		// Fall back: parse RC at offset 6 on error responses.
		rc := binary.BigEndian.Uint32(rsp[6:10])
		if rc != 0 {
			return tpm2.TPMRC(rc)
		}
		return err
	}
	_ = hdr
	rc := binary.BigEndian.Uint32(rsp[6:10])
	if tpm2.TPMRC(rc) != tpm2.TPMRCSuccess {
		return tpm2.TPMRC(rc)
	}
	return nil
}
