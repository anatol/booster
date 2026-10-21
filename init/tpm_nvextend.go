package main

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// nvExtend runs TPM2_NV_Extend on an index whose write is authorized by
// policySession (TPMA_NV_POLICYWRITE). go-tpm v0.9.8 defines the command code
// but no command type, and its executor is unexported, so the command is
// marshaled here. The policy session carries no HMAC: it is unbound and unsalted
// and the write policy has no PolicyAuthValue, as in systemd's tpm2_make_policy_session.
func nvExtend(t transport.TPM, nvIndex tpm2.TPMHandle, policySession tpm2.TPMHandle, data []byte) error {
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}

	var auth []byte
	auth = binary.BigEndian.AppendUint32(auth, uint32(policySession))
	auth = binary.BigEndian.AppendUint16(auth, uint16(len(nonce)))
	auth = append(auth, nonce...)
	auth = append(auth, 0) // sessionAttributes: no continueSession, the TPM flushes it
	auth = binary.BigEndian.AppendUint16(auth, 0)

	var cmd []byte
	cmd = binary.BigEndian.AppendUint16(cmd, uint16(tpm2.TPMSTSessions))
	cmd = binary.BigEndian.AppendUint32(cmd, 0) // size, patched below
	cmd = binary.BigEndian.AppendUint32(cmd, uint32(tpm2.TPMCCNVExtend))
	cmd = binary.BigEndian.AppendUint32(cmd, uint32(nvIndex)) // authHandle
	cmd = binary.BigEndian.AppendUint32(cmd, uint32(nvIndex)) // nvIndex
	cmd = binary.BigEndian.AppendUint32(cmd, uint32(len(auth)))
	cmd = append(cmd, auth...)
	cmd = binary.BigEndian.AppendUint16(cmd, uint16(len(data)))
	cmd = append(cmd, data...)
	binary.BigEndian.PutUint32(cmd[2:6], uint32(len(cmd)))

	rsp, err := t.Send(cmd)
	if err != nil {
		return fmt.Errorf("NV_Extend: %w", err)
	}
	if len(rsp) < 10 {
		return fmt.Errorf("NV_Extend: short response (%d bytes)", len(rsp))
	}
	if rc := tpm2.TPMRC(binary.BigEndian.Uint32(rsp[6:10])); rc != tpm2.TPMRCSuccess {
		return fmt.Errorf("NV_Extend: %w", rc)
	}
	return nil
}
