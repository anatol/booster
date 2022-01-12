package main

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseParams(t *testing.T) {
	require.Error(t, parseParams("rd.luks.name=ab6d7d78-b816-4495-928d-766d6607035e=root rd.luks.name=7843d77f-cdd6-4289-a4de-a708c4aacede=swap rd.luks.name=7f28c723-fd6b-4640-bc94-9366edd8880d=cache root=UUID=e8e81fc3-8f81-4a3a-ac3d-aab36aa0c45f video=efifb:on add_efi_memmap zswap.enabled=1 zswap.max_pool_percent=100 zswap.zpool=z3fold resume=/dev/mapper/swap acpi=copy_dsdt rd.luks.options=tpm2-device=auto"))

	require.NoError(t, parseParams("rd.luks.name=ab6d7d78-b816-4495-928d-766d6607035e=root rd.luks.name=7843d77f-cdd6-4289-a4de-a708c4aacede=swap rd.luks.name=7f28c723-fd6b-4640-bc94-9366edd8880d=cache root=UUID=e8e81fc3-8f81-4a3a-ac3d-aab36aa0c45f video=efifb:on add_efi_memmap zswap.enabled=1 zswap.max_pool_percent=100 zswap.zpool=z3fold resume=/dev/mapper/swap acpi=copy_dsdt"))
	require.Equal(t, "/dev/mapper/swap", cmdResume.data)
	require.Equal(t, refPath, cmdResume.format)
	require.Len(t, luksMappings, 1) // only last item is added to the mapping
}
