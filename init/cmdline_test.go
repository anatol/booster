package main

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseParamsInvalidLuksOptions(t *testing.T) {
	luksMappings = nil

	require.Error(t, parseParams("rd.luks.name=ab6d7d78-b816-4495-928d-766d6607035e=root rd.luks.name=7843d77f-cdd6-4289-a4de-a708c4aacede=swap rd.luks.name=7f28c723-fd6b-4640-bc94-9366edd8880d=cache root=UUID=e8e81fc3-8f81-4a3a-ac3d-aab36aa0c45f video=efifb:on add_efi_memmap zswap.enabled=1 zswap.max_pool_percent=100 zswap.zpool=z3fold resume=/dev/mapper/swap acpi=copy_dsdt rd.luks.options=tpm2-device=auto"))
}

func TestParseParams(t *testing.T) {
	luksMappings = nil

	require.NoError(t, parseParams("rd.luks.name=ab6d7d78-b816-4495-928d-766d6607035e=root rd.luks.name=7843d77f-cdd6-4289-a4de-a708c4aacede=swap rd.luks.name=7f28c723-fd6b-4640-bc94-9366edd8880d=cache root=UUID=e8e81fc3-8f81-4a3a-ac3d-aab36aa0c45f video=efifb:on add_efi_memmap rd.luks.options=no-read-workqueue zswap.enabled=1 zswap.max_pool_percent=100 zswap.zpool=z3fold resume=/dev/mapper/swap acpi=copy_dsdt"))
	require.Equal(t, "/dev/mapper/swap", cmdResume.data)
	require.Equal(t, refPath, cmdResume.format)
	require.Equal(t, "e8e81fc3-8f81-4a3a-ac3d-aab36aa0c45f", cmdRoot.data.(UUID).toString())
	require.Equal(t, refFsUUID, cmdRoot.format)
	require.Len(t, luksMappings, 3)

	root := luksMappings[0]
	require.Equal(t, "root", root.name)
	require.Equal(t, []string{"no-read-workqueue"}, root.options)
	require.Equal(t, refFsUUID, root.ref.format)
	require.Equal(t, "ab6d7d78-b816-4495-928d-766d6607035e", root.ref.data.(UUID).toString())

	swap := luksMappings[1]
	require.Equal(t, "swap", swap.name)
	require.Equal(t, []string{"no-read-workqueue"}, swap.options)
	require.Equal(t, refFsUUID, swap.ref.format)
	require.Equal(t, "7843d77f-cdd6-4289-a4de-a708c4aacede", swap.ref.data.(UUID).toString())

	cache := luksMappings[2]
	require.Equal(t, "cache", cache.name)
	require.Equal(t, []string{"no-read-workqueue"}, cache.options)
	require.Equal(t, refFsUUID, cache.ref.format)
	require.Equal(t, "7f28c723-fd6b-4640-bc94-9366edd8880d", cache.ref.data.(UUID).toString())
}
